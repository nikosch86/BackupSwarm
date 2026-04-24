package cli

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/daemon"
	"backupswarm/pkg/token"
)

func newJoinCmd(dataDir *string) *cobra.Command {
	var (
		advertisedAddr string
		timeout        time.Duration
		tokenFile      string
		thenRun        bool
		backupDir      string
		chunkSize      int
		scanInterval   time.Duration
	)
	cmd := &cobra.Command{
		Use:   "join [token]",
		Short: "Accept an invite token, verify the peer over TLS, and persist",
		Long: "Accept an invite token (positional arg or --token-file), dial " +
			"the introducer over QUIC with TLS pubkey pinning, exchange the " +
			"join handshake, and persist the peer. --token-file polls the " +
			"path until the file appears (bounded by --timeout) so " +
			"orchestrators like docker-compose can land the token in a " +
			"shared volume before the introducer has written it. --then-run " +
			"transitions into the sync daemon after the handshake so the " +
			"command stands up a node end-to-end.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if tokenFile != "" && len(args) > 0 {
				return fmt.Errorf("--token-file cannot be combined with a positional <token>")
			}
			if tokenFile == "" && len(args) == 0 {
				return fmt.Errorf("<token> is required (or pass --token-file)")
			}

			var tokStr string
			if tokenFile != "" {
				waitCtx, waitCancel := withTimeout(cmd.Context(), timeout)
				var err error
				tokStr, err = waitForTokenFile(waitCtx, tokenFile)
				waitCancel()
				if err != nil {
					return err
				}
			} else {
				tokStr = args[0]
			}

			sess, err := openPeerSession(*dataDir)
			if err != nil {
				return err
			}
			sessHandedOff := false
			defer func() {
				if !sessHandedOff {
					_ = sess.Close()
				}
			}()

			ctx, cancel := withTimeout(cmd.Context(), timeout)
			peer, err := bootstrap.DoJoin(ctx, tokStr, sess.id.PrivateKey, advertisedAddr, sess.peerStore)
			cancel()
			if err != nil {
				return fmt.Errorf("join: %w", err)
			}
			slog.InfoContext(cmd.Context(), "joined peer",
				"peer_pub", hex.EncodeToString(peer.PubKey),
				"peer_addr", peer.Addr,
			)

			if !thenRun {
				return nil
			}
			// Hand off the open peer store to the daemon; daemon.Run
			// closes it on exit. The daemon binds its own listener from
			// ListenAddr — we have no pre-bound listener on the joiner
			// side (DoJoin dialed instead of listening).
			sessHandedOff = true
			return daemon.Run(cmd.Context(), daemon.Options{
				DataDir:      sess.dir,
				BackupDir:    backupDir,
				ListenAddr:   advertisedAddr,
				PeerStore:    sess.peerStore,
				ChunkSize:    chunkSize,
				ScanInterval: scanInterval,
				Progress:     cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVar(&advertisedAddr, "listen", "", "Our advertised listen address (shared with --then-run as the daemon's listener)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Dial / token-file wait timeout")
	cmd.Flags().StringVar(&tokenFile, "token-file", "", "Read the token from this file path, polling until it exists")
	cmd.Flags().BoolVar(&thenRun, "then-run", false, "After the handshake, transition into the sync daemon")
	cmd.Flags().StringVar(&backupDir, "backup-dir", "", "Directory to keep synced (used with --then-run)")
	cmd.Flags().IntVar(&chunkSize, "chunk-size", 1<<20, "Target chunk size in bytes (used with --then-run)")
	cmd.Flags().DurationVar(&scanInterval, "scan-interval", 60*time.Second, "Period between incremental scan passes (used with --then-run)")
	return cmd
}

// waitForTokenFile polls path until it contains a decodable token, or
// until ctx is cancelled. Used by join's --token-file flag to absorb
// the docker-compose-style race where the invitee starts before the
// inviter has written the shared token.
func waitForTokenFile(ctx context.Context, path string) (string, error) {
	const pollInterval = 250 * time.Millisecond
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			tokStr := strings.TrimSpace(string(data))
			if _, _, decodeErr := token.Decode(tokStr); decodeErr == nil {
				return tokStr, nil
			}
			// File exists but not yet a valid token (partial write or
			// stale content). Treat as "keep waiting".
		} else if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, io.EOF) {
			return "", fmt.Errorf("read token file %q: %w", path, err)
		}
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("waiting for token file %q: %w", path, ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}
