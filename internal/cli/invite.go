package cli

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/daemon"
	bsquic "backupswarm/internal/quic"
	"backupswarm/pkg/token"
)

func newInviteCmd(dataDir *string) *cobra.Command {
	var (
		listenAddr string
		timeout    time.Duration
		tokenOut   string
		thenRun    bool
	)
	cmd := &cobra.Command{
		Use:   "invite",
		Short: "Print an invite token and wait for one peer to join",
		Long: "Generate an invite token, open a QUIC listener, and block for " +
			"one incoming join handshake. With --then-run, transition into " +
			"the sync daemon (storage-peer role) after the handshake completes " +
			"so the same command can stand up a node end-to-end. --token-out " +
			"also writes the printed token to a file (atomic rename) for " +
			"orchestrated setups like docker-compose that share the token via " +
			"a volume.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if listenAddr == "" {
				return fmt.Errorf("--listen is required (the address peers will dial)")
			}
			sess, err := openPeerSession(*dataDir)
			if err != nil {
				return err
			}
			// Ownership of sess and listener is handed off to daemon.Run
			// when --then-run fires; these flags guard against double-close.
			sessHandedOff := false
			defer func() {
				if !sessHandedOff {
					_ = sess.Close()
				}
			}()

			listener, err := bsquic.Listen(listenAddr, sess.id.PrivateKey)
			if err != nil {
				return fmt.Errorf("listen on %q: %w", listenAddr, err)
			}
			listenerHandedOff := false
			defer func() {
				if !listenerHandedOff {
					_ = listener.Close()
				}
			}()

			// Use the listener's actual bound addr so ":0" (ephemeral
			// port) still produces a usable token.
			tokStr, err := token.Encode(listener.Addr().String(), sess.id.PublicKey)
			if err != nil {
				return fmt.Errorf("encode token: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), tokStr)
			if tokenOut != "" {
				if err := writeTokenFile(tokenOut, tokStr); err != nil {
					return fmt.Errorf("write token file: %w", err)
				}
			}

			ctx, cancel := withTimeout(cmd.Context(), timeout)
			defer cancel()
			peer, err := bootstrap.AcceptJoin(ctx, listener, sess.peerStore)
			if err != nil {
				return fmt.Errorf("accept join: %w", err)
			}
			slog.InfoContext(ctx, "peer joined",
				"peer_pub", hex.EncodeToString(peer.PubKey),
				"peer_addr", peer.Addr,
			)

			if !thenRun {
				return nil
			}
			// Hand off listener + peer store to the daemon, which runs
			// in storage-peer-only mode (no BackupDir). daemon.Run owns
			// closing both on exit.
			listenerHandedOff = true
			sessHandedOff = true
			return daemon.Run(cmd.Context(), daemon.Options{
				DataDir:   sess.dir,
				Listener:  listener,
				PeerStore: sess.peerStore,
				Progress:  cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVar(&listenAddr, "listen", "", "Address to listen on (host:port)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Maximum time to wait for a joiner (0 = no timeout)")
	cmd.Flags().StringVar(&tokenOut, "token-out", "", "Write the printed token to this file (atomic)")
	cmd.Flags().BoolVar(&thenRun, "then-run", false, "After the handshake, transition into the sync daemon (storage-peer role)")
	return cmd
}

// tokenTempFile narrows the surface writeTokenFile needs from a
// temp-file handle, so the white-box test can swap in a fake whose
// Write/Close leg fails — following the same seam pattern internal/store
// uses for its atomic Put.
type tokenTempFile interface {
	WriteString(string) (int, error)
	Close() error
	Name() string
}

// createTokenTempFunc is the seam that lets tests inject a tokenTempFile
// whose methods fail. Production never reassigns it.
var createTokenTempFunc = func(dir, pattern string) (tokenTempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// writeTokenFile writes tok+newline to path via a same-directory temp
// file + rename, so concurrent readers never observe a partially-written
// token. Used by --token-out.
func writeTokenFile(path, tok string) error {
	dir := filepath.Dir(path)
	tmp, err := createTokenTempFunc(dir, ".token-")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.WriteString(tok + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	committed = true
	return nil
}
