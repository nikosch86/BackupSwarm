package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
)

const peerStoreFile = "peers.db"

func newJoinCmd(dataDir *string) *cobra.Command {
	var advertisedAddr string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "join <token>",
		Short: "Accept an invite token, verify the peer over TLS, and persist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}
			id, _, err := node.Ensure(dir)
			if err != nil {
				return fmt.Errorf("ensure identity: %w", err)
			}
			peerStore, err := peers.Open(filepath.Join(dir, peerStoreFile))
			if err != nil {
				return fmt.Errorf("open peer store: %w", err)
			}
			defer func() { _ = peerStore.Close() }()

			ctx := cmd.Context()
			if timeout > 0 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, timeout)
				defer cancel()
			}
			peer, err := bootstrap.DoJoin(ctx, args[0], id.PrivateKey, advertisedAddr, peerStore)
			if err != nil {
				return fmt.Errorf("join: %w", err)
			}
			slog.InfoContext(ctx, "joined peer",
				"peer_pub", hex.EncodeToString(peer.PubKey),
				"peer_addr", peer.Addr,
			)
			return nil
		},
	}
	cmd.Flags().StringVar(&advertisedAddr, "listen", "", "Our advertised listen address for peers to dial us back (optional)")
	cmd.Flags().DurationVar(&timeout, "timeout", 30*time.Second, "Dial timeout")
	return cmd
}
