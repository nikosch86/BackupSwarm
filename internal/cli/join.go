package cli

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/bootstrap"
)

func newJoinCmd(dataDir *string) *cobra.Command {
	var advertisedAddr string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "join <token>",
		Short: "Accept an invite token, verify the peer over TLS, and persist",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			sess, err := openPeerSession(*dataDir)
			if err != nil {
				return err
			}
			defer func() { _ = sess.Close() }()

			ctx, cancel := withTimeout(cmd.Context(), timeout)
			defer cancel()
			peer, err := bootstrap.DoJoin(ctx, args[0], sess.id.PrivateKey, advertisedAddr, sess.peerStore)
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
