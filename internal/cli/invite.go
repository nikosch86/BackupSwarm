package cli

import (
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/bootstrap"
	bsquic "backupswarm/internal/quic"
	"backupswarm/pkg/token"
)

func newInviteCmd(dataDir *string) *cobra.Command {
	var listenAddr string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "invite",
		Short: "Print an invite token and wait for one peer to join",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if listenAddr == "" {
				return fmt.Errorf("--listen is required (the address peers will dial)")
			}
			sess, err := openPeerSession(*dataDir)
			if err != nil {
				return err
			}
			defer func() { _ = sess.Close() }()

			listener, err := bsquic.Listen(listenAddr, sess.id.PrivateKey)
			if err != nil {
				return fmt.Errorf("listen on %q: %w", listenAddr, err)
			}
			defer func() { _ = listener.Close() }()

			// Use the listener's actual bound addr so ":0" (ephemeral
			// port) still produces a usable token.
			tokStr, err := token.Encode(listener.Addr().String(), sess.id.PublicKey)
			if err != nil {
				return fmt.Errorf("encode token: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), tokStr)

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
			return nil
		},
	}
	cmd.Flags().StringVar(&listenAddr, "listen", "", "Address to listen on (host:port)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Maximum time to wait for a joiner (0 = no timeout)")
	return cmd
}
