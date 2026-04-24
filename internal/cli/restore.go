package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/index"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/restore"
)

// ErrNoStoragePeer is returned when peers.db has no entry with a
// non-empty address — the restore command cannot fetch blobs from
// nowhere.
var errNoStoragePeer = fmt.Errorf("no storage peer with a dialable address in peers.db; run `join <token>` first")

// errMultiplePeers matches daemon.ErrMultiplePeers: M1 supports one
// storage peer per swarm; multi-peer placement lands in M2.14.
var errMultiplePeers = fmt.Errorf("multiple dialable peers in peers.db; restore supports exactly one for now")

func newRestoreCmd(dataDir *string) *cobra.Command {
	var dialTimeout time.Duration
	cmd := &cobra.Command{
		Use:   "restore <dest>",
		Short: "Fetch every indexed file from the storage peer and reassemble it under <dest>",
		Long: "Read the local index and the storage peer recorded in peers.db, fetch each " +
			"chunk, decrypt it, verify its plaintext hash, and write the file to " +
			"<dest>/<original-absolute-path>. <dest> must be absolute.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			dest := args[0]
			if !filepath.IsAbs(dest) {
				return fmt.Errorf("<dest> must be an absolute path; got %q", dest)
			}
			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}
			id, _, err := node.Ensure(dir)
			if err != nil {
				return fmt.Errorf("ensure identity: %w", err)
			}
			rk, _, err := node.EnsureRecipient(dir)
			if err != nil {
				return fmt.Errorf("ensure recipient keys: %w", err)
			}

			peerStore, err := peers.Open(filepath.Join(dir, peers.DefaultFilename))
			if err != nil {
				return fmt.Errorf("open peer store: %w", err)
			}
			defer func() { _ = peerStore.Close() }()
			peer, err := pickSingleDialablePeer(peerStore)
			if err != nil {
				return err
			}

			idx, err := index.Open(filepath.Join(dir, "index.db"))
			if err != nil {
				return fmt.Errorf("open index: %w", err)
			}
			defer func() { _ = idx.Close() }()

			dialCtx, dialCancel := context.WithTimeout(cmd.Context(), dialTimeout)
			defer dialCancel()
			conn, err := bsquic.Dial(dialCtx, peer.Addr, id.PrivateKey, peer.PubKey)
			if err != nil {
				return fmt.Errorf("dial peer %q: %w", peer.Addr, err)
			}
			defer func() { _ = conn.Close() }()

			return restore.Run(cmd.Context(), restore.Options{
				Dest:          dest,
				Conn:          conn,
				Index:         idx,
				RecipientPub:  rk.PublicKey,
				RecipientPriv: rk.PrivateKey,
				Progress:      cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().DurationVar(&dialTimeout, "dial-timeout", 30*time.Second, "Timeout for the initial dial to the storage peer")
	return cmd
}

// pickSingleDialablePeer returns the single peer in ps with a
// non-empty address, or an error if zero or more than one exist.
// Matches daemon.pickStoragePeer's contract without forcing an
// import of the daemon package into the CLI.
func pickSingleDialablePeer(ps *peers.Store) (*peers.Peer, error) {
	all, err := ps.List()
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	var dialable []peers.Peer
	for _, p := range all {
		if p.Addr != "" {
			dialable = append(dialable, p)
		}
	}
	switch len(dialable) {
	case 0:
		return nil, errNoStoragePeer
	case 1:
		p := dialable[0]
		return &p, nil
	default:
		return nil, errMultiplePeers
	}
}
