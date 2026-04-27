package cli

import (
	"context"
	"crypto/ed25519"
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

// errNoStoragePeer is returned when peers.db has no storage candidate
// with a non-empty address — restore cannot fetch blobs from nowhere.
var errNoStoragePeer = fmt.Errorf("no storage peer with a dialable address in peers.db; run `join <token>` first")

func newRestoreCmd(dataDir *string) *cobra.Command {
	var dialTimeout time.Duration
	cmd := &cobra.Command{
		Use:   "restore <dest>",
		Short: "Fetch every indexed file from known storage peers and reassemble it under <dest>",
		Long: "Read the local index and the storage peers recorded in peers.db, dial each, " +
			"fetch every chunk from a peer that holds it, decrypt it, verify its plaintext " +
			"hash, and write the file to <dest>/<original-absolute-path>. <dest> must be absolute.",
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
			storagePeers, err := listDialableStoragePeers(peerStore)
			if err != nil {
				return err
			}

			idx, err := index.Open(filepath.Join(dir, "index.db"))
			if err != nil {
				return fmt.Errorf("open index: %w", err)
			}
			defer func() { _ = idx.Close() }()

			conns, closeFn, err := dialAll(cmd.Context(), storagePeers, id.PrivateKey, dialTimeout)
			if err != nil {
				return err
			}
			defer closeFn()

			return restore.Run(cmd.Context(), restore.Options{
				Dest:          dest,
				Conns:         conns,
				Index:         idx,
				RecipientPub:  rk.PublicKey,
				RecipientPriv: rk.PrivateKey,
				Progress:      cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().DurationVar(&dialTimeout, "dial-timeout", 30*time.Second, "Timeout for each dial to a storage peer")
	return cmd
}

// listDialableStoragePeers returns every peer in ps with a non-empty
// Addr and a Role that admits storage. errNoStoragePeer fires on empty.
func listDialableStoragePeers(ps *peers.Store) ([]peers.Peer, error) {
	all, err := ps.List()
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	var dialable []peers.Peer
	for _, p := range all {
		if p.Addr != "" && p.Role.IsStorageCandidate() {
			dialable = append(dialable, p)
		}
	}
	if len(dialable) == 0 {
		return nil, errNoStoragePeer
	}
	return dialable, nil
}

// dialAll dials every peer best-effort. Returns the successful conns and
// a closer that closes them all. Errors only when zero dials succeeded.
func dialAll(ctx context.Context, peerList []peers.Peer, priv ed25519.PrivateKey, timeout time.Duration) ([]*bsquic.Conn, func(), error) {
	conns := make([]*bsquic.Conn, 0, len(peerList))
	var firstErr error
	for _, p := range peerList {
		dialCtx, dialCancel := context.WithTimeout(ctx, timeout)
		conn, err := bsquic.Dial(dialCtx, p.Addr, priv, p.PubKey, nil)
		dialCancel()
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("dial peer %q: %w", p.Addr, err)
			}
			continue
		}
		conns = append(conns, conn)
	}
	if len(conns) == 0 {
		return nil, func() {}, firstErr
	}
	closer := func() {
		for _, c := range conns {
			_ = c.Close()
		}
	}
	return conns, closer, nil
}
