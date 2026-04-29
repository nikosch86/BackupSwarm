package cli

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
)

// errNoSnapshotAvailable is returned when no storage peer holds an index snapshot.
var errNoSnapshotAvailable = errors.New("no storage peer holds an index snapshot for this node; run a daemon long enough to publish at least one snapshot first")

// fetchSnapshotFunc is the test seam for snapshot fetches.
var fetchSnapshotFunc = backup.SendGetIndexSnapshot

func newRestoreIndexCmd(dataDir *string) *cobra.Command {
	var dialTimeout time.Duration
	cmd := &cobra.Command{
		Use:   "restore-index",
		Short: "Fetch the encrypted index snapshot from a storage peer and write it into the local index.db",
		Long: "Disaster-recovery primitive. Reads identity + recipient keys from --data-dir, dials " +
			"each storage peer recorded in peers.db, asks each for its latest encrypted index " +
			"snapshot, decrypts the first successful response, and writes the entries into the " +
			"local index.db. Run this before `restore` on a fresh node that has its keys + a " +
			"populated peers.db but no index of its own.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
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

			conns, closeFn, err := dialAll(cmd.Context(), storagePeers, id.PrivateKey, dialTimeout)
			if err != nil {
				return err
			}
			defer closeFn()

			blob, err := fetchAnyIndexSnapshot(cmd.Context(), conns)
			if err != nil {
				return err
			}
			entries, err := decodeSnapshotBlob(blob, rk.PublicKey, rk.PrivateKey)
			if err != nil {
				return fmt.Errorf("decode snapshot: %w", err)
			}

			idx, err := index.Open(filepath.Join(dir, "index.db"))
			if err != nil {
				return fmt.Errorf("open index: %w", err)
			}
			defer func() { _ = idx.Close() }()

			if err := index.ApplySnapshot(idx, entries); err != nil {
				return fmt.Errorf("apply snapshot: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "restored index: %d entries written to %s\n",
				len(entries), filepath.Join(dir, "index.db"))
			return nil
		},
	}
	cmd.Flags().DurationVar(&dialTimeout, "dial-timeout", 30*time.Second, "Timeout for each dial to a storage peer")
	return cmd
}

// fetchAnyIndexSnapshot returns the first successfully fetched snapshot blob.
func fetchAnyIndexSnapshot(ctx context.Context, conns []*bsquic.Conn) ([]byte, error) {
	if len(conns) == 0 {
		return nil, errNoSnapshotAvailable
	}
	var last error
	for _, c := range conns {
		blob, err := fetchSnapshotFunc(ctx, c)
		if err != nil {
			last = err
			continue
		}
		if len(blob) > 0 {
			return blob, nil
		}
		last = errors.New("peer returned empty snapshot blob")
	}
	if last == nil {
		last = errNoSnapshotAvailable
	}
	return nil, fmt.Errorf("%w: %v", errNoSnapshotAvailable, last)
}

// decodeSnapshotBlob decrypts blob and unmarshals the inner snapshot payload.
func decodeSnapshotBlob(blob []byte, pub, priv *[crypto.RecipientKeySize]byte) ([]index.FileEntry, error) {
	ec, err := crypto.UnmarshalEncryptedChunk(blob)
	if err != nil {
		return nil, fmt.Errorf("unmarshal encrypted chunk: %w", err)
	}
	plain, err := crypto.Decrypt(ec, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("decrypt: %w", err)
	}
	entries, err := index.UnmarshalSnapshot(plain)
	if err != nil {
		return nil, fmt.Errorf("unmarshal snapshot: %w", err)
	}
	return entries, nil
}
