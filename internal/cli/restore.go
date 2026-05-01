package cli

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/index"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/restore"
)

// errNoStoragePeer is returned when peers.db has no dialable storage peer.
var errNoStoragePeer = fmt.Errorf("no storage peer with a dialable address in peers.db; run `join <token>` first")

func newRestoreCmd(dataDir *string) *cobra.Command {
	var (
		dialTimeout  time.Duration
		retryTimeout time.Duration
		retryBackoff time.Duration
	)
	cmd := &cobra.Command{
		Use:   "restore <dest>",
		Short: "Fetch every indexed file from known storage peers and reassemble the tree under <dest>",
		Long: "Read the local index and the storage peers recorded in peers.db, dial each, " +
			"fetch every chunk from a peer that holds it, decrypt it, verify its plaintext " +
			"hash, and write each file under <dest> at its path relative to the original " +
			"backup root. <dest> must be absolute. Every filesystem operation is rooted at " +
			"<dest>, so a tampered index can never redirect writes outside the destination. " +
			"With --retry-timeout > 0, files whose chunks are unreachable on the first pass " +
			"are deferred and retried with exponential backoff; peers are re-dialed between " +
			"attempts so newly-online peers join the conn pool.",
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

			tracker := newConnTracker()
			defer tracker.closeAll()

			initial, err := dialAndTrack(cmd.Context(), storagePeers, id.PrivateKey, dialTimeout, tracker)
			if err != nil {
				return err
			}

			redial := func(ctx context.Context) ([]*bsquic.Conn, error) {
				return dialAndTrack(ctx, storagePeers, id.PrivateKey, dialTimeout, tracker)
			}
			if retryTimeout <= 0 {
				redial = nil
			}

			return restore.Run(cmd.Context(), restore.Options{
				Dest:          dest,
				Conns:         initial,
				Index:         idx,
				RecipientPub:  rk.PublicKey,
				RecipientPriv: rk.PrivateKey,
				Progress:      cmd.OutOrStdout(),
				RetryTimeout:  retryTimeout,
				RetryBackoff:  retryBackoff,
				Redial:        redial,
			})
		},
	}
	cmd.Flags().DurationVar(&dialTimeout, "dial-timeout", 30*time.Second, "Timeout for each dial to a storage peer")
	cmd.Flags().DurationVar(&retryTimeout, "retry-timeout", 0, "Maximum total time to retry deferred files when peers are unreachable (0 disables retries)")
	cmd.Flags().DurationVar(&retryBackoff, "retry-backoff", time.Second, "Initial backoff between retry attempts; doubles up to 30s")
	return cmd
}

// listDialableStoragePeers returns dialable storage peers from ps.
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

// connTracker collects every conn dialed by the restore command so that
// every retry's fresh dial gets cleaned up by a single defer at the end.
type connTracker struct {
	mu    sync.Mutex
	conns []*bsquic.Conn
}

func newConnTracker() *connTracker { return &connTracker{} }

func (t *connTracker) add(c *bsquic.Conn) {
	t.mu.Lock()
	t.conns = append(t.conns, c)
	t.mu.Unlock()
}

func (t *connTracker) closeAll() {
	t.mu.Lock()
	conns := t.conns
	t.conns = nil
	t.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

// dialAndTrack dials every peer best-effort and records each successful
// conn in tracker for later closeAll. Returns the successful conns plus
// the first dial error only when zero peers connected.
func dialAndTrack(ctx context.Context, peerList []peers.Peer, priv ed25519.PrivateKey, timeout time.Duration, tracker *connTracker) ([]*bsquic.Conn, error) {
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
		tracker.add(conn)
		conns = append(conns, conn)
	}
	if len(conns) == 0 {
		return nil, firstErr
	}
	return conns, nil
}

// dialAll returns successful conns and a closeFn that shuts them down.
func dialAll(ctx context.Context, peerList []peers.Peer, priv ed25519.PrivateKey, timeout time.Duration) ([]*bsquic.Conn, func(), error) {
	tracker := newConnTracker()
	conns, err := dialAndTrack(ctx, peerList, priv, timeout, tracker)
	if err != nil {
		return nil, func() {}, err
	}
	return conns, tracker.closeAll, nil
}
