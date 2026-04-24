package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"backupswarm/internal/node"
	"backupswarm/internal/peers"
)

// peerSession bundles the per-command bootstrap that `invite` and
// `join` share: a resolved data dir, a materialised node identity, and
// an opened peer store. Callers must Close() to release the bbolt file
// lock the peer store holds.
type peerSession struct {
	dir       string
	id        *node.Identity
	peerStore *peers.Store
}

// openPeerSession resolves the data dir (flag > env > XDG > $HOME),
// ensures the node identity exists on disk (creating Ed25519 keys on
// first use), and opens the peer store at <dir>/peers.db. On any error
// the caller does not need to clean up — partially-opened resources are
// released before the error is returned.
func openPeerSession(explicitDataDir string) (*peerSession, error) {
	dir, err := resolveDataDir(explicitDataDir)
	if err != nil {
		return nil, err
	}
	id, _, err := node.Ensure(dir)
	if err != nil {
		return nil, fmt.Errorf("ensure identity: %w", err)
	}
	peerStore, err := peers.Open(filepath.Join(dir, peers.DefaultFilename))
	if err != nil {
		return nil, fmt.Errorf("open peer store: %w", err)
	}
	return &peerSession{dir: dir, id: id, peerStore: peerStore}, nil
}

// Close releases the peer store's bbolt file lock. Safe to defer
// immediately after a successful openPeerSession.
func (s *peerSession) Close() error {
	return s.peerStore.Close()
}

// withTimeout returns ctx (and a no-op cancel) when d <= 0, otherwise a
// context.WithTimeout pair. The non-positive branch lets `--timeout 0`
// mean "no timeout" without forcing every caller to branch on the flag
// before deferring cancel.
func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}
