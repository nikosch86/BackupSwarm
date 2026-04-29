package cli

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"backupswarm/internal/node"
	"backupswarm/internal/peers"
)

// peerSession bundles the per-command resolved data dir, identity, and peer store.
type peerSession struct {
	dir       string
	id        *node.Identity
	peerStore *peers.Store
}

// openPeerSession resolves the data dir, ensures the identity, and opens peers.db.
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

// Close releases the peer store's bbolt file lock.
func (s *peerSession) Close() error {
	return s.peerStore.Close()
}

// withTimeout returns ctx and a no-op cancel for d<=0, else context.WithTimeout.
func withTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if d <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}
