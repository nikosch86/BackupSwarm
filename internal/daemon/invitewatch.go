package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sync/atomic"
	"time"

	"backupswarm/internal/invites"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
)

// defaultInviteWatchInterval is the pending-invite cache refresh interval.
const defaultInviteWatchInterval = 1 * time.Second

// pendingCache holds the lock-free count of pending invite secrets.
type pendingCache struct {
	n atomic.Int32
}

// makeVerifyPeer returns a VerifyPeerFunc admitting known peers and
// peers presenting a pending invite.
func makeVerifyPeer(peerStore *peers.Store, pc *pendingCache) bsquic.VerifyPeerFunc {
	return func(pub ed25519.PublicKey) error {
		if _, err := peerStore.Get(pub); err == nil {
			return nil
		} else if !errors.Is(err, peers.ErrPeerNotFound) {
			return fmt.Errorf("lookup peer %x: %w", pub[:8], err)
		}
		if pc.n.Load() > 0 {
			return nil
		}
		return fmt.Errorf("unknown peer %x and no pending invites", pub[:8])
	}
}

// refreshPendingInvites updates pc with the current pending count.
func refreshPendingInvites(ctx context.Context, dataDir string, pc *pendingCache) {
	path := filepath.Join(dataDir, invites.DefaultFilename)
	s, err := invites.Open(path)
	if err != nil {
		slog.WarnContext(ctx, "open invites.db", "err", err)
		return
	}
	n, countErr := s.PendingCount()
	_ = s.Close()
	if countErr != nil {
		slog.WarnContext(ctx, "count pending invites", "err", countErr)
		return
	}
	pc.n.Store(int32(n))
}

// pollPendingInvites refreshes pc on entry and once per interval.
func pollPendingInvites(ctx context.Context, dataDir string, pc *pendingCache, interval time.Duration) {
	refreshPendingInvites(ctx, dataDir, pc)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshPendingInvites(ctx, dataDir, pc)
		}
	}
}
