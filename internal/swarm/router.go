package swarm

import (
	"context"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"

	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
)

// Router carries the dependencies for receiving and forwarding peer
// announcements. A nil Dedup disables dedup; a nil Conns disables forwarding.
type Router struct {
	Store *peers.Store
	Dedup *DedupCache
	Conns *ConnSet
	// OnApplied, when non-nil, fires after Apply succeeds and before
	// forwarding. Runs synchronously on the dispatcher goroutine.
	OnApplied func(context.Context, protocol.PeerAnnouncement)
}

// HandleStream reads one announcement frame from r, dedup-checks it,
// applies it to the Store, and forwards to every conn except senderPub.
// An empty senderPub disables exclusion.
func (r *Router) HandleStream(ctx context.Context, rd io.Reader, senderPub []byte) error {
	ann, err := protocol.ReadPeerAnnouncement(rd, MaxAnnouncementAddrLen)
	if err != nil {
		return fmt.Errorf("read announcement: %w", err)
	}
	if r.Dedup != nil && r.Dedup.Seen(ann.ID) {
		slog.DebugContext(ctx, "announcement already seen; dropping",
			"id", hex.EncodeToString(ann.ID[:]),
			"kind", ann.Kind,
		)
		return nil
	}
	if err := Apply(ann, r.Store); err != nil {
		slog.WarnContext(ctx, "apply announcement",
			"kind", ann.Kind,
			"peer_pub", hex.EncodeToString(ann.PubKey[:]),
			"err", err)
		return fmt.Errorf("apply announcement: %w", err)
	}
	slog.InfoContext(ctx, "applied announcement",
		"kind", ann.Kind,
		"peer_pub", hex.EncodeToString(ann.PubKey[:]),
		"addr", ann.Addr,
		"id", hex.EncodeToString(ann.ID[:]),
	)
	if r.OnApplied != nil {
		r.OnApplied(ctx, ann)
	}
	if r.Conns == nil {
		return nil
	}
	targets := r.Conns.SnapshotExcept(senderPub)
	Forward(ctx, ann, targets)
	return nil
}

// Forward writes ann to every conn in targets on a fresh
// MsgPeerAnnouncement stream. Per-conn failures are logged and skipped.
func Forward(ctx context.Context, ann protocol.PeerAnnouncement, targets []*bsquic.Conn) {
	for _, conn := range targets {
		sendAnnouncement(ctx, conn, ann)
	}
}
