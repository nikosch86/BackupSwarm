// Package swarm carries membership-event logic: applying inbound
// PeerAnnouncements to the local peer store, broadcasting them to live
// connections, and reading them off inbound streams.
package swarm

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
)

// MaxAnnouncementAddrLen caps the advertised address length on inbound
// announcements (1 KiB — same cap bootstrap uses for join hellos).
const MaxAnnouncementAddrLen = 1 << 10

// Test-only seams; production never reassigns these.
var (
	storeAddFunc           = func(s *peers.Store, p peers.Peer) error { return s.Add(p) }
	writeMsgTypeFunc       = protocol.WriteMessageType
	writeAnnouncementFrame = protocol.WritePeerAnnouncement
)

// Apply commits ann to store. PeerJoined never overwrites an existing
// record, PeerLeft is idempotent on unknown peers, and AddressChanged
// updates only Addr (Role is preserved).
func Apply(ann protocol.PeerAnnouncement, store *peers.Store) error {
	pub := ed25519.PublicKey(ann.PubKey[:])
	switch ann.Kind {
	case protocol.AnnouncePeerJoined:
		if _, err := store.Get(pub); err == nil {
			return nil
		} else if !errors.Is(err, peers.ErrPeerNotFound) {
			return fmt.Errorf("apply PeerJoined: get existing: %w", err)
		}
		newPeer := peers.Peer{
			Addr:   ann.Addr,
			PubKey: append(ed25519.PublicKey(nil), ann.PubKey[:]...),
			Role:   peers.Role(ann.Role),
		}
		if err := storeAddFunc(store, newPeer); err != nil {
			return fmt.Errorf("apply PeerJoined: add: %w", err)
		}
		return nil
	case protocol.AnnouncePeerLeft:
		if err := store.Remove(pub); err != nil && !errors.Is(err, peers.ErrPeerNotFound) {
			return fmt.Errorf("apply PeerLeft: remove: %w", err)
		}
		return nil
	case protocol.AnnounceAddressChanged:
		existing, err := store.Get(pub)
		if errors.Is(err, peers.ErrPeerNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("apply AddressChanged: get: %w", err)
		}
		existing.Addr = ann.Addr
		if err := storeAddFunc(store, existing); err != nil {
			return fmt.Errorf("apply AddressChanged: add: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("apply: unknown announcement kind %d", ann.Kind)
	}
}

// ServeAnnouncementStream reads one PeerAnnouncement frame from r and
// applies it to store. The MsgPeerAnnouncement type byte is expected to
// already be consumed by the caller's dispatcher.
func ServeAnnouncementStream(ctx context.Context, r io.Reader, store *peers.Store) error {
	ann, err := protocol.ReadPeerAnnouncement(r, MaxAnnouncementAddrLen)
	if err != nil {
		return fmt.Errorf("read announcement: %w", err)
	}
	if err := Apply(ann, store); err != nil {
		slog.WarnContext(ctx, "apply announcement",
			"kind", ann.Kind,
			"peer_pub", hex.EncodeToString(ann.PubKey[:]),
			"err", err)
		return fmt.Errorf("apply announcement: %w", err)
	}
	slog.DebugContext(ctx, "applied announcement",
		"kind", ann.Kind,
		"peer_pub", hex.EncodeToString(ann.PubKey[:]),
		"addr", ann.Addr,
	)
	return nil
}

// BroadcastPeerJoined opens one MsgPeerAnnouncement stream per connection
// and writes a PeerJoined frame for joiner. Per-conn failures are logged
// and skipped so one dead peer cannot drop the rest of the broadcast.
func BroadcastPeerJoined(ctx context.Context, conns []*bsquic.Conn, joiner peers.Peer) error {
	if len(joiner.PubKey) != ed25519.PublicKeySize {
		return fmt.Errorf("broadcast PeerJoined: pubkey size %d, want %d", len(joiner.PubKey), ed25519.PublicKeySize)
	}
	if joiner.Role == peers.RoleUnspecified {
		return fmt.Errorf("broadcast PeerJoined: role unspecified")
	}
	var ann protocol.PeerAnnouncement
	ann.Kind = protocol.AnnouncePeerJoined
	copy(ann.PubKey[:], joiner.PubKey)
	ann.Role = byte(joiner.Role)
	ann.Addr = joiner.Addr
	for _, conn := range conns {
		sendAnnouncement(ctx, conn, ann)
	}
	return nil
}

// sendAnnouncement opens a stream on conn, writes MsgPeerAnnouncement +
// the frame, and closes the stream. Errors are logged and swallowed.
func sendAnnouncement(ctx context.Context, conn *bsquic.Conn, ann protocol.PeerAnnouncement) {
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		slog.WarnContext(ctx, "broadcast announcement: open stream",
			"peer_pub", hex.EncodeToString(conn.RemotePub()),
			"err", err)
		return
	}
	defer func() { _ = stream.Close() }()
	if err := writeMsgTypeFunc(stream, protocol.MsgPeerAnnouncement); err != nil {
		slog.WarnContext(ctx, "broadcast announcement: write message type",
			"peer_pub", hex.EncodeToString(conn.RemotePub()),
			"err", err)
		return
	}
	if err := writeAnnouncementFrame(stream, ann); err != nil {
		slog.WarnContext(ctx, "broadcast announcement: write frame",
			"peer_pub", hex.EncodeToString(conn.RemotePub()),
			"err", err)
		return
	}
}
