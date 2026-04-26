package swarm_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"

	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	"backupswarm/internal/swarm"
)

func openStore(t *testing.T) *peers.Store {
	t.Helper()
	s, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub
}

func pubArray(pub ed25519.PublicKey) [32]byte {
	var arr [32]byte
	copy(arr[:], pub)
	return arr
}

func TestApply_PeerJoined_InsertsNew(t *testing.T) {
	store := openStore(t)
	pub := mustKey(t)

	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}
	if err := swarm.Apply(ann, store); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, err := store.Get(pub)
	if err != nil {
		t.Fatalf("Get after Apply: %v", err)
	}
	if got.Addr != ann.Addr || got.Role != peers.RolePeer {
		t.Errorf("got %+v, want addr=%q role=peer", got, ann.Addr)
	}
}

func TestApply_PeerJoined_PreservesExistingRole(t *testing.T) {
	store := openStore(t)
	pub := mustKey(t)
	if err := store.Add(peers.Peer{Addr: "10.0.0.1:1", PubKey: pub, Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("Add introducer: %v", err)
	}

	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer), // wire says RolePeer; locally we have RoleIntroducer
		Addr:   "10.0.0.99:99",
	}
	if err := swarm.Apply(ann, store); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, err := store.Get(pub)
	if err != nil {
		t.Fatalf("Get after Apply: %v", err)
	}
	if got.Role != peers.RoleIntroducer {
		t.Errorf("role = %v, want RoleIntroducer (locally-authoritative record must not be downgraded)", got.Role)
	}
	if got.Addr != "10.0.0.1:1" {
		t.Errorf("addr = %q, want %q (PeerJoined must not clobber existing addr)", got.Addr, "10.0.0.1:1")
	}
}

func TestApply_PeerLeft_RemovesExisting(t *testing.T) {
	store := openStore(t)
	pub := mustKey(t)
	if err := store.Add(peers.Peer{Addr: "10.0.0.1:1", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	ann := protocol.PeerAnnouncement{Kind: protocol.AnnouncePeerLeft, PubKey: pubArray(pub)}
	if err := swarm.Apply(ann, store); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if _, err := store.Get(pub); !errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("Get after PeerLeft: err = %v, want ErrPeerNotFound", err)
	}
}

func TestApply_PeerLeft_IdempotentOnUnknown(t *testing.T) {
	store := openStore(t)
	pub := mustKey(t)

	ann := protocol.PeerAnnouncement{Kind: protocol.AnnouncePeerLeft, PubKey: pubArray(pub)}
	if err := swarm.Apply(ann, store); err != nil {
		t.Errorf("Apply on unknown peer: %v, want nil (idempotent)", err)
	}
}

func TestApply_AddressChanged_UpdatesAddrPreservesRole(t *testing.T) {
	store := openStore(t)
	pub := mustKey(t)
	if err := store.Add(peers.Peer{Addr: "10.0.0.1:1", PubKey: pub, Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnounceAddressChanged,
		PubKey: pubArray(pub),
		Addr:   "192.0.2.7:9000",
	}
	if err := swarm.Apply(ann, store); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	got, err := store.Get(pub)
	if err != nil {
		t.Fatalf("Get after Apply: %v", err)
	}
	if got.Addr != ann.Addr {
		t.Errorf("addr = %q, want %q", got.Addr, ann.Addr)
	}
	if got.Role != peers.RoleIntroducer {
		t.Errorf("role = %v, want RoleIntroducer (AddressChanged must not modify role)", got.Role)
	}
}

func TestApply_AddressChanged_UnknownPeerNoOp(t *testing.T) {
	store := openStore(t)
	pub := mustKey(t)

	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnounceAddressChanged,
		PubKey: pubArray(pub),
		Addr:   "192.0.2.7:9000",
	}
	if err := swarm.Apply(ann, store); err != nil {
		t.Errorf("Apply on unknown peer: %v, want nil (no-op)", err)
	}
	if _, err := store.Get(pub); !errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("Get after no-op: err = %v, want ErrPeerNotFound", err)
	}
}

func TestApply_RejectsInvalidKind(t *testing.T) {
	store := openStore(t)
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncementKind(99),
		PubKey: pubArray(mustKey(t)),
	}
	if err := swarm.Apply(ann, store); err == nil {
		t.Error("Apply accepted unknown kind")
	}
}

func TestServeAnnouncementStream_AppliesPeerJoined(t *testing.T) {
	store := openStore(t)
	pub := mustKey(t)

	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}
	var buf bytes.Buffer
	if err := protocol.WritePeerAnnouncement(&buf, ann); err != nil {
		t.Fatalf("WritePeerAnnouncement: %v", err)
	}
	if err := swarm.ServeAnnouncementStream(context.Background(), &buf, store); err != nil {
		t.Fatalf("ServeAnnouncementStream: %v", err)
	}
	got, err := store.Get(pub)
	if err != nil {
		t.Fatalf("Get after Serve: %v", err)
	}
	if got.Addr != ann.Addr || got.Role != peers.RolePeer {
		t.Errorf("got %+v, want addr=%q role=peer", got, ann.Addr)
	}
}

func TestServeAnnouncementStream_AppliesPeerLeft(t *testing.T) {
	store := openStore(t)
	pub := mustKey(t)
	if err := store.Add(peers.Peer{Addr: "10.0.0.1:1", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	var buf bytes.Buffer
	if err := protocol.WritePeerAnnouncement(&buf, protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerLeft,
		PubKey: pubArray(pub),
	}); err != nil {
		t.Fatalf("WritePeerAnnouncement: %v", err)
	}
	if err := swarm.ServeAnnouncementStream(context.Background(), &buf, store); err != nil {
		t.Fatalf("ServeAnnouncementStream: %v", err)
	}
	if _, err := store.Get(pub); !errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("Get after Serve PeerLeft: err = %v, want ErrPeerNotFound", err)
	}
}

func TestServeAnnouncementStream_RejectsTruncatedFrame(t *testing.T) {
	store := openStore(t)
	if err := swarm.ServeAnnouncementStream(context.Background(), bytes.NewReader([]byte{1, 2, 3}), store); err == nil {
		t.Error("ServeAnnouncementStream accepted truncated frame")
	}
}

func TestServeAnnouncementStream_RejectsUnknownKind(t *testing.T) {
	store := openStore(t)
	frame := append([]byte{99}, bytes.Repeat([]byte{0xaa}, 32)...)
	frame = append(frame, 1, 0, 0, 0, 0)
	if err := swarm.ServeAnnouncementStream(context.Background(), bytes.NewReader(frame), store); err == nil {
		t.Error("ServeAnnouncementStream accepted unknown kind")
	}
}

// closedStore returns a Store whose underlying bbolt db has been closed.
// Operations on it return wrapped bbolt errors (NOT ErrPeerNotFound).
func closedStore(t *testing.T) *peers.Store {
	t.Helper()
	s, err := peers.Open(filepath.Join(t.TempDir(), "closed.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return s
}

func TestApply_PeerJoined_GetErrorSurfacesWrapped(t *testing.T) {
	store := closedStore(t)
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		PubKey: pubArray(mustKey(t)),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}
	err := swarm.Apply(ann, store)
	if err == nil {
		t.Fatal("Apply succeeded on closed store")
	}
	if errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("err = %v, want non-NotFound store error", err)
	}
}

func TestApply_PeerLeft_RemoveErrorSurfacesWrapped(t *testing.T) {
	store := closedStore(t)
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerLeft,
		PubKey: pubArray(mustKey(t)),
	}
	err := swarm.Apply(ann, store)
	if err == nil {
		t.Fatal("Apply succeeded on closed store")
	}
	if errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("err = %v, want non-NotFound store error (got wrapped ErrPeerNotFound)", err)
	}
}

func TestApply_AddressChanged_GetErrorSurfacesWrapped(t *testing.T) {
	store := closedStore(t)
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnounceAddressChanged,
		PubKey: pubArray(mustKey(t)),
		Addr:   "192.0.2.7:9000",
	}
	err := swarm.Apply(ann, store)
	if err == nil {
		t.Fatal("Apply succeeded on closed store")
	}
	if errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("err = %v, want non-NotFound store error", err)
	}
}

func TestServeAnnouncementStream_PropagatesApplyError(t *testing.T) {
	store := closedStore(t)
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		PubKey: pubArray(mustKey(t)),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}
	var buf bytes.Buffer
	if err := protocol.WritePeerAnnouncement(&buf, ann); err != nil {
		t.Fatalf("WritePeerAnnouncement: %v", err)
	}
	err := swarm.ServeAnnouncementStream(context.Background(), &buf, store)
	if err == nil {
		t.Fatal("ServeAnnouncementStream succeeded against closed store")
	}
}

func TestBroadcastPeerJoined_RejectsBadPubKeySize(t *testing.T) {
	joiner := peers.Peer{
		Addr:   "192.0.2.7:9000",
		PubKey: []byte{1, 2, 3},
		Role:   peers.RolePeer,
	}
	if err := swarm.BroadcastPeerJoined(context.Background(), nil, joiner); err == nil {
		t.Error("BroadcastPeerJoined accepted short pubkey")
	}
}

func TestBroadcastPeerJoined_RejectsRoleUnspecified(t *testing.T) {
	joiner := peers.Peer{
		Addr:   "192.0.2.7:9000",
		PubKey: mustKey(t),
		Role:   peers.RoleUnspecified,
	}
	if err := swarm.BroadcastPeerJoined(context.Background(), nil, joiner); err == nil {
		t.Error("BroadcastPeerJoined accepted RoleUnspecified")
	}
}
