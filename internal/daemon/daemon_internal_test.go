package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/index"
	"backupswarm/internal/invites"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// openPickStoragePeerStore opens a fresh peers.db and registers a
// t.Cleanup for it.
func openPickStoragePeerStore(t *testing.T) *peers.Store {
	t.Helper()
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	return ps
}

func mustGenPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return pub
}

// TestPollPendingInvites_TracksIssueAndConsume runs the poll loop with
// a tight interval, then issues + consumes an invite via a separate
// Open and asserts the cache reflects each transition within a few
// poll ticks.
func TestPollPendingInvites_TracksIssueAndConsume(t *testing.T) {
	dir := t.TempDir()
	pc := &pendingCache{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const tick = 50 * time.Millisecond
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		pollPendingInvites(ctx, dir, pc, tick)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-pollDone:
		case <-time.After(2 * time.Second):
			t.Error("poll loop did not exit within 2s of cancel")
		}
	})

	// Initial state: empty file → cache settles at 0.
	if got := pc.n.Load(); got != 0 {
		t.Errorf("initial cache = %d, want 0", got)
	}

	// Issue one invite via a separate Open (the poll loop briefly
	// releases the flock between ticks).
	openInvites := func() *invites.Store {
		s, err := invites.Open(filepath.Join(dir, invites.DefaultFilename))
		if err != nil {
			t.Fatalf("invites.Open: %v", err)
		}
		return s
	}
	store := openInvites()
	var secret, swarmID [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatalf("rand secret: %v", err)
	}
	if _, err := rand.Read(swarmID[:]); err != nil {
		t.Fatalf("rand swarmID: %v", err)
	}
	if err := store.Issue(secret, swarmID); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_ = store.Close()

	waitFor := func(want int32, deadline time.Duration) {
		end := time.Now().Add(deadline)
		for time.Now().Before(end) {
			if pc.n.Load() == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("cache never reached %d (last %d)", want, pc.n.Load())
	}
	waitFor(1, 3*time.Second)

	store2 := openInvites()
	if _, err := store2.Consume(secret); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	_ = store2.Close()
	waitFor(0, 3*time.Second)
}

// TestMakeVerifyPeer_KnownMemberAdmitted asserts a peer already in
// peers.db passes the predicate even with zero pending invites.
func TestMakeVerifyPeer_KnownMemberAdmitted(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:1", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	pc := &pendingCache{}
	verify := makeVerifyPeer(ps, pc)
	if err := verify(pub); err != nil {
		t.Errorf("known member rejected: %v", err)
	}
}

// TestMakeVerifyPeer_StrangerNoPending_Rejected asserts a peer absent
// from peers.db is rejected when the pending cache reads zero.
func TestMakeVerifyPeer_StrangerNoPending_Rejected(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	stranger := mustGenPub(t)
	pc := &pendingCache{}
	verify := makeVerifyPeer(ps, pc)
	if err := verify(stranger); err == nil {
		t.Fatal("stranger admitted with no pending invites")
	}
}

// TestMakeVerifyPeer_StrangerWithPending_Admitted asserts a stranger is
// admitted while at least one invite is pending — the join window lets
// an unknown pubkey complete the TLS handshake to consume its secret.
func TestMakeVerifyPeer_StrangerWithPending_Admitted(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	stranger := mustGenPub(t)
	pc := &pendingCache{}
	pc.n.Store(1)
	verify := makeVerifyPeer(ps, pc)
	if err := verify(stranger); err != nil {
		t.Errorf("stranger rejected during pending window: %v", err)
	}
}

// TestPickStoragePeer_SkipsRolePeer asserts a RolePeer record with a
// dialable Addr is not selected.
func TestPickStoragePeer_SkipsRolePeer(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:9", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := pickStoragePeer(ps)
	if err != nil {
		t.Fatalf("pickStoragePeer: %v", err)
	}
	if got != nil {
		t.Errorf("pickStoragePeer returned %+v, want nil for RolePeer record", got)
	}
}

// TestPickStoragePeer_AdmitsRoleIntroducer asserts a RoleIntroducer
// record is selected.
func TestPickStoragePeer_AdmitsRoleIntroducer(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:10", PubKey: pub, Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := pickStoragePeer(ps)
	if err != nil {
		t.Fatalf("pickStoragePeer: %v", err)
	}
	if got == nil {
		t.Fatal("pickStoragePeer returned nil for RoleIntroducer record")
	}
	if !bytes.Equal(got.PubKey, pub) {
		t.Errorf("pickStoragePeer returned wrong pubkey")
	}
}

// TestPickStoragePeer_AdmitsRoleStorage asserts a RoleStorage record
// is selected.
func TestPickStoragePeer_AdmitsRoleStorage(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:11", PubKey: pub, Role: peers.RoleStorage}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := pickStoragePeer(ps)
	if err != nil {
		t.Fatalf("pickStoragePeer: %v", err)
	}
	if got == nil {
		t.Fatal("pickStoragePeer returned nil for RoleStorage record")
	}
}

// TestPickStoragePeer_MixedRolesPicksStorageRoleOnly asserts that with
// one RolePeer and one RoleIntroducer both dialable, the RoleIntroducer
// is returned without ErrMultiplePeers.
func TestPickStoragePeer_MixedRolesPicksStorageRoleOnly(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	introPub := mustGenPub(t)
	peerPub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:20", PubKey: introPub, Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("Add introducer: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:21", PubKey: peerPub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add peer: %v", err)
	}
	got, err := pickStoragePeer(ps)
	if err != nil {
		t.Fatalf("pickStoragePeer: %v", err)
	}
	if got == nil {
		t.Fatal("pickStoragePeer returned nil despite a RoleIntroducer record")
	}
	if !bytes.Equal(got.PubKey, introPub) {
		t.Errorf("pickStoragePeer chose wrong record (got %x, want introducer %x)", got.PubKey[:8], introPub[:8])
	}
}

// TestPickStoragePeer_MultipleStorageRolesErrors asserts ErrMultiplePeers
// when two storage-eligible records both have dialable Addrs.
func TestPickStoragePeer_MultipleStorageRolesErrors(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:30", PubKey: mustGenPub(t), Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("Add 1: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:31", PubKey: mustGenPub(t), Role: peers.RoleStorage}); err != nil {
		t.Fatalf("Add 2: %v", err)
	}
	if _, err := pickStoragePeer(ps); !errors.Is(err, ErrMultiplePeers) {
		t.Errorf("err = %v, want ErrMultiplePeers", err)
	}
}

// TestPickStoragePeer_ListFailureSurfacesWrapped asserts a List error
// surfaces from pickStoragePeer with a "list peers" wrap.
func TestPickStoragePeer_ListFailureSurfacesWrapped(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "list-fail.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err = pickStoragePeer(ps)
	if err == nil {
		t.Fatal("pickStoragePeer returned nil on closed store")
	}
	if !strings.Contains(err.Error(), "list peers") {
		t.Errorf("err = %q, want 'list peers' wrap", err)
	}
}

// TestModeName_AllCases asserts modeName returns the expected string for every Mode value plus the unknown fallback.
func TestModeName_AllCases(t *testing.T) {
	tests := []struct {
		name string
		in   Mode
		want string
	}{
		{"idle", ModeIdle, "idle"},
		{"first-backup", ModeFirstBackup, "first-backup"},
		{"reconcile", ModeReconcile, "reconcile"},
		{"restore", ModeRestore, "restore"},
		{"purge", ModePurge, "purge"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := modeName(tc.in); got != tc.want {
				t.Errorf("modeName(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	t.Run("unknown fallback", func(t *testing.T) {
		got := modeName(ModePurge + 99)
		if !strings.HasPrefix(got, "unknown(") {
			t.Errorf("modeName(unknown) = %q, want 'unknown(...)' prefix", got)
		}
	})
}

// TestPurgeAll_ListFailure asserts an idx.List failure surfaces from purgeAll as "list index".
func TestPurgeAll_ListFailure(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "purge-list-fail.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("index.Close: %v", err)
	}

	err = purgeAll(context.Background(), idx, nil, io.Discard)
	if err == nil {
		t.Fatal("purgeAll returned nil on closed index")
	}
	if !strings.Contains(err.Error(), "list index") {
		t.Errorf("err = %q, want 'list index' prefix", err)
	}
}

// TestPurgeAll_ContextCancelled asserts an already-cancelled context makes purgeAll return without driving any Prune calls.
func TestPurgeAll_ContextCancelled(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "purge-ctx-cancel.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	if err := idx.Put(index.FileEntry{
		Path: filepath.Join(t.TempDir(), "ghost.bin"),
		Size: 1,
		Chunks: []index.ChunkRef{
			{CiphertextHash: [32]byte{0x01}, Size: 10},
		},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = purgeAll(ctx, idx, nil, io.Discard)
	if err == nil {
		t.Fatal("purgeAll returned nil despite cancelled context")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("err = %q, want context.Canceled", err)
	}
}

// TestPurgeAll_PruneFailurePropagates asserts a backup.Prune failure surfaces from purgeAll.
func TestPurgeAll_PruneFailurePropagates(t *testing.T) {
	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	peerStore, err := store.New(filepath.Join(t.TempDir(), "peer-chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = peerStore.Close() })

	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serveCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = backup.Serve(serveCtx, listener, peerStore, nil, nil, nil) }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), ownerPriv, peerPub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()

	idx, err := index.Open(filepath.Join(t.TempDir(), "purge-prune-fail.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	ghost := filepath.Join(t.TempDir(), "ghost.bin")
	if err := idx.Put(index.FileEntry{
		Path: ghost,
		Size: 1,
		Chunks: []index.ChunkRef{
			{CiphertextHash: [32]byte{0xaa}, Size: 10},
		},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}

	err = purgeAll(context.Background(), idx, conn, io.Discard)
	if err == nil {
		t.Fatal("purgeAll returned nil despite closed conn")
	}
	if strings.Contains(err.Error(), "list index") {
		t.Errorf("err = %q, want Prune-side error, got list-index wrap", err)
	}
}
