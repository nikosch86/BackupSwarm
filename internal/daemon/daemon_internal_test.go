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
	go func() { _ = backup.Serve(serveCtx, listener, peerStore) }()

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
