package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

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

	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serveCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = backup.Serve(serveCtx, listener, peerStore) }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), ownerPriv, peerPub)
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
