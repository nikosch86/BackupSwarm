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

// TestModeName_AllCases covers every Mode enum value plus the default
// unknown-(%d) branch, which is the fallback for a Mode value produced
// outside the known constants (future enum growth, memory corruption,
// or an int cast from the wrong place). modeName is pure and unexported;
// the table-driven shape pins every arm of its switch at once.
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

	// Default branch: anything outside the known enum values lands in
	// the "unknown(%d)" fallback. Using a value guaranteed to be
	// outside the current constants (ModePurge + 99) keeps the test
	// stable if the enum grows in the future.
	t.Run("unknown fallback", func(t *testing.T) {
		got := modeName(ModePurge + 99)
		if !strings.HasPrefix(got, "unknown(") {
			t.Errorf("modeName(unknown) = %q, want 'unknown(...)' prefix", got)
		}
	})
}

// TestPurgeAll_ListFailure exercises the `idx.List` error wrap at the
// top of purgeAll. A closed bbolt index returns an error from every
// read call; purgeAll must surface it as "list index: ...".
//
// purgeAll is unexported — the white-box test here is the only cheap
// way to hit the error wrap without invoking the full daemon.Run
// orchestration (which is itself an integration test).
func TestPurgeAll_ListFailure(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "purge-list-fail.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	// Close the index so List() fails.
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

// TestPurgeAll_ContextCancelled exercises the `ctx.Err()` per-iteration
// short-circuit. An already-cancelled context should make purgeAll
// return the cancellation error rather than driving any Prune calls —
// important both for responsive shutdown and for not hammering the
// storage peer with deletes after the user hit Ctrl-C.
func TestPurgeAll_ContextCancelled(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "purge-ctx-cancel.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	// Seed at least one entry so the loop body runs and hits the ctx check.
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
	cancel() // pre-cancelled

	// conn is nil — the test is verifying we return before the Prune call
	// ever reaches conn, so a nil is fine and guards against accidental
	// progress past the guard.
	err = purgeAll(ctx, idx, nil, io.Discard)
	if err == nil {
		t.Fatal("purgeAll returned nil despite cancelled context")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("err = %q, want context.Canceled", err)
	}
}

// TestPurgeAll_PruneFailurePropagates exercises the inner backup.Prune
// error return. A dangling index entry forces Prune to DeleteChunk; the
// closed QUIC conn makes the send fail, surfacing the wrapped error.
func TestPurgeAll_PruneFailurePropagates(t *testing.T) {
	// Build a minimal peer listener so we can dial a real QUIC conn
	// against it, then close the conn so the inner Prune fails at its
	// first OpenStream. Using a real conn avoids needing a seam.
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

	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv)
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
	// Close immediately so the next OpenStream inside Prune fails.
	_ = conn.Close()

	idx, err := index.Open(filepath.Join(t.TempDir(), "purge-prune-fail.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	// Seed a dangling entry: file doesn't exist on disk, so Prune will
	// try to send a DeleteChunk and fail on the closed conn.
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
	// The Prune error is returned as-is (not wrapped with a prefix),
	// so we just assert it surfaced.
	if strings.Contains(err.Error(), "list index") {
		t.Errorf("err = %q, want Prune-side error, got list-index wrap", err)
	}
}
