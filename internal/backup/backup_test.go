package backup_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// testRig brings up a peer (listener + chunk store) and an owner QUIC
// connection to it. Everything is torn down via t.Cleanup.
type testRig struct {
	t            *testing.T
	peerStore    *store.Store
	ownerIndex   *index.Index
	ownerConn    *bsquic.Conn
	serveErr     chan error
	recipientPub *[32]byte

	peerPubKey ed25519.PublicKey
}

func newTestRig(t *testing.T) *testRig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	peerDir := t.TempDir()
	peerStore, err := store.New(filepath.Join(peerDir, "blobs"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	_ = ownerPub

	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- backup.Serve(ctx, listener, peerStore)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
	})

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	ownerConn, err := bsquic.Dial(dialCtx, listener.Addr().String(), ownerPriv, peerPub)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = ownerConn.Close() })

	ownerIndex, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = ownerIndex.Close() })

	recipientPub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	return &testRig{
		t:            t,
		peerStore:    peerStore,
		ownerIndex:   ownerIndex,
		ownerConn:    ownerConn,
		serveErr:     serveErr,
		recipientPub: recipientPub,
		peerPubKey:   peerPub,
	}
}

func writeFile(t *testing.T, path string, size int) []byte {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return data
}

func TestRun_SingleFileSmall(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "file.bin")
	data := writeFile(t, path, 1<<20) // 1 MiB, fits in one chunk at 1 MiB chunk size

	opts := backup.RunOptions{
		Path:         path,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry, err := rig.ownerIndex.Get(path)
	if err != nil {
		t.Fatalf("Index.Get: %v", err)
	}
	if len(entry.Chunks) != 1 {
		t.Fatalf("got %d chunks in index, want 1", len(entry.Chunks))
	}

	// Verify the peer has the ciphertext blob at the recorded address.
	has, err := rig.peerStore.Has(entry.Chunks[0].CiphertextHash)
	if err != nil {
		t.Fatalf("peerStore.Has: %v", err)
	}
	if !has {
		t.Error("peer store missing blob at recorded CiphertextHash")
	}

	// Plaintext hash in the index must match sha256(data).
	if entry.Chunks[0].PlaintextHash != sha256.Sum256(data) {
		t.Error("PlaintextHash in index does not match plaintext sha256")
	}
}

func TestRun_EmptyFile(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "empty.bin")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	opts := backup.RunOptions{
		Path:         path,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry, err := rig.ownerIndex.Get(path)
	if err != nil {
		t.Fatalf("Index.Get: %v", err)
	}
	if len(entry.Chunks) != 0 {
		t.Errorf("empty file got %d chunks, want 0", len(entry.Chunks))
	}
}

func TestRun_MultiChunkFile(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "big.bin")
	data := writeFile(t, path, (1<<20)*3+42) // 3 full chunks + 42-byte tail

	opts := backup.RunOptions{
		Path:         path,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry, err := rig.ownerIndex.Get(path)
	if err != nil {
		t.Fatalf("Index.Get: %v", err)
	}
	if len(entry.Chunks) != 4 {
		t.Fatalf("got %d chunks, want 4", len(entry.Chunks))
	}
	for i, ref := range entry.Chunks {
		has, err := rig.peerStore.Has(ref.CiphertextHash)
		if err != nil {
			t.Fatalf("peerStore.Has chunk %d: %v", i, err)
		}
		if !has {
			t.Errorf("chunk %d: peer missing blob", i)
		}
	}
	_ = data // end-to-end restore integrity is covered by M1.9; here we pin pipeline shape
}

func TestRun_DirectoryWalk(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	wantPaths := []string{
		filepath.Join(root, "a.txt"),
		filepath.Join(root, "sub", "b.txt"),
		filepath.Join(root, "sub", "deep", "c.txt"),
	}
	for _, p := range wantPaths {
		writeFile(t, p, 1<<20)
	}

	opts := backup.RunOptions{
		Path:         root,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	listed, err := rig.ownerIndex.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	gotPaths := make([]string, len(listed))
	for i, e := range listed {
		gotPaths[i] = e.Path
	}
	sort.Strings(gotPaths)
	sort.Strings(wantPaths)
	if fmt.Sprint(gotPaths) != fmt.Sprint(wantPaths) {
		t.Errorf("indexed paths = %v, want %v", gotPaths, wantPaths)
	}
}

func TestRun_RecordsPeerPubKey(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         path,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, err := rig.ownerIndex.Get(path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(entry.Chunks) == 0 {
		t.Fatal("no chunks recorded")
	}
	peers := entry.Chunks[0].Peers
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	if !bytes.Equal(peers[0], rig.peerPubKey) {
		t.Error("peer pubkey in index does not match storage peer")
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Run starts

	opts := backup.RunOptions{
		Path:         path,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(ctx, opts); err == nil {
		t.Error("Run with pre-cancelled ctx returned nil error")
	}
}

func TestRun_ProgressOutput(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	var progress bytes.Buffer
	opts := backup.RunOptions{
		Path:         path,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     &progress,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if progress.Len() == 0 {
		t.Error("expected progress output, got none")
	}
}

func TestRun_RejectsMissingPath(t *testing.T) {
	rig := newTestRig(t)
	opts := backup.RunOptions{
		Path:         filepath.Join(t.TempDir(), "does-not-exist"),
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err == nil {
		t.Error("Run on non-existent path returned nil error")
	}
}

func TestRun_RejectsInvalidChunkSize(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         path,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1024, // below chunk.MinChunkSize (1 MiB)
		Progress:     io.Discard,
	}
	err := backup.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run accepted below-minimum chunk size")
	}
}

func TestServe_ConcurrentRuns(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()

	var wg sync.WaitGroup
	paths := []string{
		filepath.Join(root, "p1.bin"),
		filepath.Join(root, "p2.bin"),
	}
	for _, p := range paths {
		writeFile(t, p, 1<<20)
	}

	for _, p := range paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			opts := backup.RunOptions{
				Path:         path,
				Conn:         rig.ownerConn,
				RecipientPub: rig.recipientPub,
				Index:        rig.ownerIndex,
				ChunkSize:    1 << 20,
				Progress:     io.Discard,
			}
			if err := backup.Run(context.Background(), opts); err != nil {
				t.Errorf("Run %s: %v", path, err)
			}
		}(p)
	}
	wg.Wait()

	got, err := rig.ownerIndex.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(paths) {
		t.Errorf("indexed %d files, want %d", len(got), len(paths))
	}
}

// TestRun_PeerRejection simulates a peer that returns an application-level
// error by wiring a no-space store (directory has zero bytes of space isn't
// portable; instead we feed store errors by pointing the store at a read-only
// dir via chmod). This is a soft test — if it can't produce an error it's
// skipped, but when it does fire it asserts the appErr path is propagated.
func TestRun_SkipsSymlinks(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	realFile := filepath.Join(root, "real.bin")
	writeFile(t, realFile, 1<<20)
	symlink := filepath.Join(root, "link.bin")
	if err := os.Symlink(realFile, symlink); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	var progress bytes.Buffer
	opts := backup.RunOptions{
		Path:         root,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     &progress,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := rig.ownerIndex.Get(symlink); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("symlink %q should not have been indexed", symlink)
	}
	if _, err := rig.ownerIndex.Get(realFile); err != nil {
		t.Errorf("real file should have been indexed: %v", err)
	}
	if !bytes.Contains(progress.Bytes(), []byte("skip")) {
		t.Errorf("expected skip-note in progress output, got: %q", progress.String())
	}
}

func TestRun_PropagatesIndexError(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	// Close the index so Put fails before Run records any entry.
	if err := rig.ownerIndex.Close(); err != nil {
		t.Fatalf("Close index: %v", err)
	}

	opts := backup.RunOptions{
		Path:         path,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err == nil {
		t.Fatal("Run returned nil despite closed index")
	}
}

func TestRun_PeerErrorPropagation(t *testing.T) {
	// Create a store directory, then chmod it to 0500 (read-only) so Put's
	// MkdirAll of the shard subdirectory fails.
	peerDir := t.TempDir()
	rootStoreDir := filepath.Join(peerDir, "store")
	peerStore, err := store.New(rootStoreDir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	if err := os.Chmod(rootStoreDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(rootStoreDir, 0o700) })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}

	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() { _ = backup.Serve(ctx, listener, peerStore) }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	ownerConn, err := bsquic.Dial(dialCtx, listener.Addr().String(), ownerPriv, peerPub)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = ownerConn.Close() })

	ownerIndex, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = ownerIndex.Close() })

	recipientPub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         path,
		Conn:         ownerConn,
		RecipientPub: recipientPub,
		Index:        ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	err = backup.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run succeeded despite read-only peer store")
	}
	// The owner sees the application-level error string from the peer.
	if !containsAny(err.Error(), "peer", "store") {
		t.Errorf("Run err = %v, want mention of peer/store failure", err)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if sub != "" && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

// ensure compile-time that the package-level errors we care about are usable.
var _ = errors.Is

// TestRun_DefaultsNilProgress covers the `if opts.Progress == nil`
// short-circuit: leaving Progress unset must not panic — Run silently
// falls back to io.Discard.
func TestRun_DefaultsNilProgress(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         path,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		// Progress deliberately nil — Run must fall back to io.Discard
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestRun_OpenFileError covers the os.Open error wrap in backupFile
// (backup.go lines 101-103). The path exists (Stat succeeds) but is
// unreadable because we pre-chmod it to mode 0, so the subsequent
// os.Open inside backupFile fails.
func TestRun_OpenFileError(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "unreadable.bin")
	writeFile(t, path, 1<<20)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	opts := backup.RunOptions{
		Path:         path,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	err := backup.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run on mode-0 file returned nil")
	}
}

// TestRun_WalkError covers the WalkDir walkErr propagation branch
// (backup.go lines 79-81). A subdirectory is made unreadable (mode 0)
// during the walk so WalkDir hands down an error to the walk-func,
// which Run must propagate.
func TestRun_WalkError(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	sub := filepath.Join(root, "locked")
	if err := os.Mkdir(sub, 0o000); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	opts := backup.RunOptions{
		Path:         root,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	err := backup.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run returned nil despite unreadable subdirectory")
	}
}
