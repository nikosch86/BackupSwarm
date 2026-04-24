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

// TestPrune_RemovesMissingFileFromSwarmAndIndex asserts that when a
// backed-up file disappears from disk under the backup root, Prune
// emits DeleteChunk for every chunk (peer removes the blob) and
// deletes the index entry.
func TestPrune_RemovesMissingFileFromSwarmAndIndex(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "goner.bin")
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

	// Delete the file from disk; Prune should follow through.
	if err := os.Remove(path); err != nil {
		t.Fatalf("rm: %v", err)
	}

	pruneOpts := backup.PruneOptions{
		Root:     root,
		Conn:     rig.ownerConn,
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	}
	if err := backup.Prune(context.Background(), pruneOpts); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	for i, ref := range entry.Chunks {
		has, err := rig.peerStore.Has(ref.CiphertextHash)
		if err != nil {
			t.Fatalf("peerStore.Has chunk %d: %v", i, err)
		}
		if has {
			t.Errorf("chunk %d: peer still has blob after Prune", i)
		}
	}
	if _, err := rig.ownerIndex.Get(path); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("index entry for deleted path err = %v, want ErrFileNotFound", err)
	}
}

// TestPrune_LeavesPresentFilesAlone asserts Prune does nothing for
// index entries whose paths still exist on disk, even if the file
// hasn't been re-chunked since.
func TestPrune_LeavesPresentFilesAlone(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "stable.bin")
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

	pruneOpts := backup.PruneOptions{
		Root:     root,
		Conn:     rig.ownerConn,
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	}
	if err := backup.Prune(context.Background(), pruneOpts); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	for i, ref := range entry.Chunks {
		has, err := rig.peerStore.Has(ref.CiphertextHash)
		if err != nil {
			t.Fatalf("peerStore.Has chunk %d: %v", i, err)
		}
		if !has {
			t.Errorf("chunk %d: peer lost blob for still-present file", i)
		}
	}
	if _, err := rig.ownerIndex.Get(path); err != nil {
		t.Errorf("index entry for still-present path removed: %v", err)
	}
}

// TestPrune_IgnoresEntriesOutsideRoot asserts Prune only considers
// index entries whose paths are under Root — a paranoid safeguard
// against a misconfigured daemon pointing at the wrong dir and wiping
// unrelated entries.
func TestPrune_IgnoresEntriesOutsideRoot(t *testing.T) {
	rig := newTestRig(t)
	outside := filepath.Join(t.TempDir(), "not-under-root.bin")
	writeFile(t, outside, 1<<20)
	opts := backup.RunOptions{
		Path:         outside,
		Conn:         rig.ownerConn,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := os.Remove(outside); err != nil {
		t.Fatalf("rm: %v", err)
	}

	// Prune a different root; the "not-under-root" entry stays intact.
	emptyRoot := t.TempDir()
	pruneOpts := backup.PruneOptions{
		Root:     emptyRoot,
		Conn:     rig.ownerConn,
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	}
	if err := backup.Prune(context.Background(), pruneOpts); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if _, err := rig.ownerIndex.Get(outside); err != nil {
		t.Errorf("entry outside Prune's Root removed: %v", err)
	}
}

// TestRun_IncrementalSkipsUnchanged asserts that when backup.Run is
// invoked a second time on the same file, no second upload happens —
// the peer's store sees exactly one blob per chunk, not two — and the
// index entry is unchanged.
func TestRun_IncrementalSkipsUnchanged(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "stable.bin")
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
		t.Fatalf("Run #1: %v", err)
	}
	firstEntry, err := rig.ownerIndex.Get(path)
	if err != nil {
		t.Fatalf("Get #1: %v", err)
	}

	// Snapshot the progress output of the second run so the skip note is
	// visible and we can assert "no chunks shipped" via the peer store.
	var progress bytes.Buffer
	opts.Progress = &progress
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run #2: %v", err)
	}
	secondEntry, err := rig.ownerIndex.Get(path)
	if err != nil {
		t.Fatalf("Get #2: %v", err)
	}
	if firstEntry.ModTime != secondEntry.ModTime {
		t.Errorf("ModTime changed despite unchanged file: %v -> %v", firstEntry.ModTime, secondEntry.ModTime)
	}
	if len(firstEntry.Chunks) != len(secondEntry.Chunks) {
		t.Errorf("chunk count changed: %d -> %d", len(firstEntry.Chunks), len(secondEntry.Chunks))
	}
	for i := range firstEntry.Chunks {
		if firstEntry.Chunks[i].CiphertextHash != secondEntry.Chunks[i].CiphertextHash {
			t.Errorf("chunk %d CiphertextHash changed; re-encryption happened despite unchanged file", i)
		}
	}
	if !bytes.Contains(progress.Bytes(), []byte("unchanged")) {
		t.Errorf("expected progress note mentioning 'unchanged', got %q", progress.String())
	}
}

// TestRun_IncrementalReuploadsOnSizeChange asserts that a size change
// (even with the same mtime) is picked up — the re-chunked file is
// shipped and the index entry replaced.
func TestRun_IncrementalReuploadsOnSizeChange(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "grows.bin")
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
		t.Fatalf("Run #1: %v", err)
	}
	firstEntry, err := rig.ownerIndex.Get(path)
	if err != nil {
		t.Fatalf("Get #1: %v", err)
	}

	// Grow the file by appending a byte (new size, new mtime). Index entry
	// should be replaced on the next Run.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("open-append: %v", err)
	}
	if _, err := f.Write([]byte("X")); err != nil {
		t.Fatalf("append: %v", err)
	}
	_ = f.Close()

	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run #2: %v", err)
	}
	secondEntry, err := rig.ownerIndex.Get(path)
	if err != nil {
		t.Fatalf("Get #2: %v", err)
	}
	if secondEntry.Size == firstEntry.Size {
		t.Errorf("Size unchanged after file grew: %d", secondEntry.Size)
	}
}

func TestRun_RecordsStatFields(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	statBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
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
		t.Fatalf("Get: %v", err)
	}
	if entry.Size != statBefore.Size() {
		t.Errorf("entry.Size = %d, want %d", entry.Size, statBefore.Size())
	}
	if !entry.ModTime.Equal(statBefore.ModTime()) {
		t.Errorf("entry.ModTime = %v, want %v", entry.ModTime, statBefore.ModTime())
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

// TestPrune_IndexListError covers the `opts.Index.List` error wrap in
// Prune (backup.go lines 205-208). Closing the index before the call
// makes every read fail — the error must surface as "index list: ...".
func TestPrune_IndexListError(t *testing.T) {
	rig := newTestRig(t)
	// Close the index before Prune so List() fails.
	if err := rig.ownerIndex.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:     t.TempDir(),
		Conn:     rig.ownerConn,
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil despite closed index")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("index list")) {
		t.Errorf("err = %q, want 'index list' prefix", err)
	}
}

// TestPrune_ContextCancelled covers the per-iteration ctx.Err() guard
// inside Prune's main loop (backup.go lines 211-213). A pre-cancelled
// context must bail out of the scan before any delete or index mutation
// happens — otherwise a user hitting Ctrl-C during a daemon shutdown
// could still blast the peer with deletes.
func TestPrune_ContextCancelled(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	// Seed an entry so the loop body runs and hits the ctx check.
	if err := rig.ownerIndex.Put(index.FileEntry{
		Path:   filepath.Join(root, "ghost.bin"),
		Size:   1,
		Chunks: []index.ChunkRef{{CiphertextHash: [32]byte{0x01}, Size: 10}},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := backup.Prune(ctx, backup.PruneOptions{
		Root:     root,
		Conn:     rig.ownerConn,
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil despite cancelled context")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("context canceled")) {
		t.Errorf("err = %q, want context.Canceled", err)
	}
}

// TestPrune_SendDeleteChunkError covers the sendDeleteChunk error
// wrap (backup.go lines 245-247). Closing the QUIC conn before Prune
// runs forces the delete-stream OpenStream to fail; the error must
// surface with the "delete chunk" prefix.
func TestPrune_SendDeleteChunkError(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	// Seed a dangling entry so Prune tries to send a delete.
	if err := rig.ownerIndex.Put(index.FileEntry{
		Path:   filepath.Join(root, "ghost.bin"),
		Size:   1,
		Chunks: []index.ChunkRef{{CiphertextHash: [32]byte{0x11}, Size: 10}},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	// Close the conn so sendDeleteChunk's OpenStream fails.
	_ = rig.ownerConn.Close()

	err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:     root,
		Conn:     rig.ownerConn,
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil despite closed conn")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("delete chunk")) {
		t.Errorf("err = %q, want 'delete chunk' prefix", err)
	}
}

// TestPrune_StatError covers the `statErr != os.ErrNotExist` branch
// (backup.go lines 224-226). An entry whose path is unreadable (parent
// dir with mode 0) makes os.Stat return a permission error, not
// os.ErrNotExist, so Prune must surface it as "stat ...: ..." rather
// than treating the file as "gone" and emitting a delete. This is the
// belt-and-braces path: the daemon should not silently prune entries
// whose files might still be there, just unreadable.
func TestPrune_StatError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	rig := newTestRig(t)
	root := t.TempDir()
	sub := filepath.Join(root, "locked")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	path := filepath.Join(sub, "hidden.bin")
	writeFile(t, path, 1<<20)
	// Seed the entry first so the file's stat succeeded at backup time,
	// then chmod the parent dir so Prune's os.Stat fails with EACCES.
	if err := rig.ownerIndex.Put(index.FileEntry{
		Path:   path,
		Size:   1,
		Chunks: []index.ChunkRef{{CiphertextHash: [32]byte{0xbb}, Size: 10}},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatalf("chmod locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:     root,
		Conn:     rig.ownerConn,
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil despite stat EACCES")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("stat")) {
		t.Errorf("err = %q, want 'stat' prefix", err)
	}
}
