package index_test

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"
	"time"

	"backupswarm/internal/index"
)

func newIndex(t *testing.T) *index.Index {
	t.Helper()
	path := filepath.Join(t.TempDir(), "index.db")
	ix, err := index.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = ix.Close() })
	return ix
}

func makeEntry(t *testing.T, path string, chunkCount int) index.FileEntry {
	t.Helper()
	chunks := make([]index.ChunkRef, chunkCount)
	for i := range chunks {
		plaintext := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, plaintext); err != nil {
			t.Fatalf("rand: %v", err)
		}
		ciphertext := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, ciphertext); err != nil {
			t.Fatalf("rand: %v", err)
		}
		chunks[i].PlaintextHash = sha256.Sum256(plaintext)
		chunks[i].CiphertextHash = sha256.Sum256(ciphertext)
		chunks[i].Size = int64(len(ciphertext))
		peer := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, peer); err != nil {
			t.Fatalf("rand: %v", err)
		}
		chunks[i].Peers = [][]byte{peer}
	}
	return index.FileEntry{Path: path, Chunks: chunks}
}

func TestOpen_CreatesFileAtSecurePerms(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "index.db")
	if _, err := os.Stat(filepath.Dir(dbPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("precondition: parent should not exist yet, err=%v", err)
	}
	ix, err := index.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = ix.Close() })

	info, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat db: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("db path is a directory: %s", dbPath)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("db perm = %o, want 0600", perm)
		}
		parent, err := os.Stat(filepath.Dir(dbPath))
		if err != nil {
			t.Fatalf("stat parent: %v", err)
		}
		if perm := parent.Mode().Perm(); perm != 0o700 {
			t.Errorf("parent dir perm = %o, want 0700", perm)
		}
	}
}

func TestOpen_FailsWhenParentIsFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	if _, err := index.Open(filepath.Join(blocker, "index.db")); err == nil {
		t.Fatal("Open accepted a file as parent dir")
	}
}

func TestPutGet_RoundTrip(t *testing.T) {
	ix := newIndex(t)
	entry := makeEntry(t, "/home/user/docs/report.pdf", 3)
	entry.Size = 12345
	entry.ModTime = time.Date(2026, time.April, 22, 10, 30, 0, 0, time.UTC)

	if err := ix.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := ix.Get(entry.Path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Path != entry.Path {
		t.Errorf("Path = %q, want %q", got.Path, entry.Path)
	}
	if got.Size != entry.Size {
		t.Errorf("Size = %d, want %d", got.Size, entry.Size)
	}
	if !got.ModTime.Equal(entry.ModTime) {
		t.Errorf("ModTime = %v, want %v", got.ModTime, entry.ModTime)
	}
	if len(got.Chunks) != len(entry.Chunks) {
		t.Fatalf("len(Chunks) = %d, want %d", len(got.Chunks), len(entry.Chunks))
	}
	for i := range entry.Chunks {
		if got.Chunks[i].PlaintextHash != entry.Chunks[i].PlaintextHash {
			t.Errorf("Chunks[%d].PlaintextHash mismatch", i)
		}
		if got.Chunks[i].CiphertextHash != entry.Chunks[i].CiphertextHash {
			t.Errorf("Chunks[%d].CiphertextHash mismatch", i)
		}
		if got.Chunks[i].Size != entry.Chunks[i].Size {
			t.Errorf("Chunks[%d].Size = %d, want %d", i, got.Chunks[i].Size, entry.Chunks[i].Size)
		}
		if len(got.Chunks[i].Peers) != len(entry.Chunks[i].Peers) {
			t.Errorf("Chunks[%d].Peers len = %d, want %d", i, len(got.Chunks[i].Peers), len(entry.Chunks[i].Peers))
		}
	}
}

func TestPut_Overwrites(t *testing.T) {
	ix := newIndex(t)
	first := makeEntry(t, "/a/b/c", 2)
	second := makeEntry(t, "/a/b/c", 5)

	if err := ix.Put(first); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	if err := ix.Put(second); err != nil {
		t.Fatalf("Put second: %v", err)
	}
	got, err := ix.Get("/a/b/c")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got.Chunks) != 5 {
		t.Errorf("Chunks len after overwrite = %d, want 5", len(got.Chunks))
	}
	if got.Chunks[0].PlaintextHash == first.Chunks[0].PlaintextHash {
		t.Error("overwrite did not replace chunks")
	}
}

func TestPut_EmptyChunks(t *testing.T) {
	ix := newIndex(t)
	entry := index.FileEntry{Path: "/empty", Chunks: nil}
	if err := ix.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := ix.Get("/empty")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Path != "/empty" {
		t.Errorf("Path = %q, want /empty", got.Path)
	}
	if len(got.Chunks) != 0 {
		t.Errorf("Chunks len = %d, want 0", len(got.Chunks))
	}
}

func TestGet_Missing_ReturnsErrFileNotFound(t *testing.T) {
	ix := newIndex(t)
	_, err := ix.Get("/nope")
	if err == nil {
		t.Fatal("Get accepted unknown path")
	}
	if !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("Get err = %v, want wraps ErrFileNotFound", err)
	}
}

func TestDelete_RemovesEntry(t *testing.T) {
	ix := newIndex(t)
	entry := makeEntry(t, "/deleteme", 1)
	if err := ix.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := ix.Delete(entry.Path); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := ix.Get(entry.Path); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("Get after Delete err = %v, want ErrFileNotFound", err)
	}
}

func TestDelete_Missing_ReturnsErrFileNotFound(t *testing.T) {
	ix := newIndex(t)
	err := ix.Delete("/never-indexed")
	if err == nil {
		t.Fatal("Delete accepted unknown path")
	}
	if !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("Delete err = %v, want wraps ErrFileNotFound", err)
	}
}

func TestList_Empty(t *testing.T) {
	ix := newIndex(t)
	got, err := ix.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got == nil {
		t.Error("List on empty index returned nil slice, want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("List len = %d, want 0", len(got))
	}
}

func TestList_ReturnsAllEntriesSorted(t *testing.T) {
	ix := newIndex(t)
	paths := []string{"/c/file", "/a/file", "/b/file"}
	for _, p := range paths {
		if err := ix.Put(makeEntry(t, p, 1)); err != nil {
			t.Fatalf("Put %s: %v", p, err)
		}
	}
	got, err := ix.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(paths) {
		t.Fatalf("List len = %d, want %d", len(got), len(paths))
	}
	gotPaths := make([]string, len(got))
	for i, e := range got {
		gotPaths[i] = e.Path
	}
	wantSorted := append([]string(nil), paths...)
	sort.Strings(wantSorted)
	for i := range gotPaths {
		if gotPaths[i] != wantSorted[i] {
			t.Errorf("List[%d] = %q, want %q (expect lexicographic)", i, gotPaths[i], wantSorted[i])
		}
	}
}

func TestIndex_PersistsAcrossOpen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "persist.db")
	first, err := index.Open(path)
	if err != nil {
		t.Fatalf("Open #1: %v", err)
	}
	entry := makeEntry(t, "/persisted", 4)
	if err := first.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close #1: %v", err)
	}

	second, err := index.Open(path)
	if err != nil {
		t.Fatalf("Open #2: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	got, err := second.Get(entry.Path)
	if err != nil {
		t.Fatalf("Get across reopen: %v", err)
	}
	if got.Path != entry.Path {
		t.Errorf("persisted Path = %q, want %q", got.Path, entry.Path)
	}
	if len(got.Chunks) != len(entry.Chunks) {
		t.Errorf("persisted Chunks len = %d, want %d", len(got.Chunks), len(entry.Chunks))
	}
}

func TestOperationsAfterClose_Error(t *testing.T) {
	ix := newIndex(t)
	if err := ix.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := ix.Put(makeEntry(t, "/a", 1)); err == nil {
		t.Error("Put on closed index succeeded")
	}
	if _, err := ix.Get("/a"); err == nil {
		t.Error("Get on closed index succeeded")
	}
	if err := ix.Delete("/a"); err == nil {
		t.Error("Delete on closed index succeeded")
	}
	if _, err := ix.List(); err == nil {
		t.Error("List on closed index succeeded")
	}
}

// TestOpen_ConcurrentLockFails pins the invariant that a second Open on
// the same db path returns an error rather than hanging, as long as the
// first Open is still alive. bbolt flocks the file and Index.Open
// passes a short Timeout so the second call fails fast.
func TestOpen_ConcurrentLockFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "locked.db")
	first, err := index.Open(path)
	if err != nil {
		t.Fatalf("Open #1: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	done := make(chan error, 1)
	go func() {
		_, err := index.Open(path)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("concurrent Open succeeded despite active lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("second Open did not return within 5s (expected lock failure)")
	}
}
