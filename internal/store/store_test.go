package store_test

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"backupswarm/internal/store"
)

func TestNew_CreatesDirIfMissing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "chunks")
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("precondition: %s should not exist, err=%v", root, err)
	}
	s, err := store.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if s == nil {
		t.Fatal("New returned nil Store")
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat root: %v", err)
	}
	if !info.IsDir() {
		t.Fatalf("root %s is not a directory", root)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("root perm = %o, want 0700", perm)
		}
	}
}

func TestNew_TightensExistingDirPerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perms not enforced on windows")
	}
	root := filepath.Join(t.TempDir(), "chunks")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatalf("pre-create root: %v", err)
	}
	if _, err := store.New(root); err != nil {
		t.Fatalf("New: %v", err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("root perm after New = %o, want 0700", perm)
	}
}

func TestNew_FailsWhenRootIsFile(t *testing.T) {
	bogus := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(bogus, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}
	if _, err := store.New(bogus); err == nil {
		t.Fatal("New accepted a regular file as root")
	}
}

func TestPut_ReturnsSha256Hash(t *testing.T) {
	s := newStore(t)
	data := []byte("hello, chunk store")
	got, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	want := sha256.Sum256(data)
	if got != want {
		t.Errorf("Put hash = %x, want %x", got, want)
	}
}

func TestPut_StoresAtShardedPath(t *testing.T) {
	root := t.TempDir()
	s, err := store.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data := []byte("sharded layout check")
	hash, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	hex := hex.EncodeToString(hash[:])
	path := filepath.Join(root, hex[:2], hex)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.IsDir() {
		t.Errorf("chunk path is a directory: %s", path)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("chunk file perm = %o, want 0600", perm)
		}
		parent, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatalf("stat parent: %v", err)
		}
		if perm := parent.Mode().Perm(); perm != 0o700 {
			t.Errorf("shard dir perm = %o, want 0700", perm)
		}
	}
}

func TestPut_Duplicate_IsIdempotent(t *testing.T) {
	s := newStore(t)
	data := []byte("same content twice")
	h1, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put #1: %v", err)
	}
	h2, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put #2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("duplicate Put returned different hashes: %x vs %x", h1, h2)
	}
	got, err := s.Get(h1)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("duplicate Put left wrong bytes on disk")
	}
}

func TestPut_EmptyData(t *testing.T) {
	s := newStore(t)
	h, err := s.Put(nil)
	if err != nil {
		t.Fatalf("Put nil: %v", err)
	}
	if h != sha256.Sum256(nil) {
		t.Errorf("empty Put hash = %x, want sha256('')", h)
	}
	got, err := s.Get(h)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("Get returned %d bytes for empty blob", len(got))
	}
}

func TestPut_LargeRandomRoundTrip(t *testing.T) {
	s := newStore(t)
	data := make([]byte, 2<<20) // 2 MiB
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	h, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(h)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("round-trip bytes differ")
	}
}

func TestGet_Missing_ReturnsErrChunkNotFound(t *testing.T) {
	s := newStore(t)
	var missing [sha256.Size]byte
	_, err := s.Get(missing)
	if err == nil {
		t.Fatal("Get accepted unknown hash")
	}
	if !errors.Is(err, store.ErrChunkNotFound) {
		t.Errorf("Get err = %v, want wraps ErrChunkNotFound", err)
	}
}

func TestHas_ReflectsPresence(t *testing.T) {
	s := newStore(t)
	data := []byte("presence")
	var missing [sha256.Size]byte

	ok, err := s.Has(missing)
	if err != nil {
		t.Fatalf("Has(missing): %v", err)
	}
	if ok {
		t.Error("Has(missing) = true, want false")
	}

	h, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	ok, err = s.Has(h)
	if err != nil {
		t.Fatalf("Has(stored): %v", err)
	}
	if !ok {
		t.Error("Has(stored) = false, want true")
	}
}

func TestDelete_RemovesFile(t *testing.T) {
	s := newStore(t)
	h, err := s.Put([]byte("to be removed"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(h); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	ok, err := s.Has(h)
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if ok {
		t.Error("Has after Delete = true, want false")
	}
	if _, err := s.Get(h); !errors.Is(err, store.ErrChunkNotFound) {
		t.Errorf("Get after Delete err = %v, want ErrChunkNotFound", err)
	}
}

func TestDelete_Missing_ReturnsErrChunkNotFound(t *testing.T) {
	s := newStore(t)
	var missing [sha256.Size]byte
	err := s.Delete(missing)
	if err == nil {
		t.Fatal("Delete accepted unknown hash")
	}
	if !errors.Is(err, store.ErrChunkNotFound) {
		t.Errorf("Delete err = %v, want wraps ErrChunkNotFound", err)
	}
}

func TestStore_PersistsAcrossInstances(t *testing.T) {
	root := t.TempDir()
	first, err := store.New(root)
	if err != nil {
		t.Fatalf("New #1: %v", err)
	}
	data := []byte("persistent")
	h, err := first.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close #1: %v", err)
	}

	second, err := store.New(root)
	if err != nil {
		t.Fatalf("New #2: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	got, err := second.Get(h)
	if err != nil {
		t.Fatalf("Get across instances: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("persisted bytes differ")
	}
}

func TestPut_ConcurrentSameHash(t *testing.T) {
	s := newStore(t)
	data := []byte("race condition bait")
	const writers = 8

	var wg sync.WaitGroup
	errs := make(chan error, writers)
	hashes := make(chan [sha256.Size]byte, writers)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			h, err := s.Put(data)
			if err != nil {
				errs <- err
				return
			}
			hashes <- h
		}()
	}
	wg.Wait()
	close(errs)
	close(hashes)

	for err := range errs {
		t.Errorf("concurrent Put: %v", err)
	}
	var first [sha256.Size]byte
	var seen bool
	for h := range hashes {
		if !seen {
			first = h
			seen = true
			continue
		}
		if h != first {
			t.Errorf("concurrent Put returned differing hashes: %x vs %x", h, first)
		}
	}
	got, err := s.Get(first)
	if err != nil {
		t.Fatalf("Get after concurrent Put: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("bytes on disk differ from input after concurrent Puts")
	}
}

func TestPut_ShardDirReadOnly(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	root := t.TempDir()
	s, err := store.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data := []byte("readonly-shard")
	hash := sha256.Sum256(data)
	shardDir := filepath.Join(root, hex.EncodeToString(hash[:1]))
	if err := os.MkdirAll(shardDir, 0o700); err != nil {
		t.Fatalf("seed shard: %v", err)
	}
	if err := os.Chmod(shardDir, 0o500); err != nil {
		t.Fatalf("chmod shard: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	if _, err := s.Put(data); err == nil {
		t.Fatal("Put succeeded despite read-only shard dir")
	}
}

func TestPut_ShardDirPathIsFile(t *testing.T) {
	root := t.TempDir()
	s, err := store.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data := []byte("shard-blocked")
	hash := sha256.Sum256(data)
	shardPath := filepath.Join(root, hex.EncodeToString(hash[:1]))
	if err := os.WriteFile(shardPath, nil, 0o600); err != nil {
		t.Fatalf("seed shard-as-file: %v", err)
	}
	if _, err := s.Put(data); err == nil {
		t.Fatal("Put succeeded despite shard path being a regular file")
	}
}

func TestPut_StatNonEnoentPropagates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	root := t.TempDir()
	s, err := store.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	data := []byte("stat-error")
	hash, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put seed: %v", err)
	}
	shardDir := filepath.Join(root, hex.EncodeToString(hash[:1]))
	if err := os.Chmod(shardDir, 0); err != nil {
		t.Fatalf("chmod shard: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	if _, err := s.Put(data); err == nil {
		t.Fatal("Put succeeded despite unreadable shard dir")
	}
}

func TestGet_OpenNonEnoentPropagates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	root := t.TempDir()
	s, err := store.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hash, err := s.Put([]byte("get-error"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	filePath := filepath.Join(root, hex.EncodeToString(hash[:1]), hex.EncodeToString(hash[:]))
	if err := os.Chmod(filePath, 0); err != nil {
		t.Fatalf("chmod file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filePath, 0o600) })

	_, err = s.Get(hash)
	if err == nil {
		t.Fatal("Get succeeded despite unreadable file")
	}
	if errors.Is(err, store.ErrChunkNotFound) {
		t.Errorf("Get err = %v, must not wrap ErrChunkNotFound for permission failures", err)
	}
}

func TestHas_StatNonEnoentPropagates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	root := t.TempDir()
	s, err := store.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hash, err := s.Put([]byte("has-error"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	shardDir := filepath.Join(root, hex.EncodeToString(hash[:1]))
	if err := os.Chmod(shardDir, 0); err != nil {
		t.Fatalf("chmod shard: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	if _, err := s.Has(hash); err == nil {
		t.Fatal("Has succeeded despite unreadable shard dir")
	}
}

func TestDelete_RemoveNonEnoentPropagates(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	root := t.TempDir()
	s, err := store.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hash, err := s.Put([]byte("delete-error"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	shardDir := filepath.Join(root, hex.EncodeToString(hash[:1]))
	if err := os.Chmod(shardDir, 0o500); err != nil {
		t.Fatalf("chmod shard: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	err = s.Delete(hash)
	if err == nil {
		t.Fatal("Delete succeeded despite read-only shard dir")
	}
	if errors.Is(err, store.ErrChunkNotFound) {
		t.Errorf("Delete err = %v, must not wrap ErrChunkNotFound for permission failures", err)
	}
}

// TestPutOwned_ClaimOwnerBlobOnDiskStatError asserts that a non-ENOENT
// stat error from blobOnDisk aborts claimOwner without writing an owner
// row.
func TestPutOwned_ClaimOwnerBlobOnDiskStatError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	root := t.TempDir()
	s, err := store.New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	data := []byte("claim-stat-error")
	hash, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put seed: %v", err)
	}

	shardDir := filepath.Join(root, hex.EncodeToString(hash[:1]))
	if err := os.Chmod(shardDir, 0); err != nil {
		t.Fatalf("chmod shard: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	if _, err := s.PutOwned(data, []byte("alice")); err == nil {
		t.Fatal("PutOwned succeeded despite unreadable shard dir")
	}

	if _, err := s.Owner(hash); !errors.Is(err, store.ErrNoOwnerRecorded) {
		t.Errorf("Owner err = %v, want wraps ErrNoOwnerRecorded (no owner row should have been written)", err)
	}
}

func newStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}
