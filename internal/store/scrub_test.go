package store_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"backupswarm/internal/store"
)

func TestScrub_DetectsAndDeletesCorruptBlob(t *testing.T) {
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	data := []byte("blob-to-corrupt")
	owner := bytes.Repeat([]byte{0xa1}, 32)
	h, err := s.PutOwned(data, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	hexHash := hex.EncodeToString(h[:])
	path := filepath.Join(root, hexHash[:2], hexHash)
	corrupted := append([]byte(nil), data...)
	corrupted[0] ^= 0xff
	if err := os.WriteFile(path, corrupted, 0o600); err != nil {
		t.Fatalf("corrupt file: %v", err)
	}

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Scanned != 1 || res.Corrupt != 1 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {1, 1}", res.Scanned, res.Corrupt)
	}

	if ok, err := s.Has(h); err != nil {
		t.Fatalf("Has: %v", err)
	} else if ok {
		t.Error("corrupt blob still present after Scrub")
	}
	if _, err := s.Owner(h); !errors.Is(err, store.ErrNoOwnerRecorded) {
		t.Errorf("Owner err = %v, want wraps ErrNoOwnerRecorded (owner row should be gone)", err)
	}
	if got := s.Used(); got != 0 {
		t.Errorf("Used after Scrub = %d, want 0", got)
	}
}

func TestScrub_CleanStoreNoOp(t *testing.T) {
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	a := []byte("alpha")
	b := []byte("beta-bytes")
	hA, err := s.Put(a)
	if err != nil {
		t.Fatalf("Put a: %v", err)
	}
	hB, err := s.PutOwned(b, bytes.Repeat([]byte{0xb2}, 32))
	if err != nil {
		t.Fatalf("PutOwned b: %v", err)
	}

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Scanned != 2 || res.Corrupt != 0 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {2, 0}", res.Scanned, res.Corrupt)
	}

	got, err := s.Get(hA)
	if err != nil {
		t.Fatalf("Get a: %v", err)
	}
	if !bytes.Equal(got, a) {
		t.Error("Get a returned wrong bytes after clean Scrub")
	}
	got, err = s.Get(hB)
	if err != nil {
		t.Fatalf("Get b: %v", err)
	}
	if !bytes.Equal(got, b) {
		t.Error("Get b returned wrong bytes after clean Scrub")
	}
	if want := int64(len(a) + len(b)); s.Used() != want {
		t.Errorf("Used after clean Scrub = %d, want %d", s.Used(), want)
	}
}

func TestScrub_EmptyStore(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub on empty store: %v", err)
	}
	if res.Scanned != 0 || res.Corrupt != 0 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {0, 0}", res.Scanned, res.Corrupt)
	}
}

func TestScrub_PreservesUnaffectedBlobs(t *testing.T) {
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	good := []byte("this one is fine")
	bad := []byte("this one will rot")
	owner := bytes.Repeat([]byte{0xc3}, 32)
	hGood, err := s.PutOwned(good, owner)
	if err != nil {
		t.Fatalf("PutOwned good: %v", err)
	}
	hBad, err := s.PutOwned(bad, owner)
	if err != nil {
		t.Fatalf("PutOwned bad: %v", err)
	}

	hexBad := hex.EncodeToString(hBad[:])
	pathBad := filepath.Join(root, hexBad[:2], hexBad)
	corrupted := append([]byte(nil), bad...)
	corrupted[0] ^= 0x01
	if err := os.WriteFile(pathBad, corrupted, 0o600); err != nil {
		t.Fatalf("corrupt bad: %v", err)
	}

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Scanned != 2 || res.Corrupt != 1 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {2, 1}", res.Scanned, res.Corrupt)
	}

	if ok, _ := s.Has(hGood); !ok {
		t.Error("Scrub removed the uncorrupt blob")
	}
	if ok, _ := s.Has(hBad); ok {
		t.Error("Scrub did not remove the corrupt blob")
	}
	if want := int64(len(good)); s.Used() != want {
		t.Errorf("Used after Scrub = %d, want %d", s.Used(), want)
	}
}

func TestScrub_SkipsSnapshotsAndOwnersDB(t *testing.T) {
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	owner := bytes.Repeat([]byte{0xd4}, 32)
	if err := s.PutIndexSnapshot(owner, []byte("encrypted-blob")); err != nil {
		t.Fatalf("PutIndexSnapshot: %v", err)
	}
	// Touching owners.db ensures the bbolt file is materialized.
	if _, err := s.PutOwned([]byte("seed"), owner); err != nil {
		t.Fatalf("PutOwned seed: %v", err)
	}

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	// Only the seed blob is content-addressed; snapshots and owners.db
	// must not be counted or removed.
	if res.Scanned != 1 || res.Corrupt != 0 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {1, 0}", res.Scanned, res.Corrupt)
	}

	got, err := s.GetIndexSnapshot(owner)
	if err != nil {
		t.Fatalf("GetIndexSnapshot after Scrub: %v", err)
	}
	if string(got) != "encrypted-blob" {
		t.Errorf("snapshot bytes after Scrub = %q, want %q", got, "encrypted-blob")
	}
}

func TestScrub_IgnoresStrayNonHexEntries(t *testing.T) {
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	// Stray file at root and stray dir+file under a non-hex subdir.
	if err := os.WriteFile(filepath.Join(root, "README"), []byte("hi"), 0o600); err != nil {
		t.Fatalf("seed stray root file: %v", err)
	}
	strayDir := filepath.Join(root, "notes")
	if err := os.MkdirAll(strayDir, 0o700); err != nil {
		t.Fatalf("mkdir stray: %v", err)
	}
	if err := os.WriteFile(filepath.Join(strayDir, "scratch"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed stray sub: %v", err)
	}

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Scanned != 0 || res.Corrupt != 0 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {0, 0}", res.Scanned, res.Corrupt)
	}
	if _, err := os.Stat(filepath.Join(root, "README")); err != nil {
		t.Errorf("Scrub removed stray README: %v", err)
	}
	if _, err := os.Stat(filepath.Join(strayDir, "scratch")); err != nil {
		t.Errorf("Scrub removed file under stray dir: %v", err)
	}
}

func TestScrub_ContextCancelled(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.PutOwned([]byte("data"), bytes.Repeat([]byte{0xe5}, 32)); err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Scrub(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Scrub err = %v, want context.Canceled", err)
	}
}

func TestScrub_ConcurrentPutOwnedNoCapacityDrift(t *testing.T) {
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	data := []byte("scrub-vs-put race bait")
	owner := bytes.Repeat([]byte{0xf6}, 32)
	const writers = 16

	var wg sync.WaitGroup
	errs := make(chan error, writers+1)
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.PutOwned(data, owner); err != nil {
				errs <- err
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := s.Scrub(context.Background()); err != nil {
			errs <- err
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("concurrent PutOwned/Scrub: %v", err)
	}
	if want := int64(len(data)); s.Used() != want {
		t.Errorf("Used() = %d after concurrent PutOwned + Scrub, want %d", s.Used(), want)
	}
}

func TestScrub_RootMissingIsNoop(t *testing.T) {
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := os.RemoveAll(root); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub on missing root: %v", err)
	}
	if res.Scanned != 0 || res.Corrupt != 0 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {0, 0}", res.Scanned, res.Corrupt)
	}
}

func TestScrub_RootUnreadableSurfacesError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if err := os.Chmod(root, 0o000); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })

	if _, err := s.Scrub(context.Background()); err == nil {
		t.Fatal("Scrub succeeded despite unreadable root")
	} else if errors.Is(err, os.ErrNotExist) {
		t.Errorf("Scrub err = %v, must not wrap os.ErrNotExist for permission failures", err)
	}
}

func TestScrub_ShardUnreadableSurfacesError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	h, err := s.Put([]byte("seed"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	shardDir := filepath.Join(root, hex.EncodeToString(h[:1]))
	if err := os.Chmod(shardDir, 0o000); err != nil {
		t.Fatalf("chmod shard: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	if _, err := s.Scrub(context.Background()); err == nil {
		t.Fatal("Scrub succeeded despite unreadable shard dir")
	}
}

func TestScrub_BlobUnreadableLogsAndContinues(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	h, err := s.Put([]byte("blocked"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	hexHash := hex.EncodeToString(h[:])
	blobPath := filepath.Join(root, hexHash[:2], hexHash)
	if err := os.Chmod(blobPath, 0o000); err != nil {
		t.Fatalf("chmod blob: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(blobPath, 0o600) })

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Scanned != 1 || res.Corrupt != 0 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {1, 0}", res.Scanned, res.Corrupt)
	}
	if _, statErr := os.Stat(blobPath); statErr != nil {
		t.Errorf("unreadable blob removed by Scrub (stat err=%v); should be left in place", statErr)
	}
}

func TestScrub_RemoveFailureLogsAndContinues(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	data := []byte("rot bait")
	h, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	hexHash := hex.EncodeToString(h[:])
	shardDir := filepath.Join(root, hexHash[:2])
	blobPath := filepath.Join(shardDir, hexHash)
	corrupt := append([]byte(nil), data...)
	corrupt[0] ^= 0xff
	if err := os.WriteFile(blobPath, corrupt, 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if err := os.Chmod(shardDir, 0o500); err != nil {
		t.Fatalf("chmod shard: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Scanned != 1 || res.Corrupt != 0 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {1, 0}", res.Scanned, res.Corrupt)
	}
	if _, statErr := os.Stat(blobPath); statErr != nil {
		t.Errorf("blob removed despite read-only parent shard (stat err=%v)", statErr)
	}
}

func TestScrub_SkipsSubdirInsideShard(t *testing.T) {
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	h, err := s.Put([]byte("co-located"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	shardDir := filepath.Join(root, hex.EncodeToString(h[:1]))
	if err := os.Mkdir(filepath.Join(shardDir, "subdir"), 0o700); err != nil {
		t.Fatalf("Mkdir sub: %v", err)
	}

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Scanned != 1 || res.Corrupt != 0 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {1, 0}", res.Scanned, res.Corrupt)
	}
}

func TestScrub_SkipsStrayFileInShard(t *testing.T) {
	root := t.TempDir()
	s, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	h, err := s.Put([]byte("real-blob"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	shardDir := filepath.Join(root, hex.EncodeToString(h[:1]))
	if err := os.WriteFile(filepath.Join(shardDir, "scratch"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed stray file: %v", err)
	}
	if err := os.WriteFile(filepath.Join(shardDir, "ZZ"+hex.EncodeToString(h[:])[2:]), []byte("y"), 0o600); err != nil {
		t.Fatalf("seed non-hex 64-char file: %v", err)
	}

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Scanned != 1 || res.Corrupt != 0 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {1, 0}", res.Scanned, res.Corrupt)
	}
}

func TestScrub_PersistsRemovalAcrossInstances(t *testing.T) {
	root := t.TempDir()
	first, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax #1: %v", err)
	}
	owner := bytes.Repeat([]byte{0x07}, 32)
	data := []byte("rot bait")
	h, err := first.PutOwned(data, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	hexHash := hex.EncodeToString(h[:])
	corrupt := append([]byte(nil), data...)
	corrupt[0] ^= 0x10
	if err := os.WriteFile(filepath.Join(root, hexHash[:2], hexHash), corrupt, 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}
	if _, err := first.Scrub(context.Background()); err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close #1: %v", err)
	}

	second, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax #2: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if got := second.Used(); got != 0 {
		t.Errorf("Used after reopen = %d, want 0", got)
	}
	if ok, _ := second.Has(h); ok {
		t.Error("Has after reopen = true, want false")
	}
}
