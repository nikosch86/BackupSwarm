package store

import (
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"
)

// withCreateTempFunc swaps createTempFunc for the duration of a test.
func withCreateTempFunc(t *testing.T, fn func(dir, pattern string) (tempFile, error)) {
	t.Helper()
	prev := createTempFunc
	createTempFunc = fn
	t.Cleanup(func() { createTempFunc = prev })
}

func withRenameFunc(t *testing.T, fn func(oldpath, newpath string) error) {
	t.Helper()
	prev := renameFunc
	renameFunc = fn
	t.Cleanup(func() { renameFunc = prev })
}

func withReadAllFunc(t *testing.T, fn func(r io.Reader) ([]byte, error)) {
	t.Helper()
	prev := readAllFunc
	readAllFunc = fn
	t.Cleanup(func() { readAllFunc = prev })
}

// withChmodFunc swaps chmodFunc for the duration of a test.
func withChmodFunc(t *testing.T, fn func(name string, mode os.FileMode) error) {
	t.Helper()
	prev := chmodFunc
	chmodFunc = fn
	t.Cleanup(func() { chmodFunc = prev })
}

// withDBUpdateFunc swaps dbUpdateFunc for the duration of a test.
func withDBUpdateFunc(t *testing.T, fn func(db *bbolt.DB, fn func(*bbolt.Tx) error) error) {
	t.Helper()
	prev := dbUpdateFunc
	dbUpdateFunc = fn
	t.Cleanup(func() { dbUpdateFunc = prev })
}

// fakeTempFile wraps a real *os.File and lets tests inject Write or Close failures.
type fakeTempFile struct {
	real     *os.File
	writeErr error
	closeErr error
}

func (f *fakeTempFile) Name() string { return f.real.Name() }

func (f *fakeTempFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.real.Write(p)
}

func (f *fakeTempFile) Close() error {
	realErr := f.real.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return realErr
}

// TestPutIndexSnapshot_RenameFailure_CleansUpTempFile injects an os.Rename
// failure and asserts the temp file is removed and the sentinel surfaces.
func TestPutIndexSnapshot_RenameFailure_CleansUpTempFile(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sentinel := errors.New("forced snapshot rename failure")
	var capturedTmp string
	withRenameFunc(t, func(oldpath, newpath string) error {
		capturedTmp = oldpath
		return sentinel
	})

	owner := make([]byte, 32)
	owner[0] = 0xCC
	if err := s.PutIndexSnapshot(owner, []byte("snap")); err == nil {
		t.Fatal("PutIndexSnapshot succeeded despite injected rename failure")
	} else if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if capturedTmp == "" {
		t.Fatal("rename hook never fired")
	}
	if _, statErr := os.Stat(capturedTmp); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("temp file %s not cleaned up (stat err=%v)", capturedTmp, statErr)
	}
}

// TestPutIndexSnapshot_CreateTempFailure asserts a createTempFunc error
// surfaces from PutIndexSnapshot wrapped.
func TestPutIndexSnapshot_CreateTempFailure(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sentinel := errors.New("forced snapshot create-temp failure")
	withCreateTempFunc(t, func(dir, pattern string) (tempFile, error) {
		return nil, sentinel
	})

	owner := make([]byte, 32)
	owner[0] = 0xDD
	if err := s.PutIndexSnapshot(owner, []byte("snap")); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

// TestPutIndexSnapshot_WriteFailure asserts a temp-write failure surfaces
// from PutIndexSnapshot and the temp file is cleaned up.
func TestPutIndexSnapshot_WriteFailure(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sentinel := errors.New("forced snapshot write failure")
	var capturedTmp string
	withCreateTempFunc(t, func(dir, pattern string) (tempFile, error) {
		real, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		capturedTmp = real.Name()
		return &fakeTempFile{real: real, writeErr: sentinel}, nil
	})

	owner := make([]byte, 32)
	owner[0] = 0xEE
	if err := s.PutIndexSnapshot(owner, []byte("snap")); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if capturedTmp == "" {
		t.Fatal("createTemp hook never fired")
	}
	if _, statErr := os.Stat(capturedTmp); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("temp file %s not cleaned up (stat err=%v)", capturedTmp, statErr)
	}
}

// TestPutIndexSnapshot_CloseTempFailure asserts a temp-close failure
// surfaces from PutIndexSnapshot wrapped.
func TestPutIndexSnapshot_CloseTempFailure(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sentinel := errors.New("forced snapshot close failure")
	withCreateTempFunc(t, func(dir, pattern string) (tempFile, error) {
		real, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		return &fakeTempFile{real: real, closeErr: sentinel}, nil
	})

	owner := make([]byte, 32)
	owner[0] = 0xAB
	if err := s.PutIndexSnapshot(owner, []byte("snap")); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

// TestPutIndexSnapshot_MkdirAllFailure asserts MkdirAll fails when the
// snapshots subdir path is blocked by an existing regular file.
func TestPutIndexSnapshot_MkdirAllFailure(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	blocker := filepath.Join(root, "snapshots")
	if err := os.WriteFile(blocker, []byte("squat"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	owner := make([]byte, 32)
	owner[0] = 0xBC
	err = s.PutIndexSnapshot(owner, []byte("snap"))
	if err == nil {
		t.Fatal("PutIndexSnapshot succeeded despite blocker file")
	}
}

// TestGetIndexSnapshot_OpenFailure asserts a non-NotExist os.Open error
// (e.g. mode-0 snapshot file) surfaces from GetIndexSnapshot wrapped.
func TestGetIndexSnapshot_OpenFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	owner := make([]byte, 32)
	owner[0] = 0xFE
	if err := s.PutIndexSnapshot(owner, []byte("snap")); err != nil {
		t.Fatalf("PutIndexSnapshot: %v", err)
	}
	path := snapshotPath(root, owner)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod 0: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, err = s.GetIndexSnapshot(owner)
	if err == nil {
		t.Fatal("GetIndexSnapshot succeeded despite mode-0 file")
	}
	if errors.Is(err, ErrSnapshotNotFound) {
		t.Errorf("err = %v, must not wrap ErrSnapshotNotFound for non-NotExist open errors", err)
	}
}

// TestGetIndexSnapshot_ReadFailure asserts a readAllFunc failure surfaces
// from GetIndexSnapshot wrapped.
func TestGetIndexSnapshot_ReadFailure(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	owner := make([]byte, 32)
	owner[0] = 0xCD
	if err := s.PutIndexSnapshot(owner, []byte("snap")); err != nil {
		t.Fatalf("seed snapshot: %v", err)
	}

	sentinel := errors.New("forced snapshot read failure")
	withReadAllFunc(t, func(r io.Reader) ([]byte, error) {
		return nil, sentinel
	})
	if _, err := s.GetIndexSnapshot(owner); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

// TestPut_RenameFailure_CleansUpTempFile injects an os.Rename failure and asserts Put errors and removes the temp file.
func TestPut_RenameFailure_CleansUpTempFile(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sentinel := errors.New("forced rename failure")
	var capturedTmp string
	withRenameFunc(t, func(oldpath, newpath string) error {
		capturedTmp = oldpath
		return sentinel
	})

	_, err = s.Put([]byte("rename-fail"))
	if err == nil {
		t.Fatal("Put succeeded despite injected rename failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Put err = %v, want wraps sentinel", err)
	}
	if capturedTmp == "" {
		t.Fatal("rename hook never fired — Put did not reach the rename step")
	}
	if _, statErr := os.Stat(capturedTmp); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("temp file %s was not cleaned up after rename failure (stat err=%v)", capturedTmp, statErr)
	}
}

// TestPut_WriteFailure injects a Write failure and asserts Put errors and removes the temp file.
func TestPut_WriteFailure(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sentinel := errors.New("forced write failure")
	var capturedTmp string
	withCreateTempFunc(t, func(dir, pattern string) (tempFile, error) {
		real, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		capturedTmp = real.Name()
		return &fakeTempFile{real: real, writeErr: sentinel}, nil
	})

	_, err = s.Put([]byte("write-fail"))
	if err == nil {
		t.Fatal("Put succeeded despite injected write failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Put err = %v, want wraps sentinel", err)
	}
	if capturedTmp == "" {
		t.Fatal("CreateTemp hook never fired")
	}
	if _, statErr := os.Stat(capturedTmp); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("temp file %s not cleaned up after write failure (stat err=%v)", capturedTmp, statErr)
	}
}

// TestPut_CloseFailure injects a temp-file Close failure and asserts Put errors and removes the temp file.
func TestPut_CloseFailure(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	sentinel := errors.New("forced close failure")
	var capturedTmp string
	withCreateTempFunc(t, func(dir, pattern string) (tempFile, error) {
		real, err := os.CreateTemp(dir, pattern)
		if err != nil {
			return nil, err
		}
		capturedTmp = real.Name()
		return &fakeTempFile{real: real, closeErr: sentinel}, nil
	})

	_, err = s.Put([]byte("close-fail"))
	if err == nil {
		t.Fatal("Put succeeded despite injected close failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Put err = %v, want wraps sentinel", err)
	}
	if capturedTmp == "" {
		t.Fatal("CreateTemp hook never fired")
	}
	if _, statErr := os.Stat(capturedTmp); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("temp file %s not cleaned up after close failure (stat err=%v)", capturedTmp, statErr)
	}
}

// TestGet_ReadAllFailure injects an io.ReadAll failure and asserts Get returns the wrapped error without ErrChunkNotFound.
func TestGet_ReadAllFailure(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	hash, err := s.Put([]byte("readall-fail"))
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	sentinel := errors.New("forced readall failure")
	withReadAllFunc(t, func(r io.Reader) ([]byte, error) {
		return nil, sentinel
	})

	_, err = s.Get(hash)
	if err == nil {
		t.Fatal("Get succeeded despite injected ReadAll failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Get err = %v, want wraps sentinel", err)
	}
	if errors.Is(err, ErrChunkNotFound) {
		t.Errorf("Get err = %v, must not wrap ErrChunkNotFound for read failures", err)
	}
}

// TestEnsureOwnersDB_ChmodFailure injects an os.Chmod failure and asserts PutOwned wraps it as "chmod owners db".
func TestEnsureOwnersDB_ChmodFailure(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sentinel := errors.New("forced chmod failure")
	withChmodFunc(t, func(name string, mode os.FileMode) error {
		return sentinel
	})

	_, err = s.PutOwned([]byte("owned"), []byte("alice"))
	if err == nil {
		t.Fatal("PutOwned succeeded despite injected chmod failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !containsSubstr(err.Error(), "chmod owners db") {
		t.Errorf("err = %q, want 'chmod owners db' prefix", err.Error())
	}
}

// TestEnsureOwnersDB_BucketCreateFailure injects a db.Update failure and asserts PutOwned wraps it as "create owners bucket".
func TestEnsureOwnersDB_BucketCreateFailure(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sentinel := errors.New("forced update failure")
	withDBUpdateFunc(t, func(db *bbolt.DB, fn func(*bbolt.Tx) error) error {
		return sentinel
	})

	_, err = s.PutOwned([]byte("owned"), []byte("alice"))
	if err == nil {
		t.Fatal("PutOwned succeeded despite injected Update failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !containsSubstr(err.Error(), "create owners bucket") {
		t.Errorf("err = %q, want 'create owners bucket' prefix", err.Error())
	}
}

// containsSubstr reports whether s contains sub.
func containsSubstr(s, sub string) bool {
	if len(sub) > len(s) {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestPutOwned_PutBytesFailureAfterClaim asserts the owner row persists and no blob lands on disk when putBytes fails after claimOwner.
func TestPutOwned_PutBytesFailureAfterClaim(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	owner := []byte("alice")
	data := []byte("owned-rename-fail")

	sentinel := errors.New("forced rename failure")
	withRenameFunc(t, func(oldpath, newpath string) error {
		return sentinel
	})

	hash, err := s.PutOwned(data, owner)
	if err == nil {
		t.Fatal("PutOwned succeeded despite injected rename failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("PutOwned err = %v, want wraps sentinel", err)
	}

	got, ownerErr := s.Owner(hash)
	if ownerErr != nil {
		t.Fatalf("Owner after failed PutOwned: %v", ownerErr)
	}
	if string(got) != string(owner) {
		t.Errorf("Owner = %q, want %q", got, owner)
	}

	present, hasErr := s.Has(hash)
	if hasErr != nil {
		t.Fatalf("Has after failed PutOwned: %v", hasErr)
	}
	if present {
		t.Error("Has = true, want false (blob must not be on disk after rename failure)")
	}
}

// TestRelease_ZeroIsNoop asserts release(0) leaves the used tally unchanged.
func TestRelease_ZeroIsNoop(t *testing.T) {
	s, err := NewWithMax(t.TempDir(), 32)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Put([]byte("eight!!!")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	before := s.Used()
	s.release(0)
	if got := s.Used(); got != before {
		t.Errorf("Used after release(0) = %d, want %d", got, before)
	}
}

// TestRelease_NegativeIsNoop asserts release with a non-positive count is a no-op.
func TestRelease_NegativeIsNoop(t *testing.T) {
	s, err := NewWithMax(t.TempDir(), 32)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Put([]byte("eight!!!")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	before := s.Used()
	s.release(-5)
	if got := s.Used(); got != before {
		t.Errorf("Used after release(-5) = %d, want %d", got, before)
	}
}

// TestScanUsedBytes_SkipsNonRegularEntries seeds a shard dir with a
// nested subdirectory and asserts NewWithMax reports Used summed over
// regular files only.
func TestScanUsedBytes_SkipsNonRegularEntries(t *testing.T) {
	root := t.TempDir()
	first, err := NewWithMax(root, 0)
	if err != nil {
		t.Fatalf("NewWithMax #1: %v", err)
	}
	blob := []byte("payload")
	if _, err := first.Put(blob); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	var shardDir string
	for _, e := range entries {
		if e.IsDir() {
			shardDir = filepath.Join(root, e.Name())
			break
		}
	}
	if shardDir == "" {
		t.Fatal("no shard dir found")
	}
	if err := os.Mkdir(filepath.Join(shardDir, "sub"), 0o700); err != nil {
		t.Fatalf("Mkdir sub: %v", err)
	}

	second, err := NewWithMax(root, 0)
	if err != nil {
		t.Fatalf("NewWithMax #2: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	if got := second.Used(); got != int64(len(blob)) {
		t.Errorf("Used = %d, want %d (sub-dir inside shard must be skipped)", got, len(blob))
	}
}

// TestPathFor_UsesFirstByteShardAndFullHexName asserts pathFor places the blob under the first-byte shard with a full-hex filename.
func TestPathFor_UsesFirstByteShardAndFullHexName(t *testing.T) {
	s, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var hash [sha256.Size]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	got := s.pathFor(hash)
	wantDir := filepath.Join(s.root, "00")
	if filepath.Dir(got) != wantDir {
		t.Errorf("pathFor parent = %s, want %s", filepath.Dir(got), wantDir)
	}
	if filepath.Base(got) != "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" {
		t.Errorf("pathFor base = %s, want full hex hash", filepath.Base(got))
	}
}
