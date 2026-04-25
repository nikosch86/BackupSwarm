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
// White-box only — production never reassigns it.
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
// White-box only — production never reassigns it.
func withChmodFunc(t *testing.T, fn func(name string, mode os.FileMode) error) {
	t.Helper()
	prev := chmodFunc
	chmodFunc = fn
	t.Cleanup(func() { chmodFunc = prev })
}

// withDBUpdateFunc swaps dbUpdateFunc for the duration of a test.
// White-box only — production never reassigns it.
func withDBUpdateFunc(t *testing.T, fn func(db *bbolt.DB, fn func(*bbolt.Tx) error) error) {
	t.Helper()
	prev := dbUpdateFunc
	dbUpdateFunc = fn
	t.Cleanup(func() { dbUpdateFunc = prev })
}

// fakeTempFile wraps a real *os.File so we still get a valid tmp path on
// disk (for the defer-cleanup to remove) but can inject Write/Close
// failures at will.
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
	// Always close the real file so the fd isn't leaked, but report the
	// injected error to the caller when one is set.
	realErr := f.real.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return realErr
}

// TestPut_RenameFailure_CleansUpTempFile covers the os.Rename error wrap
// in Put plus the committed==false defer cleanup that removes the leaked
// temp file. Both branches are otherwise unreachable without fault
// injection — os.Rename between two paths in the same directory on the
// same filesystem doesn't fail in normal operation.
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
	// Defer cleanup must have removed the orphan temp file.
	if _, statErr := os.Stat(capturedTmp); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("temp file %s was not cleaned up after rename failure (stat err=%v)", capturedTmp, statErr)
	}
}

// TestPut_WriteFailure exercises the tmp.Write error wrap. The real
// *os.File only fails Write on ENOSPC, EIO, or a closed fd — none of
// which we can cause portably. The seam lets us assert the branch is
// hit and the fake temp file is properly closed on the error path.
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
	// Defer cleanup must still run after a write failure.
	if capturedTmp == "" {
		t.Fatal("CreateTemp hook never fired")
	}
	if _, statErr := os.Stat(capturedTmp); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("temp file %s not cleaned up after write failure (stat err=%v)", capturedTmp, statErr)
	}
}

// TestPut_CloseFailure exercises the tmp.Close error wrap. Close errors
// from *os.File are rare (deferred write flush failure); only reachable
// in tests via the seam.
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

// TestGet_ReadAllFailure exercises the io.ReadAll mid-read error wrap
// in Get. A successfully-opened file failing part-way through a ReadAll
// requires a disk-level IO error — not reproducible on a normal tmpfs,
// so the seam carries the branch.
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

// TestEnsureOwnersDB_ChmodFailure exercises the os.Chmod error wrap
// inside ensureOwnersDB. bbolt.Open has just successfully opened the
// file, so a real Chmod failure is a stdlib invariant violation —
// only the seam reaches this branch. Same pattern as the chmodFunc
// seam in internal/index / internal/peers.
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

	// PutOwned is the shortest path to ensureOwnersDB from the exported
	// API; Put would skip it. The recorded error must wrap the sentinel
	// and mention the chmod stage.
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

// TestEnsureOwnersDB_BucketCreateFailure exercises the db.Update error
// wrap inside ensureOwnersDB. CreateBucketIfNotExists on a healthy
// freshly-opened db with a non-empty bucket name cannot fail in normal
// operation — only the seam reaches this branch.
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

// containsSubstr is a trivial substring helper used by the tests above
// to avoid importing strings into this white-box test file.
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

// TestPutOwned_PutBytesFailureAfterClaim asserts that when putBytes
// fails after claimOwner succeeds, the owner row persists and no blob
// lands on disk.
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

// Sanity check: the sharded path helper is what determines where a
// committed blob lands on disk. Keeps the internal helper from quietly
// drifting away from the Put/Get invariants.
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
