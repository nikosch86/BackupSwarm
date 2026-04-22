package index

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"
)

// withGobEncodeFunc swaps gobEncodeFunc for the duration of a test.
// White-box only — production never reassigns it.
func withGobEncodeFunc(t *testing.T, fn func(w io.Writer, v any) error) {
	t.Helper()
	prev := gobEncodeFunc
	gobEncodeFunc = fn
	t.Cleanup(func() { gobEncodeFunc = prev })
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

// TestPut_EncodeFailure exercises the gob-encode error wrap in Put.
// FileEntry's fields (string, [][]byte, [32]byte, int64) are all
// gob-safe in practice, so the real encoder cannot fail — only the
// seam reaches this branch. Same pattern as the randReader seam in
// internal/crypto and the createTempFunc seam in internal/store.
func TestPut_EncodeFailure(t *testing.T) {
	ix := openTestIndex(t)

	sentinel := errors.New("forced encode failure")
	withGobEncodeFunc(t, func(w io.Writer, v any) error {
		return sentinel
	})

	err := ix.Put(FileEntry{Path: "/encode-fail"})
	if err == nil {
		t.Fatal("Put succeeded despite injected encode failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Put err = %v, want wraps sentinel", err)
	}
}

// TestGet_DecodeFailure covers the decode-error wrap in Get. A valid
// entry is replaced with junk bytes directly in the bucket so the
// gob.NewDecoder call fails; this is the shape a corrupted on-disk
// index would take, and the error path must surface (not silently
// return an empty FileEntry).
func TestGet_DecodeFailure(t *testing.T) {
	ix := openTestIndex(t)

	writeRawValue(t, ix, "/corrupt", []byte("not a gob-encoded FileEntry"))

	_, err := ix.Get("/corrupt")
	if err == nil {
		t.Fatal("Get returned no error for corrupted value")
	}
	if errors.Is(err, ErrFileNotFound) {
		t.Errorf("Get err = %v, must not wrap ErrFileNotFound for decode failures", err)
	}
}

// TestList_DecodeFailure covers the same decode-error branch inside
// List's ForEach. One bad entry aborts the iteration and the error is
// propagated — callers of List are meant to treat a decode failure as
// index corruption, not as an empty index.
func TestList_DecodeFailure(t *testing.T) {
	ix := openTestIndex(t)

	writeRawValue(t, ix, "/bad", []byte("corrupt"))

	_, err := ix.List()
	if err == nil {
		t.Fatal("List returned no error for corrupted value")
	}
}

// TestOpen_ChmodFailure exercises the os.Chmod error wrap in Open.
// bbolt.Open has just successfully opened the file, so a real Chmod
// failure is a stdlib invariant violation — only the seam reaches this
// branch. Same pattern as the createTempFunc seam in internal/store.
func TestOpen_ChmodFailure(t *testing.T) {
	sentinel := errors.New("forced chmod failure")
	withChmodFunc(t, func(name string, mode os.FileMode) error {
		return sentinel
	})

	_, err := Open(filepath.Join(t.TempDir(), "chmod-fail.db"))
	if err == nil {
		t.Fatal("Open succeeded despite injected chmod failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Open err = %v, want wraps sentinel", err)
	}
}

// TestOpen_BucketCreateFailure exercises the db.Update error wrap in
// Open. CreateBucketIfNotExists on a freshly-opened healthy db with a
// non-empty bucket name cannot fail in normal operation — only the
// seam reaches this branch.
func TestOpen_BucketCreateFailure(t *testing.T) {
	sentinel := errors.New("forced update failure")
	withDBUpdateFunc(t, func(db *bbolt.DB, fn func(*bbolt.Tx) error) error {
		return sentinel
	})

	_, err := Open(filepath.Join(t.TempDir(), "bucket-fail.db"))
	if err == nil {
		t.Fatal("Open succeeded despite injected Update failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Open err = %v, want wraps sentinel", err)
	}
}

func openTestIndex(t *testing.T) *Index {
	t.Helper()
	ix, err := Open(filepath.Join(t.TempDir(), "internal.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = ix.Close() })
	return ix
}

// writeRawValue inserts a non-gob-encoded value under key directly in
// the bucket, bypassing Put. Used to stage corrupted-on-disk scenarios
// that Put itself could never produce.
func writeRawValue(t *testing.T, ix *Index, key string, value []byte) {
	t.Helper()
	err := ix.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketName)).Put([]byte(key), value)
	})
	if err != nil {
		t.Fatalf("write raw value: %v", err)
	}
}
