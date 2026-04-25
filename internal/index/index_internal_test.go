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
func withGobEncodeFunc(t *testing.T, fn func(w io.Writer, v any) error) {
	t.Helper()
	prev := gobEncodeFunc
	gobEncodeFunc = fn
	t.Cleanup(func() { gobEncodeFunc = prev })
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

// TestPut_EncodeFailure asserts a gob-encode failure surfaces from Put wrapped.
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

// TestGet_DecodeFailure asserts a decode failure surfaces from Get rather than returning an empty FileEntry.
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

// TestList_DecodeFailure asserts a decode failure aborts List and propagates the error.
func TestList_DecodeFailure(t *testing.T) {
	ix := openTestIndex(t)

	writeRawValue(t, ix, "/bad", []byte("corrupt"))

	_, err := ix.List()
	if err == nil {
		t.Fatal("List returned no error for corrupted value")
	}
}

// TestOpen_ChmodFailure asserts an os.Chmod failure surfaces from Open wrapped.
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

// TestOpen_BucketCreateFailure asserts a db.Update failure surfaces from Open wrapped.
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

// writeRawValue inserts a non-gob-encoded value under key directly in the bucket.
func writeRawValue(t *testing.T, ix *Index, key string, value []byte) {
	t.Helper()
	err := ix.db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(bucketName)).Put([]byte(key), value)
	})
	if err != nil {
		t.Fatalf("write raw value: %v", err)
	}
}
