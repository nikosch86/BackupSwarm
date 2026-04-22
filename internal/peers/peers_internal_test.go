package peers

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"
)

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

// TestOpen_ChmodFailure exercises the os.Chmod error wrap in Open.
// bbolt.Open has just successfully opened the file, so a real Chmod
// failure is a stdlib invariant violation — only the seam reaches this
// branch. Same pattern as the chmodFunc seam in internal/index.
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
// seam reaches this branch. Same pattern as internal/index.
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
