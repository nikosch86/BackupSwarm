package peers

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"go.etcd.io/bbolt"
)

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
