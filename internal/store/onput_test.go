package store_test

import (
	"sync/atomic"
	"testing"

	"backupswarm/internal/store"
)

// TestOnPut_FiresOncePerSuccessfulPutOwned asserts the OnPut callback
// runs exactly once per successful PutOwned with the blob's byte count.
func TestOnPut_FiresOncePerSuccessfulPutOwned(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	var bytesSeen atomic.Int64
	s, err := store.NewWithOptions(t.TempDir(), store.Options{
		OnPut: func(n int) {
			calls.Add(1)
			bytesSeen.Add(int64(n))
		},
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	data := []byte("alpha-blob-v1")
	owner := []byte("alice")
	if _, err := s.PutOwned(data, owner); err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("OnPut calls = %d, want 1", got)
	}
	if got := bytesSeen.Load(); got != int64(len(data)) {
		t.Errorf("OnPut bytes = %d, want %d", got, len(data))
	}
}

// TestOnPut_NotCalledOnNoStorage asserts a NoStorage store rejects
// PutOwned without firing the callback.
func TestOnPut_NotCalledOnNoStorage(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	s, err := store.NewWithOptions(t.TempDir(), store.Options{
		NoStorage: true,
		OnPut: func(int) {
			calls.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.PutOwned([]byte("x"), []byte("alice"))
	if err == nil {
		t.Fatal("PutOwned succeeded on NoStorage; want ErrVolumeFull")
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("OnPut calls = %d, want 0 on NoStorage rejection", got)
	}
}

// TestOnPut_NotCalledOnOwnerMismatch asserts a conflicting-owner second
// PutOwned does not fire the callback (storage was not made dirtier).
func TestOnPut_NotCalledOnOwnerMismatch(t *testing.T) {
	t.Parallel()

	var calls atomic.Int64
	s, err := store.NewWithOptions(t.TempDir(), store.Options{
		OnPut: func(int) {
			calls.Add(1)
		},
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	data := []byte("contested")
	if _, err := s.PutOwned(data, []byte("alice")); err != nil {
		t.Fatalf("PutOwned alice: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("after first put: OnPut calls = %d, want 1", got)
	}
	if _, err := s.PutOwned(data, []byte("bob")); err == nil {
		t.Fatal("PutOwned bob succeeded; want ErrOwnerMismatch")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("after rejected put: OnPut calls = %d, want still 1", got)
	}
}

// TestOnPut_NilCallbackNoPanic asserts a nil OnPut leaves the store
// usable without panicking.
func TestOnPut_NilCallbackNoPanic(t *testing.T) {
	t.Parallel()

	s, err := store.NewWithOptions(t.TempDir(), store.Options{OnPut: nil})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.PutOwned([]byte("p"), []byte("alice")); err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
}
