package store_test

import (
	"crypto/sha256"
	"errors"
	"testing"

	"backupswarm/internal/store"
)

// NoStorage stores reject all writes, report Available=0, and IsNoStorage=true.

func TestNewWithOptions_NoStorage_IsNoStorage(t *testing.T) {
	s, err := store.NewWithOptions(t.TempDir(), store.Options{NoStorage: true})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if !s.IsNoStorage() {
		t.Error("IsNoStorage = false, want true")
	}
	if got := s.Available(); got != 0 {
		t.Errorf("Available = %d, want 0", got)
	}
}

func TestNewWithOptions_DefaultIsStorageEnabled(t *testing.T) {
	s, err := store.NewWithOptions(t.TempDir(), store.Options{})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if s.IsNoStorage() {
		t.Error("IsNoStorage = true on default options, want false")
	}
}

func TestPut_NoStorage_RejectsAllWrites(t *testing.T) {
	s, err := store.NewWithOptions(t.TempDir(), store.Options{NoStorage: true})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.Put([]byte("any bytes at all"))
	if !errors.Is(err, store.ErrVolumeFull) {
		t.Errorf("Put err = %v, want wraps ErrVolumeFull", err)
	}
	if got := s.Used(); got != 0 {
		t.Errorf("Used after rejected Put = %d, want 0", got)
	}
}

func TestPutOwned_NoStorage_RejectsAndLeavesNoOwner(t *testing.T) {
	s, err := store.NewWithOptions(t.TempDir(), store.Options{NoStorage: true})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	data := []byte("blocked")
	_, err = s.PutOwned(data, []byte("alice"))
	if !errors.Is(err, store.ErrVolumeFull) {
		t.Errorf("PutOwned err = %v, want wraps ErrVolumeFull", err)
	}
	hash := sha256.Sum256(data)
	if _, err := s.Owner(hash); !errors.Is(err, store.ErrNoOwnerRecorded) {
		t.Errorf("Owner after rejected PutOwned err = %v, want wraps ErrNoOwnerRecorded", err)
	}
}
