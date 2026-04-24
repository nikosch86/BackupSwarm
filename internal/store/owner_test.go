package store_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"backupswarm/internal/store"
)

func TestPutOwned_RecordsOwner(t *testing.T) {
	s := newStore(t)
	data := []byte("owned blob")
	owner := []byte{0x01, 0x02, 0x03}

	h, err := s.PutOwned(data, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	if h != sha256.Sum256(data) {
		t.Errorf("hash = %x, want %x", h, sha256.Sum256(data))
	}
	got, err := s.Owner(h)
	if err != nil {
		t.Fatalf("Owner: %v", err)
	}
	if !bytes.Equal(got, owner) {
		t.Errorf("Owner = %x, want %x", got, owner)
	}
	// The blob should also be readable via the normal Get path.
	blob, err := s.Get(h)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !bytes.Equal(blob, data) {
		t.Error("Get bytes differ from PutOwned input")
	}
}

func TestPutOwned_IdempotentForSameOwner(t *testing.T) {
	s := newStore(t)
	data := []byte("same again")
	owner := []byte("alice")

	h1, err := s.PutOwned(data, owner)
	if err != nil {
		t.Fatalf("PutOwned #1: %v", err)
	}
	h2, err := s.PutOwned(data, owner)
	if err != nil {
		t.Fatalf("PutOwned #2: %v", err)
	}
	if h1 != h2 {
		t.Errorf("hash mismatch: %x vs %x", h1, h2)
	}
}

func TestPutOwned_DifferentOwner_RejectsDuplicate(t *testing.T) {
	s := newStore(t)
	data := []byte("contested")
	ownerA := []byte("alice")
	ownerB := []byte("bob")

	if _, err := s.PutOwned(data, ownerA); err != nil {
		t.Fatalf("PutOwned A: %v", err)
	}
	_, err := s.PutOwned(data, ownerB)
	if err == nil {
		t.Fatal("PutOwned with conflicting owner returned nil")
	}
	if !errors.Is(err, store.ErrOwnerMismatch) {
		t.Errorf("err = %v, want wraps ErrOwnerMismatch", err)
	}
	// Owner must still be the original.
	got, err := s.Owner(sha256.Sum256(data))
	if err != nil {
		t.Fatalf("Owner: %v", err)
	}
	if !bytes.Equal(got, ownerA) {
		t.Errorf("Owner after rejected conflict = %x, want %x", got, ownerA)
	}
}

func TestOwner_UnknownHash_ReturnsErrNoOwnerRecorded(t *testing.T) {
	s := newStore(t)
	var h [sha256.Size]byte
	_, err := s.Owner(h)
	if err == nil {
		t.Fatal("Owner on unknown hash returned nil")
	}
	if !errors.Is(err, store.ErrNoOwnerRecorded) {
		t.Errorf("err = %v, want wraps ErrNoOwnerRecorded", err)
	}
}

func TestOwner_PutWithoutOwner_ReturnsErrNoOwnerRecorded(t *testing.T) {
	s := newStore(t)
	data := []byte("ownerless")
	h, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, err = s.Owner(h)
	if !errors.Is(err, store.ErrNoOwnerRecorded) {
		t.Errorf("Owner on un-owned blob err = %v, want ErrNoOwnerRecorded", err)
	}
}

func TestDeleteForOwner_MatchingOwner_Removes(t *testing.T) {
	s := newStore(t)
	data := []byte("alice's file")
	owner := []byte("alice")
	h, err := s.PutOwned(data, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	if err := s.DeleteForOwner(h, owner); err != nil {
		t.Fatalf("DeleteForOwner: %v", err)
	}
	ok, err := s.Has(h)
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if ok {
		t.Error("blob still present after authorized delete")
	}
	if _, err := s.Owner(h); !errors.Is(err, store.ErrNoOwnerRecorded) {
		t.Errorf("Owner after delete err = %v, want ErrNoOwnerRecorded", err)
	}
}

func TestDeleteForOwner_WrongOwner_RejectsAndLeavesBlob(t *testing.T) {
	s := newStore(t)
	data := []byte("alice's file")
	ownerA := []byte("alice")
	ownerB := []byte("bob")
	h, err := s.PutOwned(data, ownerA)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	err = s.DeleteForOwner(h, ownerB)
	if err == nil {
		t.Fatal("DeleteForOwner with wrong owner returned nil")
	}
	if !errors.Is(err, store.ErrOwnerMismatch) {
		t.Errorf("err = %v, want wraps ErrOwnerMismatch", err)
	}
	ok, err := s.Has(h)
	if err != nil {
		t.Fatalf("Has: %v", err)
	}
	if !ok {
		t.Error("blob removed despite owner mismatch")
	}
}

func TestDeleteForOwner_UnknownHash_ReturnsErrChunkNotFound(t *testing.T) {
	s := newStore(t)
	var h [sha256.Size]byte
	err := s.DeleteForOwner(h, []byte("anyone"))
	if err == nil {
		t.Fatal("DeleteForOwner on unknown hash returned nil")
	}
	if !errors.Is(err, store.ErrChunkNotFound) {
		t.Errorf("err = %v, want wraps ErrChunkNotFound", err)
	}
}

func TestDeleteForOwner_UnownedBlob_ReturnsErrOwnerMismatch(t *testing.T) {
	s := newStore(t)
	data := []byte("ownerless")
	h, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	err = s.DeleteForOwner(h, []byte("anyone"))
	if err == nil {
		t.Fatal("DeleteForOwner on un-owned blob returned nil")
	}
	if !errors.Is(err, store.ErrOwnerMismatch) {
		t.Errorf("err = %v, want wraps ErrOwnerMismatch", err)
	}
}

func TestOwner_PersistsAcrossStoreReopen(t *testing.T) {
	root := t.TempDir()
	first, err := store.New(root)
	if err != nil {
		t.Fatalf("New #1: %v", err)
	}
	data := []byte("persistent owner")
	owner := []byte("alice")
	h, err := first.PutOwned(data, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := store.New(root)
	if err != nil {
		t.Fatalf("New #2: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	got, err := second.Owner(h)
	if err != nil {
		t.Fatalf("Owner after reopen: %v", err)
	}
	if !bytes.Equal(got, owner) {
		t.Errorf("Owner after reopen = %x, want %x", got, owner)
	}
}
