package store_test

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"backupswarm/internal/store"
)

func TestNewWithMax_ZeroIsUnlimited(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 0)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if got := s.Capacity(); got != 0 {
		t.Errorf("Capacity = %d, want 0 (unlimited)", got)
	}
	if got := s.Available(); got != math.MaxInt64 {
		t.Errorf("Available = %d, want math.MaxInt64 (unlimited)", got)
	}
}

func TestNewWithMax_NegativeRejected(t *testing.T) {
	_, err := store.NewWithMax(t.TempDir(), -1)
	if err == nil {
		t.Fatal("NewWithMax accepted negative max")
	}
}

func TestNewWithMax_InitialUsedIsZero(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 1024)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if got := s.Used(); got != 0 {
		t.Errorf("Used on empty dir = %d, want 0", got)
	}
	if got := s.Available(); got != 1024 {
		t.Errorf("Available = %d, want 1024", got)
	}
}

func TestNewWithMax_UsedReflectsExistingChunks(t *testing.T) {
	root := t.TempDir()
	first, err := store.NewWithMax(root, 0)
	if err != nil {
		t.Fatalf("NewWithMax #1: %v", err)
	}
	if _, err := first.Put([]byte("alpha-bytes")); err != nil {
		t.Fatalf("Put alpha: %v", err)
	}
	if _, err := first.Put([]byte("beta-content-here")); err != nil {
		t.Fatalf("Put beta: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := store.NewWithMax(root, 1<<20)
	if err != nil {
		t.Fatalf("NewWithMax #2: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })
	want := int64(len("alpha-bytes") + len("beta-content-here"))
	if got := second.Used(); got != want {
		t.Errorf("Used after reopen = %d, want %d", got, want)
	}
	if got := second.Available(); got != (1<<20)-want {
		t.Errorf("Available after reopen = %d, want %d", got, (1<<20)-want)
	}
}

func TestPut_ExceedsMaxBytes_ReturnsErrVolumeFull(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 8)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	_, err = s.Put([]byte("nine-byte"))
	if err == nil {
		t.Fatal("Put accepted blob larger than max")
	}
	if !errors.Is(err, store.ErrVolumeFull) {
		t.Errorf("Put err = %v, want wraps ErrVolumeFull", err)
	}
	if got := s.Used(); got != 0 {
		t.Errorf("Used after rejected Put = %d, want 0", got)
	}
}

func TestPut_ExactlyAtMax_Succeeds(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 11)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.Put([]byte("eleven-byte")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if got := s.Used(); got != 11 {
		t.Errorf("Used = %d, want 11", got)
	}
	if got := s.Available(); got != 0 {
		t.Errorf("Available = %d, want 0", got)
	}
}

func TestPut_SecondBlobOverflows_FirstStillReachable(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 12)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	first, err := s.Put([]byte("aaaaaaaa")) // 8B fits
	if err != nil {
		t.Fatalf("Put first: %v", err)
	}
	_, err = s.Put([]byte("bbbbbbbb")) // 8B does not fit (8+8 > 12)
	if !errors.Is(err, store.ErrVolumeFull) {
		t.Errorf("Put second err = %v, want wraps ErrVolumeFull", err)
	}
	if got, err := s.Get(first); err != nil || string(got) != "aaaaaaaa" {
		t.Errorf("first blob unreachable after rejected second: bytes=%q err=%v", got, err)
	}
}

func TestPut_IdempotentDoesNotDoubleCount(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 10)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	data := []byte("six-by")
	if _, err := s.Put(data); err != nil {
		t.Fatalf("Put #1: %v", err)
	}
	if _, err := s.Put(data); err != nil {
		t.Fatalf("Put #2 (duplicate): %v", err)
	}
	if got := s.Used(); got != int64(len(data)) {
		t.Errorf("Used after duplicate Put = %d, want %d", got, len(data))
	}
}

func TestDelete_ReleasesReservedBytes(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 10)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	data := []byte("six-by")
	h, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := s.Delete(h); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := s.Used(); got != 0 {
		t.Errorf("Used after Delete = %d, want 0", got)
	}
	if _, err := s.Put(data); err != nil {
		t.Errorf("Put after Delete: %v (should fit again)", err)
	}
}

func TestPutOwned_RespectsLimits(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 4)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	_, err = s.PutOwned([]byte("five!"), []byte("alice"))
	if !errors.Is(err, store.ErrVolumeFull) {
		t.Fatalf("PutOwned err = %v, want wraps ErrVolumeFull", err)
	}
	// Owner row must NOT be written when capacity-rejected — otherwise a
	// later same-content claim by a different owner would be locked out
	// indefinitely with no blob on disk to justify the row.
	hash := sha256.Sum256([]byte("five!"))
	if _, err := s.Owner(hash); !errors.Is(err, store.ErrNoOwnerRecorded) {
		t.Errorf("Owner after capacity-rejected PutOwned err = %v, want wraps ErrNoOwnerRecorded", err)
	}
}

func TestDeleteForOwner_ReleasesReservedBytes(t *testing.T) {
	s, err := store.NewWithMax(t.TempDir(), 12)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	data := []byte("six-by")
	h, err := s.PutOwned(data, []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	if err := s.DeleteForOwner(h, []byte("alice")); err != nil {
		t.Fatalf("DeleteForOwner: %v", err)
	}
	if got := s.Used(); got != 0 {
		t.Errorf("Used after DeleteForOwner = %d, want 0", got)
	}
}

func TestPut_RollbackOnRenameFailure(t *testing.T) {
	root := t.TempDir()
	s, err := store.NewWithMax(root, 100)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	wantUsedBefore := int64(0)
	if got := s.Used(); got != wantUsedBefore {
		t.Fatalf("Used precondition = %d, want 0", got)
	}

	// Block the shard dir's rename target by pre-creating the shard path
	// as a regular file, so the shard MkdirAll fails and the put aborts
	// before the rename. That exercises the reservation-rollback path.
	failBlob := []byte("rollback-bait")
	hash := sha256.Sum256(failBlob)
	shardPath := filepath.Join(root, hex.EncodeToString(hash[:1]))
	if err := os.WriteFile(shardPath, nil, 0o600); err != nil {
		t.Fatalf("seed shard-as-file: %v", err)
	}

	if _, err := s.Put(failBlob); err == nil {
		t.Fatal("Put unexpectedly succeeded with shard path occupied")
	}
	if got := s.Used(); got != wantUsedBefore {
		t.Errorf("Used after failed Put = %d, want %d (rollback failed)", got, wantUsedBefore)
	}
	if got := s.Available(); got != 100 {
		t.Errorf("Available after failed Put = %d, want 100", got)
	}
}

// TestNewWithMax_ReducedCapBelowExistingUsage covers the operator
// scenario "I started the daemon with a smaller --max-storage than what
// is already on disk." The store must open cleanly (existing chunks
// stay), Available clamps to zero, new Put is rejected, but Delete
// still works and eventually frees enough space for new puts.
func TestNewWithMax_ReducedCapBelowExistingUsage(t *testing.T) {
	root := t.TempDir()
	first, err := store.NewWithMax(root, 0)
	if err != nil {
		t.Fatalf("NewWithMax #1: %v", err)
	}
	bigBlob := []byte("0123456789abcdef") // 16B
	hash, err := first.Put(bigBlob)
	if err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	const reducedCap = 8
	second, err := store.NewWithMax(root, reducedCap)
	if err != nil {
		t.Fatalf("NewWithMax with reduced cap: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	if got := second.Used(); got != int64(len(bigBlob)) {
		t.Errorf("Used = %d, want %d (existing chunks preserved)", got, len(bigBlob))
	}
	if got := second.Capacity(); got != reducedCap {
		t.Errorf("Capacity = %d, want %d", got, reducedCap)
	}
	if got := second.Available(); got != 0 {
		t.Errorf("Available = %d, want 0 (clamped when over-cap)", got)
	}

	if _, err := second.Put([]byte("any-new-chunk")); !errors.Is(err, store.ErrVolumeFull) {
		t.Errorf("over-cap Put err = %v, want wraps ErrVolumeFull", err)
	}

	if got, err := second.Get(hash); err != nil || string(got) != string(bigBlob) {
		t.Errorf("existing blob unreachable: bytes=%q err=%v", got, err)
	}

	if err := second.Delete(hash); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := second.Used(); got != 0 {
		t.Errorf("Used after Delete = %d, want 0", got)
	}
	if _, err := second.Put([]byte("ok-now")); err != nil {
		t.Errorf("Put after enough Delete: %v (should fit)", err)
	}
}

func TestPut_ConcurrentLimitNeverExceeded(t *testing.T) {
	const max = 32
	const writers = 8
	s, err := store.NewWithMax(t.TempDir(), max)
	if err != nil {
		t.Fatalf("NewWithMax: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			data := []byte{byte('a' + i), byte('a' + i), byte('a' + i), byte('a' + i),
				byte('a' + i), byte('a' + i), byte('a' + i), byte('a' + i)} // 8B unique per writer
			_, _ = s.Put(data)
		}(i)
	}
	wg.Wait()

	if got := s.Used(); got > max {
		t.Errorf("Used after concurrent Puts = %d, exceeds max %d", got, max)
	}
}
