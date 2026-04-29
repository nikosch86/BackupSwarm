package store_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/store"
)

// fakeClock returns a sequence of times derived from a mutable wall.
type fakeClock struct {
	now atomic.Pointer[time.Time]
}

func newFakeClock(t time.Time) *fakeClock {
	c := &fakeClock{}
	c.now.Store(&t)
	return c
}

func (c *fakeClock) Now() time.Time { return *c.now.Load() }

func (c *fakeClock) Set(t time.Time) { c.now.Store(&t) }

func (c *fakeClock) Advance(d time.Duration) { c.Set(c.Now().Add(d)) }

func newTTLStore(t *testing.T, ttl time.Duration, clock *fakeClock) *store.Store {
	t.Helper()
	s, err := store.NewWithOptions(t.TempDir(), store.Options{
		ChunkTTL: ttl,
		Now:      clock.Now,
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestPutOwned_RecordsExpiryWhenTTLSet(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	ttl := 30 * 24 * time.Hour
	s := newTTLStore(t, ttl, clock)

	h, err := s.PutOwned([]byte("ttl content"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	exp, err := s.ExpiresAt(h)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	want := clock.Now().Add(ttl)
	if !exp.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", exp, want)
	}
}

func TestPutOwned_NoExpiryWhenTTLZero(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	s := newTTLStore(t, 0, clock)

	h, err := s.PutOwned([]byte("no ttl"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	if _, err := s.ExpiresAt(h); !errors.Is(err, store.ErrNoExpiryRecorded) {
		t.Errorf("ExpiresAt err = %v, want ErrNoExpiryRecorded", err)
	}
}

func TestPutOwned_SameOwnerRefreshesExpiry(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	ttl := 30 * 24 * time.Hour
	s := newTTLStore(t, ttl, clock)

	data := []byte("refresh me")
	owner := []byte("alice")
	h, err := s.PutOwned(data, owner)
	if err != nil {
		t.Fatalf("PutOwned #1: %v", err)
	}

	clock.Advance(7 * 24 * time.Hour)
	if _, err := s.PutOwned(data, owner); err != nil {
		t.Fatalf("PutOwned #2: %v", err)
	}

	exp, err := s.ExpiresAt(h)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	want := clock.Now().Add(ttl)
	if !exp.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v (refreshed by re-put)", exp, want)
	}
}

func TestRenewForOwner_ExtendsExpiry(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	ttl := 30 * 24 * time.Hour
	s := newTTLStore(t, ttl, clock)

	h, err := s.PutOwned([]byte("renewable"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	clock.Advance(10 * 24 * time.Hour)
	if err := s.RenewForOwner(h, []byte("alice")); err != nil {
		t.Fatalf("RenewForOwner: %v", err)
	}

	exp, err := s.ExpiresAt(h)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	want := clock.Now().Add(ttl)
	if !exp.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v", exp, want)
	}
}

func TestRenewForOwner_RejectsWrongOwner(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	s := newTTLStore(t, 30*24*time.Hour, clock)

	h, err := s.PutOwned([]byte("alice's"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	if err := s.RenewForOwner(h, []byte("mallory")); !errors.Is(err, store.ErrOwnerMismatch) {
		t.Errorf("err = %v, want wraps ErrOwnerMismatch", err)
	}
}

func TestRenewForOwner_UnknownHash_ReturnsErrChunkNotFound(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	s := newTTLStore(t, 30*24*time.Hour, clock)

	var h [sha256.Size]byte
	err := s.RenewForOwner(h, []byte("alice"))
	if !errors.Is(err, store.ErrChunkNotFound) {
		t.Errorf("err = %v, want wraps ErrChunkNotFound", err)
	}
}

func TestRenewForOwner_TTLZero_StillValidatesOwner(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	s := newTTLStore(t, 0, clock)

	h, err := s.PutOwned([]byte("no-ttl"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	if err := s.RenewForOwner(h, []byte("mallory")); !errors.Is(err, store.ErrOwnerMismatch) {
		t.Errorf("err = %v, want ErrOwnerMismatch even when TTL=0", err)
	}
	if err := s.RenewForOwner(h, []byte("alice")); err != nil {
		t.Fatalf("RenewForOwner with TTL=0 should succeed for valid owner, got %v", err)
	}
}

func TestExpireSweep_RemovesExpiredBlobs(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	ttl := 30 * 24 * time.Hour
	s := newTTLStore(t, ttl, clock)

	h, err := s.PutOwned([]byte("expiring"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	clock.Advance(31 * 24 * time.Hour)
	res, err := s.ExpireSweep(context.Background())
	if err != nil {
		t.Fatalf("ExpireSweep: %v", err)
	}
	if res.Scanned == 0 {
		t.Errorf("Scanned = 0, want at least 1")
	}
	if res.Expired != 1 {
		t.Errorf("Expired = %d, want 1", res.Expired)
	}

	if ok, _ := s.Has(h); ok {
		t.Error("blob still present after expire sweep")
	}
	if _, err := s.Owner(h); !errors.Is(err, store.ErrNoOwnerRecorded) {
		t.Errorf("Owner err = %v, want ErrNoOwnerRecorded after expiry", err)
	}
	if _, err := s.ExpiresAt(h); !errors.Is(err, store.ErrNoExpiryRecorded) {
		t.Errorf("ExpiresAt err = %v, want ErrNoExpiryRecorded after expiry", err)
	}
}

func TestExpireSweep_LeavesFreshBlobs(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	ttl := 30 * 24 * time.Hour
	s := newTTLStore(t, ttl, clock)

	h, err := s.PutOwned([]byte("fresh"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	clock.Advance(7 * 24 * time.Hour)

	res, err := s.ExpireSweep(context.Background())
	if err != nil {
		t.Fatalf("ExpireSweep: %v", err)
	}
	if res.Expired != 0 {
		t.Errorf("Expired = %d, want 0 (fresh blob)", res.Expired)
	}
	if ok, _ := s.Has(h); !ok {
		t.Error("fresh blob removed by expire sweep")
	}
}

func TestExpireSweep_TTLZeroIsNoop(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	s := newTTLStore(t, 0, clock)

	h, err := s.PutOwned([]byte("no expiry"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	clock.Advance(365 * 24 * time.Hour)

	res, err := s.ExpireSweep(context.Background())
	if err != nil {
		t.Fatalf("ExpireSweep: %v", err)
	}
	if res.Expired != 0 || res.Scanned != 0 {
		t.Errorf("Result = %+v, want zero scan with TTL=0", res)
	}
	if ok, _ := s.Has(h); !ok {
		t.Error("blob removed despite TTL=0")
	}
}

func TestExpireSweep_RespectsContextCancel(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	s := newTTLStore(t, 30*24*time.Hour, clock)

	if _, err := s.PutOwned([]byte("a"), []byte("alice")); err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.ExpireSweep(ctx); err == nil {
		t.Error("ExpireSweep returned nil despite cancelled ctx")
	}
}

func TestDeleteForOwner_ClearsExpiryRow(t *testing.T) {
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	s := newTTLStore(t, 30*24*time.Hour, clock)

	h, err := s.PutOwned([]byte("delete me"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	if err := s.DeleteForOwner(h, []byte("alice")); err != nil {
		t.Fatalf("DeleteForOwner: %v", err)
	}
	if _, err := s.ExpiresAt(h); !errors.Is(err, store.ErrNoExpiryRecorded) {
		t.Errorf("ExpiresAt after delete err = %v, want ErrNoExpiryRecorded", err)
	}
}

func TestExpiresAt_PersistsAcrossReopen(t *testing.T) {
	root := t.TempDir()
	clock := newFakeClock(time.Unix(1_000_000, 0).UTC())
	ttl := 30 * 24 * time.Hour

	first, err := store.NewWithOptions(root, store.Options{
		ChunkTTL: ttl,
		Now:      clock.Now,
	})
	if err != nil {
		t.Fatalf("New #1: %v", err)
	}
	h, err := first.PutOwned([]byte("persist"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	want := clock.Now().Add(ttl)
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := store.NewWithOptions(root, store.Options{
		ChunkTTL: ttl,
		Now:      clock.Now,
	})
	if err != nil {
		t.Fatalf("New #2: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	got, err := second.ExpiresAt(h)
	if err != nil {
		t.Fatalf("ExpiresAt after reopen: %v", err)
	}
	if !got.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v after reopen", got, want)
	}
}
