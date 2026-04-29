package store

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

func mustPutOwned(t *testing.T, s *Store, data, owner []byte) [sha256.Size]byte {
	t.Helper()
	h, err := s.PutOwned(data, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	return h
}

func mutateExpiry(t *testing.T, s *Store, hash [sha256.Size]byte, value []byte) {
	t.Helper()
	db, err := s.ensureOwnersDB()
	if err != nil {
		t.Fatalf("ensureOwnersDB: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(expiriesBucket)).Put(hash[:], value)
	}); err != nil {
		t.Fatalf("mutate expiry: %v", err)
	}
}

func deleteExpiry(t *testing.T, s *Store, hash [sha256.Size]byte) {
	t.Helper()
	db, err := s.ensureOwnersDB()
	if err != nil {
		t.Fatalf("ensureOwnersDB: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(expiriesBucket)).Delete(hash[:])
	}); err != nil {
		t.Fatalf("delete expiry: %v", err)
	}
}

func TestExpiresAt_MalformedRowReturnsError(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hash := mustPutOwned(t, s, []byte("malformed"), []byte("alice"))
	mutateExpiry(t, s, hash, []byte{0x01, 0x02, 0x03})

	if _, err := s.ExpiresAt(hash); err == nil {
		t.Fatal("ExpiresAt returned nil despite malformed expiry row")
	} else if errors.Is(err, ErrNoExpiryRecorded) {
		t.Errorf("err = %v, must not wrap ErrNoExpiryRecorded for malformed row", err)
	}
}

func TestExpireSweep_SkipsMalformedRows(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hash := mustPutOwned(t, s, []byte("short-row"), []byte("alice"))
	mutateExpiry(t, s, hash, []byte{0x00, 0x00})

	res, err := s.ExpireSweep(context.Background())
	if err != nil {
		t.Fatalf("ExpireSweep: %v", err)
	}
	if res.Scanned != 0 {
		t.Errorf("Scanned = %d, want 0 (malformed row must skip)", res.Scanned)
	}
	if res.Expired != 0 {
		t.Errorf("Expired = %d, want 0", res.Expired)
	}
	if ok, _ := s.Has(hash); !ok {
		t.Error("blob removed even though expiry row was malformed")
	}
}

func TestExpireOne_RowDeletedConcurrently(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hash := mustPutOwned(t, s, []byte("row-deleted"), []byte("alice"))
	deleteExpiry(t, s, hash)

	removed, err := s.expireOne(hash, now.Add(-time.Second).UnixNano())
	if err != nil {
		t.Fatalf("expireOne: %v", err)
	}
	if removed {
		t.Error("expireOne reported removal despite missing expiry row")
	}
	if ok, _ := s.Has(hash); !ok {
		t.Error("blob removed when expiry row was missing")
	}
}

func TestExpireOne_DeadlineBumpedSinceScan(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hash := mustPutOwned(t, s, []byte("bumped-deadline"), []byte("alice"))
	stale := now.Add(-time.Hour).UnixNano()

	removed, err := s.expireOne(hash, stale)
	if err != nil {
		t.Fatalf("expireOne: %v", err)
	}
	if removed {
		t.Error("expireOne removed blob despite deadline bumped past observed value")
	}
	if ok, _ := s.Has(hash); !ok {
		t.Error("blob removed despite renewed deadline")
	}
}

func TestExpireOne_MalformedCurrentRowFallsThrough(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hash := mustPutOwned(t, s, []byte("malformed-current"), []byte("alice"))
	mutateExpiry(t, s, hash, []byte{0xff})

	removed, err := s.expireOne(hash, now.UnixNano())
	if err != nil {
		t.Fatalf("expireOne: %v", err)
	}
	if !removed {
		t.Error("expireOne did not remove blob when current row malformed (fallthrough path)")
	}
}

func TestExpireOne_BlobAlreadyMissing(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hash := mustPutOwned(t, s, []byte("missing-blob"), []byte("alice"))

	deadlineBytes := make([]byte, 8)
	deadline := now.Add(-time.Hour).UnixNano()
	binary.BigEndian.PutUint64(deadlineBytes, uint64(deadline))
	mutateExpiry(t, s, hash, deadlineBytes)

	if err := os.Remove(s.pathFor(hash)); err != nil {
		t.Fatalf("remove blob: %v", err)
	}

	removed, err := s.expireOne(hash, deadline)
	if err != nil {
		t.Fatalf("expireOne: %v", err)
	}
	if !removed {
		t.Error("expireOne did not report removal for already-missing blob")
	}
	if _, err := s.Owner(hash); !errors.Is(err, ErrNoOwnerRecorded) {
		t.Errorf("Owner err = %v, want ErrNoOwnerRecorded after row cleanup", err)
	}
}

func TestExpireOne_RemoveBlobError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hash := mustPutOwned(t, s, []byte("rm-fail"), []byte("alice"))

	deadlineBytes := make([]byte, 8)
	deadline := now.Add(-time.Hour).UnixNano()
	binary.BigEndian.PutUint64(deadlineBytes, uint64(deadline))
	mutateExpiry(t, s, hash, deadlineBytes)

	shardDir := filepath.Dir(s.pathFor(hash))
	if err := os.Chmod(shardDir, 0o500); err != nil {
		t.Fatalf("chmod shard dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	_, err = s.expireOne(hash, deadline)
	if err == nil {
		t.Fatal("expireOne returned nil despite remove failure on read-only shard dir")
	}
	if !errors.Is(err, os.ErrPermission) && !strings.Contains(err.Error(), "remove expired") {
		t.Errorf("err = %v, want 'remove expired' wrap", err)
	}
}

func TestExpireOne_StatNonNotExistError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	hash := mustPutOwned(t, s, []byte("stat-fail"), []byte("alice"))

	deadlineBytes := make([]byte, 8)
	deadline := now.Add(-time.Hour).UnixNano()
	binary.BigEndian.PutUint64(deadlineBytes, uint64(deadline))
	mutateExpiry(t, s, hash, deadlineBytes)

	shardDir := filepath.Dir(s.pathFor(hash))
	if err := os.Chmod(shardDir, 0o000); err != nil {
		t.Fatalf("chmod shard dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	_, err = s.expireOne(hash, deadline)
	if err == nil {
		t.Fatal("expireOne returned nil despite stat error on locked shard dir")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("err = %v, must not wrap os.ErrNotExist for permission failure", err)
	}
}

func TestExpireSweep_SkipsMalformedHashKey(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.PutOwned([]byte("seed"), []byte("alice")); err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	db, err := s.ensureOwnersDB()
	if err != nil {
		t.Fatalf("ensureOwnersDB: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		buf := make([]byte, 8)
		binary.BigEndian.PutUint64(buf, uint64(now.UnixNano()))
		return tx.Bucket([]byte(expiriesBucket)).Put([]byte("short-key"), buf)
	}); err != nil {
		t.Fatalf("inject short key: %v", err)
	}

	res, err := s.ExpireSweep(context.Background())
	if err != nil {
		t.Fatalf("ExpireSweep: %v", err)
	}
	if res.Scanned != 1 {
		t.Errorf("Scanned = %d, want 1 (malformed key must skip but real row counted)", res.Scanned)
	}
}

func TestExpiresAt_EnsureOwnersDBError(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sentinel := errors.New("forced chmod failure")
	withChmodFunc(t, func(name string, mode os.FileMode) error {
		return sentinel
	})

	var hash [sha256.Size]byte
	if _, err := s.ExpiresAt(hash); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestRenewForOwner_EnsureOwnersDBError(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	root := t.TempDir()
	first, err := NewWithOptions(root, Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	hash, err := first.PutOwned([]byte("seed"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := NewWithOptions(root, Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions #2: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	sentinel := errors.New("forced chmod failure")
	withChmodFunc(t, func(name string, mode os.FileMode) error {
		return sentinel
	})

	if err := second.RenewForOwner(hash, []byte("alice")); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestExpireSweep_EnsureOwnersDBError(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sentinel := errors.New("forced chmod failure")
	withChmodFunc(t, func(name string, mode os.FileMode) error {
		return sentinel
	})

	if _, err := s.ExpireSweep(context.Background()); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestClaimOwner_BlobOnDiskError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	now := time.Unix(1_000_000, 0).UTC()
	root := t.TempDir()
	s, err := NewWithOptions(root, Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	data := []byte("blob-stat-fail")
	hash := sha256.Sum256(data)
	shardDir := filepath.Dir(s.pathFor(hash))
	if err := os.MkdirAll(shardDir, 0o700); err != nil {
		t.Fatalf("mkdir shard dir: %v", err)
	}
	if err := os.Chmod(shardDir, 0o000); err != nil {
		t.Fatalf("chmod shard dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	err = s.claimOwner(hash, []byte("alice"))
	if err == nil {
		t.Fatal("claimOwner returned nil despite locked shard dir")
	}
	if errors.Is(err, ErrOwnerMismatch) {
		t.Errorf("err = %v, must not wrap ErrOwnerMismatch for stat failure", err)
	}
}

func TestExpireOne_EnsureOwnersDBError(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sentinel := errors.New("forced chmod failure")
	withChmodFunc(t, func(name string, mode os.FileMode) error {
		return sentinel
	})

	var hash [sha256.Size]byte
	if _, err := s.expireOne(hash, 0); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestExpireSweep_CtxCancelMidLoop(t *testing.T) {
	now := time.Unix(1_000_000, 0).UTC()
	s, err := NewWithOptions(t.TempDir(), Options{
		ChunkTTL: 30 * 24 * time.Hour,
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	for i := 0; i < 3; i++ {
		if _, err := s.PutOwned([]byte(fmt.Sprintf("blob-%d", i)), []byte("alice")); err != nil {
			t.Fatalf("PutOwned %d: %v", i, err)
		}
	}

	db, err := s.ensureOwnersDB()
	if err != nil {
		t.Fatalf("ensureOwnersDB: %v", err)
	}
	stale := now.Add(-time.Hour).UnixNano()
	if err := db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(expiriesBucket))
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(stale))
		return bucket.ForEach(func(k, _ []byte) error {
			return bucket.Put(k, buf[:])
		})
	}); err != nil {
		t.Fatalf("backdate expiries: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := s.ExpireSweep(ctx); err == nil {
		t.Error("ExpireSweep returned nil despite cancelled ctx with due entries")
	}
}
