// Package store is the on-disk chunk store: opaque blobs keyed by
// sha256(content), laid out as <root>/<hh>/<full-hex-hash>.
package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sync"
	"time"

	"go.etcd.io/bbolt"
)

const (
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600

	ownersFile       = "owners.db"
	ownersBucket     = "owners"
	expiriesBucket   = "expiries"
	ownersLockTimout = 2 * time.Second
)

// tempFile lets tests substitute a fake that fails Write or Close.
type tempFile interface {
	Name() string
	Write(p []byte) (n int, err error)
	Close() error
}

// Test-only seams; production never reassigns these.
var (
	createTempFunc = func(dir, pattern string) (tempFile, error) {
		return os.CreateTemp(dir, pattern)
	}
	renameFunc   = os.Rename
	readAllFunc  = io.ReadAll
	chmodFunc    = os.Chmod
	dbUpdateFunc = func(db *bbolt.DB, fn func(*bbolt.Tx) error) error {
		return db.Update(fn)
	}
)

// ErrChunkNotFound is returned when no blob exists for the given hash.
var ErrChunkNotFound = errors.New("chunk not found")

// ErrNoOwnerRecorded is returned when a blob has no recorded uploader pubkey.
var ErrNoOwnerRecorded = errors.New("no owner recorded for blob")

// ErrOwnerMismatch is returned when a request does not match the stored owner.
var ErrOwnerMismatch = errors.New("owner mismatch")

// ErrVolumeFull is returned when a write would exceed MaxBytes capacity.
var ErrVolumeFull = errors.New("storage volume full")

// ErrNoExpiryRecorded is returned when no expiry row exists for the hash.
var ErrNoExpiryRecorded = errors.New("no expiry recorded for blob")

// Store is a content-addressed chunk store. Put is atomic via temp+rename
// and idempotent for repeated writes of identical content.
type Store struct {
	root      string
	maxBytes  int64
	noStorage bool
	chunkTTL  time.Duration
	now       func() time.Time

	// owners is lazily opened on first owner-tracking call.
	ownersMu sync.Mutex
	owners   *bbolt.DB

	// usedMu guards the running used-bytes tally.
	usedMu sync.Mutex
	used   int64

	// hashLocks serializes the reserve+claim+write+commit window per hash.
	hashLocks sync.Map
}

// Options configures NewWithOptions. Zero values use sensible defaults.
type Options struct {
	// MaxBytes caps total stored bytes; 0 = unlimited.
	MaxBytes int64
	// NoStorage refuses all Put/PutOwned with ErrVolumeFull and forces
	// Available() to 0; takes precedence over MaxBytes.
	NoStorage bool
	// ChunkTTL is the lifetime applied to each PutOwned blob; 0 disables TTL.
	ChunkTTL time.Duration
	// Now is the clock used for expiry stamping; nil defaults to time.Now.
	Now func() time.Time
}

// New opens (or initializes) a store rooted at dir with default options.
func New(dir string) (*Store, error) {
	return NewWithOptions(dir, Options{})
}

// NewWithMax opens a store rooted at dir with the given capacity cap.
func NewWithMax(dir string, maxBytes int64) (*Store, error) {
	return NewWithOptions(dir, Options{MaxBytes: maxBytes})
}

// NewWithOptions opens (or initializes) a store rooted at dir using opts.
func NewWithOptions(dir string, opts Options) (*Store, error) {
	if opts.MaxBytes < 0 {
		return nil, fmt.Errorf("max bytes must be non-negative, got %d", opts.MaxBytes)
	}
	if opts.ChunkTTL < 0 {
		return nil, fmt.Errorf("chunk TTL must be non-negative, got %v", opts.ChunkTTL)
	}
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("create store dir %q: %w", dir, err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("chmod store dir %q: %w", dir, err)
	}
	used, err := scanUsedBytes(dir)
	if err != nil {
		return nil, fmt.Errorf("scan used bytes: %w", err)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	return &Store{
		root:      dir,
		maxBytes:  opts.MaxBytes,
		noStorage: opts.NoStorage,
		chunkTTL:  opts.ChunkTTL,
		now:       now,
		used:      used,
	}, nil
}

// Close releases the owners bbolt handle. Idempotent.
func (s *Store) Close() error {
	s.ownersMu.Lock()
	defer s.ownersMu.Unlock()
	if s.owners == nil {
		return nil
	}
	err := s.owners.Close()
	s.owners = nil
	return err
}

// Put writes data and returns its SHA-256. Idempotent; no owner recorded.
func (s *Store) Put(data []byte) ([sha256.Size]byte, error) {
	hash := sha256.Sum256(data)
	if s.noStorage {
		return hash, ErrVolumeFull
	}
	finish, err := s.reserveForBlob(hash, int64(len(data)))
	if err != nil {
		return hash, err
	}
	committed := false
	defer func() { finish(committed) }()
	if _, err := s.writeBlob(data, hash); err != nil {
		return hash, err
	}
	committed = true
	return hash, nil
}

// PutOwned writes data and records owner. Same-owner repeat is a no-op;
// different owner or unowned existing blob returns ErrOwnerMismatch.
func (s *Store) PutOwned(data, owner []byte) ([sha256.Size]byte, error) {
	hash := sha256.Sum256(data)
	if s.noStorage {
		return hash, ErrVolumeFull
	}
	finish, err := s.reserveForBlob(hash, int64(len(data)))
	if err != nil {
		return hash, err
	}
	committed := false
	defer func() { finish(committed) }()
	if err := s.claimOwner(hash, owner); err != nil {
		return hash, err
	}
	if _, err := s.writeBlob(data, hash); err != nil {
		return hash, err
	}
	committed = true
	return hash, nil
}

// reserveForBlob locks the hash, reserves n bytes when the blob is absent,
// and returns a finish closure that unlocks and rolls back when uncommitted.
func (s *Store) reserveForBlob(hash [sha256.Size]byte, n int64) (finish func(committed bool), err error) {
	mu := s.lockForHash(hash)
	mu.Lock()
	has, err := s.blobOnDisk(hash)
	if err != nil {
		mu.Unlock()
		return nil, err
	}
	if has {
		return func(bool) { mu.Unlock() }, nil
	}
	if err := s.reserve(n); err != nil {
		mu.Unlock()
		return nil, err
	}
	return func(committed bool) {
		if !committed {
			s.release(n)
		}
		mu.Unlock()
	}, nil
}

// lockForHash returns a per-hash mutex.
func (s *Store) lockForHash(hash [sha256.Size]byte) *sync.Mutex {
	if v, ok := s.hashLocks.Load(hash); ok {
		return v.(*sync.Mutex)
	}
	actual, _ := s.hashLocks.LoadOrStore(hash, &sync.Mutex{})
	return actual.(*sync.Mutex)
}

// writeBlob writes data to its content-addressed path; populated path is a no-op.
func (s *Store) writeBlob(data []byte, hash [sha256.Size]byte) ([sha256.Size]byte, error) {
	path := s.pathFor(hash)

	if _, err := os.Stat(path); err == nil {
		return hash, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return hash, fmt.Errorf("stat %q: %w", path, err)
	}

	shardDir := filepath.Dir(path)
	if err := os.MkdirAll(shardDir, dirPerm); err != nil {
		return hash, fmt.Errorf("create shard dir %q: %w", shardDir, err)
	}

	tmp, err := createTempFunc(shardDir, ".put-*")
	if err != nil {
		return hash, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return hash, fmt.Errorf("write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return hash, fmt.Errorf("close temp file: %w", err)
	}
	if err := renameFunc(tmpPath, path); err != nil {
		return hash, fmt.Errorf("rename %q -> %q: %w", tmpPath, path, err)
	}
	renamed = true
	return hash, nil
}

// Get returns the bytes stored under hash, or ErrChunkNotFound.
func (s *Store) Get(hash [sha256.Size]byte) ([]byte, error) {
	path := s.pathFor(hash)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %x", ErrChunkNotFound, hash)
		}
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()
	data, err := readAllFunc(f)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	return data, nil
}

// Has reports whether a blob with the given hash is present.
func (s *Store) Has(hash [sha256.Size]byte) (bool, error) {
	path := s.pathFor(hash)
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat %q: %w", path, err)
}

// Delete removes the blob for hash without owner authorization.
func (s *Store) Delete(hash [sha256.Size]byte) error {
	path := s.pathFor(hash)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %x", ErrChunkNotFound, hash)
		}
		return fmt.Errorf("stat %q: %w", path, err)
	}
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: %x", ErrChunkNotFound, hash)
		}
		return fmt.Errorf("remove %q: %w", path, err)
	}
	s.release(info.Size())
	return nil
}

// Owner returns the Ed25519 pubkey recorded for hash, or ErrNoOwnerRecorded.
func (s *Store) Owner(hash [sha256.Size]byte) ([]byte, error) {
	db, err := s.ensureOwnersDB()
	if err != nil {
		return nil, err
	}
	var out []byte
	err = db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(ownersBucket))
		v := b.Get(hash[:])
		if v == nil {
			return fmt.Errorf("%w: %x", ErrNoOwnerRecorded, hash)
		}
		out = bytes.Clone(v)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// GetForOwner returns the blob bytes only when the recorded owner matches.
// Returns ErrChunkNotFound or ErrOwnerMismatch on failure.
func (s *Store) GetForOwner(hash [sha256.Size]byte, owner []byte) ([]byte, error) {
	ok, err := s.Has(hash)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("%w: %x", ErrChunkNotFound, hash)
	}
	db, err := s.ensureOwnersDB()
	if err != nil {
		return nil, err
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(ownersBucket))
		v := b.Get(hash[:])
		if v == nil || !bytes.Equal(v, owner) {
			return fmt.Errorf("%w: %x", ErrOwnerMismatch, hash)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return s.Get(hash)
}

// DeleteForOwner removes the blob only when the recorded owner matches.
// Returns ErrChunkNotFound or ErrOwnerMismatch on failure.
func (s *Store) DeleteForOwner(hash [sha256.Size]byte, owner []byte) error {
	ok, err := s.Has(hash)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %x", ErrChunkNotFound, hash)
	}
	db, err := s.ensureOwnersDB()
	if err != nil {
		return err
	}
	if err := db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(ownersBucket))
		v := b.Get(hash[:])
		if v == nil || !bytes.Equal(v, owner) {
			return fmt.Errorf("%w: %x", ErrOwnerMismatch, hash)
		}
		return nil
	}); err != nil {
		return err
	}
	if err := s.Delete(hash); err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		if err := tx.Bucket([]byte(ownersBucket)).Delete(hash[:]); err != nil {
			return err
		}
		return tx.Bucket([]byte(expiriesBucket)).Delete(hash[:])
	})
}

// RenewForOwner refreshes the expiry to now+ChunkTTL when owner matches.
// Returns ErrChunkNotFound or ErrOwnerMismatch on failure.
func (s *Store) RenewForOwner(hash [sha256.Size]byte, owner []byte) error {
	mu := s.lockForHash(hash)
	mu.Lock()
	defer mu.Unlock()
	ok, err := s.blobOnDisk(hash)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("%w: %x", ErrChunkNotFound, hash)
	}
	db, err := s.ensureOwnersDB()
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(ownersBucket))
		v := b.Get(hash[:])
		if v == nil || !bytes.Equal(v, owner) {
			return fmt.Errorf("%w: %x", ErrOwnerMismatch, hash)
		}
		return s.writeExpiryTx(tx, hash)
	})
}

// ExpiresAt returns the recorded expiry deadline for hash, or ErrNoExpiryRecorded.
func (s *Store) ExpiresAt(hash [sha256.Size]byte) (time.Time, error) {
	db, err := s.ensureOwnersDB()
	if err != nil {
		return time.Time{}, err
	}
	var nanos int64
	err = db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket([]byte(expiriesBucket)).Get(hash[:])
		if v == nil {
			return fmt.Errorf("%w: %x", ErrNoExpiryRecorded, hash)
		}
		if len(v) != 8 {
			return fmt.Errorf("expiry row %x has %d bytes, want 8", hash, len(v))
		}
		nanos = int64(binary.BigEndian.Uint64(v))
		return nil
	})
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, nanos), nil
}

// ExpireResult is the per-pass count of expiry rows scanned and blobs removed.
type ExpireResult struct {
	Scanned int
	Expired int
}

// ExpireSweep removes blobs whose recorded deadline has passed.
func (s *Store) ExpireSweep(ctx context.Context) (ExpireResult, error) {
	var res ExpireResult
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if s.chunkTTL == 0 {
		return res, nil
	}
	db, err := s.ensureOwnersDB()
	if err != nil {
		return res, err
	}
	now := s.now().UnixNano()
	type expiredEntry struct {
		hash     [sha256.Size]byte
		deadline int64
	}
	var due []expiredEntry
	err = db.View(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(expiriesBucket)).ForEach(func(k, v []byte) error {
			if len(k) != sha256.Size || len(v) != 8 {
				return nil
			}
			res.Scanned++
			deadline := int64(binary.BigEndian.Uint64(v))
			if deadline > now {
				return nil
			}
			var h [sha256.Size]byte
			copy(h[:], k)
			due = append(due, expiredEntry{hash: h, deadline: deadline})
			return nil
		})
	})
	if err != nil {
		return res, fmt.Errorf("scan expiries: %w", err)
	}
	for _, e := range due {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		removed, err := s.expireOne(e.hash, e.deadline)
		if err != nil {
			return res, err
		}
		if removed {
			res.Expired++
		}
	}
	return res, nil
}

// expireOne removes the blob and rows when the deadline still matches.
// Returns true when a removal happened.
func (s *Store) expireOne(hash [sha256.Size]byte, observedDeadline int64) (bool, error) {
	mu := s.lockForHash(hash)
	mu.Lock()
	defer mu.Unlock()
	db, err := s.ensureOwnersDB()
	if err != nil {
		return false, err
	}
	current := observedDeadline
	err = db.View(func(tx *bbolt.Tx) error {
		v := tx.Bucket([]byte(expiriesBucket)).Get(hash[:])
		if v == nil {
			current = 0
			return nil
		}
		if len(v) != 8 {
			return nil
		}
		current = int64(binary.BigEndian.Uint64(v))
		return nil
	})
	if err != nil {
		return false, err
	}
	if current == 0 {
		return false, nil
	}
	if current != observedDeadline {
		return false, nil
	}
	path := s.pathFor(hash)
	info, err := os.Stat(path)
	switch {
	case err == nil:
		if rmErr := os.Remove(path); rmErr != nil && !errors.Is(rmErr, os.ErrNotExist) {
			return false, fmt.Errorf("remove expired %q: %w", path, rmErr)
		}
		s.release(info.Size())
	case errors.Is(err, os.ErrNotExist):
		// Blob already gone; proceed with row cleanup.
	default:
		return false, fmt.Errorf("stat expired %q: %w", path, err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		if err := tx.Bucket([]byte(ownersBucket)).Delete(hash[:]); err != nil {
			return err
		}
		return tx.Bucket([]byte(expiriesBucket)).Delete(hash[:])
	}); err != nil {
		return false, fmt.Errorf("clear rows for %x: %w", hash, err)
	}
	return true, nil
}

// claimOwner records owner for hash and refreshes the expiry row.
// Rejects a differing record or an unowned blob already on disk.
func (s *Store) claimOwner(hash [sha256.Size]byte, owner []byte) error {
	db, err := s.ensureOwnersDB()
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(ownersBucket))
		if existing := b.Get(hash[:]); existing != nil {
			if !bytes.Equal(existing, owner) {
				return fmt.Errorf("%w: %x", ErrOwnerMismatch, hash)
			}
			return s.writeExpiryTx(tx, hash)
		}
		blobPresent, err := s.blobOnDisk(hash)
		if err != nil {
			return err
		}
		if blobPresent {
			return fmt.Errorf("%w: %x", ErrOwnerMismatch, hash)
		}
		if err := b.Put(hash[:], append([]byte(nil), owner...)); err != nil {
			return err
		}
		return s.writeExpiryTx(tx, hash)
	})
}

// writeExpiryTx writes now+ChunkTTL into the expiries bucket; no-op when ChunkTTL == 0.
func (s *Store) writeExpiryTx(tx *bbolt.Tx, hash [sha256.Size]byte) error {
	if s.chunkTTL == 0 {
		return nil
	}
	deadline := s.now().Add(s.chunkTTL).UnixNano()
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(deadline))
	return tx.Bucket([]byte(expiriesBucket)).Put(hash[:], buf[:])
}

// blobOnDisk reports whether a blob file for hash is currently stored.
func (s *Store) blobOnDisk(hash [sha256.Size]byte) (bool, error) {
	_, err := os.Stat(s.pathFor(hash))
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("stat %q: %w", s.pathFor(hash), err)
}

// ensureOwnersDB lazily opens the owners bbolt db.
func (s *Store) ensureOwnersDB() (*bbolt.DB, error) {
	s.ownersMu.Lock()
	defer s.ownersMu.Unlock()
	if s.owners != nil {
		return s.owners, nil
	}
	path := filepath.Join(s.root, ownersFile)
	db, err := bbolt.Open(path, filePerm, &bbolt.Options{Timeout: ownersLockTimout})
	if err != nil {
		return nil, fmt.Errorf("open owners db: %w", err)
	}
	if err := chmodFunc(path, filePerm); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("chmod owners db: %w", err)
	}
	if err := dbUpdateFunc(db, func(tx *bbolt.Tx) error {
		if _, err := tx.CreateBucketIfNotExists([]byte(ownersBucket)); err != nil {
			return err
		}
		_, err := tx.CreateBucketIfNotExists([]byte(expiriesBucket))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create owners bucket: %w", err)
	}
	s.owners = db
	return db, nil
}

// pathFor returns the on-disk path for hash in the sharded layout.
func (s *Store) pathFor(hash [sha256.Size]byte) string {
	hexHash := hex.EncodeToString(hash[:])
	return filepath.Join(s.root, hexHash[:2], hexHash)
}

// Used returns the running tally of bytes occupied by stored blobs.
func (s *Store) Used() int64 {
	s.usedMu.Lock()
	defer s.usedMu.Unlock()
	return s.used
}

// Capacity returns the configured maximum bytes; 0 means unlimited.
func (s *Store) Capacity() int64 {
	return s.maxBytes
}

// Available returns Capacity-Used, math.MaxInt64 when unlimited, or 0 when NoStorage.
func (s *Store) Available() int64 {
	if s.noStorage {
		return 0
	}
	if s.maxBytes == 0 {
		return math.MaxInt64
	}
	s.usedMu.Lock()
	defer s.usedMu.Unlock()
	avail := s.maxBytes - s.used
	if avail < 0 {
		return 0
	}
	return avail
}

// IsNoStorage reports whether this store rejects every Put/PutOwned.
func (s *Store) IsNoStorage() bool {
	return s.noStorage
}

// reserve adds n to the used tally; returns ErrVolumeFull on overflow.
func (s *Store) reserve(n int64) error {
	if n <= 0 {
		return nil
	}
	s.usedMu.Lock()
	defer s.usedMu.Unlock()
	if s.maxBytes > 0 && s.used+n > s.maxBytes {
		return fmt.Errorf("%w: would exceed cap by %d bytes", ErrVolumeFull, s.used+n-s.maxBytes)
	}
	s.used += n
	return nil
}

// release subtracts n from the used tally; clamps to zero.
func (s *Store) release(n int64) {
	if n <= 0 {
		return
	}
	s.usedMu.Lock()
	defer s.usedMu.Unlock()
	s.used -= n
	if s.used < 0 {
		s.used = 0
	}
}

// scanUsedBytes sums regular-file sizes under root's shard directories.
func scanUsedBytes(root string) (int64, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("read root %q: %w", root, err)
	}
	var total int64
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if e.Name() == snapshotsDir {
			continue
		}
		shardDir := filepath.Join(root, e.Name())
		shardEntries, err := os.ReadDir(shardDir)
		if err != nil {
			return 0, fmt.Errorf("read shard %q: %w", shardDir, err)
		}
		for _, f := range shardEntries {
			if !f.Type().IsRegular() {
				continue
			}
			info, err := f.Info()
			if err != nil {
				return 0, fmt.Errorf("stat %q: %w", filepath.Join(shardDir, f.Name()), err)
			}
			total += info.Size()
		}
	}
	return total, nil
}
