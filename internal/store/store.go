// Package store is the on-disk chunk store: opaque byte blobs keyed by
// sha256(content), laid out as <root>/<hh>/<full-hex-hash> for 256-way
// sharding. An optional <root>/owners.db (bbolt) records the Ed25519
// pubkey of the uploading peer for each blob written via PutOwned so
// DeleteForOwner can enforce owner-authorized deletion.
package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

// ErrChunkNotFound is returned by Get, Delete, and DeleteForOwner when
// no blob exists for the given hash.
var ErrChunkNotFound = errors.New("chunk not found")

// ErrNoOwnerRecorded is returned by Owner when a blob exists on disk but
// was stored via Put (not PutOwned) and has no uploader pubkey.
var ErrNoOwnerRecorded = errors.New("no owner recorded for blob")

// ErrOwnerMismatch is returned when a PutOwned or DeleteForOwner request
// does not match the stored owner (maps to an authz failure).
var ErrOwnerMismatch = errors.New("owner mismatch")

// Store is a content-addressed chunk store rooted at a local directory.
// Safe for concurrent use: Put is atomic via temp-file + rename and
// idempotent for repeated writes of identical content.
type Store struct {
	root string

	// owners is lazily opened on first owner-tracking call; plain Put
	// never touches it. ownersMu makes lazy-open race-safe.
	ownersMu sync.Mutex
	owners   *bbolt.DB
}

// New opens (or initializes) a store rooted at dir. Dir is created and
// chmod'd to 0700; returns an error if dir is not creatable as a directory.
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("create store dir %q: %w", dir, err)
	}
	// Tighten perms in case dir pre-existed with a looser mode.
	if err := os.Chmod(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("chmod store dir %q: %w", dir, err)
	}
	return &Store{root: dir}, nil
}

// Close releases the lazily-opened owners bbolt handle. Idempotent.
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
// Callers needing owner-authorized delete must use PutOwned instead.
func (s *Store) Put(data []byte) ([sha256.Size]byte, error) {
	return s.putBytes(data)
}

// PutOwned is Put plus an owner record. Same-owner + same-content is a
// no-op; different owner returns ErrOwnerMismatch. An on-disk blob with
// no recorded owner is treated as quarantined and also returns ErrOwnerMismatch.
func (s *Store) PutOwned(data, owner []byte) ([sha256.Size]byte, error) {
	hash := sha256.Sum256(data)
	if err := s.claimOwner(hash, owner); err != nil {
		return hash, err
	}
	if _, err := s.putBytes(data); err != nil {
		return hash, err
	}
	return hash, nil
}

func (s *Store) putBytes(data []byte) ([sha256.Size]byte, error) {
	hash := sha256.Sum256(data)
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

	// os.CreateTemp opens the file with mode 0600, which matches filePerm —
	// no explicit Chmod needed.
	tmp, err := createTempFunc(shardDir, ".put-*")
	if err != nil {
		return hash, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
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
	committed = true
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

// Has reports whether a blob with the given hash is present. Returns an
// error only for unexpected IO failures (permission, EIO, etc.).
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

// Delete removes the blob for hash. Does NOT enforce owner authorization —
// callers needing that must use DeleteForOwner.
func (s *Store) Delete(hash [sha256.Size]byte) error {
	path := s.pathFor(hash)
	err := os.Remove(path)
	if err == nil {
		return nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %x", ErrChunkNotFound, hash)
	}
	return fmt.Errorf("remove %q: %w", path, err)
}

// Owner returns the Ed25519 pubkey recorded for hash. Returns
// ErrNoOwnerRecorded if the blob was stored via Put (not PutOwned) or no
// such hash is known.
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

// GetForOwner returns the blob bytes only if the recorded owner matches.
// Returns ErrChunkNotFound (no blob) or ErrOwnerMismatch (owner check
// failed, including unowned blobs). On error, no bytes are returned.
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

// DeleteForOwner removes the blob only if the recorded owner matches.
// Returns ErrChunkNotFound (no blob) or ErrOwnerMismatch (owner check
// failed, including unowned blobs). On error, disk state is untouched.
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
	// Authorize first (read-only), then commit both removals.
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
		return tx.Bucket([]byte(ownersBucket)).Delete(hash[:])
	})
}

// claimOwner asserts owner for hash. Matches an existing record, rejects a
// differing one, and refuses to claim an unowned blob already on disk.
// Writes the owner row only when no prior record exists and no orphan blob.
func (s *Store) claimOwner(hash [sha256.Size]byte, owner []byte) error {
	db, err := s.ensureOwnersDB()
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(ownersBucket))
		if existing := b.Get(hash[:]); existing != nil {
			if bytes.Equal(existing, owner) {
				return nil
			}
			return fmt.Errorf("%w: %x", ErrOwnerMismatch, hash)
		}
		blobPresent, err := s.blobOnDisk(hash)
		if err != nil {
			return err
		}
		if blobPresent {
			return fmt.Errorf("%w: %x", ErrOwnerMismatch, hash)
		}
		return b.Put(hash[:], append([]byte(nil), owner...))
	})
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

// ensureOwnersDB lazily opens the owners bbolt db. Safe for concurrent
// use — guarded by ownersMu and idempotent on repeat calls.
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
		_, err := tx.CreateBucketIfNotExists([]byte(ownersBucket))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create owners bucket: %w", err)
	}
	s.owners = db
	return db, nil
}

// pathFor returns the on-disk path for a given hash in the sharded layout.
func (s *Store) pathFor(hash [sha256.Size]byte) string {
	hexHash := hex.EncodeToString(hash[:])
	return filepath.Join(s.root, hexHash[:2], hexHash)
}
