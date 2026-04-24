// Package store is the on-disk chunk store: a content-addressed,
// flat-file repository of opaque byte blobs keyed by sha256(content).
//
// Callers pass raw bytes to Put and receive the SHA-256 hash used as the
// content address. The store is agnostic about what the bytes mean — on
// owner nodes it typically holds encrypted chunks produced by
// internal/crypto, on storage peers it holds whatever ciphertext arrived
// over the wire. Mapping from plaintext chunk hashes (see internal/chunk)
// to on-disk blob hashes lives in the index (M1.7), not here.
//
// Layout: <root>/<hh>/<full-hex-hash>, where <hh> is the first byte of
// the hash in lowercase hex. 256 shard directories keep any single
// directory well below filesystem fan-out limits. An optional owners db
// lives at <root>/owners.db (bbolt) and records the Ed25519 pubkey of
// the uploading peer for each blob written via PutOwned; DeleteForOwner
// consults it to enforce owner-authorized deletion (M1.9).
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

// tempFile is the subset of *os.File that Put uses for its temp-file
// write-then-rename dance. Abstracted as an interface so internal tests
// can substitute a fake that fails Write or Close — the syscall error
// paths in Put are otherwise unreachable without fault injection.
type tempFile interface {
	Name() string
	Write(p []byte) (n int, err error)
	Close() error
}

// Package-level seams so internal tests can exercise post-CreateTemp
// error branches (write, close, rename) and Get's mid-read failure.
// Production code never reassigns these — same pattern as the
// randReader seam in internal/crypto and internal/quic.
var (
	createTempFunc = func(dir, pattern string) (tempFile, error) {
		return os.CreateTemp(dir, pattern)
	}
	renameFunc  = os.Rename
	readAllFunc = io.ReadAll
	// chmodFunc seams the post-bbolt.Open os.Chmod call in
	// ensureOwnersDB. A real chmod on a file the current process just
	// successfully opened is a stdlib-invariant success; fault injection
	// is the only way to exercise the error wrap. Same pattern as the
	// chmodFunc seam in internal/index and internal/peers.
	chmodFunc = os.Chmod
	// dbUpdateFunc seams the bucket-creation Update on a freshly-opened
	// owners db. Bolt's Update never fails on a healthy db that
	// CreateBucketIfNotExists was just called on with a non-empty name,
	// so the error wrap is only reachable via the seam. Same pattern as
	// the dbUpdateFunc seam in internal/index and internal/peers.
	dbUpdateFunc = func(db *bbolt.DB, fn func(*bbolt.Tx) error) error {
		return db.Update(fn)
	}
)

// ErrChunkNotFound is returned by Get, Delete, and DeleteForOwner when a
// hash has never been stored or has already been deleted. Callers use
// errors.Is to distinguish "missing" from other IO errors.
var ErrChunkNotFound = errors.New("chunk not found")

// ErrNoOwnerRecorded is returned by Owner when a blob exists on disk but
// was stored via Put (not PutOwned) and therefore has no associated
// uploader pubkey. Callers distinguish this from a plain missing blob so
// the delete path can refuse unowned blobs loudly rather than silently.
var ErrNoOwnerRecorded = errors.New("no owner recorded for blob")

// ErrOwnerMismatch is returned by PutOwned when a second PutOwned for
// the same content arrives from a different owner, and by DeleteForOwner
// when the requesting owner does not match the stored owner (or when the
// blob has no owner recorded at all). Callers use errors.Is to map this
// to an authz failure on the peer-side protocol handler.
var ErrOwnerMismatch = errors.New("owner mismatch")

// Store is a content-addressed chunk store rooted at a local directory.
// A Store is safe for concurrent use: Put is atomic via temp-file + rename
// and idempotent for repeated writes of identical content.
type Store struct {
	root string

	// owners is lazily opened on first call that needs owner tracking
	// (PutOwned / Owner / DeleteForOwner). Plain Put never touches it,
	// so stores created purely for content-addressed reads pay no bbolt
	// cost. Access is guarded by ownersMu so lazy-open is race-safe.
	ownersMu sync.Mutex
	owners   *bbolt.DB
}

// New opens (or initializes) a store rooted at dir. The directory is
// created at 0700 if missing; an existing directory has its permissions
// tightened to 0700. Returns an error if dir cannot be created as a
// directory (e.g. path exists as a regular file, or a parent is not
// writable).
func New(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("create store dir %q: %w", dir, err)
	}
	// MkdirAll is a no-op on an existing dir with looser perms; force-tighten.
	if err := os.Chmod(dir, dirPerm); err != nil {
		return nil, fmt.Errorf("chmod store dir %q: %w", dir, err)
	}
	return &Store{root: dir}, nil
}

// Close releases any lazily-opened backing resources (currently the
// owners bbolt handle). Close is idempotent and safe to call on a Store
// that never touched its owners db.
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

// Put writes data to the store and returns its SHA-256 content address.
// If a blob with the same hash already exists, Put is a no-op and returns
// the same hash without error. Writes land atomically via temp-file +
// rename so concurrent Puts of the same content never tear.
//
// Put records no owner; callers that need owner-authorized deletion
// (storage peers accepting chunks from the wire) must use PutOwned.
func (s *Store) Put(data []byte) ([sha256.Size]byte, error) {
	return s.putBytes(data)
}

// PutOwned is Put plus an owner record: the uploader's public key
// is persisted alongside the blob so DeleteForOwner can later enforce
// that only the same owner authorizes removal.
//
// If the content already exists and the recorded owner does not equal
// owner, PutOwned returns ErrOwnerMismatch and leaves the stored owner
// unchanged. Same owner + same content is a no-op and returns nil.
func (s *Store) PutOwned(data, owner []byte) ([sha256.Size]byte, error) {
	hash, err := s.putBytes(data)
	if err != nil {
		return hash, err
	}
	if err := s.recordOwner(hash, owner); err != nil {
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

// Get returns the bytes previously stored under hash, or ErrChunkNotFound
// if no such blob exists.
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

// Delete removes the blob for hash. Returns ErrChunkNotFound if no such
// blob exists. Delete does NOT consult the owners db and does NOT
// enforce owner-authorized deletion — callers that need authorization
// (the peer-side DeleteChunk handler) must use DeleteForOwner instead.
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

// DeleteForOwner removes the blob at hash only if the recorded owner
// equals owner. Returns ErrChunkNotFound if the blob does not exist on
// disk, and ErrOwnerMismatch if the owner check fails (including the
// case where no owner was recorded for the blob).
//
// On success the blob and its owner entry are both removed; on any
// error the on-disk state is untouched.
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

// recordOwner writes owner as the owner of hash. If an owner is already
// recorded and differs, returns ErrOwnerMismatch without overwriting.
func (s *Store) recordOwner(hash [sha256.Size]byte, owner []byte) error {
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
		return b.Put(hash[:], append([]byte(nil), owner...))
	})
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
