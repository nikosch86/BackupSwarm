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
// directory well below filesystem fan-out limits.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const (
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600
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
)

// ErrChunkNotFound is returned by Get, Delete, and (via Has=false) when a
// hash has never been stored or has already been deleted. Callers use
// errors.Is to distinguish "missing" from other IO errors.
var ErrChunkNotFound = errors.New("chunk not found")

// Store is a content-addressed chunk store rooted at a local directory.
// A Store is safe for concurrent use: Put is atomic via temp-file + rename
// and idempotent for repeated writes of identical content.
type Store struct {
	root string
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

// Put writes data to the store and returns its SHA-256 content address.
// If a blob with the same hash already exists, Put is a no-op and returns
// the same hash without error. Writes land atomically via temp-file +
// rename so concurrent Puts of the same content never tear.
func (s *Store) Put(data []byte) ([sha256.Size]byte, error) {
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
// blob exists.
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

// pathFor returns the on-disk path for a given hash in the sharded layout.
func (s *Store) pathFor(hash [sha256.Size]byte) string {
	hexHash := hex.EncodeToString(hash[:])
	return filepath.Join(s.root, hexHash[:2], hexHash)
}
