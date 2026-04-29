// Package index is a local bbolt-backed index mapping each backed-up
// file path to its ordered chunk list and the peers known to hold each
// chunk. The owner is authoritative over its own index.
package index

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

const (
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600

	bucketName = "files"

	// openLockTimeout fails fast on an already-open index (caller bug).
	openLockTimeout = 2 * time.Second
)

// ErrFileNotFound is returned by Get and Delete when no entry exists.
var ErrFileNotFound = errors.New("file not found in index")

// ChunkRef locates one chunk of a backed-up file. PlaintextHash is sha256
// of plaintext; CiphertextHash is sha256 of the encrypted blob (storage
// address). Peers lists Ed25519 pubkeys of peers holding the blob.
type ChunkRef struct {
	PlaintextHash  [32]byte
	CiphertextHash [32]byte
	Size           int64
	Peers          [][]byte
}

// FileEntry is the index record for one backed-up file. Chunks is ordered;
// Size and ModTime are the plaintext file's stat at backup time and drive
// the scan's incremental-skip stat-match.
type FileEntry struct {
	Path    string
	Size    int64
	ModTime time.Time
	Chunks  []ChunkRef
}

// Index is a bbolt-backed local index. Safe for concurrent use — bbolt
// serializes all write transactions internally.
type Index struct {
	db *bbolt.DB
}

// Test-only seams; production never reassigns these.
var (
	gobEncodeFunc = func(w io.Writer, v any) error {
		return gob.NewEncoder(w).Encode(v)
	}
	chmodFunc    = os.Chmod
	dbUpdateFunc = func(db *bbolt.DB, fn func(*bbolt.Tx) error) error {
		return db.Update(fn)
	}
)

// Open opens (or initializes) the index at path. Parent is mkdir 0700;
// the bbolt file is chmod'd to 0600 explicitly to defeat a lax umask.
func Open(path string) (*Index, error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, dirPerm); err != nil {
		return nil, fmt.Errorf("create index dir %q: %w", parent, err)
	}
	db, err := bbolt.Open(path, filePerm, &bbolt.Options{Timeout: openLockTimeout})
	if err != nil {
		return nil, fmt.Errorf("open index %q: %w", path, err)
	}
	// Defeat umask — keep the db 0600 on disk.
	if err := chmodFunc(path, filePerm); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("chmod index %q: %w", path, err)
	}
	if err := dbUpdateFunc(db, func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create bucket: %w", err)
	}
	return &Index{db: db}, nil
}

// OpenReadOnly opens an existing index at path with bbolt's shared read
// lock. Errors on a missing file; never creates files, directories, or
// buckets.
func OpenReadOnly(path string) (*Index, error) {
	db, err := bbolt.Open(path, filePerm, &bbolt.Options{
		Timeout:  openLockTimeout,
		ReadOnly: true,
	})
	if err != nil {
		return nil, fmt.Errorf("open index %q (read-only): %w", path, err)
	}
	return &Index{db: db}, nil
}

// Close closes the underlying bbolt database. Operations on a closed
// Index return an error.
func (ix *Index) Close() error {
	return ix.db.Close()
}

// Put upserts entry, replacing any previous record at the same path.
func (ix *Index) Put(entry FileEntry) error {
	var buf bytes.Buffer
	if err := gobEncodeFunc(&buf, &entry); err != nil {
		return fmt.Errorf("encode entry %q: %w", entry.Path, err)
	}
	return ix.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.Put([]byte(entry.Path), buf.Bytes())
	})
}

// Get returns the entry for path. Returns ErrFileNotFound if no entry
// exists; other errors indicate IO or decode failures.
func (ix *Index) Get(path string) (FileEntry, error) {
	var out FileEntry
	err := ix.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		raw := b.Get([]byte(path))
		if raw == nil {
			return fmt.Errorf("%w: %s", ErrFileNotFound, path)
		}
		if err := gob.NewDecoder(bytes.NewReader(raw)).Decode(&out); err != nil {
			return fmt.Errorf("decode entry %q: %w", path, err)
		}
		return nil
	})
	if err != nil {
		return FileEntry{}, err
	}
	return out, nil
}

// Delete removes the entry for path. Returns ErrFileNotFound if no
// entry exists.
func (ix *Index) Delete(path string) error {
	return ix.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b.Get([]byte(path)) == nil {
			return fmt.Errorf("%w: %s", ErrFileNotFound, path)
		}
		return b.Delete([]byte(path))
	})
}

// List returns every entry in the index. Order is byte-lexicographic by
// Path (the native bbolt iteration order). The returned slice is empty,
// not nil, when the index holds no entries.
func (ix *Index) List() ([]FileEntry, error) {
	out := make([]FileEntry, 0)
	err := ix.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.ForEach(func(k, v []byte) error {
			var entry FileEntry
			if err := gob.NewDecoder(bytes.NewReader(v)).Decode(&entry); err != nil {
				return fmt.Errorf("decode entry %q: %w", k, err)
			}
			out = append(out, entry)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
