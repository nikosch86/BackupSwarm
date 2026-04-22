// Package index is a local bbolt-backed index that maps each backed-up
// file path to its ordered list of chunks and the peers known to hold
// each chunk.
//
// The owner node is authoritative over its own index. Backup (M1.8)
// upserts entries as files are chunked and shipped to peers; restore
// (M1.9) consults the index to locate each chunk. An encrypted snapshot
// of the whole index is backed up to the swarm in M3.4 as a regular
// chunk with the owner as the recipient — the index format is the
// serialization contract for that snapshot.
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

	// openLockTimeout bounds how long Open will wait for bbolt's file
	// lock. Trying to open an already-open index is a caller bug (two
	// Index values on the same file), so we fail fast rather than hang.
	openLockTimeout = 2 * time.Second
)

// ErrFileNotFound is returned by Get and Delete when no entry exists for
// the given path. Callers use errors.Is to distinguish "not indexed"
// from underlying IO or decode errors.
var ErrFileNotFound = errors.New("file not found in index")

// ChunkRef is the locator for one chunk of a backed-up file: its content
// hash, byte length, and the peers known to hold a copy.
type ChunkRef struct {
	Hash  [32]byte // sha256 of the chunk content (matches internal/store address)
	Size  int64    // byte length of the chunk as sent to peers
	Peers [][]byte // ed25519 public keys (raw 32-byte encoding) of peers holding this chunk
}

// FileEntry is the index record for a single backed-up file. Chunks is
// ordered: Chunks[i] is the i-th chunk of the file. An empty Chunks
// slice represents a zero-byte file.
type FileEntry struct {
	Path   string
	Chunks []ChunkRef
}

// Index is a bbolt-backed local index. Safe for concurrent use —
// bbolt serializes all write transactions internally.
type Index struct {
	db *bbolt.DB
}

// Package-level seams so internal tests can exercise otherwise-defensive
// branches (encode failures, db-level failures caught via a closed db).
// Production code never reassigns these — same pattern as the
// createTempFunc / randReader seams in internal/store and internal/crypto.
var (
	gobEncodeFunc = func(w io.Writer, v any) error {
		return gob.NewEncoder(w).Encode(v)
	}
	// chmodFunc seams the post-Open os.Chmod call. A real chmod on a
	// file the current process just successfully opened is a
	// stdlib-invariant success; fault injection is the only way to
	// exercise the error wrap.
	chmodFunc = os.Chmod
	// dbUpdateFunc seams the bucket-creation Update on a freshly-opened
	// db. Bolt's Update never fails on a healthy db that CreateBucketIfNotExists
	// was just called on with a non-empty name, so the error wrap is only
	// reachable via the seam.
	dbUpdateFunc = func(db *bbolt.DB, fn func(*bbolt.Tx) error) error {
		return db.Update(fn)
	}
)

// Open opens (or initializes) the index at path. The parent directory is
// created at 0700 if missing; the bbolt file is created at 0600 (an
// explicit Chmod is applied afterwards so the on-disk mode is
// deterministic regardless of the process umask).
func Open(path string) (*Index, error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, dirPerm); err != nil {
		return nil, fmt.Errorf("create index dir %q: %w", parent, err)
	}
	db, err := bbolt.Open(path, filePerm, &bbolt.Options{Timeout: openLockTimeout})
	if err != nil {
		return nil, fmt.Errorf("open index %q: %w", path, err)
	}
	// bbolt.Open honours the process umask; force the required mode
	// explicitly so a lax umask can't leave the db world-readable.
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
