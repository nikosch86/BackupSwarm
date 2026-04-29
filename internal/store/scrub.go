package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"go.etcd.io/bbolt"
)

// chunkHexLen is the on-disk filename length for content-addressed blobs:
// each sha256 byte is two hex chars.
const chunkHexLen = 2 * sha256.Size

// shardHexLen is the on-disk shard directory name length: the first byte
// of the hash, two hex chars.
const shardHexLen = 2

// ScrubResult summarizes one scrub pass: how many content-addressed
// blobs were re-hashed and how many failed the integrity check (and
// were removed).
type ScrubResult struct {
	Scanned int
	Corrupt int
}

// Scrub re-hashes every content-addressed blob in the shard tree and
// removes any whose on-disk content no longer matches its name. The
// per-hash mutex from PutOwned serializes a scrub-time delete with
// concurrent same-hash writes so Used() never double-counts.
//
// Skips snapshots/, owners.db, and any non-shard entries at the root.
// Per-blob failures (read/remove error) log and continue. Returns
// ctx.Err() when cancelled between blobs.
func (s *Store) Scrub(ctx context.Context) (ScrubResult, error) {
	var res ScrubResult
	entries, err := os.ReadDir(s.root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return res, nil
		}
		return res, fmt.Errorf("read store root %q: %w", s.root, err)
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		if !e.IsDir() {
			continue
		}
		if !isShardName(e.Name()) {
			continue
		}
		shardDir := filepath.Join(s.root, e.Name())
		if err := s.scrubShard(ctx, shardDir, &res); err != nil {
			return res, err
		}
	}
	return res, nil
}

// scrubShard walks one shard directory, re-hashing each blob whose
// filename is a 64-char hex string. Per-blob errors log and continue.
func (s *Store) scrubShard(ctx context.Context, shardDir string, res *ScrubResult) error {
	blobs, err := os.ReadDir(shardDir)
	if err != nil {
		return fmt.Errorf("read shard %q: %w", shardDir, err)
	}
	for _, b := range blobs {
		if err := ctx.Err(); err != nil {
			return err
		}
		if !b.Type().IsRegular() {
			continue
		}
		name := b.Name()
		if len(name) != chunkHexLen || !isHex(name) {
			continue
		}
		var expected [sha256.Size]byte
		if _, err := hex.Decode(expected[:], []byte(name)); err != nil {
			continue
		}
		res.Scanned++
		ok, err := s.scrubOne(ctx, expected)
		if err != nil {
			slog.WarnContext(ctx, "scrub blob failed",
				"hash", name,
				"err", err,
			)
			continue
		}
		if !ok {
			res.Corrupt++
		}
	}
	return nil
}

// scrubOne re-hashes the blob for hash and removes it if the content
// no longer matches. Returns ok=true when the blob is intact (or absent
// after a concurrent delete), ok=false when a corrupt blob was removed.
func (s *Store) scrubOne(ctx context.Context, hash [sha256.Size]byte) (bool, error) {
	mu := s.lockForHash(hash)
	mu.Lock()
	defer mu.Unlock()

	path := s.pathFor(hash)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return true, nil
		}
		return false, fmt.Errorf("open %q: %w", path, err)
	}
	sum, size, hashErr := hashStream(f)
	closeErr := f.Close()
	if hashErr != nil {
		return false, fmt.Errorf("hash %q: %w", path, hashErr)
	}
	if closeErr != nil {
		return false, fmt.Errorf("close %q: %w", path, closeErr)
	}
	if sum == hash {
		return true, nil
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("remove %q: %w", path, err)
	}
	if err := s.dropOwnerRow(hash); err != nil {
		return false, fmt.Errorf("drop owner row: %w", err)
	}
	s.release(size)
	slog.WarnContext(ctx, "scrub removed corrupt blob",
		"hash", hex.EncodeToString(hash[:]),
		"size", size,
	)
	return false, nil
}

// dropOwnerRow removes the owner record for hash, if any. A missing row
// is not an error.
func (s *Store) dropOwnerRow(hash [sha256.Size]byte) error {
	db, err := s.ensureOwnersDB()
	if err != nil {
		return err
	}
	return db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte(ownersBucket)).Delete(hash[:])
	})
}

// hashStream reads r in full, returning its sha256 sum and total bytes
// read.
func hashStream(r io.Reader) ([sha256.Size]byte, int64, error) {
	h := sha256.New()
	n, err := io.Copy(h, r)
	if err != nil {
		var zero [sha256.Size]byte
		return zero, n, err
	}
	var sum [sha256.Size]byte
	copy(sum[:], h.Sum(nil))
	return sum, n, nil
}

// isShardName reports whether name is a 2-char lowercase hex shard dir.
func isShardName(name string) bool {
	return len(name) == shardHexLen && isHex(name)
}

// isHex reports whether s is composed entirely of 0-9 / a-f.
func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
