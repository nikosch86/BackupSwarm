package store

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// snapshotsDir is the per-owner index-snapshot subdirectory under the
// store root. Files are named by 64-char lowercase hex of the owner's
// Ed25519 public key.
const snapshotsDir = "snapshots"

// ErrSnapshotNotFound is returned by GetIndexSnapshot when no snapshot
// is recorded for the requested owner.
var ErrSnapshotNotFound = errors.New("index snapshot not found")

// snapshotLocks serializes concurrent puts for the same owner so the
// temp+rename sequence cannot interleave.
var snapshotLocks sync.Map

// PutIndexSnapshot atomically writes blob as the latest index snapshot
// for the given owner pubkey, replacing any prior snapshot. The blob
// is opaque (typically encrypted) and is not tracked in Used().
func (s *Store) PutIndexSnapshot(owner, blob []byte) error {
	if err := validateOwner(owner); err != nil {
		return err
	}
	if len(blob) == 0 {
		return errors.New("index snapshot blob must be non-empty")
	}
	mu := lockForOwner(owner)
	mu.Lock()
	defer mu.Unlock()

	dir := filepath.Join(s.root, snapshotsDir)
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create snapshots dir %q: %w", dir, err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		return fmt.Errorf("chmod snapshots dir %q: %w", dir, err)
	}

	tmp, err := createTempFunc(dir, ".snapshot-*")
	if err != nil {
		return fmt.Errorf("create snapshot temp: %w", err)
	}
	tmpPath := tmp.Name()
	renamed := false
	defer func() {
		if !renamed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(blob); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write snapshot temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close snapshot temp: %w", err)
	}
	final := snapshotPath(s.root, owner)
	if err := renameFunc(tmpPath, final); err != nil {
		return fmt.Errorf("rename snapshot %q -> %q: %w", tmpPath, final, err)
	}
	renamed = true
	return nil
}

// GetIndexSnapshot returns the latest snapshot stored for owner, or
// ErrSnapshotNotFound if none has been recorded.
func (s *Store) GetIndexSnapshot(owner []byte) ([]byte, error) {
	if err := validateOwner(owner); err != nil {
		return nil, err
	}
	path := snapshotPath(s.root, owner)
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: owner %x", ErrSnapshotNotFound, owner)
		}
		return nil, fmt.Errorf("open snapshot %q: %w", path, err)
	}
	defer f.Close()
	data, err := readAllFunc(f)
	if err != nil {
		return nil, fmt.Errorf("read snapshot %q: %w", path, err)
	}
	return data, nil
}

// validateOwner enforces the Ed25519 pubkey length on owner bytes.
func validateOwner(owner []byte) error {
	if len(owner) != ed25519.PublicKeySize {
		return fmt.Errorf("owner must be %d bytes, got %d", ed25519.PublicKeySize, len(owner))
	}
	return nil
}

// snapshotPath returns the on-disk path for owner's snapshot.
func snapshotPath(root string, owner []byte) string {
	return filepath.Join(root, snapshotsDir, hex.EncodeToString(owner))
}

// lockForOwner returns a per-owner mutex, lazily creating one on first use.
func lockForOwner(owner []byte) *sync.Mutex {
	key := string(owner)
	if v, ok := snapshotLocks.Load(key); ok {
		return v.(*sync.Mutex)
	}
	actual, _ := snapshotLocks.LoadOrStore(key, &sync.Mutex{})
	return actual.(*sync.Mutex)
}
