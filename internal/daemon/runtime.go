package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RuntimeSnapshotFilename is the basename of the JSON file the daemon
// writes its live state into.
const RuntimeSnapshotFilename = "runtime.json"

// runtimeSnapshotVersion is the leading version field of every snapshot.
const runtimeSnapshotVersion = 1

// ErrNoRuntimeSnapshot is returned by ReadRuntimeSnapshot when the file
// is absent.
var ErrNoRuntimeSnapshot = errors.New("no runtime snapshot (runtime.json missing in data dir)")

// RuntimeStoreSnapshot is the daemon's local chunk-store totals.
// Capacity == 0 means unlimited.
type RuntimeStoreSnapshot struct {
	Used     int64 `json:"used"`
	Capacity int64 `json:"capacity"`
}

// RuntimePeerSnapshot is one peer's slice of the daemon's live view.
// HasCapacity is false when the last probe failed or never ran;
// RemoteUsed/RemoteMax are then unset.
type RuntimePeerSnapshot struct {
	PubKeyHex    string    `json:"pubkey"`
	Role         string    `json:"role,omitempty"`
	Addr         string    `json:"addr,omitempty"`
	Reach        string    `json:"reach"`
	RemoteUsed   int64     `json:"remote_used,omitempty"`
	RemoteMax    int64     `json:"remote_max,omitempty"`
	HasCapacity  bool      `json:"has_capacity"`
	LastProbedAt time.Time `json:"last_probed_at,omitempty"`
}

// RuntimeSnapshot is the daemon's published view of its own live state.
// Atomic-written to <data-dir>/runtime.json on every tick; removed on
// shutdown.
type RuntimeSnapshot struct {
	Version    int                   `json:"version"`
	Mode       string                `json:"mode"`
	ListenAddr string                `json:"listen_addr"`
	LastScanAt time.Time             `json:"last_scan_at"`
	LocalStore RuntimeStoreSnapshot  `json:"local_store"`
	Peers      []RuntimePeerSnapshot `json:"peers"`
}

// WriteRuntimeSnapshot atomically writes s to <dir>/runtime.json.
// The version field is set to the current schema version.
func WriteRuntimeSnapshot(dir string, s RuntimeSnapshot) error {
	s.Version = runtimeSnapshotVersion
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal runtime snapshot: %w", err)
	}
	path := filepath.Join(dir, RuntimeSnapshotFilename)
	return writeAtomicFile(path, string(raw))
}

// RemoveRuntimeSnapshot removes <dir>/runtime.json. A missing file is
// not an error.
func RemoveRuntimeSnapshot(dir string) error {
	err := os.Remove(filepath.Join(dir, RuntimeSnapshotFilename))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove runtime.json: %w", err)
	}
	return nil
}

// ReadRuntimeSnapshot returns the parsed snapshot from <dir>/runtime.json,
// or ErrNoRuntimeSnapshot when the file is absent.
func ReadRuntimeSnapshot(dir string) (RuntimeSnapshot, error) {
	path := filepath.Join(dir, RuntimeSnapshotFilename)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return RuntimeSnapshot{}, ErrNoRuntimeSnapshot
	}
	if err != nil {
		return RuntimeSnapshot{}, fmt.Errorf("read runtime.json: %w", err)
	}
	var s RuntimeSnapshot
	if err := json.Unmarshal(raw, &s); err != nil {
		return RuntimeSnapshot{}, fmt.Errorf("decode runtime.json: %w", err)
	}
	return s, nil
}
