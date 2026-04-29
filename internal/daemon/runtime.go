package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// RuntimeSnapshotFilename is the basename of the daemon's live-state JSON file.
const RuntimeSnapshotFilename = "runtime.json"

// runtimeSnapshotVersion is the schema version embedded in each snapshot.
const runtimeSnapshotVersion = 1

// ErrNoRuntimeSnapshot is returned when runtime.json is absent.
var ErrNoRuntimeSnapshot = errors.New("no runtime snapshot (runtime.json missing in data dir)")

// RuntimeStoreSnapshot is the daemon's local chunk-store totals.
// Capacity == 0 means unlimited.
type RuntimeStoreSnapshot struct {
	Used     int64 `json:"used"`
	Capacity int64 `json:"capacity"`
}

// RuntimePeerSnapshot is one peer's slice of the daemon's live view.
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

// RuntimeSnapshot is the daemon's published view of its live state.
type RuntimeSnapshot struct {
	Version    int                      `json:"version"`
	Mode       string                   `json:"mode"`
	ListenAddr string                   `json:"listen_addr"`
	LastScanAt time.Time                `json:"last_scan_at"`
	LocalStore RuntimeStoreSnapshot     `json:"local_store"`
	OwnBackup  RuntimeOwnBackupSnapshot `json:"own_backup"`
	Peers      []RuntimePeerSnapshot    `json:"peers"`
}

// WriteRuntimeSnapshot atomically writes s to <dir>/runtime.json.
func WriteRuntimeSnapshot(dir string, s RuntimeSnapshot) error {
	s.Version = runtimeSnapshotVersion
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal runtime snapshot: %w", err)
	}
	path := filepath.Join(dir, RuntimeSnapshotFilename)
	return writeAtomicFile(path, string(raw))
}

// RemoveRuntimeSnapshot removes <dir>/runtime.json; missing file is not an error.
func RemoveRuntimeSnapshot(dir string) error {
	err := os.Remove(filepath.Join(dir, RuntimeSnapshotFilename))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove runtime.json: %w", err)
	}
	return nil
}

// ReadRuntimeSnapshot parses <dir>/runtime.json or returns ErrNoRuntimeSnapshot.
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
