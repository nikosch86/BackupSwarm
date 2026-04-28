package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"

	"backupswarm/internal/daemon"
	"backupswarm/internal/index"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
)

// mustSeedIdentity provisions a node identity in dataDir.
func mustSeedIdentity(t *testing.T, dataDir string) {
	t.Helper()
	if _, _, err := node.Ensure(dataDir); err != nil {
		t.Fatalf("seed identity: %v", err)
	}
}

func TestStatusCmd_RegisteredOnRoot(t *testing.T) {
	root := NewRootCmd()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "status" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("root command missing `status` subcommand")
	}
}

// TestStatusCmd_EmptyDataDir_ErrorsWithoutProvisioning asserts status
// errors against an empty data dir without creating any files.
func TestStatusCmd_EmptyDataDir_ErrorsWithoutProvisioning(t *testing.T) {
	dataDir := t.TempDir()
	err := runStatusCommandErr(t, dataDir)
	if err == nil {
		t.Fatal("status returned nil against an empty data dir")
	}
	for _, fname := range []string{"node.key", "node.pub", "node.xkey", "index.db", peers.DefaultFilename} {
		if _, statErr := os.Stat(filepath.Join(dataDir, fname)); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("status provisioned %s (Stat err = %v)", fname, statErr)
		}
	}
}

func TestStatusCmd_FreshDataDir_NoDaemon_NoIndex(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	out := runStatusCommand(t, dataDir)
	for _, want := range []string{"node_id", "data_dir", "daemon", "not running"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q\n--- output ---\n%s", want, out)
		}
	}
	// No own backup yet — replication should be unset.
	if !strings.Contains(out, "replication") {
		t.Errorf("expected replication row even with no chunks, got:\n%s", out)
	}
}

func TestStatusCmd_WithIndexEntries_ReportsTotalsAndReplication(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	// File 1: 1 chunk replicated to 2 peers
	if err := idx.Put(index.FileEntry{
		Path: "/tmp/file-1", Size: 100, ModTime: time.Now(),
		Chunks: []index.ChunkRef{
			{Size: 200, Peers: [][]byte{pubA, pubB}},
		},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	// File 2: 2 chunks, one replicated to 1 peer, one to 2 peers
	if err := idx.Put(index.FileEntry{
		Path: "/tmp/file-2", Size: 300, ModTime: time.Now(),
		Chunks: []index.ChunkRef{
			{Size: 150, Peers: [][]byte{pubA}},
			{Size: 150, Peers: [][]byte{pubA, pubB}},
		},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out := runStatusCommand(t, dataDir)
	for _, want := range []string{"own_backup_files", "own_backup_size", "own_backup_chunks", "replication"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n--- output ---\n%s", want, out)
		}
	}
	if !strings.Contains(out, "2") || !strings.Contains(out, "3") {
		t.Errorf("expected file count 2 and chunk count 3 in output, got:\n%s", out)
	}
	// Avg replication: (2 + 1 + 2) / 3 = 1.67; min 1, max 2
	if !strings.Contains(out, "1.7") {
		t.Errorf("expected avg replication ~1.7, got:\n%s", out)
	}
	if !strings.Contains(out, "min 1") || !strings.Contains(out, "max 2") {
		t.Errorf("expected min 1 / max 2 in output, got:\n%s", out)
	}
}

func TestStatusCmd_WithDaemonSnapshot_ReportsModeListenScan(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	when := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	snap := daemon.RuntimeSnapshot{
		Mode:       "reconcile",
		ListenAddr: "127.0.0.1:7777",
		LastScanAt: when,
		LocalStore: daemon.RuntimeStoreSnapshot{Used: 1024, Capacity: 10 * 1024 * 1024 * 1024},
	}
	if err := daemon.WriteRuntimeSnapshot(dataDir, snap); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}
	out := runStatusCommand(t, dataDir)
	for _, want := range []string{"running", "reconcile", "127.0.0.1:7777", "2026-04-01T12:00:00Z"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q\n--- output ---\n%s", want, out)
		}
	}
	// 10 GiB cap should appear.
	if !strings.Contains(out, "10.0 GiB") {
		t.Errorf("expected '10.0 GiB' capacity, got:\n%s", out)
	}
}

func TestStatusCmd_QuotaRatio_OwnBackupNonZero(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{
		LocalStore: daemon.RuntimeStoreSnapshot{Used: 5000, Capacity: 0},
		OwnBackup: daemon.RuntimeOwnBackupSnapshot{
			Files: 1, Bytes: 10000, Chunks: 1, ReplMin: 1, ReplMax: 1, ReplAvg: 1,
		},
	}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}

	out := runStatusCommand(t, dataDir)
	if !strings.Contains(out, "quota_ratio") {
		t.Errorf("expected quota_ratio row, got:\n%s", out)
	}
	// 5000 / 10000 = 0.50
	if !strings.Contains(out, "0.50") {
		t.Errorf("expected ratio 0.50, got:\n%s", out)
	}
}

// TestStatusCmd_SnapshotPresent_DoesNotOpenIndex asserts the steady-state
// case where the daemon holds index.db's flock: the CLI must never touch
// the file when a snapshot is published.
func TestStatusCmd_SnapshotPresent_DoesNotOpenIndex(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{
		Mode:       "reconcile",
		ListenAddr: "127.0.0.1:7777",
		OwnBackup: daemon.RuntimeOwnBackupSnapshot{
			Files: 5, Bytes: 12345, Chunks: 9, ReplMin: 1, ReplMax: 3, ReplAvg: 2.0,
		},
	}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}

	out := runStatusCommand(t, dataDir)

	if _, err := os.Stat(filepath.Join(dataDir, "index.db")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("index.db touched despite snapshot present (Stat err = %v)", err)
	}
	for _, want := range []string{"own_backup_files", "12.1 KiB", "min 1", "max 3"} {
		if !strings.Contains(out, want) {
			t.Errorf("status output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

// TestStatusCmd_NoSnapshot_FallsBackToIndex asserts the no-daemon path
// computes own-backup totals from index.db when no runtime.json exists.
func TestStatusCmd_NoSnapshot_FallsBackToIndex(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Put(index.FileEntry{
		Path: "f", Size: 42, ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Size: 42, Peers: [][]byte{bytesOf(0x01, 32)}}},
	}); err != nil {
		t.Fatalf("seed Put: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("seed Close: %v", err)
	}

	out := runStatusCommand(t, dataDir)
	if !strings.Contains(out, "42") {
		t.Errorf("expected 42 bytes in fallback output, got:\n%s", out)
	}
	if !strings.Contains(out, "not running") {
		t.Errorf("expected 'not running' in fallback output, got:\n%s", out)
	}
}

func TestStatusCmd_QuotaRatio_NoOwnBackup(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	out := runStatusCommand(t, dataDir)
	if !strings.Contains(out, "n/a") {
		t.Errorf("expected 'n/a' ratio when no own backup, got:\n%s", out)
	}
}

func runStatusCommand(t *testing.T, dataDir string) string {
	t.Helper()
	root := NewRootCmd()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", dataDir, "status"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	return stdout.String()
}

// runStatusCommandErr drives the status subcommand and returns the
// raw Execute error so failure paths can be asserted.
func runStatusCommandErr(t *testing.T, dataDir string) error {
	t.Helper()
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", dataDir, "status"})
	return root.Execute()
}

// TestStatusCmd_SnapshotReadFailureSurfaces asserts a non-NotExist
// failure reading runtime.json wraps with "read runtime snapshot".
func TestStatusCmd_SnapshotReadFailureSurfaces(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{Mode: "reconcile"}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}
	path := filepath.Join(dataDir, "runtime.json")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	err := runStatusCommandErr(t, dataDir)
	if err == nil {
		t.Fatal("status returned nil on unreadable runtime.json")
	}
	if !strings.Contains(err.Error(), "read runtime snapshot") {
		t.Errorf("err = %q, want 'read runtime snapshot' wrap", err)
	}
}

// TestStatusCmd_FallbackListIndexFailureSurfaces seeds a corrupted gob
// blob in the index bucket so idx.List fails the no-snapshot fallback
// and the "list index" wrap surfaces from runStatusCmd.
func TestStatusCmd_FallbackListIndexFailureSurfaces(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	dbPath := filepath.Join(dataDir, "index.db")
	idx, err := index.Open(dbPath)
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("index.Close: %v", err)
	}
	db, err := bbolt.Open(dbPath, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("bbolt.Open: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte("files")).Put([]byte("/bad"), []byte("not-a-gob"))
	}); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("bbolt.Close: %v", err)
	}

	err = runStatusCommandErr(t, dataDir)
	if err == nil {
		t.Fatal("status returned nil on corrupt index")
	}
	if !strings.Contains(err.Error(), "list index") {
		t.Errorf("err = %q, want 'list index' wrap", err)
	}
}

// TestStatusCmd_FallbackOpenIndexFailureSurfaces asserts an unreadable
// index.db surfaces from the no-snapshot fallback wrapped as "open
// index".
func TestStatusCmd_FallbackOpenIndexFailureSurfaces(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	idxPath := filepath.Join(dataDir, "index.db")
	idx, err := index.Open(idxPath)
	if err != nil {
		t.Fatalf("seed index: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("seed index close: %v", err)
	}
	if err := os.Chmod(idxPath, 0o000); err != nil {
		t.Fatalf("chmod index: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(idxPath, 0o600) })

	err = runStatusCommandErr(t, dataDir)
	if err == nil {
		t.Fatal("status returned nil on unreadable index")
	}
	if !strings.Contains(err.Error(), "open index") {
		t.Errorf("err = %q, want 'open index' wrap", err)
	}
}

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
