package cli

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/daemon"
	"backupswarm/internal/index"
)

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

func TestStatusCmd_FreshDataDir_NoDaemon_NoIndex(t *testing.T) {
	out := runStatusCommand(t, t.TempDir())
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
	// Daemon snapshot says we're storing 5000 bytes for others.
	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{
		LocalStore: daemon.RuntimeStoreSnapshot{Used: 5000, Capacity: 0},
	}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}
	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Put(index.FileEntry{
		Path: "/tmp/f", Size: 10000, ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Size: 10000, Peers: [][]byte{bytesOf(0x01, 32)}}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
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

func TestStatusCmd_QuotaRatio_NoOwnBackup(t *testing.T) {
	out := runStatusCommand(t, t.TempDir())
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

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}
