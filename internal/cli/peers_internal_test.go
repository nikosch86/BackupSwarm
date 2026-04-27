package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backupswarm/internal/daemon"
)

func TestEmptyDash_EmptyReturnsDash(t *testing.T) {
	if got := emptyDash(""); got != "-" {
		t.Errorf("emptyDash(\"\") = %q, want %q", got, "-")
	}
}

func TestEmptyDash_NonEmptyPassthrough(t *testing.T) {
	if got := emptyDash("storage"); got != "storage" {
		t.Errorf("emptyDash(\"storage\") = %q, want %q", got, "storage")
	}
}

func TestFormatBytes_MiBBranch(t *testing.T) {
	got := formatBytes(2 * mib)
	if !strings.Contains(got, "MiB") {
		t.Errorf("formatBytes(2 MiB) = %q, want MiB suffix", got)
	}
	if !strings.HasPrefix(got, "2.0") {
		t.Errorf("formatBytes(2 MiB) = %q, want 2.0 prefix", got)
	}
}

func TestFormatBytes_TiBBranch(t *testing.T) {
	got := formatBytes(3 * tib)
	if !strings.Contains(got, "TiB") {
		t.Errorf("formatBytes(3 TiB) = %q, want TiB suffix", got)
	}
	if !strings.HasPrefix(got, "3.0") {
		t.Errorf("formatBytes(3 TiB) = %q, want 3.0 prefix", got)
	}
}

// TestRunPeersCmd_SurfacesNonSentinelSnapshotReadErr asserts a non-
// ErrNoRuntimeSnapshot error from ReadRuntimeSnapshot propagates with the
// "read runtime snapshot" wrapper.
func TestRunPeersCmd_SurfacesNonSentinelSnapshotReadErr(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dataDir := t.TempDir()
	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{Mode: "idle"}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}
	path := filepath.Join(dataDir, daemon.RuntimeSnapshotFilename)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	var out bytes.Buffer
	err := runPeersCmd(dataDir, &out)
	if err == nil {
		t.Fatal("runPeersCmd against unreadable runtime.json returned nil error")
	}
	if !strings.Contains(err.Error(), "read runtime snapshot") {
		t.Errorf("err = %q, want 'read runtime snapshot' substring", err)
	}
}

// TestPrintPeersFromStore_OpenError asserts peers.Open's error
// propagates with the "open peers.db" wrapper.
func TestPrintPeersFromStore_OpenError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	parent := t.TempDir()
	dataDir := filepath.Join(parent, "child")
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	var out bytes.Buffer
	err := printPeersFromStore(&out, dataDir)
	if err == nil {
		t.Fatal("printPeersFromStore against unwritable parent returned nil error")
	}
	if !strings.Contains(err.Error(), "open peers.db") {
		t.Errorf("err = %q, want 'open peers.db' substring", err)
	}
}
