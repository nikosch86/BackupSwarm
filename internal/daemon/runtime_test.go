package daemon_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/daemon"
)

func sampleSnapshot() daemon.RuntimeSnapshot {
	when := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	return daemon.RuntimeSnapshot{
		Mode:       "reconcile",
		ListenAddr: "127.0.0.1:7777",
		LastScanAt: when,
		Peers: []daemon.RuntimePeerSnapshot{
			{
				PubKeyHex:    "aabbccdd",
				Reach:        "reachable",
				RemoteUsed:   100,
				RemoteMax:    1000,
				HasCapacity:  true,
				LastProbedAt: when,
			},
			{
				PubKeyHex:   "deadbeef",
				Reach:       "unreachable",
				HasCapacity: false,
			},
		},
	}
}

func TestRuntimeSnapshot_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := sampleSnapshot()
	if err := daemon.WriteRuntimeSnapshot(dir, want); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}
	got, err := daemon.ReadRuntimeSnapshot(dir)
	if err != nil {
		t.Fatalf("ReadRuntimeSnapshot: %v", err)
	}
	want.Version = 1
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

func TestReadRuntimeSnapshot_Missing_ReturnsSentinel(t *testing.T) {
	dir := t.TempDir()
	_, err := daemon.ReadRuntimeSnapshot(dir)
	if !errors.Is(err, daemon.ErrNoRuntimeSnapshot) {
		t.Errorf("ReadRuntimeSnapshot err = %v, want ErrNoRuntimeSnapshot", err)
	}
}

func TestWriteRuntimeSnapshot_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	first := sampleSnapshot()
	first.Mode = "first-backup"
	if err := daemon.WriteRuntimeSnapshot(dir, first); err != nil {
		t.Fatalf("first write: %v", err)
	}
	second := sampleSnapshot()
	second.Mode = "reconcile"
	if err := daemon.WriteRuntimeSnapshot(dir, second); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err := daemon.ReadRuntimeSnapshot(dir)
	if err != nil {
		t.Fatalf("ReadRuntimeSnapshot: %v", err)
	}
	if got.Mode != "reconcile" {
		t.Errorf("Mode = %q after overwrite, want %q", got.Mode, "reconcile")
	}
}

func TestWriteRuntimeSnapshot_CreateTempFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	err := daemon.WriteRuntimeSnapshot(missing, sampleSnapshot())
	if err == nil {
		t.Fatal("WriteRuntimeSnapshot against missing dir returned nil error")
	}
}

func TestRemoveRuntimeSnapshot_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if err := daemon.WriteRuntimeSnapshot(dir, sampleSnapshot()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := daemon.RemoveRuntimeSnapshot(dir); err != nil {
		t.Fatalf("first remove: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, daemon.RuntimeSnapshotFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("runtime.json still present after remove: %v", err)
	}
	if err := daemon.RemoveRuntimeSnapshot(dir); err != nil {
		t.Errorf("second remove should be idempotent, got: %v", err)
	}
}

func TestRemoveRuntimeSnapshot_NonNotExistError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	if err := daemon.WriteRuntimeSnapshot(dir, sampleSnapshot()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := daemon.RemoveRuntimeSnapshot(dir)
	if err == nil {
		t.Fatal("RemoveRuntimeSnapshot against unwritable parent returned nil error")
	}
	if !strings.Contains(err.Error(), "remove runtime.json") {
		t.Errorf("err = %q, want 'remove runtime.json' substring", err)
	}
}

func TestReadRuntimeSnapshot_NonNotExistError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	if err := daemon.WriteRuntimeSnapshot(dir, sampleSnapshot()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	path := filepath.Join(dir, daemon.RuntimeSnapshotFilename)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, err := daemon.ReadRuntimeSnapshot(dir)
	if err == nil {
		t.Fatal("ReadRuntimeSnapshot against unreadable file returned nil error")
	}
	if errors.Is(err, daemon.ErrNoRuntimeSnapshot) {
		t.Errorf("err = %v, must not be ErrNoRuntimeSnapshot for non-NotExist failures", err)
	}
}

// TestDaemon_PublishesAndRemovesRuntimeSnapshot drives daemon.Run in
// storage-only mode and asserts runtime.json appears with mode and
// resolved listen addr while alive, then is removed on shutdown.
func TestDaemon_PublishesAndRemovesRuntimeSnapshot(t *testing.T) {
	dataDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			DataDir:      dataDir,
			ListenAddr:   "127.0.0.1:0",
			Progress:     io.Discard,
			ScanInterval: 100 * time.Millisecond,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	var snap daemon.RuntimeSnapshot
	for {
		var readErr error
		snap, readErr = daemon.ReadRuntimeSnapshot(dataDir)
		if readErr == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("runtime.json never appeared (last err: %v)", readErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if snap.Version != 1 {
		t.Errorf("snap.Version = %d, want 1", snap.Version)
	}
	if snap.Mode != "storage-only" {
		t.Errorf("snap.Mode = %q, want storage-only", snap.Mode)
	}
	if snap.ListenAddr == "" || snap.ListenAddr == "127.0.0.1:0" {
		t.Errorf("snap.ListenAddr = %q, want resolved port", snap.ListenAddr)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("daemon.Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon.Run did not return within 3s of cancel")
	}
	if _, err := os.Stat(filepath.Join(dataDir, daemon.RuntimeSnapshotFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("runtime.json still present after shutdown: %v", err)
	}
}

func TestReadRuntimeSnapshot_Malformed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, daemon.RuntimeSnapshotFilename)
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := daemon.ReadRuntimeSnapshot(dir)
	if err == nil {
		t.Fatal("ReadRuntimeSnapshot accepted garbage")
	}
	if errors.Is(err, daemon.ErrNoRuntimeSnapshot) {
		t.Errorf("err = %v, must not be ErrNoRuntimeSnapshot for decode failures", err)
	}
}
