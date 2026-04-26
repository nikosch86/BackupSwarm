package daemon_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/daemon"
)

func TestListenAddr_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := "127.0.0.1:54321"
	if err := daemon.WriteListenAddr(dir, want); err != nil {
		t.Fatalf("WriteListenAddr: %v", err)
	}
	got, err := daemon.ReadListenAddr(dir)
	if err != nil {
		t.Fatalf("ReadListenAddr: %v", err)
	}
	if got != want {
		t.Errorf("addr = %q, want %q", got, want)
	}
}

func TestReadListenAddr_Missing_ReturnsSentinel(t *testing.T) {
	dir := t.TempDir()
	_, err := daemon.ReadListenAddr(dir)
	if !errors.Is(err, daemon.ErrNoRunningDaemon) {
		t.Errorf("ReadListenAddr err = %v, want ErrNoRunningDaemon", err)
	}
}

func TestRemoveListenAddr_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if err := daemon.WriteListenAddr(dir, "127.0.0.1:1"); err != nil {
		t.Fatalf("WriteListenAddr: %v", err)
	}
	if err := daemon.RemoveListenAddr(dir); err != nil {
		t.Fatalf("first RemoveListenAddr: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, daemon.ListenAddrFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("listen.addr still present after remove: %v", err)
	}
	if err := daemon.RemoveListenAddr(dir); err != nil {
		t.Errorf("second RemoveListenAddr should be idempotent, got: %v", err)
	}
}

// TestDaemon_PublishesAndRemovesListenAddr drives daemon.Run in
// storage-only mode and asserts listen.addr appears with the bound
// address while the daemon is alive and is removed on shutdown.
func TestDaemon_PublishesAndRemovesListenAddr(t *testing.T) {
	dataDir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			DataDir:    dataDir,
			ListenAddr: "127.0.0.1:0",
			Progress:   io.Discard,
		})
	}()

	// Poll until the file appears (daemon needs a few ms to bind +
	// publish). 2s is plenty even on a slow CI runner.
	deadline := time.Now().Add(2 * time.Second)
	var addr string
	for {
		var readErr error
		addr, readErr = daemon.ReadListenAddr(dataDir)
		if readErr == nil && addr != "" {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("listen.addr never appeared (last err: %v)", readErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if addr == "127.0.0.1:0" {
		t.Errorf("listen.addr = %q, want resolved port (not :0)", addr)
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

	if _, err := os.Stat(filepath.Join(dataDir, daemon.ListenAddrFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("listen.addr still present after shutdown: %v", err)
	}
}

func TestWriteListenAddr_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	if err := daemon.WriteListenAddr(dir, "old"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := daemon.WriteListenAddr(dir, "new"); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err := daemon.ReadListenAddr(dir)
	if err != nil {
		t.Fatalf("ReadListenAddr: %v", err)
	}
	if got != "new" {
		t.Errorf("addr = %q, want %q", got, "new")
	}
}

// TestWriteListenAddr_CreateTempFails surfaces a wrapped create-temp
// error when the data dir does not exist.
func TestWriteListenAddr_CreateTempFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	err := daemon.WriteListenAddr(missing, "127.0.0.1:1")
	if err == nil {
		t.Fatal("WriteListenAddr against missing dir returned nil error")
	}
	if !strings.Contains(err.Error(), "create temp listen.addr") {
		t.Errorf("err = %q, want 'create temp listen.addr' substring", err)
	}
}

// TestRemoveListenAddr_NonNotExistError chmods the parent dir 0o500
// after planting the file so os.Remove errors with EACCES; the wrapper
// surfaces the remove-listen.addr prefix.
func TestRemoveListenAddr_NonNotExistError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	if err := daemon.WriteListenAddr(dir, "127.0.0.1:1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := daemon.RemoveListenAddr(dir)
	if err == nil {
		t.Fatal("RemoveListenAddr against unwritable parent returned nil error")
	}
	if !strings.Contains(err.Error(), "remove listen.addr") {
		t.Errorf("err = %q, want 'remove listen.addr' substring", err)
	}
}

// TestReadListenAddr_NonNotExistError chmods listen.addr 0o000 so
// os.ReadFile errors for a reason other than NotExist; the wrapper
// surfaces the read-listen.addr prefix instead of ErrNoRunningDaemon.
func TestReadListenAddr_NonNotExistError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	if err := daemon.WriteListenAddr(dir, "127.0.0.1:1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	path := filepath.Join(dir, daemon.ListenAddrFilename)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, err := daemon.ReadListenAddr(dir)
	if err == nil {
		t.Fatal("ReadListenAddr against unreadable file returned nil error")
	}
	if errors.Is(err, daemon.ErrNoRunningDaemon) {
		t.Errorf("err = %v, must not be ErrNoRunningDaemon for non-NotExist failures", err)
	}
	if !strings.Contains(err.Error(), "read listen.addr") {
		t.Errorf("err = %q, want 'read listen.addr' substring", err)
	}
}
