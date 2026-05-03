package daemon_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backupswarm/internal/daemon"
)

func TestRelayAddr_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := "203.0.113.5:54321"
	if err := daemon.WriteRelayAddr(dir, want); err != nil {
		t.Fatalf("WriteRelayAddr: %v", err)
	}
	got, err := daemon.ReadRelayAddr(dir)
	if err != nil {
		t.Fatalf("ReadRelayAddr: %v", err)
	}
	if got != want {
		t.Errorf("addr = %q, want %q", got, want)
	}
}

func TestReadRelayAddr_Missing_ReturnsEmpty(t *testing.T) {
	dir := t.TempDir()
	got, err := daemon.ReadRelayAddr(dir)
	if err != nil {
		t.Fatalf("ReadRelayAddr on missing file: %v", err)
	}
	if got != "" {
		t.Errorf("addr = %q, want empty for missing file", got)
	}
}

func TestRemoveRelayAddr_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if err := daemon.WriteRelayAddr(dir, "127.0.0.1:1"); err != nil {
		t.Fatalf("WriteRelayAddr: %v", err)
	}
	if err := daemon.RemoveRelayAddr(dir); err != nil {
		t.Fatalf("first RemoveRelayAddr: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, daemon.RelayAddrFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("relay.addr still present after remove: %v", err)
	}
	if err := daemon.RemoveRelayAddr(dir); err != nil {
		t.Errorf("second RemoveRelayAddr should be idempotent, got: %v", err)
	}
}

func TestWriteRelayAddr_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	if err := daemon.WriteRelayAddr(dir, "old"); err != nil {
		t.Fatalf("first write: %v", err)
	}
	if err := daemon.WriteRelayAddr(dir, "new"); err != nil {
		t.Fatalf("second write: %v", err)
	}
	got, err := daemon.ReadRelayAddr(dir)
	if err != nil {
		t.Fatalf("ReadRelayAddr: %v", err)
	}
	if got != "new" {
		t.Errorf("addr = %q, want %q", got, "new")
	}
}

func TestWriteRelayAddr_CreateTempFails(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent")
	err := daemon.WriteRelayAddr(missing, "127.0.0.1:1")
	if err == nil {
		t.Fatal("WriteRelayAddr against missing dir returned nil error")
	}
	if !strings.Contains(err.Error(), "create temp relay.addr") {
		t.Errorf("err = %q, want 'create temp relay.addr' substring", err)
	}
}
