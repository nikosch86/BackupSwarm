package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteRelayAddr_WriteFails injects a WriteString failure and asserts
// WriteRelayAddr surfaces the wrapped error and removes the orphan temp.
func TestWriteRelayAddr_WriteFails(t *testing.T) {
	dir := t.TempDir()
	sentinel := errors.New("synthetic write failure")
	withCreateListenAddrTempFunc(t, func(d, p string) (listenAddrTempFile, error) {
		real, err := os.CreateTemp(d, p)
		if err != nil {
			return nil, err
		}
		return &fakeWriteFailListenAddr{File: real, err: sentinel}, nil
	})

	err := WriteRelayAddr(dir, "127.0.0.1:1")
	if err == nil {
		t.Fatal("WriteRelayAddr succeeded despite injected write failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "write temp relay.addr") {
		t.Errorf("err = %q, want 'write temp relay.addr' substring", err)
	}
	assertNoOrphanedRelayAddrTemps(t, dir)
}

// TestWriteRelayAddr_CloseFails injects a Close failure and asserts
// WriteRelayAddr surfaces the wrapped error and removes the orphan.
func TestWriteRelayAddr_CloseFails(t *testing.T) {
	dir := t.TempDir()
	sentinel := errors.New("synthetic close failure")
	withCreateListenAddrTempFunc(t, func(d, p string) (listenAddrTempFile, error) {
		real, err := os.CreateTemp(d, p)
		if err != nil {
			return nil, err
		}
		return &fakeCloseFailListenAddr{File: real, err: sentinel}, nil
	})

	err := WriteRelayAddr(dir, "127.0.0.1:1")
	if err == nil {
		t.Fatal("WriteRelayAddr succeeded despite injected close failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "close temp relay.addr") {
		t.Errorf("err = %q, want 'close temp relay.addr' substring", err)
	}
	assertNoOrphanedRelayAddrTemps(t, dir)
}

// TestWriteRelayAddr_RenameFails plants a directory at the target path so
// os.Rename errors; the deferred cleanup must remove the temp.
func TestWriteRelayAddr_RenameFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, RelayAddrFilename)
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	err := WriteRelayAddr(dir, "127.0.0.1:1")
	if err == nil {
		t.Fatal("WriteRelayAddr succeeded with directory at target path")
	}
	if !strings.Contains(err.Error(), "rename relay.addr") {
		t.Errorf("err = %q, want 'rename relay.addr' substring", err)
	}
	assertNoOrphanedRelayAddrTemps(t, dir)
}

// TestRemoveRelayAddr_NonExistent_NoError asserts removing an absent file
// is a no-op rather than an error.
func TestRemoveRelayAddr_NonExistent_NoError(t *testing.T) {
	dir := t.TempDir()
	if err := RemoveRelayAddr(dir); err != nil {
		t.Fatalf("RemoveRelayAddr on empty dir: %v", err)
	}
}

// TestRemoveRelayAddr_PermissionError chmods the dir read-only so os.Remove
// fails with a non-NotExist error and surfaces the wrapped sentinel.
func TestRemoveRelayAddr_PermissionError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses chmod restrictions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, RelayAddrFilename)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed relay.addr: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := RemoveRelayAddr(dir)
	if err == nil {
		t.Fatal("RemoveRelayAddr succeeded on read-only dir")
	}
	if !strings.Contains(err.Error(), "remove relay.addr") {
		t.Errorf("err = %q, want 'remove relay.addr' substring", err)
	}
}

// TestReadRelayAddr_OpenError chmods the file unreadable and asserts
// ReadRelayAddr surfaces a wrapped read error.
func TestReadRelayAddr_OpenError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses chmod restrictions")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, RelayAddrFilename)
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed relay.addr: %v", err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod file: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, err := ReadRelayAddr(dir)
	if err == nil {
		t.Fatal("ReadRelayAddr succeeded on unreadable file")
	}
	if !strings.Contains(err.Error(), "read relay.addr") {
		t.Errorf("err = %q, want 'read relay.addr' substring", err)
	}
}

// assertNoOrphanedRelayAddrTemps fails the test if any .relay.addr.* temp
// files were left behind in dir.
func assertNoOrphanedRelayAddrTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".relay.addr.") {
			t.Errorf("orphan temp file: %s", e.Name())
		}
	}
}
