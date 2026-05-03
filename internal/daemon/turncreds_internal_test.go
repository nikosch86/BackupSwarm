package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestWriteTURNCreds_CreateTempFails injects a temp-file create failure
// via the createListenAddrTempFunc seam.
func TestWriteTURNCreds_CreateTempFails(t *testing.T) {
	dir := t.TempDir()
	sentinel := errors.New("synthetic create failure")
	withCreateListenAddrTempFunc(t, func(string, string) (listenAddrTempFile, error) {
		return nil, sentinel
	})

	err := WriteTURNCreds(dir, TURNCreds{Server: "s", User: "u", Pass: "p", Realm: "r"})
	if err == nil {
		t.Fatal("WriteTURNCreds succeeded despite injected create failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "create temp turn.creds") {
		t.Errorf("err = %q, want 'create temp turn.creds' substring", err)
	}
}

// TestWriteTURNCreds_WriteFails injects a WriteString failure and asserts
// the wrapped error surfaces and no orphan temp file is left behind.
func TestWriteTURNCreds_WriteFails(t *testing.T) {
	dir := t.TempDir()
	sentinel := errors.New("synthetic write failure")
	withCreateListenAddrTempFunc(t, func(d, p string) (listenAddrTempFile, error) {
		real, err := os.CreateTemp(d, p)
		if err != nil {
			return nil, err
		}
		return &fakeWriteFailListenAddr{File: real, err: sentinel}, nil
	})

	err := WriteTURNCreds(dir, TURNCreds{Server: "s", User: "u", Pass: "p", Realm: "r"})
	if err == nil {
		t.Fatal("WriteTURNCreds succeeded despite injected write failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "write temp turn.creds") {
		t.Errorf("err = %q, want 'write temp turn.creds' substring", err)
	}
	assertNoOrphanedTURNCredsTemps(t, dir)
}

// TestWriteTURNCreds_CloseFails injects a Close failure so WriteTURNCreds
// surfaces "close temp turn.creds" and the orphan is removed.
func TestWriteTURNCreds_CloseFails(t *testing.T) {
	dir := t.TempDir()
	sentinel := errors.New("synthetic close failure")
	withCreateListenAddrTempFunc(t, func(d, p string) (listenAddrTempFile, error) {
		real, err := os.CreateTemp(d, p)
		if err != nil {
			return nil, err
		}
		return &fakeCloseFailListenAddr{File: real, err: sentinel}, nil
	})

	err := WriteTURNCreds(dir, TURNCreds{Server: "s", User: "u", Pass: "p", Realm: "r"})
	if err == nil {
		t.Fatal("WriteTURNCreds succeeded despite injected close failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "close temp turn.creds") {
		t.Errorf("err = %q, want 'close temp turn.creds' substring", err)
	}
	assertNoOrphanedTURNCredsTemps(t, dir)
}

// TestWriteTURNCreds_RenameFails plants a directory at the target path so
// os.Rename errors; the deferred cleanup must remove the temp.
func TestWriteTURNCreds_RenameFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, TURNCredsFilename)
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	err := WriteTURNCreds(dir, TURNCreds{Server: "s", User: "u", Pass: "p", Realm: "r"})
	if err == nil {
		t.Fatal("WriteTURNCreds succeeded with directory at target path")
	}
	if !strings.Contains(err.Error(), "rename turn.creds") {
		t.Errorf("err = %q, want 'rename turn.creds' substring", err)
	}
	assertNoOrphanedTURNCredsTemps(t, dir)
}

func assertNoOrphanedTURNCredsTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".turn.creds.") {
			t.Errorf("orphan temp file: %s", e.Name())
		}
	}
}
