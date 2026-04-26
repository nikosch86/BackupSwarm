package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withCreateListenAddrTempFunc swaps createListenAddrTempFunc for the
// duration of a test.
func withCreateListenAddrTempFunc(t *testing.T, fn func(dir, pattern string) (listenAddrTempFile, error)) {
	t.Helper()
	prev := createListenAddrTempFunc
	createListenAddrTempFunc = fn
	t.Cleanup(func() { createListenAddrTempFunc = prev })
}

// fakeWriteFailListenAddr wraps *os.File but errors on WriteString.
type fakeWriteFailListenAddr struct {
	*os.File
	err error
}

func (f *fakeWriteFailListenAddr) WriteString(string) (int, error) { return 0, f.err }

// fakeCloseFailListenAddr wraps *os.File but errors on Close after
// closing the underlying handle.
type fakeCloseFailListenAddr struct {
	*os.File
	err error
}

func (f *fakeCloseFailListenAddr) Close() error {
	_ = f.File.Close()
	return f.err
}

// TestWriteListenAddr_WriteFails injects a WriteString failure and
// asserts WriteListenAddr surfaces the wrapped error and removes the
// orphaned temp file.
func TestWriteListenAddr_WriteFails(t *testing.T) {
	dir := t.TempDir()
	sentinel := errors.New("synthetic write failure")
	withCreateListenAddrTempFunc(t, func(d, p string) (listenAddrTempFile, error) {
		real, err := os.CreateTemp(d, p)
		if err != nil {
			return nil, err
		}
		return &fakeWriteFailListenAddr{File: real, err: sentinel}, nil
	})

	err := WriteListenAddr(dir, "127.0.0.1:1")
	if err == nil {
		t.Fatal("WriteListenAddr succeeded despite injected write failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "write temp listen.addr") {
		t.Errorf("err = %q, want 'write temp listen.addr' substring", err)
	}
	assertNoOrphanedListenAddrTemps(t, dir)
}

// TestWriteListenAddr_CloseFails injects a Close failure and asserts
// WriteListenAddr surfaces the wrapped error and removes the orphan.
func TestWriteListenAddr_CloseFails(t *testing.T) {
	dir := t.TempDir()
	sentinel := errors.New("synthetic close failure")
	withCreateListenAddrTempFunc(t, func(d, p string) (listenAddrTempFile, error) {
		real, err := os.CreateTemp(d, p)
		if err != nil {
			return nil, err
		}
		return &fakeCloseFailListenAddr{File: real, err: sentinel}, nil
	})

	err := WriteListenAddr(dir, "127.0.0.1:1")
	if err == nil {
		t.Fatal("WriteListenAddr succeeded despite injected close failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "close temp listen.addr") {
		t.Errorf("err = %q, want 'close temp listen.addr' substring", err)
	}
	assertNoOrphanedListenAddrTemps(t, dir)
}

// TestWriteListenAddr_RenameFails plants a directory at the target
// path so os.Rename errors; the deferred cleanup must remove the temp.
func TestWriteListenAddr_RenameFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, ListenAddrFilename)
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	err := WriteListenAddr(dir, "127.0.0.1:1")
	if err == nil {
		t.Fatal("WriteListenAddr succeeded with directory at target path")
	}
	if !strings.Contains(err.Error(), "rename listen.addr") {
		t.Errorf("err = %q, want 'rename listen.addr' substring", err)
	}
	assertNoOrphanedListenAddrTemps(t, dir)
}

func assertNoOrphanedListenAddrTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".listen.addr.") {
			t.Errorf("orphan temp file: %s", e.Name())
		}
	}
}
