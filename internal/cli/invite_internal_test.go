package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// withCreateTokenTempFunc swaps createTokenTempFunc for the duration of a test.
func withCreateTokenTempFunc(t *testing.T, f func(dir, pattern string) (tokenTempFile, error)) {
	t.Helper()
	prev := createTokenTempFunc
	createTokenTempFunc = f
	t.Cleanup(func() { createTokenTempFunc = prev })
}

// fakeWriteFailFile wraps *os.File but returns a synthetic error on WriteString.
type fakeWriteFailFile struct {
	*os.File
	err error
}

func (f *fakeWriteFailFile) WriteString(string) (int, error) { return 0, f.err }

// fakeCloseFailFile wraps *os.File but returns a synthetic error on Close.
type fakeCloseFailFile struct {
	*os.File
	err error
}

func (f *fakeCloseFailFile) Close() error {
	_ = f.File.Close()
	return f.err
}

// TestWriteTokenFile_WriteErrorCleansUp asserts a WriteString failure removes the orphaned temp file.
func TestWriteTokenFile_WriteErrorCleansUp(t *testing.T) {
	dir := t.TempDir()
	injected := errors.New("synthetic write failure")
	withCreateTokenTempFunc(t, func(d, p string) (tokenTempFile, error) {
		real, err := os.CreateTemp(d, p)
		if err != nil {
			return nil, err
		}
		return &fakeWriteFailFile{File: real, err: injected}, nil
	})

	err := writeTokenFile(filepath.Join(dir, "token.txt"), "tok")
	if err == nil {
		t.Fatal("expected error when WriteString fails")
	}
	if !errors.Is(err, injected) {
		t.Errorf("expected injected error in chain, got: %v", err)
	}
	if !strings.Contains(err.Error(), "write temp") {
		t.Errorf("expected 'write temp' in error, got: %v", err)
	}
	assertNoOrphanedTokenTemps(t, dir)
}

// TestWriteTokenFile_CloseErrorCleansUp asserts a Close failure removes the orphaned temp file.
func TestWriteTokenFile_CloseErrorCleansUp(t *testing.T) {
	dir := t.TempDir()
	injected := errors.New("synthetic close failure")
	withCreateTokenTempFunc(t, func(d, p string) (tokenTempFile, error) {
		real, err := os.CreateTemp(d, p)
		if err != nil {
			return nil, err
		}
		return &fakeCloseFailFile{File: real, err: injected}, nil
	})

	err := writeTokenFile(filepath.Join(dir, "token.txt"), "tok")
	if err == nil {
		t.Fatal("expected error when Close fails")
	}
	if !errors.Is(err, injected) {
		t.Errorf("expected injected error in chain, got: %v", err)
	}
	if !strings.Contains(err.Error(), "close temp") {
		t.Errorf("expected 'close temp' in error, got: %v", err)
	}
	assertNoOrphanedTokenTemps(t, dir)
}

func assertNoOrphanedTokenTemps(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".token-") {
			t.Errorf("orphaned temp file: %s", filepath.Join(dir, e.Name()))
		}
	}
}
