package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// withRandReadFunc swaps randReadFunc for the duration of a test.
func withRandReadFunc(t *testing.T, fn func(p []byte) (int, error)) {
	t.Helper()
	prev := randReadFunc
	randReadFunc = fn
	t.Cleanup(func() { randReadFunc = prev })
}

// skipIfPosixChmodInert skips when chmod barriers are not enforceable.
func skipIfPosixChmodInert(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
}

// TestWriteAtomicFile_RoundTrip asserts the happy path writes the
// payload and leaves no orphan temp file behind.
func TestWriteAtomicFile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "token.txt")
	if err := writeAtomicFile(target, "hello"); err != nil {
		t.Fatalf("writeAtomicFile: %v", err)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read target: %v", err)
	}
	if string(data) != "hello" {
		t.Errorf("payload = %q, want %q", data, "hello")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".token-") {
			t.Errorf("orphan temp file: %s", e.Name())
		}
	}
}

// TestWriteAtomicFile_CreateTempFails_NoOrphan chmods the parent dir to
// 0o500 so os.CreateTemp fails; the call must error and leave no temp
// file behind.
func TestWriteAtomicFile_CreateTempFails_NoOrphan(t *testing.T) {
	skipIfPosixChmodInert(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := writeAtomicFile(filepath.Join(dir, "token.txt"), "hi")
	if err == nil {
		t.Fatal("writeAtomicFile succeeded against unwritable dir")
	}
	if !strings.Contains(err.Error(), "create temp") {
		t.Errorf("err = %q, want 'create temp' substring", err)
	}
}

// TestWriteAtomicFile_RenameFails_RemovesTemp plants a directory at the
// target path so os.Rename fails; the temp file must be cleaned up by
// the deferred remover.
func TestWriteAtomicFile_RenameFails_RemovesTemp(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "token.txt")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir target: %v", err)
	}
	err := writeAtomicFile(target, "hi")
	if err == nil {
		t.Fatal("writeAtomicFile succeeded with directory at target")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Errorf("err = %q, want 'rename' substring", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".token-") {
			t.Errorf("orphan temp file after rename failure: %s", e.Name())
		}
	}
}

// withCreateAtomicTempFunc swaps createAtomicTempFunc for a test.
func withCreateAtomicTempFunc(t *testing.T, fn func(dir, pattern string) (atomicTempFile, error)) {
	t.Helper()
	prev := createAtomicTempFunc
	createAtomicTempFunc = fn
	t.Cleanup(func() { createAtomicTempFunc = prev })
}

// fakeAtomicWriteFail returns sentinel on WriteString.
type fakeAtomicWriteFail struct {
	*os.File
	err error
}

func (f *fakeAtomicWriteFail) WriteString(string) (int, error) { return 0, f.err }

// fakeAtomicCloseFail returns sentinel on Close after closing the
// underlying handle.
type fakeAtomicCloseFail struct {
	*os.File
	err error
}

func (f *fakeAtomicCloseFail) Close() error {
	_ = f.File.Close()
	return f.err
}

// TestWriteAtomicFile_WriteFails_RemovesTemp injects a write failure
// and asserts the wrapped error surfaces and the temp file is removed.
func TestWriteAtomicFile_WriteFails_RemovesTemp(t *testing.T) {
	dir := t.TempDir()
	sentinel := errors.New("synthetic write failure")
	withCreateAtomicTempFunc(t, func(d, p string) (atomicTempFile, error) {
		real, err := os.CreateTemp(d, p)
		if err != nil {
			return nil, err
		}
		return &fakeAtomicWriteFail{File: real, err: sentinel}, nil
	})
	err := writeAtomicFile(filepath.Join(dir, "token.txt"), "hi")
	if err == nil {
		t.Fatal("writeAtomicFile succeeded despite injected write failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "write temp") {
		t.Errorf("err = %q, want 'write temp' substring", err)
	}
	for _, e := range mustReadDir(t, dir) {
		if strings.HasPrefix(e.Name(), ".token-") {
			t.Errorf("orphan temp file: %s", e.Name())
		}
	}
}

// TestWriteAtomicFile_CloseFails_RemovesTemp injects a Close failure
// and asserts the wrapped error surfaces and the temp file is removed.
func TestWriteAtomicFile_CloseFails_RemovesTemp(t *testing.T) {
	dir := t.TempDir()
	sentinel := errors.New("synthetic close failure")
	withCreateAtomicTempFunc(t, func(d, p string) (atomicTempFile, error) {
		real, err := os.CreateTemp(d, p)
		if err != nil {
			return nil, err
		}
		return &fakeAtomicCloseFail{File: real, err: sentinel}, nil
	})
	err := writeAtomicFile(filepath.Join(dir, "token.txt"), "hi")
	if err == nil {
		t.Fatal("writeAtomicFile succeeded despite injected close failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "close temp") {
		t.Errorf("err = %q, want 'close temp' substring", err)
	}
	for _, e := range mustReadDir(t, dir) {
		if strings.HasPrefix(e.Name(), ".token-") {
			t.Errorf("orphan temp file: %s", e.Name())
		}
	}
}

// mustReadDir returns the entries in dir or fails the test.
func mustReadDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	return entries
}

// TestIssueInvite_OpenFails surfaces the open-invites.db wrap when the
// data dir is unwritable.
func TestIssueInvite_OpenFails(t *testing.T) {
	skipIfPosixChmodInert(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	_, err = IssueInvite(dir, "127.0.0.1:1", pub, nil)
	if err == nil {
		t.Fatal("IssueInvite succeeded against unwritable dir")
	}
	if !strings.Contains(err.Error(), "open invites.db") {
		t.Errorf("err = %q, want 'open invites.db' substring", err)
	}
}

// TestIssueInvite_IssueCollision pins randReadFunc so the second call
// generates the same secret as the first; the invites store rejects the
// duplicate and IssueInvite surfaces the wrapped error.
func TestIssueInvite_IssueCollision(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	calls := 0
	withRandReadFunc(t, func(p []byte) (int, error) {
		for i := range p {
			p[i] = byte(calls % 2)
		}
		calls++
		return len(p), nil
	})
	if _, err := IssueInvite(dir, "127.0.0.1:1", pub, nil); err != nil {
		t.Fatalf("first IssueInvite: %v", err)
	}
	_, err = IssueInvite(dir, "127.0.0.1:1", pub, nil)
	if err == nil {
		t.Fatal("second IssueInvite with pinned secret returned nil error")
	}
	if !strings.Contains(err.Error(), "issue") {
		t.Errorf("err = %q, want 'issue' substring", err)
	}
}

// TestIssueInvite_RandFails surfaces the rand-failure wrap when
// randReadFunc returns an error.
func TestIssueInvite_RandFails(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	sentinel := errors.New("forced rand failure")
	withRandReadFunc(t, func(p []byte) (int, error) { return 0, sentinel })
	_, err = IssueInvite(dir, "127.0.0.1:1", pub, nil)
	if err == nil {
		t.Fatal("IssueInvite succeeded despite rand failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

// TestIssueInvite_EncodeFails passes a malformed pubkey so token.Encode
// rejects it; the error must surface with the encode-token wrap.
func TestIssueInvite_EncodeFails(t *testing.T) {
	dir := t.TempDir()
	_, err := IssueInvite(dir, "127.0.0.1:1", ed25519.PublicKey{0x00}, nil)
	if err == nil {
		t.Fatal("IssueInvite with malformed pubkey returned nil error")
	}
	if !strings.Contains(err.Error(), "encode token") {
		t.Errorf("err = %q, want 'encode token' substring", err)
	}
}

// TestResolveSwarmCA_HasCAFails chmods the data dir 0o000 so ca.Has
// errors on stat; the wrapper surfaces the check-ca prefix.
func TestResolveSwarmCA_HasCAFails(t *testing.T) {
	skipIfPosixChmodInert(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	_, err := ResolveSwarmCA(context.Background(), dir, false)
	if err == nil {
		t.Fatal("ResolveSwarmCA against unreadable dir returned nil error")
	}
	if !strings.Contains(err.Error(), "check ca") {
		t.Errorf("err = %q, want 'check ca' substring", err)
	}
}

// TestResolveSwarmCA_LoadsExistingCA exercises the second-call branch:
// ca.Has=true, ca.Load succeeds, ResolveSwarmCA returns the same CA
// without regenerating.
func TestResolveSwarmCA_LoadsExistingCA(t *testing.T) {
	dir := t.TempDir()
	first, err := ResolveSwarmCA(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("first ResolveSwarmCA: %v", err)
	}
	second, err := ResolveSwarmCA(context.Background(), dir, false)
	if err != nil {
		t.Fatalf("second ResolveSwarmCA: %v", err)
	}
	if second == nil {
		t.Fatal("second ResolveSwarmCA returned nil CA")
	}
	if string(second.CertDER) != string(first.CertDER) {
		t.Error("second ResolveSwarmCA returned a different CertDER")
	}
}
