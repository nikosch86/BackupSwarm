package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/ca"
	"backupswarm/internal/daemon"
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

// TestReadListenAddrWithWait_NoWaitFailsFast asserts wait <= 0 returns
// the daemon.ErrNoRunningDaemon sentinel immediately when listen.addr
// is absent.
func TestReadListenAddrWithWait_NoWaitFailsFast(t *testing.T) {
	dir := t.TempDir()
	_, err := readListenAddrWithWait(context.Background(), dir, 0)
	if !errors.Is(err, daemon.ErrNoRunningDaemon) {
		t.Errorf("err = %v, want ErrNoRunningDaemon", err)
	}
}

// TestReadListenAddrWithWait_FilePresentReturnsAddr exercises the wait
// loop's success path: listen.addr exists before the first poll, so the
// helper returns its trimmed contents on the first iteration.
func TestReadListenAddrWithWait_FilePresentReturnsAddr(t *testing.T) {
	dir := t.TempDir()
	const want = "127.0.0.1:1234"
	if err := daemon.WriteListenAddr(dir, want); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := readListenAddrWithWait(context.Background(), dir, time.Second)
	if err != nil {
		t.Fatalf("readListenAddrWithWait: %v", err)
	}
	if got != want {
		t.Errorf("addr = %q, want %q", got, want)
	}
}

// TestReadListenAddrWithWait_AppearsDuringPoll writes listen.addr from
// a goroutine after the first poll fails; the helper retries and
// returns the value once the file lands.
func TestReadListenAddrWithWait_AppearsDuringPoll(t *testing.T) {
	dir := t.TempDir()
	const want = "127.0.0.1:5678"
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = daemon.WriteListenAddr(dir, want)
	}()
	got, err := readListenAddrWithWait(context.Background(), dir, 2*time.Second)
	if err != nil {
		t.Fatalf("readListenAddrWithWait: %v", err)
	}
	if got != want {
		t.Errorf("addr = %q, want %q", got, want)
	}
}

// TestReadListenAddrWithWait_TimeoutReturnsSentinel polls a never-
// populated dir until wait elapses; the final return preserves
// daemon.ErrNoRunningDaemon for callers that wrap on it.
func TestReadListenAddrWithWait_TimeoutReturnsSentinel(t *testing.T) {
	dir := t.TempDir()
	_, err := readListenAddrWithWait(context.Background(), dir, 200*time.Millisecond)
	if !errors.Is(err, daemon.ErrNoRunningDaemon) {
		t.Errorf("err = %v, want ErrNoRunningDaemon after timeout", err)
	}
}

// TestReadListenAddrWithWait_ContextCanceled cancels ctx mid-poll and
// asserts the helper surfaces ctx.Err.
func TestReadListenAddrWithWait_ContextCanceled(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(150 * time.Millisecond)
		cancel()
	}()
	_, err := readListenAddrWithWait(ctx, dir, 2*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// TestReadListenAddrWithWait_NonSentinelErrorPropagates seeds a
// chmod-0 file so daemon.ReadListenAddr surfaces a non-sentinel error;
// the helper must propagate immediately rather than retry.
func TestReadListenAddrWithWait_NonSentinelErrorPropagates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	if err := daemon.WriteListenAddr(dir, "127.0.0.1:1"); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, daemon.ListenAddrFilename), 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, daemon.ListenAddrFilename), 0o600) })

	_, err := readListenAddrWithWait(context.Background(), dir, time.Second)
	if err == nil {
		t.Fatal("readListenAddrWithWait against unreadable file returned nil error")
	}
	if errors.Is(err, daemon.ErrNoRunningDaemon) {
		t.Errorf("err = %v, must not be ErrNoRunningDaemon for non-NotExist failures", err)
	}
}

// TestReadSwarmCACertIfPresent_AbsentReturnsNil asserts a fresh dir
// with no CA returns (nil, nil) — pin-mode tokens carry no CA bytes.
func TestReadSwarmCACertIfPresent_AbsentReturnsNil(t *testing.T) {
	got, err := readSwarmCACertIfPresent(t.TempDir())
	if err != nil {
		t.Fatalf("readSwarmCACertIfPresent: %v", err)
	}
	if got != nil {
		t.Errorf("got %d bytes, want nil", len(got))
	}
}

// TestReadSwarmCACertIfPresent_PresentReturnsDER seeds a real CA on
// disk and asserts the helper returns its CertDER bytes.
func TestReadSwarmCACertIfPresent_PresentReturnsDER(t *testing.T) {
	dir := t.TempDir()
	gen, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	if err := ca.Save(dir, gen); err != nil {
		t.Fatalf("ca.Save: %v", err)
	}
	got, err := readSwarmCACertIfPresent(dir)
	if err != nil {
		t.Fatalf("readSwarmCACertIfPresent: %v", err)
	}
	if string(got) != string(gen.CertDER) {
		t.Errorf("returned CertDER mismatch: got %d bytes, want %d", len(got), len(gen.CertDER))
	}
}

// TestReadSwarmCACertIfPresent_LoadFails seeds ca.key + a corrupt
// ca.crt so ca.Has=true but ca.Load errors on parse; the helper
// surfaces the load-ca prefix.
func TestReadSwarmCACertIfPresent_LoadFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), make([]byte, 64), 0o600); err != nil {
		t.Fatalf("write ca.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("not-a-cert"), 0o644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	_, err := readSwarmCACertIfPresent(dir)
	if err == nil {
		t.Fatal("readSwarmCACertIfPresent with corrupt ca.crt returned nil error")
	}
	if !strings.Contains(err.Error(), "load ca") {
		t.Errorf("err = %q, want 'load ca' substring", err)
	}
}

// TestReadSwarmCACertIfPresent_HasFails chmods the dir 0o000 so
// ca.Has errors; the helper surfaces the check-ca prefix.
func TestReadSwarmCACertIfPresent_HasFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err := readSwarmCACertIfPresent(dir)
	if err == nil {
		t.Fatal("readSwarmCACertIfPresent against unreadable dir returned nil error")
	}
	if !strings.Contains(err.Error(), "check ca") {
		t.Errorf("err = %q, want 'check ca' substring", err)
	}
}
