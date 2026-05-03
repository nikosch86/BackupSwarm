package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backupswarm/internal/daemon"
)

// TestResolveAutoHost_EmptySTUNServerErrors covers the early-return branch
// when stunServer is the empty string.
func TestResolveAutoHost_EmptySTUNServerErrors(t *testing.T) {
	_, err := resolveAutoHost(context.Background(), "")
	if err == nil {
		t.Fatal("resolveAutoHost(\"\") returned nil error")
	}
	if !strings.Contains(err.Error(), "--advertise-addr=auto requires --stun-server") {
		t.Errorf("err = %q, want '--advertise-addr=auto requires --stun-server'", err)
	}
}

// TestInviteCmd_AdvertiseAddrAuto_NoDaemonReturnsSentinel exercises the
// auto branch when listen.addr is absent: the daemon.ErrNoRunningDaemon
// sentinel must be wrapped with the run-the-daemon-first hint.
func TestInviteCmd_AdvertiseAddrAuto_NoDaemonReturnsSentinel(t *testing.T) {
	dataDir := t.TempDir()

	orig := cliDiscoverFunc
	t.Cleanup(func() { cliDiscoverFunc = orig })
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		t.Fatal("STUN must not be queried before listen.addr is read")
		return "", nil
	}

	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--data-dir", dataDir, "invite", "--advertise-addr", "auto"})
	err := root.Execute()
	if err == nil {
		t.Fatal("invite --advertise-addr=auto without daemon returned nil error")
	}
	if !errors.Is(err, daemon.ErrNoRunningDaemon) {
		t.Errorf("err = %v, want wraps daemon.ErrNoRunningDaemon", err)
	}
	if !strings.Contains(err.Error(), "start the daemon first") {
		t.Errorf("err = %q, want 'start the daemon first' hint", err)
	}
}

// TestInviteCmd_AdvertiseAddrAuto_NonSentinelListenErrPropagates seeds an
// unreadable listen.addr file so daemon.ReadListenAddr surfaces a non-
// sentinel error in the auto branch; the cmd must surface the read-
// listen.addr wrap rather than the no-running-daemon hint.
func TestInviteCmd_AdvertiseAddrAuto_NonSentinelListenErrPropagates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "127.0.0.1:1"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}
	if err := os.Chmod(filepath.Join(dataDir, daemon.ListenAddrFilename), 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dataDir, daemon.ListenAddrFilename), 0o600) })

	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--data-dir", dataDir, "invite", "--advertise-addr", "auto"})
	err := root.Execute()
	if err == nil {
		t.Fatal("invite --advertise-addr=auto with unreadable listen.addr returned nil error")
	}
	if errors.Is(err, daemon.ErrNoRunningDaemon) {
		t.Errorf("err = %v, must not be ErrNoRunningDaemon for non-NotExist failures", err)
	}
	if !strings.Contains(err.Error(), "read listen.addr") {
		t.Errorf("err = %q, want 'read listen.addr' wrap", err)
	}
}

// TestInviteCmd_AdvertiseAddrAuto_MalformedListenAddrErrors plants a
// listen.addr without a port; the auto branch's net.SplitHostPort must
// surface a parse-listen.addr wrap.
func TestInviteCmd_AdvertiseAddrAuto_MalformedListenAddrErrors(t *testing.T) {
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "no-port"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}

	orig := cliDiscoverFunc
	t.Cleanup(func() { cliDiscoverFunc = orig })
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		t.Fatal("STUN must not be queried after malformed listen.addr fails to parse")
		return "", nil
	}

	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--data-dir", dataDir, "invite", "--advertise-addr", "auto"})
	err := root.Execute()
	if err == nil {
		t.Fatal("invite --advertise-addr=auto with malformed listen.addr returned nil error")
	}
	if !strings.Contains(err.Error(), "parse listen.addr") {
		t.Errorf("err = %q, want 'parse listen.addr' wrap", err)
	}
}

// TestInviteCmd_DefaultBranchNonSentinelListenErrPropagates seeds an
// unreadable listen.addr in the default (no advertise) branch so the
// non-sentinel arm of the listen.addr error switch is taken.
func TestInviteCmd_DefaultBranchNonSentinelListenErrPropagates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "127.0.0.1:1"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}
	if err := os.Chmod(filepath.Join(dataDir, daemon.ListenAddrFilename), 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dataDir, daemon.ListenAddrFilename), 0o600) })

	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--data-dir", dataDir, "invite"})
	err := root.Execute()
	if err == nil {
		t.Fatal("invite with unreadable listen.addr returned nil error")
	}
	if errors.Is(err, daemon.ErrNoRunningDaemon) {
		t.Errorf("err = %v, must not be ErrNoRunningDaemon for non-NotExist failures", err)
	}
	if !strings.Contains(err.Error(), "read listen.addr") {
		t.Errorf("err = %q, want 'read listen.addr' wrap", err)
	}
}

// TestInviteCmd_ReadRelayAddrFails plants a directory at relay.addr so
// os.ReadFile returns an EISDIR-shaped error; the cmd must surface the
// read-relay.addr wrap.
func TestInviteCmd_ReadRelayAddrFails(t *testing.T) {
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "127.0.0.1:1"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, daemon.RelayAddrFilename), 0o700); err != nil {
		t.Fatalf("mkdir relay.addr: %v", err)
	}

	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--data-dir", dataDir, "invite"})
	err := root.Execute()
	if err == nil {
		t.Fatal("invite with relay.addr-as-dir returned nil error")
	}
	if !strings.Contains(err.Error(), "read relay.addr") {
		t.Errorf("err = %q, want 'read relay.addr' wrap", err)
	}
}

// TestInviteCmd_ReadTURNCredsFails plants a directory at turn.creds so
// os.ReadFile returns EISDIR; the cmd must surface the read-turn.creds wrap.
func TestInviteCmd_ReadTURNCredsFails(t *testing.T) {
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "127.0.0.1:1"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, daemon.TURNCredsFilename), 0o700); err != nil {
		t.Fatalf("mkdir turn.creds: %v", err)
	}

	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--data-dir", dataDir, "invite"})
	err := root.Execute()
	if err == nil {
		t.Fatal("invite with turn.creds-as-dir returned nil error")
	}
	if !strings.Contains(err.Error(), "read turn.creds") {
		t.Errorf("err = %q, want 'read turn.creds' wrap", err)
	}
}

// TestInviteCmd_IssueInviteFails plants a directory at the invites.db
// path so bbolt fails to open it; the cmd must surface the issue-invite wrap.
func TestInviteCmd_IssueInviteFails(t *testing.T) {
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "127.0.0.1:1"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dataDir, "invites.db"), 0o700); err != nil {
		t.Fatalf("mkdir invites.db: %v", err)
	}

	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--data-dir", dataDir, "invite"})
	err := root.Execute()
	if err == nil {
		t.Fatal("invite with invites.db-as-dir returned nil error")
	}
	if !strings.Contains(err.Error(), "issue invite") {
		t.Errorf("err = %q, want 'issue invite' wrap", err)
	}
}

// TestInviteCmd_ReadCAFails seeds ca.key + a corrupt ca.crt so
// readSwarmCACertIfPresent surfaces a load-ca error through the cmd.
func TestInviteCmd_ReadCAFails(t *testing.T) {
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "127.0.0.1:1"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "ca.key"), make([]byte, 64), 0o600); err != nil {
		t.Fatalf("write ca.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "ca.crt"), []byte("not-a-cert"), 0o644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}

	root := NewRootCmd()
	var stderr bytes.Buffer
	root.SetOut(io.Discard)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", dataDir, "invite"})
	err := root.Execute()
	if err == nil {
		t.Fatal("invite with corrupt ca.crt returned nil error")
	}
	if !strings.Contains(err.Error(), "load ca") {
		t.Errorf("err = %q, want 'load ca' wrap", err)
	}
}
