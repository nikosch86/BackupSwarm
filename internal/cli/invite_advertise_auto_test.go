package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"

	"backupswarm/internal/daemon"
	"backupswarm/pkg/token"
)

// TestInviteCmd_AdvertiseAddrAuto_ResolvesViaSTUN seeds listen.addr,
// then runs `invite --advertise-addr=auto` with the STUN seam mocked
// out. The issued token must combine the STUN-discovered host with the
// listen.addr port.
func TestInviteCmd_AdvertiseAddrAuto_ResolvesViaSTUN(t *testing.T) {
	dataDir := t.TempDir()
	const boundAddr = "127.0.0.1:54321"
	if err := daemon.WriteListenAddr(dataDir, boundAddr); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}

	orig := cliDiscoverFunc
	t.Cleanup(func() { cliDiscoverFunc = orig })
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return "203.0.113.7", nil
	}

	root := NewRootCmd()
	stdout := &syncBuffer{}
	root.SetOut(stdout)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"invite",
		"--advertise-addr", "auto",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("invite: %v", err)
	}

	tokStr := strings.TrimSpace(stdout.String())
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tok.Addr != "203.0.113.7:54321" {
		t.Errorf("token.Addr = %q, want 203.0.113.7:54321", tok.Addr)
	}
}

func TestInviteCmd_AdvertiseAddrAuto_FromEnv(t *testing.T) {
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "127.0.0.1:8888"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}
	t.Setenv("BACKUPSWARM_ADVERTISE_ADDR", "auto")

	orig := cliDiscoverFunc
	t.Cleanup(func() { cliDiscoverFunc = orig })
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return "198.51.100.42", nil
	}

	root := NewRootCmd()
	stdout := &syncBuffer{}
	root.SetOut(stdout)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--data-dir", dataDir, "invite"})
	if err := root.Execute(); err != nil {
		t.Fatalf("invite: %v", err)
	}

	tokStr := strings.TrimSpace(stdout.String())
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tok.Addr != "198.51.100.42:8888" {
		t.Errorf("token.Addr = %q, want 198.51.100.42:8888", tok.Addr)
	}
}

func TestInviteCmd_AdvertiseAddrAuto_STUNFailureSurfaces(t *testing.T) {
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "127.0.0.1:9999"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}

	orig := cliDiscoverFunc
	t.Cleanup(func() { cliDiscoverFunc = orig })
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return "", errors.New("network unreachable")
	}

	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"invite",
		"--advertise-addr", "auto",
	})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected STUN failure to surface")
	}
	if !strings.Contains(err.Error(), "network unreachable") {
		t.Errorf("err = %v, want STUN failure mentioned", err)
	}
}

func TestInviteCmd_StunServerFlag(t *testing.T) {
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "127.0.0.1:7777"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}

	orig := cliDiscoverFunc
	t.Cleanup(func() { cliDiscoverFunc = orig })
	var seenServer atomic.Value
	cliDiscoverFunc = func(_ context.Context, server string) (string, error) {
		seenServer.Store(server)
		return "203.0.113.7", nil
	}

	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"invite",
		"--advertise-addr", "auto",
		"--stun-server", "stun.example.org:3478",
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("invite: %v", err)
	}
	if got, _ := seenServer.Load().(string); got != "stun.example.org:3478" {
		t.Errorf("--stun-server flag not propagated: got %q", got)
	}
}
