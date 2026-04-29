package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"backupswarm/internal/daemon"
	"backupswarm/pkg/token"
)

// TestInviteCmd_AdvertiseAddrOverridesListen asserts the steady-state
// `invite` flag overrides the listen.addr file when present.
func TestInviteCmd_AdvertiseAddrOverridesListen(t *testing.T) {
	dataDir := t.TempDir()
	const boundAddr = "127.0.0.1:54321"
	const advertise = "203.0.113.7:7777"
	if err := daemon.WriteListenAddr(dataDir, boundAddr); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}

	root := NewRootCmd()
	stdout := &syncBuffer{}
	root.SetOut(stdout)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"invite",
		"--advertise-addr", advertise,
	})
	if err := root.Execute(); err != nil {
		t.Fatalf("invite: %v", err)
	}

	tokStr := strings.TrimSpace(stdout.String())
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tok.Addr != advertise {
		t.Errorf("token.Addr = %q, want %q", tok.Addr, advertise)
	}
}

// TestInviteCmd_AdvertiseAddrFromEnv asserts the env-var fallback works
// when --advertise-addr is omitted.
func TestInviteCmd_AdvertiseAddrFromEnv(t *testing.T) {
	dataDir := t.TempDir()
	const boundAddr = "127.0.0.1:54321"
	const advertise = "203.0.113.7:9999"
	if err := daemon.WriteListenAddr(dataDir, boundAddr); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}
	t.Setenv("BACKUPSWARM_ADVERTISE_ADDR", advertise)

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
	if tok.Addr != advertise {
		t.Errorf("token.Addr = %q, want %q", tok.Addr, advertise)
	}
}

// TestInviteCmd_BadAdvertiseAddrRejected asserts a malformed value errors
// before any token is issued.
func TestInviteCmd_BadAdvertiseAddrRejected(t *testing.T) {
	dataDir := t.TempDir()
	if err := daemon.WriteListenAddr(dataDir, "127.0.0.1:1"); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}

	root := NewRootCmd()
	var stderr bytes.Buffer
	root.SetOut(io.Discard)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"invite",
		"--advertise-addr", "no-port",
	})
	err := root.Execute()
	if err == nil {
		t.Fatal("invite with bad --advertise-addr returned nil")
	}
}
