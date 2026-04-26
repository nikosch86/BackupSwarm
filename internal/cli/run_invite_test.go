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
	"time"

	"backupswarm/internal/ca"
	"backupswarm/pkg/token"
)

// runRunInviteForToken starts `run --invite`, waits for the founder
// token to appear on stdout, cancels the daemon, and returns the
// printed token. Used by CA-mode tests that only care about the issued
// token, not the daemon's steady-state behavior.
func runRunInviteForToken(t *testing.T, dataDir string, extra ...string) string {
	t.Helper()
	args := []string{
		"--data-dir", dataDir,
		"run",
		"--listen", "127.0.0.1:0",
		"--invite",
	}
	args = append(args, extra...)

	cmd := NewRootCmd()
	stdout := &syncBuffer{}
	cmd.SetOut(stdout)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(args)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()
	tok := waitForToken(t, stdout, 5*time.Second)
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("run --invite: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run --invite did not exit within 5s of cancel")
	}
	return tok
}

func TestRunCmd_InviteAutoGeneratesCAOnFirstRun(t *testing.T) {
	dataDir := t.TempDir()
	tokStr := runRunInviteForToken(t, dataDir)
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if len(tok.CACert) == 0 {
		t.Fatal("token CACert empty on first run --invite (expected auto-generated CA)")
	}
	hasCA, err := ca.Has(dataDir)
	if err != nil {
		t.Fatalf("ca.Has: %v", err)
	}
	if !hasCA {
		t.Error("first run --invite did not persist a CA on disk")
	}
	loaded, err := ca.Load(dataDir)
	if err != nil {
		t.Fatalf("ca.Load: %v", err)
	}
	if !bytes.Equal(tok.CACert, loaded.CertDER) {
		t.Error("token CACert does not match persisted ca.crt DER")
	}
}

func TestRunCmd_InviteReusesCAAcrossRuns(t *testing.T) {
	dataDir := t.TempDir()
	first := runRunInviteForToken(t, dataDir)
	second := runRunInviteForToken(t, dataDir)
	tok1, err := token.Decode(first)
	if err != nil {
		t.Fatalf("decode first: %v", err)
	}
	tok2, err := token.Decode(second)
	if err != nil {
		t.Fatalf("decode second: %v", err)
	}
	if !bytes.Equal(tok1.CACert, tok2.CACert) {
		t.Error("second run --invite produced a different CA cert; CA must be stable across invites")
	}
}

func TestRunCmd_InviteNoCAFlag_MarksPin(t *testing.T) {
	dataDir := t.TempDir()
	tokStr := runRunInviteForToken(t, dataDir, "--no-ca")
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(tok.CACert) != 0 {
		t.Errorf("token CACert = %d bytes, want 0 with --no-ca", len(tok.CACert))
	}
	if hasCA, _ := ca.Has(dataDir); hasCA {
		t.Error("--no-ca created a CA on disk")
	}
	pin, err := ca.IsPinMode(dataDir)
	if err != nil {
		t.Fatalf("ca.IsPinMode: %v", err)
	}
	if !pin {
		t.Error("--no-ca did not write the pin-mode marker")
	}
}

func TestRunCmd_InviteNoCAOnCAModeFails(t *testing.T) {
	dataDir := t.TempDir()
	if first := runRunInviteForToken(t, dataDir); first == "" {
		t.Fatal("seed run --invite produced no token")
	}

	cmd := NewRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--listen", "127.0.0.1:0",
		"--invite",
		"--no-ca",
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err == nil {
		t.Error("run --invite --no-ca on a CA-mode swarm returned nil error")
	}
}

func TestRunCmd_TokenOutRequiresInvite(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--token-out", filepath.Join(t.TempDir(), "tok.txt"),
	})
	if err := root.Execute(); err == nil {
		t.Error("run --token-out without --invite returned nil error")
	}
}

func TestRunCmd_NoCARequiresInvite(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--no-ca",
	})
	if err := root.Execute(); err == nil {
		t.Error("run --no-ca without --invite returned nil error")
	}
}

func TestRunCmd_Invite_WritesTokenOutAtomically(t *testing.T) {
	dataDir := t.TempDir()
	tokenPath := filepath.Join(t.TempDir(), "founder.token")

	root := NewRootCmd()
	stdout := &syncBuffer{}
	root.SetOut(stdout)
	root.SetErr(io.Discard)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--listen", "127.0.0.1:0",
		"--invite",
		"--token-out", tokenPath,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	defer func() {
		cancel()
		<-done
	}()

	stdoutTok := waitForToken(t, stdout, 5*time.Second)

	deadline := time.Now().Add(5 * time.Second)
	for {
		if data, err := os.ReadFile(tokenPath); err == nil {
			fileTok := strings.TrimSpace(string(data))
			if fileTok == stdoutTok {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("--token-out file never matched stdout token within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}
