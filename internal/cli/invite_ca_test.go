package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"backupswarm/internal/ca"
	"backupswarm/pkg/token"
)

// runInvitePrintToken runs `invite` against 127.0.0.1:0 with a short
// timeout and returns the token printed before the timeout fires.
func runInvitePrintToken(t *testing.T, dataDir string, extra ...string) string {
	t.Helper()
	args := []string{
		"--data-dir", dataDir,
		"invite",
		"--listen", "127.0.0.1:0",
		"--timeout", "200ms",
	}
	args = append(args, extra...)
	cmd := NewRootCmd()
	var stdout bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs(args)
	_ = cmd.Execute()
	return strings.TrimSpace(stdout.String())
}

func TestInviteCmd_AutoGeneratesCAOnFirstRun(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "node")

	tokStr := runInvitePrintToken(t, dataDir)
	if tokStr == "" {
		t.Fatal("invite did not print a token")
	}
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if len(tok.CACert) == 0 {
		t.Fatal("first invite: token CACert is empty, want auto-generated CA cert")
	}
	got, err := ca.Has(dataDir)
	if err != nil {
		t.Fatalf("ca.Has: %v", err)
	}
	if !got {
		t.Error("first invite did not persist a CA on disk")
	}
	loaded, err := ca.Load(dataDir)
	if err != nil {
		t.Fatalf("ca.Load: %v", err)
	}
	if !bytes.Equal(tok.CACert, loaded.CertDER) {
		t.Error("token CACert does not match persisted ca.crt DER")
	}
}

func TestInviteCmd_ReusesCAAcrossInvites(t *testing.T) {
	// Second invite must reuse the first invite's CA cert.
	dataDir := filepath.Join(t.TempDir(), "node")
	first := runInvitePrintToken(t, dataDir)
	second := runInvitePrintToken(t, dataDir)
	tok1, err := token.Decode(first)
	if err != nil {
		t.Fatalf("decode #1: %v", err)
	}
	tok2, err := token.Decode(second)
	if err != nil {
		t.Fatalf("decode #2: %v", err)
	}
	if !bytes.Equal(tok1.CACert, tok2.CACert) {
		t.Error("second invite produced a different CA cert; CA must be stable across invites")
	}
}

func TestInviteCmd_NoCAFlagSkipsCAAndMarksPin(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "node")
	tokStr := runInvitePrintToken(t, dataDir, "--no-ca")
	if tokStr == "" {
		t.Fatal("invite --no-ca did not print a token")
	}
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if len(tok.CACert) != 0 {
		t.Errorf("token CACert = %d bytes, want 0 with --no-ca", len(tok.CACert))
	}
	hasCA, err := ca.Has(dataDir)
	if err != nil {
		t.Fatalf("ca.Has: %v", err)
	}
	if hasCA {
		t.Error("invite --no-ca created a CA on disk")
	}
	pin, err := ca.IsPinMode(dataDir)
	if err != nil {
		t.Fatalf("ca.IsPinMode: %v", err)
	}
	if !pin {
		t.Error("invite --no-ca did not write a pin-mode marker")
	}
}

func TestInviteCmd_PinModePersistsAcrossPlainInvites(t *testing.T) {
	// Plain invite after --no-ca must honor the pin marker, not auto-generate.
	dataDir := filepath.Join(t.TempDir(), "node")
	if first := runInvitePrintToken(t, dataDir, "--no-ca"); first == "" {
		t.Fatal("first invite --no-ca did not print a token")
	}
	tokStr := runInvitePrintToken(t, dataDir)
	if tokStr == "" {
		t.Fatal("second plain invite did not print a token")
	}
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode token: %v", err)
	}
	if len(tok.CACert) != 0 {
		t.Errorf("plain invite after --no-ca produced CACert (%d bytes); should respect pin marker", len(tok.CACert))
	}
	if got, _ := ca.Has(dataDir); got {
		t.Error("plain invite after --no-ca generated a CA")
	}
}

func TestInviteCmd_NoCAOnCAModeFails(t *testing.T) {
	// --no-ca on a CA-mode swarm must error.
	dataDir := filepath.Join(t.TempDir(), "node")
	if first := runInvitePrintToken(t, dataDir); first == "" {
		t.Fatal("first invite did not print a token")
	}

	cmd := NewRootCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{
		"--data-dir", dataDir,
		"invite",
		"--listen", "127.0.0.1:0",
		"--timeout", "200ms",
		"--no-ca",
	})
	if err := cmd.Execute(); err == nil {
		t.Error("invite --no-ca on a CA-mode swarm returned nil error")
	}
}

func TestResolveInviteCA_NoCAMarkPinModeFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dataDir := filepath.Join(t.TempDir(), "node")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	if err := os.Chmod(dataDir, 0o500); err != nil {
		t.Fatalf("chmod data dir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o700) })

	_, err := resolveInviteCA(context.Background(), dataDir, true)
	if err == nil {
		t.Fatal("resolveInviteCA with un-writable pin-mode marker returned nil error")
	}
	if !strings.Contains(err.Error(), "mark pin mode") {
		t.Errorf("error = %q, want 'mark pin mode' prefix", err)
	}
}

func TestResolveInviteCA_LoadCAFails(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "node")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir data dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "ca.key"), make([]byte, ed25519.PrivateKeySize), 0o600); err != nil {
		t.Fatalf("write ca.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "ca.crt"), []byte("not-a-cert"), 0o644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}

	_, err := resolveInviteCA(context.Background(), dataDir, false)
	if err == nil {
		t.Fatal("resolveInviteCA with corrupt CA returned nil error")
	}
	if !strings.Contains(err.Error(), "load ca") {
		t.Errorf("error = %q, want 'load ca' prefix", err)
	}
}
