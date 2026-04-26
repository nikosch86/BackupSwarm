package daemon_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"backupswarm/internal/ca"
	"backupswarm/internal/daemon"
	"backupswarm/internal/invites"
	"backupswarm/pkg/token"
)

func TestResolveSwarmCA_AutoGeneratesOnFirstCall(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	got, err := daemon.ResolveSwarmCA(context.Background(), dataDir, false)
	if err != nil {
		t.Fatalf("ResolveSwarmCA: %v", err)
	}
	if got == nil {
		t.Fatal("ResolveSwarmCA returned nil; want auto-generated CA")
	}
	hasCA, err := ca.Has(dataDir)
	if err != nil {
		t.Fatalf("ca.Has: %v", err)
	}
	if !hasCA {
		t.Error("ResolveSwarmCA did not persist CA on disk")
	}
}

func TestResolveSwarmCA_NoCAMarksPin(t *testing.T) {
	dataDir := t.TempDir()
	got, err := daemon.ResolveSwarmCA(context.Background(), dataDir, true)
	if err != nil {
		t.Fatalf("ResolveSwarmCA: %v", err)
	}
	if got != nil {
		t.Error("ResolveSwarmCA(noCA=true) returned non-nil CA")
	}
	pin, err := ca.IsPinMode(dataDir)
	if err != nil {
		t.Fatalf("ca.IsPinMode: %v", err)
	}
	if !pin {
		t.Error("ResolveSwarmCA(noCA=true) did not write pin marker")
	}
}

func TestResolveSwarmCA_NoCAOnCAModeErrors(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := daemon.ResolveSwarmCA(context.Background(), dataDir, false); err != nil {
		t.Fatalf("seed CA: %v", err)
	}
	_, err := daemon.ResolveSwarmCA(context.Background(), dataDir, true)
	if err == nil {
		t.Fatal("ResolveSwarmCA(noCA=true) on a CA-mode swarm returned nil error")
	}
}

func TestResolveSwarmCA_PinModePersistsAcrossPlainCalls(t *testing.T) {
	dataDir := t.TempDir()
	if _, err := daemon.ResolveSwarmCA(context.Background(), dataDir, true); err != nil {
		t.Fatalf("seed pin: %v", err)
	}
	got, err := daemon.ResolveSwarmCA(context.Background(), dataDir, false)
	if err != nil {
		t.Fatalf("ResolveSwarmCA: %v", err)
	}
	if got != nil {
		t.Error("plain ResolveSwarmCA on a pin-mode swarm produced a CA; should respect pin marker")
	}
	if hasCA, _ := ca.Has(dataDir); hasCA {
		t.Error("plain ResolveSwarmCA on pin-mode swarm generated a CA")
	}
}

func TestResolveSwarmCA_NoCAMarkPinModeFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("perm-based error injection requires POSIX")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dataDir := t.TempDir()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(dataDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dataDir, 0o700) })

	_, err := daemon.ResolveSwarmCA(context.Background(), dataDir, true)
	if err == nil {
		t.Fatal("ResolveSwarmCA with un-writable pin marker returned nil error")
	}
	if !strings.Contains(err.Error(), "mark pin mode") {
		t.Errorf("err = %q, want 'mark pin mode' substring", err)
	}
}

func TestResolveSwarmCA_LoadCAFails(t *testing.T) {
	dataDir := t.TempDir()
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "ca.key"), make([]byte, ed25519.PrivateKeySize), 0o600); err != nil {
		t.Fatalf("write ca.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "ca.crt"), []byte("not-a-cert"), 0o644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	_, err := daemon.ResolveSwarmCA(context.Background(), dataDir, false)
	if err == nil {
		t.Fatal("ResolveSwarmCA with corrupt CA returned nil error")
	}
	if !strings.Contains(err.Error(), "load ca") {
		t.Errorf("err = %q, want 'load ca' substring", err)
	}
}

func TestIssueInvite_RoundTrip(t *testing.T) {
	dataDir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	const addr = "127.0.0.1:1234"
	tokStr, err := daemon.IssueInvite(dataDir, addr, pub, nil)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tok.Addr != addr {
		t.Errorf("token addr = %q, want %q", tok.Addr, addr)
	}
	if !tok.Pub.Equal(pub) {
		t.Error("token pub mismatch")
	}

	// The freshly-issued secret must be Consume'able from a separate
	// Open — proves Issue persisted it under bbolt's flock.
	store, err := invites.Open(filepath.Join(dataDir, invites.DefaultFilename))
	if err != nil {
		t.Fatalf("invites.Open: %v", err)
	}
	defer func() { _ = store.Close() }()
	gotSwarm, err := store.Consume(tok.Secret)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if gotSwarm != tok.SwarmID {
		t.Error("consumed swarmID does not match token")
	}
}

func TestIssueInvite_EmbedsCACert(t *testing.T) {
	dataDir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	caCertDER := []byte("fake-ca-cert-bytes")
	tokStr, err := daemon.IssueInvite(dataDir, "127.0.0.1:1", pub, caCertDER)
	if err != nil {
		t.Fatalf("IssueInvite: %v", err)
	}
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(tok.CACert) != string(caCertDER) {
		t.Errorf("token CACert = %x, want %x", tok.CACert, caCertDER)
	}
}
