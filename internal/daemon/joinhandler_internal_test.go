package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backupswarm/internal/peers"
)

// TestLoadSwarmCAIfPresent_AbsentReturnsNil asserts a fresh dir with no
// CA returns (nil, nil) — the daemon stays in pin-mode without forcing
// a CA on every test.
func TestLoadSwarmCAIfPresent_AbsentReturnsNil(t *testing.T) {
	dir := t.TempDir()
	got, err := loadSwarmCAIfPresent(dir)
	if err != nil {
		t.Fatalf("loadSwarmCAIfPresent: %v", err)
	}
	if got != nil {
		t.Error("loadSwarmCAIfPresent returned non-nil CA on a fresh dir")
	}
}

// TestLoadSwarmCAIfPresent_HasFails chmods the data dir 0o000 so ca.Has
// errors; the wrapper surfaces the check-ca prefix.
func TestLoadSwarmCAIfPresent_HasFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, err := loadSwarmCAIfPresent(dir)
	if err == nil {
		t.Fatal("loadSwarmCAIfPresent against unreadable dir returned nil error")
	}
	if !strings.Contains(err.Error(), "check ca") {
		t.Errorf("err = %q, want 'check ca' substring", err)
	}
}

// TestLoadSwarmCAIfPresent_LoadFails seeds a corrupt ca.crt + matching
// ca.key so ca.Has=true but ca.Load errors on parse; the wrapper
// surfaces the load-ca prefix.
func TestLoadSwarmCAIfPresent_LoadFails(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), make([]byte, ed25519.PrivateKeySize), 0o600); err != nil {
		t.Fatalf("write ca.key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("not-a-cert"), 0o644); err != nil {
		t.Fatalf("write ca.crt: %v", err)
	}
	_, err := loadSwarmCAIfPresent(dir)
	if err == nil {
		t.Fatal("loadSwarmCAIfPresent with corrupt ca.crt returned nil error")
	}
	if !strings.Contains(err.Error(), "load ca") {
		t.Errorf("err = %q, want 'load ca' substring", err)
	}
}

// TestMakeJoinHandler_OpenInvitesFails chmods the data dir 0o500 so
// invites.Open errors; the handler must surface the open-invites.db
// wrap before reaching bootstrap.HandleJoinStream.
func TestMakeJoinHandler_OpenInvitesFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })

	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	handler := makeJoinHandler(dir, ps, nil, nil)
	joinerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	err = handler(context.Background(), &nopReadWriter{}, joinerPub)
	if err == nil {
		t.Fatal("handler against unwritable invites dir returned nil error")
	}
	if !strings.Contains(err.Error(), "open invites.db") {
		t.Errorf("err = %q, want 'open invites.db' substring", err)
	}
}

// nopReadWriter satisfies io.ReadWriter without performing any I/O so
// the join handler errors at invites.Open before consuming any bytes.
type nopReadWriter struct{}

func (*nopReadWriter) Read(p []byte) (int, error)  { return 0, nil }
func (*nopReadWriter) Write(p []byte) (int, error) { return len(p), nil }
