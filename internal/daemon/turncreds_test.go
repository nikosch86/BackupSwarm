package daemon_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backupswarm/internal/daemon"
)

// TestTURNCreds_RoundTrip writes creds and reads them back via the public
// API; both directions are covered in one go.
func TestTURNCreds_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	want := daemon.TURNCreds{
		Server: "turn.example.org:3478",
		User:   "alice",
		Pass:   "secret",
		Realm:  "example.org",
	}
	if err := daemon.WriteTURNCreds(dir, want); err != nil {
		t.Fatalf("WriteTURNCreds: %v", err)
	}
	got, err := daemon.ReadTURNCreds(dir)
	if err != nil {
		t.Fatalf("ReadTURNCreds: %v", err)
	}
	if got != want {
		t.Errorf("creds = %+v, want %+v", got, want)
	}
}

// TestReadTURNCreds_Missing returns the zero value with no error so
// callers can treat absent as "no shared joiner-side TURN credentials".
func TestReadTURNCreds_Missing(t *testing.T) {
	dir := t.TempDir()
	got, err := daemon.ReadTURNCreds(dir)
	if err != nil {
		t.Fatalf("ReadTURNCreds on missing file: %v", err)
	}
	if got != (daemon.TURNCreds{}) {
		t.Errorf("creds = %+v, want zero value", got)
	}
}

// TestReadTURNCreds_MalformedJSON plants invalid JSON and asserts the
// wrapper surfaces "parse turn.creds".
func TestReadTURNCreds_MalformedJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, daemon.TURNCredsFilename)
	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatalf("plant garbage: %v", err)
	}
	_, err := daemon.ReadTURNCreds(dir)
	if err == nil {
		t.Fatal("ReadTURNCreds accepted malformed JSON")
	}
	if !strings.Contains(err.Error(), "parse turn.creds") {
		t.Errorf("err = %q, want 'parse turn.creds' substring", err)
	}
}

// TestReadTURNCreds_PermissionDenied chmods the file 0o000 so os.ReadFile
// errors for a reason other than NotExist; the wrapper surfaces "read
// turn.creds" rather than returning a zero value.
func TestReadTURNCreds_PermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	if err := daemon.WriteTURNCreds(dir, daemon.TURNCreds{Server: "s", User: "u", Pass: "p", Realm: "r"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	path := filepath.Join(dir, daemon.TURNCredsFilename)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	_, err := daemon.ReadTURNCreds(dir)
	if err == nil {
		t.Fatal("ReadTURNCreds against unreadable file returned nil error")
	}
	if !strings.Contains(err.Error(), "read turn.creds") {
		t.Errorf("err = %q, want 'read turn.creds' substring", err)
	}
}

// TestRemoveTURNCreds_Idempotent asserts a missing file is not an error
// and a present file is removed.
func TestRemoveTURNCreds_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if err := daemon.WriteTURNCreds(dir, daemon.TURNCreds{Server: "s", User: "u", Pass: "p", Realm: "r"}); err != nil {
		t.Fatalf("WriteTURNCreds: %v", err)
	}
	if err := daemon.RemoveTURNCreds(dir); err != nil {
		t.Fatalf("first RemoveTURNCreds: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, daemon.TURNCredsFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("turn.creds still present after remove: %v", err)
	}
	if err := daemon.RemoveTURNCreds(dir); err != nil {
		t.Errorf("second RemoveTURNCreds should be idempotent, got: %v", err)
	}
}

// TestRemoveTURNCreds_NonNotExistError chmods the parent dir 0o500 so
// os.Remove errors with EACCES; the wrapper must surface
// "remove turn.creds".
func TestRemoveTURNCreds_NonNotExistError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	if err := daemon.WriteTURNCreds(dir, daemon.TURNCreds{Server: "s", User: "u", Pass: "p", Realm: "r"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := daemon.RemoveTURNCreds(dir)
	if err == nil {
		t.Fatal("RemoveTURNCreds against unwritable parent returned nil error")
	}
	if !strings.Contains(err.Error(), "remove turn.creds") {
		t.Errorf("err = %q, want 'remove turn.creds' substring", err)
	}
}
