package invites_test

import (
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"backupswarm/internal/invites"
)

func mustRandom(t *testing.T) [32]byte {
	t.Helper()
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return b
}

func openTemp(t *testing.T) (*invites.Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "invites.db")
	s, err := invites.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func TestStore_RoundTrip(t *testing.T) {
	s, _ := openTemp(t)
	secret := mustRandom(t)
	swarmID := mustRandom(t)

	if err := s.Issue(secret, swarmID); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	got, err := s.Consume(secret)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if got != swarmID {
		t.Errorf("Consume swarmID mismatch")
	}
}

func TestStore_ConsumeUnknownSecret(t *testing.T) {
	s, _ := openTemp(t)
	if _, err := s.Consume(mustRandom(t)); !errors.Is(err, invites.ErrUnknown) {
		t.Errorf("err = %v, want ErrUnknown", err)
	}
}

func TestStore_DoubleConsume_RejectsSecond(t *testing.T) {
	s, _ := openTemp(t)
	secret := mustRandom(t)
	if err := s.Issue(secret, mustRandom(t)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Consume(secret); err != nil {
		t.Fatalf("first Consume: %v", err)
	}
	if _, err := s.Consume(secret); !errors.Is(err, invites.ErrAlreadyUsed) {
		t.Errorf("second Consume err = %v, want ErrAlreadyUsed", err)
	}
}

func TestStore_IssueTwice_RejectsSecond(t *testing.T) {
	s, _ := openTemp(t)
	secret := mustRandom(t)
	if err := s.Issue(secret, mustRandom(t)); err != nil {
		t.Fatalf("first Issue: %v", err)
	}
	if err := s.Issue(secret, mustRandom(t)); !errors.Is(err, invites.ErrSecretExists) {
		t.Errorf("second Issue err = %v, want ErrSecretExists", err)
	}
}

func TestStore_PendingPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invites.db")
	s, err := invites.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	secret := mustRandom(t)
	swarmID := mustRandom(t)
	if err := s.Issue(secret, swarmID); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := invites.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	got, err := s2.Consume(secret)
	if err != nil {
		t.Fatalf("Consume after reopen: %v", err)
	}
	if got != swarmID {
		t.Error("swarmID mismatch after reopen")
	}
}

func TestStore_ConsumedPersistsAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invites.db")
	s, err := invites.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	secret := mustRandom(t)
	if err := s.Issue(secret, mustRandom(t)); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if _, err := s.Consume(secret); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	s2, err := invites.Open(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	if _, err := s2.Consume(secret); !errors.Is(err, invites.ErrAlreadyUsed) {
		t.Errorf("Consume after reopen err = %v, want ErrAlreadyUsed", err)
	}
}

func TestStore_OpenCreatesParentDir(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "invites.db")
	s, err := invites.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
}

func TestStore_OpenSecondInstance_FailsFast(t *testing.T) {
	_, path := openTemp(t)
	s2, err := invites.Open(path)
	if err == nil {
		_ = s2.Close()
		t.Fatal("second Open succeeded; want lock contention error")
	}
}

func TestStore_OpenMkdirAllFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod barrier ineffective for root")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o500); err != nil {
		t.Fatalf("chmod parent: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	path := filepath.Join(parent, "blocked", "invites.db")
	if _, err := invites.Open(path); err == nil {
		t.Fatal("Open succeeded despite unwritable parent")
	}
}

func TestStore_OpenRejectsCorruptValue(t *testing.T) {
	// Manually populated bucket with an invalid version byte must be
	// rejected by Consume rather than misparsed.
	s, _ := openTemp(t)
	if err := s.PutRawForTest([32]byte{1, 2, 3}, []byte{0xFF, 0x00}); err != nil {
		t.Fatalf("seed raw: %v", err)
	}
	if _, err := s.Consume([32]byte{1, 2, 3}); err == nil {
		t.Error("Consume accepted corrupt record")
	}
}
