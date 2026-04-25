package peers

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"
)

// withChmodFunc swaps chmodFunc for the duration of a test.
func withChmodFunc(t *testing.T, fn func(name string, mode os.FileMode) error) {
	t.Helper()
	prev := chmodFunc
	chmodFunc = fn
	t.Cleanup(func() { chmodFunc = prev })
}

// withDBUpdateFunc swaps dbUpdateFunc for the duration of a test.
func withDBUpdateFunc(t *testing.T, fn func(db *bbolt.DB, fn func(*bbolt.Tx) error) error) {
	t.Helper()
	prev := dbUpdateFunc
	dbUpdateFunc = fn
	t.Cleanup(func() { dbUpdateFunc = prev })
}

// TestOpen_ChmodFailure asserts an os.Chmod failure surfaces from Open wrapped.
func TestOpen_ChmodFailure(t *testing.T) {
	sentinel := errors.New("forced chmod failure")
	withChmodFunc(t, func(name string, mode os.FileMode) error {
		return sentinel
	})

	_, err := Open(filepath.Join(t.TempDir(), "chmod-fail.db"))
	if err == nil {
		t.Fatal("Open succeeded despite injected chmod failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Open err = %v, want wraps sentinel", err)
	}
}

// TestOpen_BucketCreateFailure asserts a db.Update failure surfaces from Open wrapped.
func TestOpen_BucketCreateFailure(t *testing.T) {
	sentinel := errors.New("forced update failure")
	withDBUpdateFunc(t, func(db *bbolt.DB, fn func(*bbolt.Tx) error) error {
		return sentinel
	})

	_, err := Open(filepath.Join(t.TempDir(), "bucket-fail.db"))
	if err == nil {
		t.Fatal("Open succeeded despite injected Update failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Open err = %v, want wraps sentinel", err)
	}
}

// TestEncodeDecodeValue_RoundTrip asserts the wire format round-trips every defined Role.
func TestEncodeDecodeValue_RoundTrip(t *testing.T) {
	cases := []struct {
		role Role
		addr string
	}{
		{RolePeer, "127.0.0.1:1"},
		{RoleIntroducer, "10.0.0.1:443"},
		{RoleStorage, ""},
	}
	for _, tc := range cases {
		raw := encodeValue(tc.role, tc.addr)
		if len(raw) < 2 || raw[0] != valueFormatVersion {
			t.Fatalf("encoded value missing version prefix: % x", raw)
		}
		role, addr, err := decodeValue(raw)
		if err != nil {
			t.Fatalf("decode %v: %v", tc.role, err)
		}
		if role != tc.role {
			t.Errorf("role = %v, want %v", role, tc.role)
		}
		if addr != tc.addr {
			t.Errorf("addr = %q, want %q", addr, tc.addr)
		}
	}
}

// TestDecodeValue_RejectsTruncated asserts decode fails on too-short values.
func TestDecodeValue_RejectsTruncated(t *testing.T) {
	if _, _, err := decodeValue(nil); err == nil {
		t.Error("decodeValue(nil) returned nil error")
	}
	if _, _, err := decodeValue([]byte{valueFormatVersion}); err == nil {
		t.Error("decodeValue(version-only) returned nil error")
	}
}

// TestDecodeValue_RejectsUnknownVersion asserts decode fails on an unknown version byte.
func TestDecodeValue_RejectsUnknownVersion(t *testing.T) {
	if _, _, err := decodeValue([]byte{0x99, byte(RolePeer)}); err == nil {
		t.Error("decodeValue(unknown version) returned nil error")
	}
}

// seedRawValue writes raw bytes directly into the bucket, bypassing
// Add's encoding and Open's migration heuristic.
func seedRawValue(t *testing.T, path string, pub ed25519.PublicKey, raw []byte) {
	t.Helper()
	db, err := bbolt.Open(path, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		if err != nil {
			return err
		}
		return b.Put(pub, raw)
	}); err != nil {
		_ = db.Close()
		t.Fatalf("seed put: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
}

// TestGet_WrongSizePubkey asserts Get rejects a pubkey of the wrong length.
func TestGet_WrongSizePubkey(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "get-bad-pub.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.Get([]byte{1, 2, 3}); err == nil {
		t.Error("Get accepted wrong-size pubkey")
	}
}

// TestGet_DecodeFailureSurfacesWrapped asserts a corrupted record under
// pub surfaces from Get with a "decode peer record" wrap.
func TestGet_DecodeFailureSurfacesWrapped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "get-corrupt.db")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	seedRawValue(t, path, pub, []byte{valueFormatVersion})

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.Get(pub); err == nil {
		t.Fatal("Get returned nil error on truncated record")
	} else if !strings.Contains(err.Error(), "decode peer record") {
		t.Errorf("Get err = %v, want 'decode peer record' wrap", err)
	}
}

// TestList_DecodeFailureSurfacesWrapped asserts a corrupted record
// surfaces from List with a "decode peer record" wrap.
func TestList_DecodeFailureSurfacesWrapped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list-corrupt.db")
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	seedRawValue(t, path, pub, []byte{valueFormatVersion})

	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if _, err := s.List(); err == nil {
		t.Fatal("List returned nil error on truncated record")
	} else if !strings.Contains(err.Error(), "decode peer record") {
		t.Errorf("List err = %v, want 'decode peer record' wrap", err)
	}
}
