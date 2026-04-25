package invites

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// withChmodFunc swaps chmodFunc for the duration of a test.
func withChmodFunc(t *testing.T, fn func(name string, mode os.FileMode) error) {
	t.Helper()
	prev := chmodFunc
	chmodFunc = fn
	t.Cleanup(func() { chmodFunc = prev })
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

// TestDecodeValue_RejectsTruncated asserts decode fails on values shorter than 2 bytes.
func TestDecodeValue_RejectsTruncated(t *testing.T) {
	if _, _, err := decodeValue(nil); err == nil {
		t.Error("decodeValue(nil) returned nil error")
	}
	if _, _, err := decodeValue([]byte{valueFormatVersion}); err == nil {
		t.Error("decodeValue(version-only) returned nil error")
	}
}

// TestDecodeValue_RejectsWrongBodySize asserts decode fails when the body
// length does not match the swarmID size.
func TestDecodeValue_RejectsWrongBodySize(t *testing.T) {
	raw := []byte{valueFormatVersion, statusPending, 0xAA, 0xBB, 0xCC}
	if _, _, err := decodeValue(raw); err == nil {
		t.Error("decodeValue(short body) returned nil error")
	}
}
