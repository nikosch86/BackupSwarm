package store_test

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"backupswarm/internal/store"
)

func TestPutGetIndexSnapshot_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	owner := bytes.Repeat([]byte{0x11}, 32)
	blob := []byte("encrypted index snapshot payload")
	if err := st.PutIndexSnapshot(owner, blob); err != nil {
		t.Fatalf("PutIndexSnapshot: %v", err)
	}
	got, err := st.GetIndexSnapshot(owner)
	if err != nil {
		t.Fatalf("GetIndexSnapshot: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob round-trip mismatch")
	}
}

func TestPutIndexSnapshot_RejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	owner := bytes.Repeat([]byte{0x11}, 32)
	if err := st.PutIndexSnapshot(owner, nil); err == nil {
		t.Error("PutIndexSnapshot accepted nil blob")
	}
	if err := st.PutIndexSnapshot(owner, []byte{}); err == nil {
		t.Error("PutIndexSnapshot accepted empty blob")
	}
}

func TestPutIndexSnapshot_RejectsBadOwner(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.PutIndexSnapshot(nil, []byte("x")); err == nil {
		t.Error("accepted nil owner")
	}
	if err := st.PutIndexSnapshot([]byte("short"), []byte("x")); err == nil {
		t.Error("accepted owner of wrong length")
	}
}

func TestPutIndexSnapshot_OverwritesExisting(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	owner := bytes.Repeat([]byte{0x22}, 32)
	if err := st.PutIndexSnapshot(owner, []byte("first")); err != nil {
		t.Fatalf("PutIndexSnapshot first: %v", err)
	}
	if err := st.PutIndexSnapshot(owner, []byte("second")); err != nil {
		t.Fatalf("PutIndexSnapshot second: %v", err)
	}
	got, err := st.GetIndexSnapshot(owner)
	if err != nil {
		t.Fatalf("GetIndexSnapshot: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("GetIndexSnapshot = %q, want %q", got, "second")
	}
}

func TestGetIndexSnapshot_NotFound(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	owner := bytes.Repeat([]byte{0x33}, 32)
	_, err = st.GetIndexSnapshot(owner)
	if err == nil {
		t.Fatal("GetIndexSnapshot returned no error for missing owner")
	}
	if !errors.Is(err, store.ErrSnapshotNotFound) {
		t.Errorf("err = %v, want wraps ErrSnapshotNotFound", err)
	}
}

func TestGetIndexSnapshot_RejectsBadOwner(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if _, err := st.GetIndexSnapshot(nil); err == nil {
		t.Error("accepted nil owner")
	}
	if _, err := st.GetIndexSnapshot([]byte("short")); err == nil {
		t.Error("accepted owner of wrong length")
	}
}

func TestPutIndexSnapshot_DistinctOwners(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	a := bytes.Repeat([]byte{0xAA}, 32)
	b := bytes.Repeat([]byte{0xBB}, 32)
	if err := st.PutIndexSnapshot(a, []byte("alpha")); err != nil {
		t.Fatalf("Put a: %v", err)
	}
	if err := st.PutIndexSnapshot(b, []byte("beta")); err != nil {
		t.Fatalf("Put b: %v", err)
	}

	gotA, err := st.GetIndexSnapshot(a)
	if err != nil {
		t.Fatalf("Get a: %v", err)
	}
	if string(gotA) != "alpha" {
		t.Errorf("Get a = %q, want alpha", gotA)
	}
	gotB, err := st.GetIndexSnapshot(b)
	if err != nil {
		t.Fatalf("Get b: %v", err)
	}
	if string(gotB) != "beta" {
		t.Errorf("Get b = %q, want beta", gotB)
	}
}

func TestPutIndexSnapshot_FilePerms(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix perms only")
	}
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	owner := bytes.Repeat([]byte{0x44}, 32)
	if err := st.PutIndexSnapshot(owner, []byte("secret")); err != nil {
		t.Fatalf("PutIndexSnapshot: %v", err)
	}
	matches, err := filepath.Glob(filepath.Join(dir, "snapshots", "*"))
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("snapshots dir has %d entries, want 1", len(matches))
	}
	info, err := os.Stat(matches[0])
	if err != nil {
		t.Fatalf("stat snapshot: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("snapshot perm = %o, want 0600", perm)
	}
	parent, err := os.Stat(filepath.Join(dir, "snapshots"))
	if err != nil {
		t.Fatalf("stat snapshots dir: %v", err)
	}
	if perm := parent.Mode().Perm(); perm != 0o700 {
		t.Errorf("snapshots dir perm = %o, want 0700", perm)
	}
}

// TestNew_SkipsSnapshotsDirInUsedScan asserts startup `Used()` does not
// count snapshot bytes — snapshots live alongside chunks but are not
// gated by the chunk capacity counter.
func TestNew_SkipsSnapshotsDirInUsedScan(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	owner := bytes.Repeat([]byte{0x55}, 32)
	if err := st.PutIndexSnapshot(owner, bytes.Repeat([]byte{1}, 1024)); err != nil {
		t.Fatalf("PutIndexSnapshot: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	st2, err := store.New(dir)
	if err != nil {
		t.Fatalf("re-open New: %v", err)
	}
	t.Cleanup(func() { _ = st2.Close() })
	if used := st2.Used(); used != 0 {
		t.Errorf("Used after re-open = %d, want 0 (snapshots excluded)", used)
	}
}
