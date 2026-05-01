package restore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// withOpenInRootFunc swaps openInRootFunc for the duration of a test.
func withOpenInRootFunc(t *testing.T, fn func(root *os.Root, name string, flag int, perm os.FileMode) (writableFile, error)) {
	t.Helper()
	prev := openInRootFunc
	openInRootFunc = fn
	t.Cleanup(func() { openInRootFunc = prev })
}

// withChtimesInRootFunc swaps chtimesInRootFunc for the duration of a test.
func withChtimesInRootFunc(t *testing.T, fn func(root *os.Root, name string, atime time.Time, mtime time.Time) error) {
	t.Helper()
	prev := chtimesInRootFunc
	chtimesInRootFunc = fn
	t.Cleanup(func() { chtimesInRootFunc = prev })
}

// withOpenRootFunc swaps openRootFunc for the duration of a test.
func withOpenRootFunc(t *testing.T, fn func(name string) (*os.Root, error)) {
	t.Helper()
	prev := openRootFunc
	openRootFunc = fn
	t.Cleanup(func() { openRootFunc = prev })
}

// withRenameInRootFunc swaps renameInRootFunc for the duration of a test.
func withRenameInRootFunc(t *testing.T, fn func(root *os.Root, oldName, newName string) error) {
	t.Helper()
	prev := renameInRootFunc
	renameInRootFunc = fn
	t.Cleanup(func() { renameInRootFunc = prev })
}

// fakeWritableFile wraps a real *os.File and lets tests inject Write or Close failures.
type fakeWritableFile struct {
	real     *os.File
	writeErr error
	closeErr error
}

func (f *fakeWritableFile) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	return f.real.Write(p)
}

func (f *fakeWritableFile) Close() error {
	realErr := f.real.Close()
	if f.closeErr != nil {
		return f.closeErr
	}
	return realErr
}

// seedRig brings up an owner/peer rig with one seeded file and returns the restore Options.
func seedRig(t *testing.T) Options {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	peerDir := t.TempDir()
	peerStore, err := store.New(filepath.Join(peerDir, "blobs"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = peerStore.Close() })

	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() { _ = backup.Serve(ctx, listener, peerStore, nil, nil, nil) }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	ownerConn, err := bsquic.Dial(dialCtx, listener.Addr().String(), ownerPriv, peerPub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = ownerConn.Close() })

	idx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	recipientPub, recipientPriv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	src := t.TempDir()
	if err := os.WriteFile(filepath.Join(src, "seed.bin"), []byte("seed"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         src,
		Conns:        []*bsquic.Conn{ownerConn},
		RecipientPub: recipientPub,
		Index:        idx,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("backup.Run: %v", err)
	}

	return Options{
		Conns:         []*bsquic.Conn{ownerConn},
		Index:         idx,
		RecipientPub:  recipientPub,
		RecipientPriv: recipientPriv,
		Progress:      io.Discard,
	}
}

// TestRestoreFile_WriteFailure injects a Write error and asserts restoreFile wraps it as "write chunk".
func TestRestoreFile_WriteFailure(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	sentinel := errors.New("forced write failure")
	withOpenInRootFunc(t, func(root *os.Root, name string, flag int, perm os.FileMode) (writableFile, error) {
		real, err := root.OpenFile(name, flag, perm)
		if err != nil {
			return nil, err
		}
		return &fakeWritableFile{real: real, writeErr: sentinel}, nil
	})

	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run returned nil despite injected write failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "write chunk") {
		t.Errorf("err = %q, want 'write chunk' mention", err)
	}
}

// TestRestoreFile_CloseFailure injects a Close error and asserts restoreFile wraps it.
func TestRestoreFile_CloseFailure(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	sentinel := errors.New("forced close failure")
	withOpenInRootFunc(t, func(root *os.Root, name string, flag int, perm os.FileMode) (writableFile, error) {
		real, err := root.OpenFile(name, flag, perm)
		if err != nil {
			return nil, err
		}
		return &fakeWritableFile{real: real, closeErr: sentinel}, nil
	})

	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run returned nil despite injected close failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "close") {
		t.Errorf("err = %q, want 'close' mention", err)
	}
}

// TestRestoreFile_ChtimesFailure injects an os.Chtimes error and asserts restoreFile wraps it.
func TestRestoreFile_ChtimesFailure(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	sentinel := errors.New("forced chtimes failure")
	withChtimesInRootFunc(t, func(root *os.Root, name string, atime, mtime time.Time) error {
		return sentinel
	})

	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run returned nil despite injected chtimes failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "chtimes") {
		t.Errorf("err = %q, want 'chtimes' mention", err)
	}
}

// TestFetchChunk_NoRecordedPeers asserts fetchChunk rejects a ChunkRef
// with an empty Peers slice — there is no peer to try.
func TestFetchChunk_NoRecordedPeers(t *testing.T) {
	ref := index.ChunkRef{CiphertextHash: [32]byte{0x01}, Size: 1, Peers: nil}
	_, err := fetchChunk(context.Background(), ref, nil)
	if err == nil {
		t.Fatal("fetchChunk returned nil with no recorded peers")
	}
	if !strings.Contains(err.Error(), "no recorded peers") {
		t.Errorf("err = %q, want 'no recorded peers' mention", err)
	}
}

// TestRestoreFile_ContextCancelledInChunkLoop asserts restoreFile bails
// inside the per-chunk loop when the context is cancelled before the
// first iteration.
func TestRestoreFile_ContextCancelledInChunkLoop(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	entries, err := opts.Index.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("seeded index has no entries")
	}
	connByPub := make(map[string]*bsquic.Conn, len(opts.Conns))
	for _, c := range opts.Conns {
		connByPub[hex.EncodeToString(c.RemotePub())] = c
	}

	root, err := os.OpenRoot(opts.Dest)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	rel, err := normalizeRel(entries[0].Path)
	if err != nil {
		t.Fatalf("normalizeRel: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = restoreFile(ctx, opts, root, rel, entries[0], connByPub)
	if err == nil {
		t.Fatal("restoreFile returned nil despite cancelled ctx")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// TestNormalizeRel_TableDriven covers the rel-path validation rules:
// empty, absolute, and `..`-bearing entries all error; clean relative
// paths pass through.
func TestNormalizeRel_TableDriven(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		want    string
		wantErr bool
	}{
		{"empty", "", "", true},
		{"dotdot_prefix", "../etc/passwd", "", true},
		{"dotdot_middle", "foo/../bar", "", true},
		{"dotdot_only", "..", "", true},
		{"absolute", "/etc/passwd", "", true},
		{"absolute_with_dotdot", "/foo/../etc/passwd", "", true},
		{"relative_clean", "foo/bar", "foo/bar", false},
		{"single_dot", ".", ".", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := normalizeRel(c.in)
			if c.wantErr {
				if err == nil {
					t.Fatalf("normalizeRel(%q) = %q, want error", c.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("normalizeRel(%q) errored: %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("normalizeRel(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

var _ = sha256.Size

// TestMissingPeersError_Error_NilOrEmpty covers the early-return branch
// when the receiver is nil or carries no Files.
func TestMissingPeersError_Error_NilOrEmpty(t *testing.T) {
	cases := []struct {
		name string
		in   *MissingPeersError
	}{
		{"nil_receiver", nil},
		{"empty_files_nil", &MissingPeersError{Files: nil}},
		{"empty_files_zero", &MissingPeersError{Files: map[string][][]byte{}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in.Error()
			if !strings.Contains(got, "missing peers") {
				t.Errorf("Error() = %q, want 'missing peers' mention", got)
			}
		})
	}
}

// TestMissingPeersError_Error_OverflowSample asserts more than three
// deferred files render a "+N more" suffix and stop after the sample.
func TestMissingPeersError_Error_OverflowSample(t *testing.T) {
	mpe := &MissingPeersError{Files: map[string][][]byte{
		"a.bin": {{0x01}},
		"b.bin": {{0x02}},
		"c.bin": {{0x03}},
		"d.bin": {{0x04}},
		"e.bin": {{0x05}},
	}}
	msg := mpe.Error()
	if !strings.Contains(msg, "+2 more") {
		t.Errorf("Error() = %q, want '+2 more' suffix", msg)
	}
	// Listed files are deterministic via sort: first three of [a..e].
	if !strings.Contains(msg, "a.bin") || !strings.Contains(msg, "b.bin") || !strings.Contains(msg, "c.bin") {
		t.Errorf("Error() = %q, want first three sorted files", msg)
	}
	// d.bin and e.bin are beyond the sample window.
	if strings.Contains(msg, "d.bin") || strings.Contains(msg, "e.bin") {
		t.Errorf("Error() = %q leaked beyond-sample files", msg)
	}
}

// TestShortPub_LongPub asserts a 32-byte ed25519-shaped pubkey returns
// only the first 8 bytes hex-encoded (16 hex chars).
func TestShortPub_LongPub(t *testing.T) {
	long := make([]byte, 32)
	for i := range long {
		long[i] = byte(i)
	}
	got := shortPub(long)
	want := hex.EncodeToString(long[:8])
	if got != want {
		t.Errorf("shortPub(32B) = %q, want %q", got, want)
	}
	if len(got) != 16 {
		t.Errorf("shortPub long produced %d hex chars, want 16", len(got))
	}
}

// TestShortPub_ExactlyN asserts an 8-byte input returns the full hex
// encoding (boundary).
func TestShortPub_ExactlyN(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	got := shortPub(in)
	if got != hex.EncodeToString(in) {
		t.Errorf("shortPub(8B) = %q, want full hex", got)
	}
}

// TestRun_OpenRootFailure injects an openRootFunc error and asserts Run
// surfaces it with the "open dest" wrap.
func TestRun_OpenRootFailure(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	sentinel := errors.New("forced openRoot failure")
	withOpenRootFunc(t, func(name string) (*os.Root, error) {
		return nil, sentinel
	})

	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run returned nil despite injected openRoot failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "open dest") {
		t.Errorf("err = %q, want 'open dest' wrap", err)
	}
}

// TestRun_RetryDefaultBackoffOnZero asserts RetryBackoff == 0 falls
// through to the 1s default; the loop sleeps ~1s before the next pass.
func TestRun_RetryDefaultBackoffOnZero(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	live := opts.Conns
	var calls int
	opts.Redial = func(ctx context.Context) ([]*bsquic.Conn, error) {
		calls++
		if calls == 1 {
			return nil, nil
		}
		return live, nil
	}
	// Index entries reference a bogus peer pub; first pass defers, exercising the retry sleep.
	entries, err := opts.Index.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("seedRig produced no entries")
	}
	original := append([][]byte(nil), entries[0].Chunks[0].Peers...)
	bogus := make([]byte, ed25519.PublicKeySize)
	for i := range bogus {
		bogus[i] = byte(i + 1)
	}
	entries[0].Chunks[0].Peers = [][]byte{bogus}
	if err := opts.Index.Put(entries[0]); err != nil {
		t.Fatalf("Put bogus peer: %v", err)
	}
	t.Cleanup(func() {
		entries[0].Chunks[0].Peers = original
		_ = opts.Index.Put(entries[0])
	})

	opts.RetryBackoff = 0
	opts.RetryTimeout = 3 * time.Second

	start := time.Now()
	_ = Run(context.Background(), opts)
	elapsed := time.Since(start)
	if elapsed < 900*time.Millisecond {
		t.Errorf("elapsed %v < ~1s, default backoff was not applied", elapsed)
	}
	if calls == 0 {
		t.Error("Redial was never invoked despite RetryTimeout > 0")
	}
}

// TestRun_RetryBackoffCap asserts the doubled backoff is clamped to
// maxBackoffCap; the deadline-bounded sleep keeps the test fast.
func TestRun_RetryBackoffCap(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	entries, err := opts.Index.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	original := append([][]byte(nil), entries[0].Chunks[0].Peers...)
	bogus := make([]byte, ed25519.PublicKeySize)
	bogus[0] = 0xff
	entries[0].Chunks[0].Peers = [][]byte{bogus}
	if err := opts.Index.Put(entries[0]); err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Cleanup(func() {
		entries[0].Chunks[0].Peers = original
		_ = opts.Index.Put(entries[0])
	})

	opts.RetryBackoff = maxBackoffCap + time.Second
	opts.RetryTimeout = 80 * time.Millisecond
	opts.Redial = func(ctx context.Context) ([]*bsquic.Conn, error) {
		return opts.Conns, nil
	}

	start := time.Now()
	err = Run(context.Background(), opts)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Run returned nil despite never recovering peer")
	}
	var mpe *MissingPeersError
	if !errors.As(err, &mpe) {
		t.Fatalf("err = %T, want *MissingPeersError", err)
	}
	if elapsed > 600*time.Millisecond {
		t.Errorf("elapsed %v exceeded the small budget", elapsed)
	}
}

// TestRun_RetryCtxCanceledDuringSleep asserts a cancellation during the
// retry loop's sleep returns ctx.Err promptly.
func TestRun_RetryCtxCanceledDuringSleep(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	entries, err := opts.Index.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	original := append([][]byte(nil), entries[0].Chunks[0].Peers...)
	bogus := make([]byte, ed25519.PublicKeySize)
	bogus[0] = 0xee
	entries[0].Chunks[0].Peers = [][]byte{bogus}
	if err := opts.Index.Put(entries[0]); err != nil {
		t.Fatalf("Put: %v", err)
	}
	t.Cleanup(func() {
		entries[0].Chunks[0].Peers = original
		_ = opts.Index.Put(entries[0])
	})

	opts.RetryBackoff = 5 * time.Second
	opts.RetryTimeout = 30 * time.Second
	opts.Redial = func(ctx context.Context) ([]*bsquic.Conn, error) {
		return opts.Conns, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err = Run(ctx, opts)
	elapsed := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if elapsed > 2*time.Second {
		t.Errorf("elapsed %v — cancel didn't interrupt the long sleep", elapsed)
	}
}

// TestRestoreFile_MkdirParentFailure pre-creates a regular file where a
// parent dir is needed so root.MkdirAll fails with a wrapped error.
func TestRestoreFile_MkdirParentFailure(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	entries, err := opts.Index.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("seedRig produced no entries")
	}
	parent := "block"
	if err := os.WriteFile(filepath.Join(opts.Dest, parent), []byte("squat"), 0o600); err != nil {
		t.Fatalf("write squatter: %v", err)
	}

	connByPub := buildConnMap(opts.Conns)
	root, err := os.OpenRoot(opts.Dest)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	rel := filepath.Join(parent, "child.bin")
	_, ferr := restoreFile(context.Background(), opts, root, rel, entries[0], connByPub)
	if ferr == nil {
		t.Fatal("restoreFile returned nil despite parent collision")
	}
	if !strings.Contains(ferr.Error(), "mkdir parent") {
		t.Errorf("err = %q, want 'mkdir parent' wrap", ferr)
	}
}

// TestRestoreFile_RefuseSymlink pre-creates a symlink at the target
// rel path; restoreFile must refuse to overwrite it.
func TestRestoreFile_RefuseSymlink(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	entries, err := opts.Index.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("seedRig produced no entries")
	}
	rel, err := normalizeRel(entries[0].Path)
	if err != nil {
		t.Fatalf("normalizeRel: %v", err)
	}
	target := filepath.Join(opts.Dest, rel)
	if err := os.Symlink("/etc/passwd", target); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	connByPub := buildConnMap(opts.Conns)
	root, err := os.OpenRoot(opts.Dest)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	_, ferr := restoreFile(context.Background(), opts, root, rel, entries[0], connByPub)
	if ferr == nil {
		t.Fatal("restoreFile returned nil despite symlink at rel")
	}
	if !strings.Contains(ferr.Error(), "refuse to overwrite symlink") {
		t.Errorf("err = %q, want 'refuse to overwrite symlink' wrap", ferr)
	}
}

// TestRestoreFile_RenameFailure injects a renameInRootFunc error and
// asserts restoreFile wraps it as "rename".
func TestRestoreFile_RenameFailure(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	sentinel := errors.New("forced rename failure")
	withRenameInRootFunc(t, func(root *os.Root, oldName, newName string) error {
		return sentinel
	})

	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run returned nil despite injected rename failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Errorf("err = %q, want 'rename' wrap", err)
	}
}

// TestRestoreFile_OpenPartialFailure injects an openInRootFunc error on
// the .partial create call and asserts restoreFile wraps it as "create".
func TestRestoreFile_OpenPartialFailure(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	sentinel := errors.New("forced create failure")
	withOpenInRootFunc(t, func(root *os.Root, name string, flag int, perm os.FileMode) (writableFile, error) {
		return nil, sentinel
	})

	err := Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run returned nil despite injected create failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !strings.Contains(err.Error(), "create") {
		t.Errorf("err = %q, want 'create' wrap", err)
	}
}

// TestRestoreFile_DedupSeenPeers asserts that when ChunkRef.Peers
// contains the same pubkey twice, the dedup-continue branch fires and
// the missingPeers slice contains the pubkey only once.
func TestRestoreFile_DedupSeenPeers(t *testing.T) {
	opts := seedRig(t)
	opts.Dest = t.TempDir()

	entries, err := opts.Index.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(entries) == 0 {
		t.Fatal("seedRig produced no entries")
	}
	bogus := make([]byte, ed25519.PublicKeySize)
	bogus[0] = 0x42
	entries[0].Chunks[0].Peers = [][]byte{bogus, bogus, bogus}

	root, err := os.OpenRoot(opts.Dest)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { _ = root.Close() })

	rel, err := normalizeRel(entries[0].Path)
	if err != nil {
		t.Fatalf("normalizeRel: %v", err)
	}
	missing, ferr := restoreFile(context.Background(), opts, root, rel, entries[0], map[string]*bsquic.Conn{})
	if ferr == nil {
		t.Fatal("restoreFile returned nil with no live conn")
	}
	if len(missing) != 1 {
		t.Errorf("missing = %d entries, want 1 (dedup of triple-listed peer)", len(missing))
	}
}
