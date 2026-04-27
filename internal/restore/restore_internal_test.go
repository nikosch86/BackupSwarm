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

// withOpenFileFunc swaps openFileFunc for the duration of a test.
func withOpenFileFunc(t *testing.T, fn func(name string, flag int, perm os.FileMode) (writableFile, error)) {
	t.Helper()
	prev := openFileFunc
	openFileFunc = fn
	t.Cleanup(func() { openFileFunc = prev })
}

// withChtimesFunc swaps chtimesFunc for the duration of a test.
func withChtimesFunc(t *testing.T, fn func(name string, atime time.Time, mtime time.Time) error) {
	t.Helper()
	prev := chtimesFunc
	chtimesFunc = fn
	t.Cleanup(func() { chtimesFunc = prev })
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
	path := filepath.Join(src, "seed.bin")
	if err := os.WriteFile(path, []byte("seed"), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
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
	withOpenFileFunc(t, func(name string, flag int, perm os.FileMode) (writableFile, error) {
		real, err := os.OpenFile(name, flag, perm)
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
	withOpenFileFunc(t, func(name string, flag int, perm os.FileMode) (writableFile, error) {
		real, err := os.OpenFile(name, flag, perm)
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
	withChtimesFunc(t, func(name string, atime, mtime time.Time) error {
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

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = restoreFile(ctx, opts, entries[0], connByPub)
	if err == nil {
		t.Fatal("restoreFile returned nil despite cancelled ctx")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

var _ = sha256.Size
