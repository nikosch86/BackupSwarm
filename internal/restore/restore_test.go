package restore_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
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
	"backupswarm/internal/restore"
	"backupswarm/internal/store"
)

// restoreRig bundles a peer listener+store with an owner conn, index, and recipient keys, plus a helper to seed chunks.
type restoreRig struct {
	t             *testing.T
	peerStore     *store.Store
	ownerIndex    *index.Index
	ownerConn     *bsquic.Conn
	recipientPub  *[32]byte
	recipientPriv *[32]byte
	peerPubKey    ed25519.PublicKey
}

func newRestoreRig(t *testing.T) *restoreRig {
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

	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() { _ = backup.Serve(ctx, listener, peerStore) }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	ownerConn, err := bsquic.Dial(dialCtx, listener.Addr().String(), ownerPriv, peerPub)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = ownerConn.Close() })

	ownerIndex, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = ownerIndex.Close() })

	recipientPub, recipientPriv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	return &restoreRig{
		t:             t,
		peerStore:     peerStore,
		ownerIndex:    ownerIndex,
		ownerConn:     ownerConn,
		recipientPub:  recipientPub,
		recipientPriv: recipientPriv,
		peerPubKey:    peerPub,
	}
}

func (r *restoreRig) backupFile(path string, data []byte) {
	r.t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		r.t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		r.t.Fatalf("write seed file: %v", err)
	}
	opts := backup.RunOptions{
		Path:         path,
		Conn:         r.ownerConn,
		RecipientPub: r.recipientPub,
		Index:        r.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		r.t.Fatalf("backup seed: %v", err)
	}
}

// TestRun_PreservesModTime asserts restored files carry the mtime recorded in the index entry.
func TestRun_PreservesModTime(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	srcPath := filepath.Join(srcRoot, "timed.bin")
	rig.backupFile(srcPath, []byte("timed payload"))
	entry, err := rig.ownerIndex.Get(srcPath)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	dest := t.TempDir()
	if err := restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	}); err != nil {
		t.Fatalf("restore.Run: %v", err)
	}
	info, err := os.Stat(filepath.Join(dest, srcPath))
	if err != nil {
		t.Fatalf("stat restored: %v", err)
	}
	if !info.ModTime().Equal(entry.ModTime) {
		t.Errorf("restored mtime = %v, want %v", info.ModTime(), entry.ModTime)
	}
}

// TestRun_RestoresSingleFile reconstructs a backed-up file under a fresh
// Dest using only the index and the peer's chunk store (byte-exact).
func TestRun_RestoresSingleFile(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	srcPath := filepath.Join(srcRoot, "alpha.bin")
	data := bytes.Repeat([]byte("ALPHA"), 1<<18) // ~1.25 MiB, two chunks
	rig.backupFile(srcPath, data)

	dest := t.TempDir()
	opts := restore.Options{
		Dest:          dest,
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	}
	if err := restore.Run(context.Background(), opts); err != nil {
		t.Fatalf("restore.Run: %v", err)
	}

	restored := filepath.Join(dest, srcPath)
	got, err := os.ReadFile(restored)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Errorf("restored bytes differ from original")
	}
}

// TestRun_RestoresDirectoryTree asserts a multi-file backup round-trips.
func TestRun_RestoresDirectoryTree(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	files := map[string][]byte{
		filepath.Join(srcRoot, "a.txt"):         []byte("alpha bytes"),
		filepath.Join(srcRoot, "sub", "b.txt"):  bytes.Repeat([]byte("B"), 1<<20),
		filepath.Join(srcRoot, "sub", "c.bin"):  bytes.Repeat([]byte{0xcc}, 1<<21),
		filepath.Join(srcRoot, "deep", "d.log"): []byte(""), // zero-byte file
	}
	for p, d := range files {
		rig.backupFile(p, d)
	}

	dest := t.TempDir()
	if err := restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	}); err != nil {
		t.Fatalf("restore.Run: %v", err)
	}

	for original, want := range files {
		got, err := os.ReadFile(filepath.Join(dest, original))
		if err != nil {
			t.Errorf("read %s: %v", original, err)
			continue
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s: bytes differ after restore", original)
		}
	}
}

// TestRun_RestoreVerifiesPlaintextHash asserts restore fails when the recorded plaintext hash doesn't match decrypted bytes.
func TestRun_RestoreVerifiesPlaintextHash(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	srcPath := filepath.Join(srcRoot, "tampered.bin")
	rig.backupFile(srcPath, []byte("untampered original bytes"))

	entry, err := rig.ownerIndex.Get(srcPath)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	entry.Chunks[0].PlaintextHash = [32]byte{0xde, 0xad, 0xbe, 0xef}
	if err := rig.ownerIndex.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	dest := t.TempDir()
	err = restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Fatal("restore.Run accepted mismatched PlaintextHash")
	}
	if !strings.Contains(err.Error(), "hash") {
		t.Errorf("err = %q, want mention of hash mismatch", err)
	}
}

// TestRun_PeerMissingBlob asserts a chunk missing from the peer surfaces as a restore-level error.
func TestRun_PeerMissingBlob(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	srcPath := filepath.Join(srcRoot, "orphan.bin")
	rig.backupFile(srcPath, []byte("will-be-deleted-from-peer"))

	entry, err := rig.ownerIndex.Get(srcPath)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	for _, ref := range entry.Chunks {
		if err := rig.peerStore.Delete(ref.CiphertextHash); err != nil {
			t.Fatalf("peerStore.Delete: %v", err)
		}
	}

	dest := t.TempDir()
	err = restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Fatal("restore.Run returned nil despite orphaned chunk")
	}
}

// TestRun_EmptyIndex asserts a restore over an empty index returns no error and writes nothing.
func TestRun_EmptyIndex(t *testing.T) {
	rig := newRestoreRig(t)
	dest := t.TempDir()
	if err := restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	}); err != nil {
		t.Fatalf("restore.Run on empty index: %v", err)
	}
	ents, err := os.ReadDir(dest)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(ents) != 0 {
		t.Errorf("dest = %d entries, want 0", len(ents))
	}
}

// TestRun_ProgressOutput asserts per-file progress notes reach the writer.
func TestRun_ProgressOutput(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	path := filepath.Join(srcRoot, "logged.bin")
	rig.backupFile(path, []byte("logged payload"))

	var out bytes.Buffer
	if err := restore.Run(context.Background(), restore.Options{
		Dest:          t.TempDir(),
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      &out,
	}); err != nil {
		t.Fatalf("restore.Run: %v", err)
	}
	if !bytes.Contains(out.Bytes(), []byte("restored")) {
		t.Errorf("progress output = %q, want mention of 'restored'", out.String())
	}
}

// TestRun_NilProgress asserts a nil Progress writer doesn't panic.
func TestRun_NilProgress(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	rig.backupFile(filepath.Join(srcRoot, "f.bin"), []byte("n"))

	if err := restore.Run(context.Background(), restore.Options{
		Dest:          t.TempDir(),
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
	}); err != nil {
		t.Fatalf("restore.Run: %v", err)
	}
}

// TestRun_ContextCancellation asserts a pre-cancelled context bails out.
func TestRun_ContextCancellation(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	rig.backupFile(filepath.Join(srcRoot, "f.bin"), []byte("x"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := restore.Run(ctx, restore.Options{
		Dest:          t.TempDir(),
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Error("restore.Run with pre-cancelled ctx returned nil error")
	}
}

// TestRun_RequiresAbsoluteDest asserts a relative Dest is rejected.
func TestRun_RequiresAbsoluteDest(t *testing.T) {
	rig := newRestoreRig(t)
	err := restore.Run(context.Background(), restore.Options{
		Dest:          "rel/path",
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Fatal("restore.Run accepted relative Dest")
	}
}

// TestRun_IndexListError asserts that a closed index surfaces a list error.
func TestRun_IndexListError(t *testing.T) {
	rig := newRestoreRig(t)
	if err := rig.ownerIndex.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := restore.Run(context.Background(), restore.Options{
		Dest:          t.TempDir(),
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Fatal("restore.Run returned nil on closed index")
	}
}

// TestRun_UnmarshalError points the index at garbage bytes on the peer and asserts restore surfaces an unmarshal error.
func TestRun_UnmarshalError(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	srcPath := filepath.Join(srcRoot, "corrupt.bin")
	rig.backupFile(srcPath, []byte("real bytes"))

	entry, err := rig.ownerIndex.Get(srcPath)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	garbage := []byte{0xff, 0x00, 0xff}
	newHash, err := rig.peerStore.Put(garbage)
	if err != nil {
		t.Fatalf("seed garbage: %v", err)
	}
	entry.Chunks[0].CiphertextHash = newHash
	if err := rig.ownerIndex.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	err = restore.Run(context.Background(), restore.Options{
		Dest:          t.TempDir(),
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Fatal("restore.Run accepted unmarshalable blob")
	}
	if !strings.Contains(err.Error(), "unmarshal") {
		t.Errorf("err = %q, want 'unmarshal' mention", err)
	}
}

// TestRun_DecryptError asserts restore fails when a recipient keypair other than the one chunks were encrypted for is used.
func TestRun_DecryptError(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	srcPath := filepath.Join(srcRoot, "wrong-key.bin")
	rig.backupFile(srcPath, []byte("encrypted with rig key"))

	wrongPub, wrongPriv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	err = restore.Run(context.Background(), restore.Options{
		Dest:          t.TempDir(),
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  wrongPub,
		RecipientPriv: wrongPriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Fatal("restore.Run accepted wrong recipient keys")
	}
	if !strings.Contains(err.Error(), "decrypt") && !strings.Contains(err.Error(), "unwrap") {
		t.Errorf("err = %q, want 'decrypt' or 'unwrap' mention", err)
	}
}

// TestRun_MkdirError points Dest at a read-only tree and asserts restoreFile surfaces the mkdir failure.
func TestRun_MkdirError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	rig.backupFile(filepath.Join(srcRoot, "f.bin"), []byte("x"))

	ro := t.TempDir()
	if err := os.Chmod(ro, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(ro, 0o700) })

	err := restore.Run(context.Background(), restore.Options{
		Dest:          ro,
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Fatal("restore.Run accepted read-only Dest")
	}
}

// TestRun_GetChunkError asserts a closed conn surfaces the transport err.
func TestRun_GetChunkError(t *testing.T) {
	rig := newRestoreRig(t)
	srcRoot := t.TempDir()
	rig.backupFile(filepath.Join(srcRoot, "f.bin"), []byte("bytes"))
	_ = rig.ownerConn.Close()

	err := restore.Run(context.Background(), restore.Options{
		Dest:          t.TempDir(),
		Conn:          rig.ownerConn,
		Index:         rig.ownerIndex,
		RecipientPub:  rig.recipientPub,
		RecipientPriv: rig.recipientPriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Fatal("restore.Run returned nil despite closed conn")
	}
	_ = errors.Is
}
