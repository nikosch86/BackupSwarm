package restore_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/restore"
	"backupswarm/internal/store"
)

// peerInst is one storage peer in the multi-peer restore rig.
type peerInst struct {
	store    *store.Store
	pubKey   ed25519.PublicKey
	priv     ed25519.PrivateKey
	listener *bsquic.Listener
}

func newRestorePeerInst(t *testing.T, ctx context.Context) *peerInst {
	t.Helper()
	dir := t.TempDir()
	st, err := store.New(filepath.Join(dir, "blobs"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", priv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = backup.Serve(ctx, listener, st, nil, nil, nil) }()
	t.Cleanup(func() { _ = listener.Close() })
	return &peerInst{store: st, pubKey: pub, priv: priv, listener: listener}
}

// TestRestore_MultiPeer_PicksCorrectConn asserts restore fetches each
// chunk from the peer recorded in ChunkRef.Peers, even when multiple
// conns are available.
func TestRestore_MultiPeer_PicksCorrectConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	peerA := newRestorePeerInst(t, ctx)
	peerB := newRestorePeerInst(t, ctx)
	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	_ = ownerPub

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	connA, err := bsquic.Dial(dialCtx, peerA.listener.Addr().String(), ownerPriv, peerA.pubKey, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial A: %v", err)
	}
	t.Cleanup(func() { _ = connA.Close() })
	dialCtx, dialCancel = context.WithTimeout(context.Background(), 5*time.Second)
	connB, err := bsquic.Dial(dialCtx, peerB.listener.Addr().String(), ownerPriv, peerB.pubKey, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial B: %v", err)
	}
	t.Cleanup(func() { _ = connB.Close() })

	idx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	rpub, rpriv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	src := t.TempDir()
	srcPath := filepath.Join(src, "doc.bin")
	wantBytes := []byte("multi-peer restore test")
	if err := os.WriteFile(srcPath, wantBytes, 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	// Backup with redundancy=2, so both peers hold the chunk.
	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         src,
		Conns:        []*bsquic.Conn{connA, connB},
		Redundancy:   2,
		RecipientPub: rpub,
		Index:        idx,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("backup.Run: %v", err)
	}

	// Restore from a fresh dest; both conns available.
	dest := t.TempDir()
	if err := restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conns:         []*bsquic.Conn{connA, connB},
		Index:         idx,
		RecipientPub:  rpub,
		RecipientPriv: rpriv,
		Progress:      io.Discard,
	}); err != nil {
		t.Fatalf("restore.Run: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, filepath.Base(srcPath)))
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != string(wantBytes) {
		t.Errorf("restored content = %q, want %q", got, wantBytes)
	}
}

// TestRestore_MultiPeer_FallbackOnUnreachablePeer asserts restore
// proceeds when one recorded peer's conn is closed; the second peer
// in ChunkRef.Peers is tried.
func TestRestore_MultiPeer_FallbackOnUnreachablePeer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	peerA := newRestorePeerInst(t, ctx)
	peerB := newRestorePeerInst(t, ctx)
	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	connA, err := bsquic.Dial(dialCtx, peerA.listener.Addr().String(), ownerPriv, peerA.pubKey, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial A: %v", err)
	}
	t.Cleanup(func() { _ = connA.Close() })
	dialCtx, dialCancel = context.WithTimeout(context.Background(), 5*time.Second)
	connB, err := bsquic.Dial(dialCtx, peerB.listener.Addr().String(), ownerPriv, peerB.pubKey, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial B: %v", err)
	}
	t.Cleanup(func() { _ = connB.Close() })

	idx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	rpub, rpriv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	src := t.TempDir()
	srcPath := filepath.Join(src, "doc.bin")
	wantBytes := []byte("fallback content")
	if err := os.WriteFile(srcPath, wantBytes, 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         src,
		Conns:        []*bsquic.Conn{connA, connB},
		Redundancy:   2,
		RecipientPub: rpub,
		Index:        idx,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("backup.Run: %v", err)
	}

	// Close peerA's conn — restore must fall back to peerB.
	_ = connA.Close()

	dest := t.TempDir()
	if err := restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conns:         []*bsquic.Conn{connA, connB},
		Index:         idx,
		RecipientPub:  rpub,
		RecipientPriv: rpriv,
		Progress:      io.Discard,
	}); err != nil {
		t.Fatalf("restore.Run with peerA dead: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, filepath.Base(srcPath)))
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if string(got) != string(wantBytes) {
		t.Errorf("restored content = %q, want %q", got, wantBytes)
	}
}

// TestRestore_MultiPeer_NoMatchingConn asserts restore errors when
// none of ChunkRef.Peers matches a conn in opts.Conns.
func TestRestore_MultiPeer_NoMatchingConn(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	peerA := newRestorePeerInst(t, ctx)
	peerStranger := newRestorePeerInst(t, ctx)
	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	connA, err := bsquic.Dial(dialCtx, peerA.listener.Addr().String(), ownerPriv, peerA.pubKey, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial A: %v", err)
	}
	t.Cleanup(func() { _ = connA.Close() })
	dialCtx, dialCancel = context.WithTimeout(context.Background(), 5*time.Second)
	connStranger, err := bsquic.Dial(dialCtx, peerStranger.listener.Addr().String(), ownerPriv, peerStranger.pubKey, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial stranger: %v", err)
	}
	t.Cleanup(func() { _ = connStranger.Close() })

	idx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	rpub, rpriv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	// Backup to peerA only; index records peerA's pubkey.
	src := t.TempDir()
	srcPath := filepath.Join(src, "doc.bin")
	if err := os.WriteFile(srcPath, []byte("data"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         src,
		Conns:        []*bsquic.Conn{connA},
		Redundancy:   1,
		RecipientPub: rpub,
		Index:        idx,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("backup.Run: %v", err)
	}

	// Restore using only the stranger — no match for ChunkRef.Peers[0].
	dest := t.TempDir()
	err = restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conns:         []*bsquic.Conn{connStranger},
		Index:         idx,
		RecipientPub:  rpub,
		RecipientPriv: rpriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Fatal("restore.Run succeeded with no matching conn for chunk")
	}
}
