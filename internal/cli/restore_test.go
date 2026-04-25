package cli

import (
	"bytes"
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
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

func TestRestoreCmd_RegisteredOnRoot(t *testing.T) {
	root := NewRootCmd()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "restore" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("root command missing `restore` subcommand")
	}
}

func TestRestoreCmd_RequiresDestArg(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", t.TempDir(), "restore"})
	if err := root.Execute(); err == nil {
		t.Error("restore accepted missing dest argument")
	}
}

func TestRestoreCmd_RejectsRelativeDest(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", t.TempDir(), "restore", "rel/path"})
	if err := root.Execute(); err == nil {
		t.Error("restore accepted relative dest")
	}
}

// TestRestoreCmd_EndToEnd stands up a real peer, seeds the local
// dataDir with identity/recipient keys/peers.db/index + real chunks
// on the peer, and confirms the restore subcommand produces the
// original files under the given dest.
func TestRestoreCmd_EndToEnd(t *testing.T) {
	peerStore, err := store.New(filepath.Join(t.TempDir(), "peer-chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = peerStore.Close() })

	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serveCtx, serveCancel := context.WithCancel(context.Background())
	t.Cleanup(serveCancel)
	go func() { _ = backup.Serve(serveCtx, listener, peerStore) }()

	// Seed owner-side data dir: identity, recipient keys, peers.db, index + chunks.
	dataDir := t.TempDir()
	id, _, err := node.Ensure(dataDir)
	if err != nil {
		t.Fatalf("node.Ensure: %v", err)
	}
	rk, _, err := node.EnsureRecipient(dataDir)
	if err != nil {
		t.Fatalf("node.EnsureRecipient: %v", err)
	}
	ps, err := peers.Open(filepath.Join(dataDir, "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: listener.Addr().String(), PubKey: peerPub}); err != nil {
		t.Fatalf("peers.Add: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("peers.Close: %v", err)
	}

	ix, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = ix.Close() })

	// Backup a real file to the peer (populates index + ships chunks).
	srcRoot := t.TempDir()
	srcPath := filepath.Join(srcRoot, "doc.bin")
	wantBytes := bytes.Repeat([]byte("Z"), 1<<18)
	if err := os.WriteFile(srcPath, wantBytes, 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	_ = rk // ensure used if test logic grows
	ownerConn, err := func() (*bsquic.Conn, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return bsquic.Dial(ctx, listener.Addr().String(), id.PrivateKey, peerPub)
	}()
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         srcPath,
		Conn:         ownerConn,
		RecipientPub: rk.PublicKey,
		Index:        ix,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("backup.Run: %v", err)
	}
	_ = ownerConn.Close()
	// Close the index so the restore CLI can open it under its own handle.
	if err := ix.Close(); err != nil {
		t.Fatalf("ix.Close: %v", err)
	}

	dest := t.TempDir()
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"restore", dest,
	})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("restore execute: %v", err)
	}

	// Restored file lands at Dest + srcPath.
	restored, err := os.ReadFile(filepath.Join(dest, srcPath))
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, wantBytes) {
		t.Error("restored bytes differ from original")
	}

	// Prevent unused-imports flags.
	_ = crypto.RecipientKeySize
}

// TestRestoreCmd_NoPeer exercises the no-peer branch. Without an entry
// in peers.db the restore cannot dial anyone; the command must error
// rather than silently succeed on an empty dest.
func TestRestoreCmd_NoPeer(t *testing.T) {
	dataDir := t.TempDir()
	dest := t.TempDir()
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", dataDir, "restore", dest})
	if err := root.Execute(); err == nil {
		t.Error("restore accepted missing storage peer")
	}
}

// TestRestoreCmd_MultiplePeers exercises the multi-peer rejection.
func TestRestoreCmd_MultiplePeers(t *testing.T) {
	dataDir := t.TempDir()
	dest := t.TempDir()
	ps, err := peers.Open(filepath.Join(dataDir, "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:1001", PubKey: pub1}); err != nil {
		t.Fatalf("Add 1: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:1002", PubKey: pub2}); err != nil {
		t.Fatalf("Add 2: %v", err)
	}
	_ = ps.Close()

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", dataDir, "restore", dest})
	if err := root.Execute(); err == nil {
		t.Error("restore accepted multiple dialable peers")
	}
}

// TestRestoreCmd_EnsureIdentityError covers the `node.Ensure` error
// wrap: squat node.key as a directory so Save's WriteFile fails when
// Ensure tries to persist a fresh identity.
func TestRestoreCmd_EnsureIdentityError(t *testing.T) {
	dataDir := t.TempDir()
	// Squat the private-key path with a directory so Save fails.
	if err := os.Mkdir(filepath.Join(dataDir, "node.key"), 0o700); err != nil {
		t.Fatalf("mkdir node.key squatter: %v", err)
	}

	dest := t.TempDir()
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", dataDir, "restore", dest})
	if err := root.Execute(); err == nil {
		t.Error("restore returned nil when identity save must fail")
	}
}

// TestRestoreCmd_IndexOpenError squats `index.db` as a directory so
// index.Open (bbolt) fails; covers the `open index` error wrap.
func TestRestoreCmd_IndexOpenError(t *testing.T) {
	dataDir := t.TempDir()
	// Seed a valid peers.db entry so we get past pickSingleDialablePeer.
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ps, err := peers.Open(filepath.Join(dataDir, "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:1", PubKey: pub}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	_ = ps.Close()
	// Squat index.db as a directory so bbolt.Open fails.
	if err := os.Mkdir(filepath.Join(dataDir, "index.db"), 0o700); err != nil {
		t.Fatalf("mkdir index.db squatter: %v", err)
	}

	dest := t.TempDir()
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", dataDir, "restore", dest})
	if err := root.Execute(); err == nil {
		t.Error("restore returned nil when index.Open must fail")
	}
}

// TestRestoreCmd_DialFailure covers the dial-error branch when peers.db
// points at an unreachable address.
func TestRestoreCmd_DialFailure(t *testing.T) {
	dataDir := t.TempDir()
	dest := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ps, err := peers.Open(filepath.Join(dataDir, "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:1", PubKey: pub}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	_ = ps.Close()

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"restore", dest,
		"--dial-timeout", "200ms",
	})
	if err := root.Execute(); err == nil {
		t.Error("restore accepted unreachable peer")
	}
}
