package daemon_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/daemon"
	"backupswarm/internal/index"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// seedPeer opens peers.db at <dataDir>/peers.db and writes the single
// storage peer the daemon should dial. Mirrors what a real `invite`/
// `join` handshake would have persisted.
func seedPeer(t *testing.T, dataDir, addr string, pub []byte) {
	t.Helper()
	ps, err := peers.Open(filepath.Join(dataDir, "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	defer ps.Close()
	if err := ps.Add(peers.Peer{Addr: addr, PubKey: pub}); err != nil {
		t.Fatalf("peers.Add: %v", err)
	}
}

// scanRig spins up a real peer (store + listener + Serve) plus an
// owner-side QUIC connection, index, and recipient pubkey. Mirrors the
// rig pattern in internal/backup but scoped to what daemon tests need.
type scanRig struct {
	peerStore    *store.Store
	ownerIndex   *index.Index
	ownerConn    *bsquic.Conn
	recipientPub *[crypto.RecipientKeySize]byte
	peerPub      ed25519.PublicKey
}

func newScanRig(t *testing.T) *scanRig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	peerStore, err := store.New(filepath.Join(t.TempDir(), "chunks"))
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

	recipientPub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	return &scanRig{
		peerStore:    peerStore,
		ownerIndex:   ownerIndex,
		ownerConn:    ownerConn,
		recipientPub: recipientPub,
		peerPub:      peerPub,
	}
}

func writeFile(t *testing.T, path string, size int) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
}

// TestScanOnce_BackupAndPrune asserts one pass ships changed files and
// emits deletes for missing ones in a single call.
func TestScanOnce_BackupAndPrune(t *testing.T) {
	rig := newScanRig(t)
	root := t.TempDir()
	keep := filepath.Join(root, "keep.bin")
	goner := filepath.Join(root, "goner.bin")
	writeFile(t, keep, 1<<20)
	writeFile(t, goner, 1<<20)

	opts := daemon.ScanOnceOptions{
		BackupDir:    root,
		Conn:         rig.ownerConn,
		Index:        rig.ownerIndex,
		RecipientPub: rig.recipientPub,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := daemon.ScanOnce(context.Background(), opts); err != nil {
		t.Fatalf("ScanOnce #1: %v", err)
	}
	entry, err := rig.ownerIndex.Get(goner)
	if err != nil {
		t.Fatalf("Get goner: %v", err)
	}

	// Remove one file and run again; the second pass should prune.
	if err := os.Remove(goner); err != nil {
		t.Fatalf("rm goner: %v", err)
	}
	var progress bytes.Buffer
	opts.Progress = &progress
	if err := daemon.ScanOnce(context.Background(), opts); err != nil {
		t.Fatalf("ScanOnce #2: %v", err)
	}
	if _, err := rig.ownerIndex.Get(goner); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("goner still in index after prune: %v", err)
	}
	if _, err := rig.ownerIndex.Get(keep); err != nil {
		t.Errorf("keep lost from index: %v", err)
	}
	for _, ref := range entry.Chunks {
		has, err := rig.peerStore.Has(ref.CiphertextHash)
		if err != nil {
			t.Fatalf("peerStore.Has: %v", err)
		}
		if has {
			t.Error("peer still holds blob for pruned file")
		}
	}
	if !bytes.Contains(progress.Bytes(), []byte("pruned")) {
		t.Errorf("expected 'pruned' progress note, got %q", progress.String())
	}
}

// TestScanOnce_NilProgress asserts nil Progress falls back to io.Discard
// without panicking.
func TestScanOnce_NilProgress(t *testing.T) {
	rig := newScanRig(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.bin"), 1<<20)
	opts := daemon.ScanOnceOptions{
		BackupDir:    root,
		Conn:         rig.ownerConn,
		Index:        rig.ownerIndex,
		RecipientPub: rig.recipientPub,
		ChunkSize:    1 << 20,
	}
	if err := daemon.ScanOnce(context.Background(), opts); err != nil {
		t.Fatalf("ScanOnce: %v", err)
	}
}

// TestScanOnce_BackupFailurePropagates asserts a backup.Run error wraps
// as "backup run: ...". We trigger a failure by giving an invalid
// ChunkSize (below MinChunkSize).
func TestScanOnce_BackupFailurePropagates(t *testing.T) {
	rig := newScanRig(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.bin"), 1<<20)
	opts := daemon.ScanOnceOptions{
		BackupDir:    root,
		Conn:         rig.ownerConn,
		Index:        rig.ownerIndex,
		RecipientPub: rig.recipientPub,
		ChunkSize:    1, // invalid
		Progress:     io.Discard,
	}
	err := daemon.ScanOnce(context.Background(), opts)
	if err == nil {
		t.Fatal("ScanOnce accepted invalid chunk size")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("backup run")) {
		t.Errorf("err = %q, want 'backup run' prefix", err)
	}
}

// TestScanOnce_PruneFailurePropagates asserts a Prune error wraps as
// "prune: ...". We force a failure by closing the index between Run and
// Prune... but that's hard; easier to close the peer connection before
// the Prune call reaches it. Instead we set up a scenario where Run
// succeeds (no files) but Prune hits a closed index.
func TestScanOnce_PruneFailurePropagates(t *testing.T) {
	rig := newScanRig(t)
	root := t.TempDir()
	// Pre-populate the index with a dangling entry (file doesn't exist)
	// so Prune tries to send deletes.
	if err := rig.ownerIndex.Put(index.FileEntry{
		Path:   filepath.Join(root, "ghost.bin"),
		Size:   1,
		Chunks: []index.ChunkRef{{CiphertextHash: [32]byte{0xaa}, Size: 10}},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	// Close the owner's QUIC connection; Prune's sendDeleteChunk will fail.
	_ = rig.ownerConn.Close()

	opts := daemon.ScanOnceOptions{
		BackupDir:    root,
		Conn:         rig.ownerConn,
		Index:        rig.ownerIndex,
		RecipientPub: rig.recipientPub,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	err := daemon.ScanOnce(context.Background(), opts)
	if err == nil {
		t.Fatal("ScanOnce accepted closed-conn prune")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("prune")) {
		t.Errorf("err = %q, want 'prune' prefix", err)
	}
}

// TestRun_RefusesWhenBackupDirEmptyButIndexPopulated asserts the guard
// fires all the way through Run, not just in Classify. An empty backup
// dir with a populated index and no --restore/--purge must fail before
// any network activity.
func TestRun_RefusesWhenBackupDirEmptyButIndexPopulated(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()

	// Seed a populated index at dataDir/index.db (the name Run expects).
	ix, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("seed index: %v", err)
	}
	if err := ix.Put(index.FileEntry{Path: filepath.Join(backupDir, "gone.bin"), Size: 1}); err != nil {
		t.Fatalf("seed put: %v", err)
	}
	if err := ix.Close(); err != nil {
		t.Fatalf("close seed index: %v", err)
	}

	err = daemon.Run(context.Background(), daemon.Options{
		DataDir:    dataDir,
		BackupDir:  backupDir,
		ListenAddr: "127.0.0.1:0",
		ChunkSize:  1 << 20,
	})
	if err == nil {
		t.Fatal("Run accepted empty-local + populated-index without --restore/--purge")
	}
	if !errors.Is(err, daemon.ErrRefuseStart) {
		t.Errorf("err = %v, want wraps ErrRefuseStart", err)
	}
}

// TestRun_IdleStorageOnlyExitsOnContextCancel asserts that a daemon
// started with no --peer (pure storage-peer role) blocks cleanly until
// context cancellation and returns nil.
func TestRun_IdleStorageOnlyExitsOnContextCancel(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			DataDir:    dataDir,
			BackupDir:  backupDir,
			ListenAddr: "127.0.0.1:0",
			ChunkSize:  1 << 20,
			Progress:   io.Discard,
		})
	}()

	// Cancel after a short delay so Run has time to enter its wait.
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned err = %v, want nil on cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancel")
	}
}

// peerRig spins up a pure storage peer (identity + listener + Serve) at
// a random local address. Owner-side tests use the returned addr + pub
// to drive daemon.Run end-to-end.
type peerRig struct {
	addr      string
	pub       ed25519.PublicKey
	store     *store.Store
	storeRoot string
	listener  *bsquic.Listener
	serveDone chan error
}

func newPeerRig(t *testing.T) *peerRig {
	t.Helper()
	storeRoot := filepath.Join(t.TempDir(), "peer-chunks")
	peerStore, err := store.New(storeRoot)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = peerStore.Close() })

	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serveCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() { done <- backup.Serve(serveCtx, listener, peerStore) }()

	return &peerRig{
		addr:      listener.Addr().String(),
		pub:       peerPub,
		store:     peerStore,
		storeRoot: storeRoot,
		listener:  listener,
		serveDone: done,
	}
}

// TestRun_WithPeer_FirstBackupShipsChunks exercises the full happy path:
// fresh data dir, backup dir with one file, peer is up. Daemon starts,
// does at least one scan pass, the peer sees the blob, then we cancel
// and expect clean exit. The storage peer is persisted via peers.db —
// mirroring how `invite`/`join` would have persisted it.
func TestRun_WithPeer_FirstBackupShipsChunks(t *testing.T) {
	peer := newPeerRig(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	writeFile(t, filepath.Join(backupDir, "file.bin"), 1<<20)
	seedPeer(t, dataDir, peer.addr, peer.pub)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			DataDir:      dataDir,
			BackupDir:    backupDir,
			ListenAddr:   "127.0.0.1:0",
			ChunkSize:    1 << 20,
			ScanInterval: 50 * time.Millisecond,
			Progress:     io.Discard,
		})
	}()

	// Wait up to ~3s for the peer store to see at least one blob.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(peer.storeRoot)
		if err == nil && len(entries) > 0 {
			// Found at least one shard directory; good enough signal that
			// a chunk landed. (The owners db file is also in root but it's
			// created lazily on first PutOwned so it's fine either way.)
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit within 5s of cancel")
	}

	// Confirm the peer store has at least one blob subdir (proves ScanOnce
	// ran and sent something).
	entries, err := os.ReadDir(peer.storeRoot)
	if err != nil {
		t.Fatalf("read peer store root: %v", err)
	}
	var shards int
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) == 2 {
			shards++
		}
	}
	if shards == 0 {
		t.Error("peer store has no shard dirs; daemon did not ship any chunks")
	}
}

// TestRun_RestoreMode: after a backup, empty the backup dir and restart
// the daemon with --restore. Every file previously backed up must be
// rewritten to disk under backupDir with original content and mtime.
// Paths in the index are absolute (under backupDir), so Dest = "/"
// puts them back where they originally were.
func TestRun_RestoreMode(t *testing.T) {
	peer := newPeerRig(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	filePath := filepath.Join(backupDir, "restored.bin")
	writeFile(t, filePath, 1<<20)
	originalBytes, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read original: %v", err)
	}
	originalInfo, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat original: %v", err)
	}
	seedPeer(t, dataDir, peer.addr, peer.pub)

	// Stage 1: run a normal daemon long enough to ship the file.
	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() {
		done1 <- daemon.Run(ctx1, daemon.Options{
			DataDir:      dataDir,
			BackupDir:    backupDir,
			ListenAddr:   "127.0.0.1:0",
			ChunkSize:    1 << 20,
			ScanInterval: 50 * time.Millisecond,
			Progress:     io.Discard,
		})
	}()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(peer.storeRoot)
		if err == nil && hasShardDir(entries) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel1()
	<-done1

	// Remove the local file so backupDir is empty for the restore run.
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("rm original: %v", err)
	}

	// Stage 2: run with --restore. The file should reappear at its original path.
	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() {
		done2 <- daemon.Run(ctx2, daemon.Options{
			DataDir:      dataDir,
			BackupDir:    backupDir,
			ListenAddr:   "127.0.0.1:0",
			ChunkSize:    1 << 20,
			ScanInterval: 50 * time.Millisecond,
			Restore:      true,
			Progress:     io.Discard,
		})
	}()
	// Poll for the file reappearing (bounded).
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filePath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel2()

	select {
	case err := <-done2:
		if err != nil {
			t.Errorf("Run restore err = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run restore did not exit within 5s of cancel")
	}

	// File must be back, with original bytes and mtime.
	restored, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("read restored: %v", err)
	}
	if !bytes.Equal(restored, originalBytes) {
		t.Error("restored bytes differ from original")
	}
	restoredInfo, err := os.Stat(filePath)
	if err != nil {
		t.Fatalf("stat restored: %v", err)
	}
	if !restoredInfo.ModTime().Equal(originalInfo.ModTime()) {
		t.Errorf("restored mtime = %v, want original %v", restoredInfo.ModTime(), originalInfo.ModTime())
	}
}

// TestRun_PurgeMode clears the index and sends deletes for every entry.
func TestRun_PurgeMode(t *testing.T) {
	peer := newPeerRig(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()

	// First: run a short backup with a file so the peer actually has a
	// blob, and the index is populated. Then remove the file and restart
	// with --purge.
	filePath := filepath.Join(backupDir, "doomed.bin")
	writeFile(t, filePath, 1<<20)
	seedPeer(t, dataDir, peer.addr, peer.pub)

	ctx1, cancel1 := context.WithCancel(context.Background())
	done1 := make(chan error, 1)
	go func() {
		done1 <- daemon.Run(ctx1, daemon.Options{
			DataDir:      dataDir,
			BackupDir:    backupDir,
			ListenAddr:   "127.0.0.1:0",
			ChunkSize:    1 << 20,
			ScanInterval: 50 * time.Millisecond,
			Progress:     io.Discard,
		})
	}()
	// Wait for the backup to happen.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(peer.storeRoot)
		if err == nil && hasShardDir(entries) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel1()
	<-done1

	// Now empty the backup dir and run with --purge. Index is populated
	// and backup dir is empty => ModePurge.
	if err := os.Remove(filePath); err != nil {
		t.Fatalf("rm: %v", err)
	}

	ctx2, cancel2 := context.WithCancel(context.Background())
	done2 := make(chan error, 1)
	go func() {
		done2 <- daemon.Run(ctx2, daemon.Options{
			DataDir:      dataDir,
			BackupDir:    backupDir,
			ListenAddr:   "127.0.0.1:0",
			ChunkSize:    1 << 20,
			ScanInterval: 50 * time.Millisecond,
			Purge:        true,
			Progress:     io.Discard,
		})
	}()
	// Wait for the purge + idle transition.
	time.Sleep(500 * time.Millisecond)
	cancel2()

	select {
	case err := <-done2:
		if err != nil {
			t.Errorf("Run purge err = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run purge did not exit within 5s of cancel")
	}

	// After purge, all shard dirs should be empty (the blobs were removed).
	entries, err := os.ReadDir(peer.storeRoot)
	if err != nil {
		t.Fatalf("read peer store root: %v", err)
	}
	for _, e := range entries {
		if !e.IsDir() || len(e.Name()) != 2 {
			continue
		}
		contents, err := os.ReadDir(filepath.Join(peer.storeRoot, e.Name()))
		if err != nil {
			t.Fatalf("read shard: %v", err)
		}
		if len(contents) != 0 {
			t.Errorf("shard %s still has %d entries after purge", e.Name(), len(contents))
		}
	}
}

func hasShardDir(entries []os.DirEntry) bool {
	for _, e := range entries {
		if e.IsDir() && len(e.Name()) == 2 {
			return true
		}
	}
	return false
}

// TestRun_DialFailure covers the dial-error branch when the peer from
// peers.db points at nothing listening.
func TestRun_DialFailure(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	writeFile(t, filepath.Join(backupDir, "a.bin"), 1<<20)

	anyPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	seedPeer(t, dataDir, "127.0.0.1:1", anyPub) // nothing listens here

	err = daemon.Run(context.Background(), daemon.Options{
		DataDir:     dataDir,
		BackupDir:   backupDir,
		ListenAddr:  "127.0.0.1:0",
		ChunkSize:   1 << 20,
		DialTimeout: 200 * time.Millisecond,
		Progress:    io.Discard,
	})
	if err == nil {
		t.Fatal("Run accepted unreachable peer")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("dial peer")) {
		t.Errorf("err = %q, want 'dial peer' prefix", err)
	}
}

// TestRun_MultiplePeers rejects startup when peers.db has more than
// one dialable entry. M1.9 assumes a single storage peer; M2.14 adds
// weighted-random placement across multiple peers.
func TestRun_MultiplePeers(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()

	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)
	seedPeer(t, dataDir, "127.0.0.1:1001", pub1)
	seedPeer(t, dataDir, "127.0.0.1:1002", pub2)

	err := daemon.Run(context.Background(), daemon.Options{
		DataDir:    dataDir,
		BackupDir:  backupDir,
		ListenAddr: "127.0.0.1:0",
		ChunkSize:  1 << 20,
		Progress:   io.Discard,
	})
	if err == nil {
		t.Fatal("Run accepted multiple dialable peers")
	}
	if !errors.Is(err, daemon.ErrMultiplePeers) {
		t.Errorf("err = %v, want wraps ErrMultiplePeers", err)
	}
}

// TestRun_StorageOnly_NoBackupDir asserts that omitting BackupDir
// starts the daemon in pure storage-peer mode and that a real owner
// can still ship a chunk through it. Proves the --backup-dir-optional
// path isn't just a clean exit but a fully functional storage role.
func TestRun_StorageOnly_NoBackupDir(t *testing.T) {
	dataDir := t.TempDir()

	// Start daemon with no BackupDir on a concrete port we can dial.
	listener, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("probe udp port: %v", err)
	}
	listenAddr := listener.LocalAddr().String()
	_ = listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			DataDir:    dataDir,
			ListenAddr: listenAddr,
			ChunkSize:  1 << 20,
			Progress:   io.Discard,
		})
	}()
	// Give the daemon a moment to bind.
	time.Sleep(200 * time.Millisecond)

	// The daemon's pubkey is at <dataDir>/node.pub after node.Ensure.
	pubBytes, err := os.ReadFile(filepath.Join(dataDir, "node.pub"))
	if err != nil {
		t.Fatalf("read node.pub: %v", err)
	}
	daemonPub := ed25519.PublicKey(pubBytes)

	// Dial the daemon and send one PutChunk stream manually.
	_, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, listenAddr, ownerPriv, daemonPub)
	if err != nil {
		cancel()
		t.Fatalf("dial daemon: %v", err)
	}
	defer conn.Close()

	// The simplest way to confirm the storage path works is to run the
	// backup.Run pipeline into the daemon's listener. Build an index +
	// recipient key for the owner side, back up a small file.
	ownerIdx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("owner index: %v", err)
	}
	defer ownerIdx.Close()
	recipientPub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("recipient keys: %v", err)
	}

	srcDir := t.TempDir()
	writeFile(t, filepath.Join(srcDir, "file.bin"), 1<<20)
	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         srcDir,
		Conn:         conn,
		RecipientPub: recipientPub,
		Index:        ownerIdx,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		cancel()
		t.Fatalf("backup.Run against storage-only daemon: %v", err)
	}

	// Confirm the daemon persisted the blob under its store root.
	entries, err := os.ReadDir(filepath.Join(dataDir, "chunks"))
	if err != nil {
		t.Fatalf("read daemon chunks dir: %v", err)
	}
	if !hasShardDir(entries) {
		t.Error("storage-only daemon did not persist the inbound chunk")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("storage-only daemon returned err = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("storage-only daemon did not exit within 5s of cancel")
	}
}

// TestRun_IgnoresPeersWithEmptyAddr asserts that peers with empty Addr
// (recorded by `join` when the joiner had no --listen) don't count
// toward the dialable-peer tally. With only an addr-less entry the
// daemon should enter storage-only idle mode rather than error.
func TestRun_IgnoresPeersWithEmptyAddr(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()

	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	seedPeer(t, dataDir, "", pub)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			DataDir:    dataDir,
			BackupDir:  backupDir,
			ListenAddr: "127.0.0.1:0",
			ChunkSize:  1 << 20,
			Progress:   io.Discard,
		})
	}()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run err = %v, want nil after cancel (addr-less peer should be ignored)", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return within 5s of cancel")
	}
}

// TestRun_StorageOnly_BadListenAddr covers the bsquic.Listen error
// wrap in Run on the BackupDir == "" path. A syntactically invalid UDP
// address makes quic-go's ListenAddr fail before any bind attempt. The
// error must surface as 'listen "..."': the daemon should not silently
// fall through to an idle state.
func TestRun_StorageOnly_BadListenAddr(t *testing.T) {
	dataDir := t.TempDir()
	err := daemon.Run(context.Background(), daemon.Options{
		DataDir:    dataDir,
		ListenAddr: "not-a-valid-addr",
		ChunkSize:  1 << 20,
		Progress:   io.Discard,
	})
	if err == nil {
		t.Fatal("Run accepted malformed ListenAddr")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("listen")) {
		t.Errorf("err = %q, want 'listen' in message", err)
	}
}

// TestRun_WithBackupDir_BadListenAddr covers the bsquic.Listen error
// wrap in Run on the BackupDir != "" path. Identical shape to the
// storage-only variant but goes through the Classify path first.
func TestRun_WithBackupDir_BadListenAddr(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	// Non-empty backup dir + empty index -> ModeFirstBackup, which
	// requires the listener to come up. A bad ListenAddr must fail
	// here before any dial attempt.
	writeFile(t, filepath.Join(backupDir, "file.bin"), 1<<20)

	err := daemon.Run(context.Background(), daemon.Options{
		DataDir:    dataDir,
		BackupDir:  backupDir,
		ListenAddr: "not-a-valid-addr",
		ChunkSize:  1 << 20,
		Progress:   io.Discard,
	})
	if err == nil {
		t.Fatal("Run accepted malformed ListenAddr")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("listen")) {
		t.Errorf("err = %q, want 'listen' in message", err)
	}
}

// TestBackupDirHasRegularFiles_UnreadableSubdir covers the walk-error
// branch: a subdirectory set to mode 0 causes WalkDir to surface an
// error on descent, which BackupDirHasRegularFiles must propagate.
func TestBackupDirHasRegularFiles_UnreadableSubdir(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	sub := filepath.Join(dir, "locked")
	if err := os.Mkdir(sub, 0o000); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	_, err := daemon.BackupDirHasRegularFiles(dir)
	if err == nil {
		t.Error("BackupDirHasRegularFiles accepted unreadable subdir")
	}
}

// TestBackupDirHasRegularFiles_PathIsFile covers the not-a-directory
// branch.
func TestBackupDirHasRegularFiles_PathIsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.bin")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := daemon.BackupDirHasRegularFiles(path); err == nil {
		t.Error("BackupDirHasRegularFiles accepted regular-file path as dir")
	}
}

// Compile-time assertion that fs.DirEntry is used somewhere, documenting
// where the symlink-vs-regular distinction is being enforced.
var _ fs.DirEntry = (fs.DirEntry)(nil)
