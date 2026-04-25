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

// seedPeer opens peers.db at <dataDir>/peers.db and writes a single storage peer.
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

// scanRig spins up a real peer plus an owner-side QUIC connection, index, and recipient pubkey.
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

// TestScanOnce_BackupAndPrune asserts one pass ships changed files and emits deletes for missing ones.
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

// TestScanOnce_NilProgress asserts nil Progress falls back to io.Discard without panicking.
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

// TestScanOnce_BackupFailurePropagates asserts a backup.Run error wraps as "backup run".
func TestScanOnce_BackupFailurePropagates(t *testing.T) {
	rig := newScanRig(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "a.bin"), 1<<20)
	opts := daemon.ScanOnceOptions{
		BackupDir:    root,
		Conn:         rig.ownerConn,
		Index:        rig.ownerIndex,
		RecipientPub: rig.recipientPub,
		ChunkSize:    1,
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

// TestScanOnce_PruneFailurePropagates asserts a Prune error wraps as "prune".
func TestScanOnce_PruneFailurePropagates(t *testing.T) {
	rig := newScanRig(t)
	root := t.TempDir()
	if err := rig.ownerIndex.Put(index.FileEntry{
		Path:   filepath.Join(root, "ghost.bin"),
		Size:   1,
		Chunks: []index.ChunkRef{{CiphertextHash: [32]byte{0xaa}, Size: 10}},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}
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

// TestRun_RefusesWhenBackupDirEmptyButIndexPopulated asserts Run wraps ErrRefuseStart for an empty backup dir with a populated index.
func TestRun_RefusesWhenBackupDirEmptyButIndexPopulated(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()

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

// TestRun_IdleStorageOnlyExitsOnContextCancel asserts a no-peer daemon blocks until context cancellation and returns nil.
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

// peerRig spins up a pure storage peer at a random local address.
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

// TestRun_WithPeer_FirstBackupShipsChunks asserts the daemon ships a chunk to the peer in one happy-path scan and exits cleanly on cancel.
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

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(peer.storeRoot)
		if err == nil && len(entries) > 0 {
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

// TestRun_RestoreMode asserts a restart with --restore rewrites every indexed file with matching content and mtime.
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

	if err := os.Remove(filePath); err != nil {
		t.Fatalf("rm original: %v", err)
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
			Restore:      true,
			Progress:     io.Discard,
		})
	}()
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

// TestRun_PurgeMode asserts --purge sends deletes for every index entry and clears the peer's blobs.
func TestRun_PurgeMode(t *testing.T) {
	peer := newPeerRig(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()

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

// TestRun_DialFailure asserts Run wraps a dial failure as "dial peer" when peers.db points at nothing listening.
func TestRun_DialFailure(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	writeFile(t, filepath.Join(backupDir, "a.bin"), 1<<20)

	anyPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	seedPeer(t, dataDir, "127.0.0.1:1", anyPub)

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

// TestRun_MultiplePeers asserts Run wraps ErrMultiplePeers when peers.db has more than one dialable entry.
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

// TestRun_StorageOnly_NoBackupDir asserts a daemon started with no BackupDir accepts an inbound chunk from a real owner.
func TestRun_StorageOnly_NoBackupDir(t *testing.T) {
	dataDir := t.TempDir()

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
	time.Sleep(200 * time.Millisecond)

	pubBytes, err := os.ReadFile(filepath.Join(dataDir, "node.pub"))
	if err != nil {
		t.Fatalf("read node.pub: %v", err)
	}
	daemonPub := ed25519.PublicKey(pubBytes)

	_, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, listenAddr, ownerPriv, daemonPub)
	if err != nil {
		cancel()
		t.Fatalf("dial daemon: %v", err)
	}
	defer conn.Close()

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

// TestRun_IgnoresPeersWithEmptyAddr asserts peers with empty Addr do not count toward the dialable-peer tally.
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

// TestRun_StorageOnly_BadListenAddr asserts an invalid ListenAddr surfaces as a "listen" error on the BackupDir == "" path.
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

// TestRun_WithBackupDir_BadListenAddr asserts an invalid ListenAddr surfaces as a "listen" error on the BackupDir != "" path.
func TestRun_WithBackupDir_BadListenAddr(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()
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

// TestBackupDirHasRegularFiles_UnreadableSubdir asserts a WalkDir error from an unreadable subdir is propagated.
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

// TestBackupDirHasRegularFiles_PathIsFile asserts BackupDirHasRegularFiles errors when the path is a regular file.
func TestBackupDirHasRegularFiles_PathIsFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file.bin")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := daemon.BackupDirHasRegularFiles(path); err == nil {
		t.Error("BackupDirHasRegularFiles accepted regular-file path as dir")
	}
}

var _ fs.DirEntry = (fs.DirEntry)(nil)
