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
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/daemon"
	"backupswarm/internal/index"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
	"backupswarm/internal/swarm"
)

// seedPeer opens peers.db at <dataDir>/peers.db and writes a single
// RoleIntroducer peer.
func seedPeer(t *testing.T, dataDir, addr string, pub []byte) {
	t.Helper()
	ps, err := peers.Open(filepath.Join(dataDir, "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	defer ps.Close()
	if err := ps.Add(peers.Peer{Addr: addr, PubKey: pub, Role: peers.RoleIntroducer}); err != nil {
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

	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() { _ = backup.Serve(ctx, listener, peerStore, nil, nil, nil, nil, nil) }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	ownerConn, err := bsquic.Dial(dialCtx, listener.Addr().String(), ownerPriv, peerPub, nil)
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
		Conns:        []*bsquic.Conn{rig.ownerConn},
		Index:        rig.ownerIndex,
		RecipientPub: rig.recipientPub,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := daemon.ScanOnce(context.Background(), opts); err != nil {
		t.Fatalf("ScanOnce #1: %v", err)
	}
	entry, err := rig.ownerIndex.Get(filepath.Base(goner))
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
	if _, err := rig.ownerIndex.Get(filepath.Base(goner)); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("goner still in index after prune: %v", err)
	}
	if _, err := rig.ownerIndex.Get(filepath.Base(keep)); err != nil {
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
		Conns:        []*bsquic.Conn{rig.ownerConn},
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
		Conns:        []*bsquic.Conn{rig.ownerConn},
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

// TestScanOnce_PruneFailurePropagates asserts a Prune error wraps as
// "prune". An empty backup dir drives Run to a no-op so the closed
// index trips Prune.Index.List, not the Run side.
func TestScanOnce_PruneFailurePropagates(t *testing.T) {
	rig := newScanRig(t)
	root := t.TempDir() // empty: Run walks no files, no chunks placed
	if err := rig.ownerIndex.Close(); err != nil {
		t.Fatalf("Close index: %v", err)
	}

	opts := daemon.ScanOnceOptions{
		BackupDir:    root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		Index:        rig.ownerIndex,
		RecipientPub: rig.recipientPub,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	err := daemon.ScanOnce(context.Background(), opts)
	if err == nil {
		t.Fatal("ScanOnce accepted closed-index prune")
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

// TestRun_RejectsNegativeGracePeriod asserts daemon.Run errors before
// touching any state when GracePeriod is negative.
func TestRun_RejectsNegativeGracePeriod(t *testing.T) {
	err := daemon.Run(context.Background(), daemon.Options{
		DataDir:     t.TempDir(),
		BackupDir:   t.TempDir(),
		ListenAddr:  "127.0.0.1:0",
		ChunkSize:   1 << 20,
		GracePeriod: -1 * time.Second,
		Progress:    io.Discard,
	})
	if err == nil {
		t.Fatal("Run accepted negative GracePeriod")
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
	// accepts counts inbound conns observed via backup.ConnObserver.
	accepts atomic.Int32
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
	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	rig := &peerRig{
		addr:      listener.Addr().String(),
		pub:       peerPub,
		store:     peerStore,
		storeRoot: storeRoot,
		listener:  listener,
	}

	serveCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	obs := &backup.ConnObserver{
		OnAccept: func(*bsquic.Conn) { rig.accepts.Add(1) },
	}
	go func() { done <- backup.Serve(serveCtx, listener, peerStore, nil, nil, nil, nil, obs) }()
	rig.serveDone = done
	return rig
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

// TestRun_ModeTransitionsToReconcileAfterRestore asserts runtime.json
// reports Mode == "reconcile" once the daemon falls through from a
// completed ModeRestore into the scan loop.
func TestRun_ModeTransitionsToReconcileAfterRestore(t *testing.T) {
	peer := newPeerRig(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	filePath := filepath.Join(backupDir, "restored.bin")
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
		if hasShardDir(mustReadDir(t, peer.storeRoot)) {
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
	defer func() {
		cancel2()
		<-done2
	}()

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filePath); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(filePath); err != nil {
		t.Fatalf("file never restored: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	var snap daemon.RuntimeSnapshot
	for time.Now().Before(deadline) {
		var err error
		snap, err = daemon.ReadRuntimeSnapshot(dataDir)
		if err == nil && snap.Mode == "reconcile" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("snapshot.Mode after restore = %q, want %q", snap.Mode, "reconcile")
}

// TestRun_ModeTransitionsToIdleAfterPurge asserts runtime.json reports
// Mode == "idle" once the daemon falls through from a completed
// ModePurge into the scan loop.
func TestRun_ModeTransitionsToIdleAfterPurge(t *testing.T) {
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
		if hasShardDir(mustReadDir(t, peer.storeRoot)) {
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
	defer func() {
		cancel2()
		<-done2
	}()

	deadline = time.Now().Add(3 * time.Second)
	var snap daemon.RuntimeSnapshot
	for time.Now().Before(deadline) {
		var err error
		snap, err = daemon.ReadRuntimeSnapshot(dataDir)
		if err == nil && snap.Mode == "idle" {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("snapshot.Mode after purge = %q, want %q", snap.Mode, "idle")
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

// TestRun_DialsAllKnownPeers asserts that with two dialable peers in
// peers.db, the daemon dials both on startup and ships chunks to one
// of them on the first scan.
func TestRun_DialsAllKnownPeers(t *testing.T) {
	peer1 := newPeerRig(t)
	peer2 := newPeerRig(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	writeFile(t, filepath.Join(backupDir, "file.bin"), 1<<20)
	seedPeer(t, dataDir, peer1.addr, peer1.pub)
	seedPeer(t, dataDir, peer2.addr, peer2.pub)

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

	bothAccepted := func() bool { return peer1.accepts.Load() >= 1 && peer2.accepts.Load() >= 1 }
	someShipped := func() bool {
		return hasShardDir(mustReadDir(t, peer1.storeRoot)) || hasShardDir(mustReadDir(t, peer2.storeRoot))
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if bothAccepted() && someShipped() {
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

	if got := peer1.accepts.Load(); got < 1 {
		t.Errorf("peer1 accepts = %d, want >= 1 (daemon must dial all known peers)", got)
	}
	if got := peer2.accepts.Load(); got < 1 {
		t.Errorf("peer2 accepts = %d, want >= 1 (daemon must dial all known peers)", got)
	}
	// Chunks land in exactly one rig — the chosen backup target.
	if !someShipped() {
		t.Error("neither peer received chunks; backup target was not selected")
	}
}

// TestRun_BestEffortDial_OnePeerOffline asserts that with one alive
// and one unreachable peer in peers.db, the daemon continues with the
// alive peer and ships chunks.
func TestRun_BestEffortDial_OnePeerOffline(t *testing.T) {
	alive := newPeerRig(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	writeFile(t, filepath.Join(backupDir, "file.bin"), 1<<20)
	seedPeer(t, dataDir, alive.addr, alive.pub)

	deadPub, _, _ := ed25519.GenerateKey(rand.Reader)
	seedPeer(t, dataDir, "127.0.0.1:1", deadPub)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			DataDir:      dataDir,
			BackupDir:    backupDir,
			ListenAddr:   "127.0.0.1:0",
			ChunkSize:    1 << 20,
			DialTimeout:  500 * time.Millisecond,
			ScanInterval: 50 * time.Millisecond,
			Progress:     io.Discard,
		})
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hasShardDir(mustReadDir(t, alive.storeRoot)) {
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

	if !hasShardDir(mustReadDir(t, alive.storeRoot)) {
		t.Error("alive peer did not receive chunks — best-effort dial dropped the alive peer")
	}
}

func mustReadDir(t *testing.T, dir string) []os.DirEntry {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	return entries
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

	// Seed the owner's pubkey in peers.db before the daemon opens it; the
	// listener gates membership at TLS handshake.
	ownerPub, ownerPriv, _ := ed25519.GenerateKey(rand.Reader)
	seedPeer(t, dataDir, "", ownerPub)

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

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, listenAddr, ownerPriv, daemonPub, nil)
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
		Conns:        []*bsquic.Conn{conn},
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

// TestRun_RejectsUnknownPeerAtHandshake asserts the daemon's listener rejects a dialer whose pubkey is not in peers.db.
func TestRun_RejectsUnknownPeerAtHandshake(t *testing.T) {
	dataDir := t.TempDir()

	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("probe udp port: %v", err)
	}
	listenAddr := probe.LocalAddr().String()
	_ = probe.Close()

	knownPub, _, _ := ed25519.GenerateKey(rand.Reader)
	seedPeer(t, dataDir, "127.0.0.1:1", knownPub)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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

	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, listenAddr, strangerPriv, daemonPub, nil)
	if err == nil {
		defer func() { _ = conn.Close() }()
		s, sErr := conn.OpenStream(dialCtx)
		if sErr == nil {
			_, _ = s.Write([]byte("ping"))
			_ = s.Close()
			if _, rErr := io.Copy(io.Discard, s); rErr == nil {
				t.Fatal("daemon accepted a stream from a stranger; F-01 not enforced")
			}
		}
	}

	chunksDir := filepath.Join(dataDir, "chunks")
	entries, _ := os.ReadDir(chunksDir)
	if hasShardDir(entries) {
		t.Errorf("daemon persisted bytes from a rejected peer; F-01 not enforced")
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

// TestRun_NoStorageCandidate_FallsThroughToStorageOnly asserts a daemon
// with a dialable RolePeer (no storage candidates) falls through to the
// storage-only wait and returns nil on context cancel.
func TestRun_NoStorageCandidate_FallsThroughToStorageOnly(t *testing.T) {
	peer := newPeerRig(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	writeFile(t, filepath.Join(backupDir, "file.bin"), 1<<20)

	ps, err := peers.Open(filepath.Join(dataDir, "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: peer.addr, PubKey: peer.pub, Role: peers.RolePeer}); err != nil {
		ps.Close()
		t.Fatalf("peers.Add: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("peers.Close: %v", err)
	}

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
		if peer.accepts.Load() >= 1 {
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
}

// TestRun_ReachabilityMarkedOnDialFailure asserts a dial failure flips
// the peer's entry in the supplied ReachabilityMap to StateUnreachable.
func TestRun_ReachabilityMarkedOnDialFailure(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	writeFile(t, filepath.Join(backupDir, "a.bin"), 1<<20)

	deadPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	seedPeer(t, dataDir, "127.0.0.1:1", deadPub)

	reach := swarm.NewReachabilityMap()
	if err := daemon.Run(context.Background(), daemon.Options{
		DataDir:      dataDir,
		BackupDir:    backupDir,
		ListenAddr:   "127.0.0.1:0",
		ChunkSize:    1 << 20,
		DialTimeout:  200 * time.Millisecond,
		Progress:     io.Discard,
		Reachability: reach,
	}); err == nil {
		t.Fatal("Run accepted unreachable peer")
	}
	if got := reach.State(deadPub); got != swarm.StateUnreachable {
		t.Errorf("dead peer State = %v, want StateUnreachable", got)
	}
	if reach.IsReachable(deadPub) {
		t.Error("dead peer reported reachable")
	}
}

// TestRun_ReachabilityMarkedOnDialSuccess asserts a successful dial
// flips the peer's entry to StateReachable while the daemon is running,
// and to StateUnreachable after the deferred close fires on shutdown.
func TestRun_ReachabilityMarkedOnDialSuccess(t *testing.T) {
	peer := newPeerRig(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	writeFile(t, filepath.Join(backupDir, "file.bin"), 1<<20)
	seedPeer(t, dataDir, peer.addr, peer.pub)

	reach := swarm.NewReachabilityMap()
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
			Reachability: reach,
		})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if reach.IsReachable(peer.pub) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reach.IsReachable(peer.pub) {
		cancel()
		<-done
		t.Fatal("alive peer never marked reachable")
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

	if got := reach.State(peer.pub); got != swarm.StateUnreachable {
		t.Errorf("alive peer State after shutdown = %v, want StateUnreachable", got)
	}
}

// TestRun_ReachabilityMarkedOnInboundAccept asserts the ConnObserver
// inbound hooks flip a remote dialer to StateReachable on accept and
// StateUnreachable when the conn closes.
func TestRun_ReachabilityMarkedOnInboundAccept(t *testing.T) {
	dataDir := t.TempDir()

	probe, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("probe udp port: %v", err)
	}
	listenAddr := probe.LocalAddr().String()
	_ = probe.Close()

	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	seedPeer(t, dataDir, "", ownerPub)

	reach := swarm.NewReachabilityMap()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			DataDir:      dataDir,
			ListenAddr:   listenAddr,
			ChunkSize:    1 << 20,
			Progress:     io.Discard,
			Reachability: reach,
		})
	}()
	time.Sleep(200 * time.Millisecond)

	pubBytes, err := os.ReadFile(filepath.Join(dataDir, "node.pub"))
	if err != nil {
		cancel()
		<-done
		t.Fatalf("read node.pub: %v", err)
	}
	daemonPub := ed25519.PublicKey(pubBytes)

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, listenAddr, ownerPriv, daemonPub, nil)
	if err != nil {
		cancel()
		<-done
		t.Fatalf("dial daemon: %v", err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if reach.IsReachable(ownerPub) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !reach.IsReachable(ownerPub) {
		_ = conn.Close()
		cancel()
		<-done
		t.Fatal("inbound dialer never marked reachable via OnAccept")
	}

	_ = conn.Close()
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if reach.State(ownerPub) == swarm.StateUnreachable {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := reach.State(ownerPub); got != swarm.StateUnreachable {
		cancel()
		<-done
		t.Errorf("inbound dialer State after close = %v, want StateUnreachable", got)
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
}

// TestRun_PostStartupPeer_DialedBySweep asserts a storage peer added
// to peers.db after the daemon's initial scan is dialed and registered
// by the next scan tick's redial sweep.
func TestRun_PostStartupPeer_DialedBySweep(t *testing.T) {
	peer1 := newPeerRig(t)
	peer2 := newPeerRig(t)
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	writeFile(t, filepath.Join(backupDir, "file.bin"), 1<<20)

	// Open peerStore here and hand off via Options.PeerStore so the
	// test keeps the handle for the post-startup Add.
	peerStore, err := peers.Open(filepath.Join(dataDir, "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := peerStore.Add(peers.Peer{Addr: peer1.addr, PubKey: peer1.pub, Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("seed peer1: %v", err)
	}

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
			PeerStore:    peerStore,
		})
	}()

	// Wait for the initial scan to ship to peer1.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if hasShardDir(mustReadDir(t, peer1.storeRoot)) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !hasShardDir(mustReadDir(t, peer1.storeRoot)) {
		cancel()
		<-done
		t.Fatal("peer1 never received initial chunks; daemon never reached the scan loop")
	}
	if peer2.accepts.Load() != 0 {
		cancel()
		<-done
		t.Fatalf("peer2 already accepted %d conns before peers.db update", peer2.accepts.Load())
	}

	// Adding peer2 to peers.db while the daemon is running models an
	// applied PeerJoined announcement; the next scan sweep dials it.
	if err := peerStore.Add(peers.Peer{Addr: peer2.addr, PubKey: peer2.pub, Role: peers.RoleStorage}); err != nil {
		cancel()
		<-done
		t.Fatalf("post-startup Add peer2: %v", err)
	}

	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if peer2.accepts.Load() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if peer2.accepts.Load() < 1 {
		cancel()
		<-done
		t.Fatalf("peer2 accepts = %d, want >= 1 (redial sweep should have dialed peer2 after peers.db Add)", peer2.accepts.Load())
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

var _ fs.DirEntry = (fs.DirEntry)(nil)
