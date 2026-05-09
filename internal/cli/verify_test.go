package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.etcd.io/bbolt"

	"backupswarm/internal/daemon"
	"backupswarm/internal/index"
	"backupswarm/internal/peers"
	"backupswarm/internal/verify"
)

func TestVerifyCmd_RegisteredOnRoot(t *testing.T) {
	root := NewRootCmd()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "verify" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("root command missing `verify` subcommand")
	}
}

// TestVerifyCmd_EmptyDataDir_ErrorsWithoutProvisioning asserts verify
// errors on a missing identity and creates no files in the data dir.
func TestVerifyCmd_EmptyDataDir_ErrorsWithoutProvisioning(t *testing.T) {
	dataDir := t.TempDir()
	err := runVerifyCommandErr(t, dataDir)
	if err == nil {
		t.Fatal("verify returned nil against an empty data dir")
	}
	for _, fname := range []string{"node.key", "node.pub", "node.xkey", "index.db", peers.DefaultFilename} {
		if _, statErr := os.Stat(filepath.Join(dataDir, fname)); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("verify provisioned %s (Stat err = %v)", fname, statErr)
		}
	}
}

func TestVerifyCmd_SnapshotPath_FullyReplicated_HumanReadable(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)

	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Put(index.FileEntry{
		Path: "ok.txt", Size: 100, ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Size: 100, Peers: [][]byte{pubA, pubB}}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{
		Mode:       "reconcile",
		ListenAddr: "127.0.0.1:7777",
		Peers: []daemon.RuntimePeerSnapshot{
			{PubKeyHex: hex.EncodeToString(pubA), Reach: "reachable"},
			{PubKeyHex: hex.EncodeToString(pubB), Reach: "reachable"},
		},
	}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}

	out := runVerifyCommand(t, dataDir, "--redundancy", "2")
	for _, want := range []string{"redundancy", "2", "total_files", "total_chunks", "at_target", "1"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output missing %q\n--- output ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "UNDER-REPLICATED FILES") {
		t.Errorf("expected no under-replicated section when fully replicated, got:\n%s", out)
	}
}

func TestVerifyCmd_SnapshotPath_UnderReplicated_ListsFile(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)

	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Put(index.FileEntry{
		Path: "broken.txt", Size: 100, ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Size: 100, Peers: [][]byte{pubA, pubB}}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{
		Peers: []daemon.RuntimePeerSnapshot{
			{PubKeyHex: hex.EncodeToString(pubA), Reach: "reachable"},
			{PubKeyHex: hex.EncodeToString(pubB), Reach: "unreachable"},
		},
	}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}

	out := runVerifyCommand(t, dataDir, "--redundancy", "2")
	for _, want := range []string{"under_replicated", "broken.txt", "MISSING PEERS", hex.EncodeToString(pubB)[:16]} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

func TestVerifyCmd_JSONOutput(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)

	pubA := bytesOf(0xa1, 32)
	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Put(index.FileEntry{
		Path: "f.txt", Size: 100, ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Size: 100, Peers: [][]byte{pubA}}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{
		Peers: []daemon.RuntimePeerSnapshot{
			{PubKeyHex: hex.EncodeToString(pubA), Reach: "reachable"},
		},
	}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}

	out := runVerifyCommand(t, dataDir, "--json")
	var report verify.Report
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("decode --json output: %v\n--- output ---\n%s", err, out)
	}
	if report.TotalFiles != 1 || report.TotalChunks != 1 || report.AtTarget != 1 {
		t.Errorf("decoded report = %+v, want files=1 chunks=1 at_target=1", report)
	}
	if report.Redundancy != 1 {
		t.Errorf("default Redundancy=%d, want 1", report.Redundancy)
	}
}

func TestVerifyCmd_NoSnapshot_FallsBackToPeersDB(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)

	// Seed peers.db with one peer (acts as the holder for the chunk).
	ps, err := peers.Open(filepath.Join(dataDir, peers.DefaultFilename))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	holderPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "10.0.0.1:7777", PubKey: holderPub, Role: peers.RoleStorage}); err != nil {
		t.Fatalf("ps.Add: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("ps.Close: %v", err)
	}

	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Put(index.FileEntry{
		Path: "f.txt", Size: 100, ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Size: 100, Peers: [][]byte{holderPub}}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out := runVerifyCommand(t, dataDir)
	if !strings.Contains(out, "daemon not running") {
		t.Errorf("expected 'daemon not running' notice, got:\n%s", out)
	}
	if !strings.Contains(out, "f.txt") {
		t.Errorf("expected under-replicated 'f.txt' in fallback output:\n%s", out)
	}
}

func TestVerifyCmd_NoSnapshot_NoIndex_StillRuns(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	out := runVerifyCommand(t, dataDir)
	for _, want := range []string{"total_files", "total_chunks", "0"} {
		if !strings.Contains(out, want) {
			t.Errorf("verify output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

func TestVerifyCmd_RedundancyMustBePositive(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	err := runVerifyCommandErr(t, dataDir, "--redundancy", "0")
	if err == nil {
		t.Fatal("verify returned nil for --redundancy 0")
	}
	if !strings.Contains(err.Error(), "redundancy") {
		t.Errorf("err = %q, want 'redundancy' in message", err)
	}
}

// TestVerifyCmd_SnapshotPath_DoesNotOpenPeersDB asserts that when the
// runtime snapshot is present, verify resolves reachability from the
// snapshot only and never touches peers.db. (index.db is opened
// read-only in every case — chunk Peers lists are not in the snapshot.)
func TestVerifyCmd_SnapshotPath_DoesNotOpenPeersDB(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)

	pubA := bytesOf(0xa1, 32)
	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Put(index.FileEntry{
		Path: "f.txt", Size: 100, ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Size: 100, Peers: [][]byte{pubA}}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{
		Peers: []daemon.RuntimePeerSnapshot{
			{PubKeyHex: hex.EncodeToString(pubA), Reach: "reachable"},
		},
	}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}

	_ = runVerifyCommand(t, dataDir)

	if _, statErr := os.Stat(filepath.Join(dataDir, peers.DefaultFilename)); !errors.Is(statErr, os.ErrNotExist) {
		t.Errorf("verify provisioned peers.db unnecessarily (Stat err = %v)", statErr)
	}
}

// TestVerifyCmd_MissingPeersSortedDescByChunksThenAscByHex asserts the
// missing-peers section orders peers by chunks-affected (descending),
// then by hex pubkey (ascending) on tie.
func TestVerifyCmd_MissingPeersSortedDescByChunksThenAscByHex(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)

	pubLow := bytesOf(0x01, 32)  // 1 chunk affected, low hex
	pubHigh := bytesOf(0xff, 32) // 1 chunk affected, high hex (tie-break)
	pubMid := bytesOf(0x80, 32)  // 2 chunks affected (highest impact, should be first)

	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Put(index.FileEntry{
		Path: "f1.txt", Size: 100, ModTime: time.Now(),
		Chunks: []index.ChunkRef{
			{Size: 50, Peers: [][]byte{pubLow, pubMid}},
			{Size: 50, Peers: [][]byte{pubHigh, pubMid}},
		},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}

	out := runVerifyCommand(t, dataDir)
	missing := out[strings.Index(out, "MISSING PEERS"):]
	idxMid := strings.Index(missing, hex.EncodeToString(pubMid)[:shortPubHexLen])
	idxLow := strings.Index(missing, hex.EncodeToString(pubLow)[:shortPubHexLen])
	idxHigh := strings.Index(missing, hex.EncodeToString(pubHigh)[:shortPubHexLen])
	if idxMid < 0 || idxLow < 0 || idxHigh < 0 {
		t.Fatalf("missing one of mid/low/high in output:\n%s", missing)
	}
	if !(idxMid < idxLow && idxLow < idxHigh) {
		t.Errorf("expected order mid (2 chunks) < low (1, hex 01..) < high (1, hex ff..); got positions mid=%d low=%d high=%d\n%s",
			idxMid, idxLow, idxHigh, missing)
	}
}

func TestVerifyCmd_UnderReplicatedListCappedWithMore(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)

	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	for i := 0; i < underReplicatedListCap+5; i++ {
		if err := idx.Put(index.FileEntry{
			Path:    fmtPath(i),
			Size:    100,
			ModTime: time.Now(),
			Chunks:  []index.ChunkRef{{Size: 100, Peers: [][]byte{pubA, pubB}}},
		}); err != nil {
			t.Fatalf("Put: %v", err)
		}
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{
		Peers: []daemon.RuntimePeerSnapshot{
			{PubKeyHex: hex.EncodeToString(pubA), Reach: "reachable"},
			{PubKeyHex: hex.EncodeToString(pubB), Reach: "unreachable"},
		},
	}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}

	out := runVerifyCommand(t, dataDir, "--redundancy", "2")
	if !strings.Contains(out, "+5 more") {
		t.Errorf("expected '+5 more' summary line, got:\n%s", out)
	}
	if !strings.Contains(out, "MISSING PEERS") {
		t.Errorf("expected 'MISSING PEERS' section, got:\n%s", out)
	}
}

// TestVerifyCmd_MissingPeersListCappedWithMore asserts the +N more
// summary appears in the missing-peers section once the cap is exceeded.
func TestVerifyCmd_MissingPeersListCappedWithMore(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)

	idx, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	peerCount := missingPeersListCap + 5
	chunkPeers := make([][]byte, peerCount)
	for i := range chunkPeers {
		chunkPeers[i] = bytesOf(byte(i+1), 32)
	}
	if err := idx.Put(index.FileEntry{
		Path: "wide.txt", Size: 100, ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Size: 100, Peers: chunkPeers}},
	}); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}

	out := runVerifyCommand(t, dataDir)
	missingSection := out[strings.Index(out, "MISSING PEERS"):]
	if !strings.Contains(missingSection, "+5 more") {
		t.Errorf("expected '+5 more' under MISSING PEERS, got:\n%s", missingSection)
	}
}

func TestVerifyCmd_SnapshotReadFailureSurfaces(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	if err := daemon.WriteRuntimeSnapshot(dataDir, daemon.RuntimeSnapshot{}); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}
	path := filepath.Join(dataDir, "runtime.json")
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	err := runVerifyCommandErr(t, dataDir)
	if err == nil {
		t.Fatal("verify returned nil on unreadable runtime.json")
	}
	if !strings.Contains(err.Error(), "read runtime snapshot") {
		t.Errorf("err = %q, want 'read runtime snapshot' wrap", err)
	}
}

func TestVerifyCmd_FallbackOpenIndexFailureSurfaces(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	idxPath := filepath.Join(dataDir, "index.db")
	idx, err := index.Open(idxPath)
	if err != nil {
		t.Fatalf("seed index: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("seed index close: %v", err)
	}
	if err := os.Chmod(idxPath, 0o000); err != nil {
		t.Fatalf("chmod index: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(idxPath, 0o600) })

	err = runVerifyCommandErr(t, dataDir)
	if err == nil {
		t.Fatal("verify returned nil on unreadable index")
	}
	if !strings.Contains(err.Error(), "open index") {
		t.Errorf("err = %q, want 'open index' wrap", err)
	}
}

func TestVerifyCmd_FallbackOpenPeersFailureSurfaces(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	psPath := filepath.Join(dataDir, peers.DefaultFilename)
	ps, err := peers.Open(psPath)
	if err != nil {
		t.Fatalf("seed peers: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("seed peers close: %v", err)
	}
	if err := os.Chmod(psPath, 0o000); err != nil {
		t.Fatalf("chmod peers: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(psPath, 0o600) })

	err = runVerifyCommandErr(t, dataDir)
	if err == nil {
		t.Fatal("verify returned nil on unreadable peers.db")
	}
	if !strings.Contains(err.Error(), "open peers.db") {
		t.Errorf("err = %q, want 'open peers.db' wrap", err)
	}
}

func TestVerifyCmd_FallbackListPeersFailureSurfaces(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	psPath := filepath.Join(dataDir, peers.DefaultFilename)
	ps, err := peers.Open(psPath)
	if err != nil {
		t.Fatalf("seed peers: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("seed peers close: %v", err)
	}
	db, err := bbolt.Open(psPath, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("bbolt.Open: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte("peers")).Put([]byte("garbage"), []byte("not-a-record"))
	}); err != nil {
		t.Fatalf("seed garbage: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("bbolt.Close: %v", err)
	}

	err = runVerifyCommandErr(t, dataDir)
	if err == nil {
		t.Fatal("verify returned nil on corrupt peers.db record")
	}
	if !strings.Contains(err.Error(), "list peers") {
		t.Errorf("err = %q, want 'list peers' wrap", err)
	}
}

func TestVerifyCmd_ListIndexFailureSurfaces(t *testing.T) {
	dataDir := t.TempDir()
	mustSeedIdentity(t, dataDir)
	dbPath := filepath.Join(dataDir, "index.db")
	idx, err := index.Open(dbPath)
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("index.Close: %v", err)
	}
	corruptIndexBucket(t, dbPath, "/bad")

	err = runVerifyCommandErr(t, dataDir)
	if err == nil {
		t.Fatal("verify returned nil on corrupt index")
	}
	if !strings.Contains(err.Error(), "list index") {
		t.Errorf("err = %q, want 'list index' wrap", err)
	}
}

// fmtPath returns a deterministic zero-padded path so the ordered
// finding list is predictable.
func fmtPath(i int) string {
	return fmt.Sprintf("f-%02d", i)
}

func corruptIndexBucket(t *testing.T, dbPath, key string) {
	t.Helper()
	db, err := bbolt.Open(dbPath, 0o600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		t.Fatalf("bbolt.Open: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte("files")).Put([]byte(key), []byte("not-a-gob"))
	}); err != nil {
		t.Fatalf("seed corrupt: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("bbolt.Close: %v", err)
	}
}

func runVerifyCommand(t *testing.T, dataDir string, extra ...string) string {
	t.Helper()
	root := NewRootCmd()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	args := append([]string{"--data-dir", dataDir, "verify"}, extra...)
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	return stdout.String()
}

func runVerifyCommandErr(t *testing.T, dataDir string, extra ...string) error {
	t.Helper()
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	args := append([]string{"--data-dir", dataDir, "verify"}, extra...)
	root.SetArgs(args)
	return root.Execute()
}
