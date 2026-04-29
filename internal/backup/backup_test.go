package backup_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// testRig brings up a peer (listener + chunk store) and an owner QUIC connection.
type testRig struct {
	t             *testing.T
	peerStore     *store.Store
	peerStoreRoot string
	listenerAddr  string
	ownerIndex    *index.Index
	ownerConn     *bsquic.Conn
	serveErr      chan error
	recipientPub  *[32]byte

	peerPubKey  ed25519.PublicKey
	ownerPubKey ed25519.PublicKey
}

func newTestRig(t *testing.T) *testRig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	peerDir := t.TempDir()
	peerStoreRoot := filepath.Join(peerDir, "blobs")
	peerStore, err := store.New(peerStoreRoot)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}

	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}

	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- backup.Serve(ctx, listener, peerStore, nil, nil, nil)
	}()
	t.Cleanup(func() {
		_ = listener.Close()
	})

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

	return &testRig{
		t:             t,
		peerStore:     peerStore,
		peerStoreRoot: peerStoreRoot,
		listenerAddr:  listener.Addr().String(),
		ownerIndex:    ownerIndex,
		ownerConn:     ownerConn,
		serveErr:      serveErr,
		recipientPub:  recipientPub,
		peerPubKey:    peerPub,
		ownerPubKey:   ownerPub,
	}
}

func writeFile(t *testing.T, path string, size int) []byte {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, data); err != nil {
		t.Fatalf("rand: %v", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	return data
}

func TestRun_SingleFileSmall(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "file.bin")
	data := writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry, err := rig.ownerIndex.Get(filepath.Base(path))
	if err != nil {
		t.Fatalf("Index.Get: %v", err)
	}
	if len(entry.Chunks) != 1 {
		t.Fatalf("got %d chunks in index, want 1", len(entry.Chunks))
	}

	has, err := rig.peerStore.Has(entry.Chunks[0].CiphertextHash)
	if err != nil {
		t.Fatalf("peerStore.Has: %v", err)
	}
	if !has {
		t.Error("peer store missing blob at recorded CiphertextHash")
	}

	if entry.Chunks[0].PlaintextHash != sha256.Sum256(data) {
		t.Error("PlaintextHash in index does not match plaintext sha256")
	}
}

func TestRun_EmptyFile(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "empty.bin")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatalf("write empty: %v", err)
	}

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry, err := rig.ownerIndex.Get(filepath.Base(path))
	if err != nil {
		t.Fatalf("Index.Get: %v", err)
	}
	if len(entry.Chunks) != 0 {
		t.Errorf("empty file got %d chunks, want 0", len(entry.Chunks))
	}
}

func TestRun_MultiChunkFile(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "big.bin")
	data := writeFile(t, path, (1<<20)*3+42)

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry, err := rig.ownerIndex.Get(filepath.Base(path))
	if err != nil {
		t.Fatalf("Index.Get: %v", err)
	}
	if len(entry.Chunks) != 4 {
		t.Fatalf("got %d chunks, want 4", len(entry.Chunks))
	}
	for i, ref := range entry.Chunks {
		has, err := rig.peerStore.Has(ref.CiphertextHash)
		if err != nil {
			t.Fatalf("peerStore.Has chunk %d: %v", i, err)
		}
		if !has {
			t.Errorf("chunk %d: peer missing blob", i)
		}
	}
	_ = data
}

func TestRun_DirectoryWalk(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	relPaths := []string{
		"a.txt",
		filepath.Join("sub", "b.txt"),
		filepath.Join("sub", "deep", "c.txt"),
	}
	for _, rel := range relPaths {
		writeFile(t, filepath.Join(root, rel), 1<<20)
	}

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}

	listed, err := rig.ownerIndex.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	gotPaths := make([]string, len(listed))
	for i, e := range listed {
		gotPaths[i] = e.Path
	}
	sort.Strings(gotPaths)
	sort.Strings(relPaths)
	if fmt.Sprint(gotPaths) != fmt.Sprint(relPaths) {
		t.Errorf("indexed paths = %v, want %v", gotPaths, relPaths)
	}
}

// TestPrune_RemovesMissingFileFromSwarmAndIndex asserts Prune deletes peer chunks and the index entry for a vanished file.
func TestPrune_RemovesMissingFileFromSwarmAndIndex(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "goner.bin")
	writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, err := rig.ownerIndex.Get(filepath.Base(path))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(entry.Chunks) == 0 {
		t.Fatal("no chunks recorded")
	}

	if err := os.Remove(path); err != nil {
		t.Fatalf("rm: %v", err)
	}

	pruneOpts := backup.PruneOptions{
		Root:     root,
		Conns:    []*bsquic.Conn{rig.ownerConn},
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	}
	if err := backup.Prune(context.Background(), pruneOpts); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	for i, ref := range entry.Chunks {
		has, err := rig.peerStore.Has(ref.CiphertextHash)
		if err != nil {
			t.Fatalf("peerStore.Has chunk %d: %v", i, err)
		}
		if has {
			t.Errorf("chunk %d: peer still has blob after Prune", i)
		}
	}
	if _, err := rig.ownerIndex.Get(filepath.Base(path)); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("index entry for deleted path err = %v, want ErrFileNotFound", err)
	}
}

// TestPrune_LeavesPresentFilesAlone asserts Prune leaves chunks and entries alone when the file still exists on disk.
func TestPrune_LeavesPresentFilesAlone(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "stable.bin")
	writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, err := rig.ownerIndex.Get(filepath.Base(path))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}

	pruneOpts := backup.PruneOptions{
		Root:     root,
		Conns:    []*bsquic.Conn{rig.ownerConn},
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	}
	if err := backup.Prune(context.Background(), pruneOpts); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	for i, ref := range entry.Chunks {
		has, err := rig.peerStore.Has(ref.CiphertextHash)
		if err != nil {
			t.Fatalf("peerStore.Has chunk %d: %v", i, err)
		}
		if !has {
			t.Errorf("chunk %d: peer lost blob for still-present file", i)
		}
	}
	if _, err := rig.ownerIndex.Get(filepath.Base(path)); err != nil {
		t.Errorf("index entry for still-present path removed: %v", err)
	}
}

// TestPrune_IgnoresTamperedEntries asserts Prune skips index entries
// whose Path is absolute or contains `..` segments (a tampered entry,
// since backup.Run only writes rel-to-Root paths). The entry is left
// in place so the operator can investigate.
func TestPrune_IgnoresTamperedEntries(t *testing.T) {
	rig := newTestRig(t)
	tamperedPaths := []string{
		filepath.Join(t.TempDir(), "absolute.bin"),
		".." + string(filepath.Separator) + "escape.bin",
	}
	for _, p := range tamperedPaths {
		if err := rig.ownerIndex.Put(index.FileEntry{
			Path:    p,
			Size:    1,
			ModTime: time.Now(),
			Chunks:  []index.ChunkRef{{CiphertextHash: [32]byte{0xaa}, Size: 10}},
		}); err != nil {
			t.Fatalf("seed tampered entry %q: %v", p, err)
		}
	}

	pruneOpts := backup.PruneOptions{
		Root:     t.TempDir(),
		Conns:    []*bsquic.Conn{rig.ownerConn},
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	}
	if err := backup.Prune(context.Background(), pruneOpts); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	for _, p := range tamperedPaths {
		if _, err := rig.ownerIndex.Get(p); err != nil {
			t.Errorf("tampered entry %q removed by Prune: %v", p, err)
		}
	}
}

// TestRun_Incremental asserts a second Run on an unchanged file skips re-encryption and a size change forces re-upload.
func TestRun_Incremental(t *testing.T) {
	tests := []struct {
		name                 string
		mutate               func(t *testing.T, path string)
		wantUnchanged        bool
		wantSizeGrew         bool
		wantProgressContains string
	}{
		{
			name:                 "unchanged file skips re-encryption",
			mutate:               func(t *testing.T, path string) {},
			wantUnchanged:        true,
			wantProgressContains: "unchanged",
		},
		{
			name: "size change forces re-upload",
			mutate: func(t *testing.T, path string) {
				f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
				if err != nil {
					t.Fatalf("open-append: %v", err)
				}
				if _, err := f.Write([]byte("X")); err != nil {
					t.Fatalf("append: %v", err)
				}
				_ = f.Close()
			},
			wantSizeGrew: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rig := newTestRig(t)
			root := t.TempDir()
			path := filepath.Join(root, "f.bin")
			writeFile(t, path, 1<<20)

			opts := backup.RunOptions{
				Path:         root,
				Conns:        []*bsquic.Conn{rig.ownerConn},
				RecipientPub: rig.recipientPub,
				Index:        rig.ownerIndex,
				ChunkSize:    1 << 20,
				Progress:     io.Discard,
			}
			if err := backup.Run(context.Background(), opts); err != nil {
				t.Fatalf("Run #1: %v", err)
			}
			firstEntry, err := rig.ownerIndex.Get(filepath.Base(path))
			if err != nil {
				t.Fatalf("Get #1: %v", err)
			}

			tc.mutate(t, path)

			var progress bytes.Buffer
			opts.Progress = &progress
			if err := backup.Run(context.Background(), opts); err != nil {
				t.Fatalf("Run #2: %v", err)
			}
			secondEntry, err := rig.ownerIndex.Get(filepath.Base(path))
			if err != nil {
				t.Fatalf("Get #2: %v", err)
			}

			if tc.wantUnchanged {
				if firstEntry.ModTime != secondEntry.ModTime {
					t.Errorf("ModTime changed despite unchanged file: %v -> %v", firstEntry.ModTime, secondEntry.ModTime)
				}
				if len(firstEntry.Chunks) != len(secondEntry.Chunks) {
					t.Errorf("chunk count changed: %d -> %d", len(firstEntry.Chunks), len(secondEntry.Chunks))
				}
				for i := range firstEntry.Chunks {
					if firstEntry.Chunks[i].CiphertextHash != secondEntry.Chunks[i].CiphertextHash {
						t.Errorf("chunk %d CiphertextHash changed; re-encryption happened despite unchanged file", i)
					}
				}
			}
			if tc.wantSizeGrew && secondEntry.Size <= firstEntry.Size {
				t.Errorf("Size did not grow: %d -> %d", firstEntry.Size, secondEntry.Size)
			}
			if tc.wantProgressContains != "" && !bytes.Contains(progress.Bytes(), []byte(tc.wantProgressContains)) {
				t.Errorf("expected progress note containing %q, got %q", tc.wantProgressContains, progress.String())
			}
		})
	}
}

func TestRun_RecordsStatFields(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	statBefore, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, err := rig.ownerIndex.Get(filepath.Base(path))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.Size != statBefore.Size() {
		t.Errorf("entry.Size = %d, want %d", entry.Size, statBefore.Size())
	}
	if !entry.ModTime.Equal(statBefore.ModTime()) {
		t.Errorf("entry.ModTime = %v, want %v", entry.ModTime, statBefore.ModTime())
	}
}

func TestRun_RecordsPeerPubKey(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, err := rig.ownerIndex.Get(filepath.Base(path))
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(entry.Chunks) == 0 {
		t.Fatal("no chunks recorded")
	}
	peers := entry.Chunks[0].Peers
	if len(peers) != 1 {
		t.Fatalf("got %d peers, want 1", len(peers))
	}
	if !bytes.Equal(peers[0], rig.peerPubKey) {
		t.Error("peer pubkey in index does not match storage peer")
	}
}

func TestRun_ContextCancellation(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(ctx, opts); err == nil {
		t.Error("Run with pre-cancelled ctx returned nil error")
	}
}

func TestRun_ProgressOutput(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	var progress bytes.Buffer
	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     &progress,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if progress.Len() == 0 {
		t.Error("expected progress output, got none")
	}
}

func TestRun_RejectsMissingPath(t *testing.T) {
	rig := newTestRig(t)
	opts := backup.RunOptions{
		Path:         filepath.Join(t.TempDir(), "does-not-exist"),
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err == nil {
		t.Error("Run on non-existent path returned nil error")
	}
}

// TestRun_RejectsEmptyPath asserts an empty opts.Path is rejected with a
// "Path is empty" message before any I/O is attempted.
func TestRun_RejectsEmptyPath(t *testing.T) {
	rig := newTestRig(t)
	opts := backup.RunOptions{
		Path:         "",
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	err := backup.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run accepted empty Path")
	}
	if !strings.Contains(err.Error(), "Path is empty") {
		t.Errorf("err = %q, want 'Path is empty' mention", err)
	}
}

// TestRun_RejectsRegularFilePath asserts a regular-file opts.Path is
// rejected with a "not a directory" message; backup is directory-only.
func TestRun_RejectsRegularFilePath(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	file := filepath.Join(root, "single.bin")
	writeFile(t, file, 1<<10)

	opts := backup.RunOptions{
		Path:         file,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	err := backup.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run accepted a regular-file Path")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("err = %q, want 'not a directory' mention", err)
	}
}

func TestRun_RejectsInvalidChunkSize(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1024,
		Progress:     io.Discard,
	}
	err := backup.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run accepted below-minimum chunk size")
	}
}

func TestServe_ConcurrentRuns(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()

	var wg sync.WaitGroup
	paths := []string{
		filepath.Join(root, "p1.bin"),
		filepath.Join(root, "p2.bin"),
	}
	for _, p := range paths {
		writeFile(t, p, 1<<20)
	}

	for _, p := range paths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			opts := backup.RunOptions{
				Path:         root,
				Conns:        []*bsquic.Conn{rig.ownerConn},
				RecipientPub: rig.recipientPub,
				Index:        rig.ownerIndex,
				ChunkSize:    1 << 20,
				Progress:     io.Discard,
			}
			if err := backup.Run(context.Background(), opts); err != nil {
				t.Errorf("Run %s: %v", path, err)
			}
		}(p)
	}
	wg.Wait()

	got, err := rig.ownerIndex.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(got) != len(paths) {
		t.Errorf("indexed %d files, want %d", len(got), len(paths))
	}
}

// TestRun_SkipsSymlinks asserts symlinks under root are not indexed and a skip note appears in progress.
func TestRun_SkipsSymlinks(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	realFile := filepath.Join(root, "real.bin")
	writeFile(t, realFile, 1<<20)
	symlink := filepath.Join(root, "link.bin")
	if err := os.Symlink(realFile, symlink); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	var progress bytes.Buffer
	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     &progress,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := rig.ownerIndex.Get(filepath.Base(symlink)); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("symlink %q should not have been indexed", symlink)
	}
	if _, err := rig.ownerIndex.Get(filepath.Base(realFile)); err != nil {
		t.Errorf("real file should have been indexed: %v", err)
	}
	if !bytes.Contains(progress.Bytes(), []byte("skip")) {
		t.Errorf("expected skip-note in progress output, got: %q", progress.String())
	}
}

func TestRun_PropagatesIndexError(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	if err := rig.ownerIndex.Close(); err != nil {
		t.Fatalf("Close index: %v", err)
	}

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	if err := backup.Run(context.Background(), opts); err == nil {
		t.Fatal("Run returned nil despite closed index")
	}
}

func TestRun_PeerErrorPropagation(t *testing.T) {
	peerDir := t.TempDir()
	rootStoreDir := filepath.Join(peerDir, "store")
	peerStore, err := store.New(rootStoreDir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	if err := os.Chmod(rootStoreDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(rootStoreDir, 0o700) })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

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

	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{ownerConn},
		RecipientPub: recipientPub,
		Index:        ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	err = backup.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run succeeded despite read-only peer store")
	}
	if !containsAny(err.Error(), "peer", "store") {
		t.Errorf("Run err = %v, want mention of peer/store failure", err)
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if sub != "" && len(s) >= len(sub) {
			for i := 0; i+len(sub) <= len(s); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

var _ = errors.Is

// TestSendGetChunk_RoundTrip exercises the exported SendGetChunk wrapper end-to-end against a real QUIC peer and store.
func TestSendGetChunk_RoundTrip(t *testing.T) {
	rig := newTestRig(t)
	blob := []byte("peer-stored ciphertext bytes")
	hash, err := rig.peerStore.PutOwned(blob, rig.ownerPubKey)
	if err != nil {
		t.Fatalf("peerStore.PutOwned: %v", err)
	}

	got, err := backup.SendGetChunk(context.Background(), rig.ownerConn, hash)
	if err != nil {
		t.Fatalf("SendGetChunk: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob mismatch: got %q, want %q", got, blob)
	}
}

// TestSendGetChunk_ForeignPeer_OwnerMismatch asserts a peer that did not
// upload the blob cannot read it back: the GetChunk handler refuses with
// the "owner_mismatch" short code.
func TestSendGetChunk_ForeignPeer_OwnerMismatch(t *testing.T) {
	rig := newTestRig(t)
	blob := []byte("alice's ciphertext")
	stranger := ed25519.PublicKey(bytes.Repeat([]byte{0xAB}, ed25519.PublicKeySize))
	hash, err := rig.peerStore.PutOwned(blob, stranger)
	if err != nil {
		t.Fatalf("peerStore.PutOwned: %v", err)
	}

	_, err = backup.SendGetChunk(context.Background(), rig.ownerConn, hash)
	if err == nil {
		t.Fatal("SendGetChunk by non-owner returned nil; expected owner_mismatch")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("owner_mismatch")) {
		t.Errorf("err = %q, want 'owner_mismatch'", err)
	}
}

// TestSendGetCapacity_RoundTrip exercises the capacity probe end-to-end
// against a real QUIC peer: a put followed by a probe should report
// used = blob length and cap = 0 (the unlimited-store sentinel).
func TestSendGetCapacity_RoundTrip(t *testing.T) {
	rig := newTestRig(t)
	blob := []byte("seed-bytes-for-capacity-probe")
	if _, err := rig.peerStore.PutOwned(blob, rig.ownerPubKey); err != nil {
		t.Fatalf("peerStore.PutOwned: %v", err)
	}

	used, cap, err := backup.SendGetCapacity(context.Background(), rig.ownerConn)
	if err != nil {
		t.Fatalf("SendGetCapacity: %v", err)
	}
	if used != int64(len(blob)) {
		t.Errorf("used = %d, want %d", used, len(blob))
	}
	if cap != 0 {
		t.Errorf("cap = %d, want 0 (unlimited)", cap)
	}
}

// TestSendPing_RoundTrip exercises the liveness probe end-to-end
// against a real QUIC peer.
func TestSendPing_RoundTrip(t *testing.T) {
	rig := newTestRig(t)
	if err := backup.SendPing(context.Background(), rig.ownerConn); err != nil {
		t.Errorf("SendPing: %v", err)
	}
}

// TestRun_DefaultsNilProgress asserts a nil opts.Progress falls back to io.Discard without panicking.
func TestRun_DefaultsNilProgress(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// TestRun_NilRecipientPubFailsEncrypt asserts backupFile surfaces the
// crypto.Encrypt rejection when RecipientPub is unset.
func TestRun_NilRecipientPubFailsEncrypt(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	err := backup.Run(context.Background(), backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: nil,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	})
	if err == nil {
		t.Fatal("Run with nil RecipientPub returned nil")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("encrypt")) {
		t.Errorf("err = %q, want 'encrypt' mention", err)
	}
}

// TestRun_OpenFileError asserts an os.Open failure inside backupFile is surfaced as an error.
func TestRun_OpenFileError(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "unreadable.bin")
	writeFile(t, path, 1<<20)
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod unreadable: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	err := backup.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run on mode-0 file returned nil")
	}
}

// TestRun_WalkError asserts a WalkDir walkErr is propagated by Run.
func TestRun_WalkError(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	sub := filepath.Join(root, "locked")
	if err := os.Mkdir(sub, 0o000); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}
	err := backup.Run(context.Background(), opts)
	if err == nil {
		t.Fatal("Run returned nil despite unreadable subdirectory")
	}
}

// TestPrune_IndexListError asserts an Index.List failure is surfaced as "index list" by Prune.
func TestPrune_IndexListError(t *testing.T) {
	rig := newTestRig(t)
	if err := rig.ownerIndex.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:     t.TempDir(),
		Conns:    []*bsquic.Conn{rig.ownerConn},
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil despite closed index")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("index list")) {
		t.Errorf("err = %q, want 'index list' prefix", err)
	}
}

// TestPrune_ContextCancelled asserts a pre-cancelled context bails out of Prune before any delete or index mutation.
func TestPrune_ContextCancelled(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	if err := rig.ownerIndex.Put(index.FileEntry{
		Path:   "ghost.bin",
		Size:   1,
		Chunks: []index.ChunkRef{{CiphertextHash: [32]byte{0x01}, Size: 10}},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := backup.Prune(ctx, backup.PruneOptions{
		Root:     root,
		Conns:    []*bsquic.Conn{rig.ownerConn},
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil despite cancelled context")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("context canceled")) {
		t.Errorf("err = %q, want context.Canceled", err)
	}
}

// TestPrune_SendDeleteChunkError asserts a sendDeleteChunk failure is surfaced as "delete chunk" by Prune.
func TestPrune_SendDeleteChunkError(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	if err := rig.ownerIndex.Put(index.FileEntry{
		Path:   "ghost.bin",
		Size:   1,
		Chunks: []index.ChunkRef{{CiphertextHash: [32]byte{0x11}, Size: 10}},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	_ = rig.ownerConn.Close()

	err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:     root,
		Conns:    []*bsquic.Conn{rig.ownerConn},
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil despite closed conn")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("delete chunk")) {
		t.Errorf("err = %q, want 'delete chunk' prefix", err)
	}
}

// TestPrune_NonNotFoundPeerErrorLogsAndFails asserts a peer returning a
// non-"not_found" application error (e.g. owner_mismatch) is logged at
// WARN and surfaces a "delete chunk" wrap when no other peer accepts.
func TestPrune_NonNotFoundPeerErrorLogsAndFails(t *testing.T) {
	rig := newTestRig(t)
	stranger := ed25519.PublicKey(bytes.Repeat([]byte{0xCD}, ed25519.PublicKeySize))
	blob := []byte("stranger-owned ciphertext")
	hash, err := rig.peerStore.PutOwned(blob, stranger)
	if err != nil {
		t.Fatalf("seed stranger blob: %v", err)
	}

	root := t.TempDir()
	if err := rig.ownerIndex.Put(index.FileEntry{
		Path:    "ghost.bin",
		Size:    int64(len(blob)),
		ModTime: time.Now(),
		Chunks: []index.ChunkRef{{
			CiphertextHash: hash,
			Size:           int64(len(blob)),
			Peers:          [][]byte{rig.peerPubKey},
		}},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}

	err = backup.Prune(context.Background(), backup.PruneOptions{
		Root:     root,
		Conns:    []*bsquic.Conn{rig.ownerConn},
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil despite owner_mismatch peer reply")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("delete chunk")) {
		t.Errorf("err = %q, want 'delete chunk' mention", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("owner_mismatch")) {
		t.Errorf("err = %q, want 'owner_mismatch' mention", err)
	}
	if has, _ := rig.peerStore.Has(hash); !has {
		t.Error("blob removed despite owner_mismatch reply")
	}
}

// TestPrune_NoConns asserts Prune rejects a call with no peer conns.
func TestPrune_NoConns(t *testing.T) {
	rig := newTestRig(t)
	err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:     t.TempDir(),
		Conns:    nil,
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil with no conns")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("no peer conns")) {
		t.Errorf("err = %q, want 'no peer conns' mention", err)
	}
}

// TestPrune_NilProgressDefaultsToDiscard asserts a nil opts.Progress is
// accepted and replaced with io.Discard internally.
func TestPrune_NilProgressDefaultsToDiscard(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	path := filepath.Join(root, "vanish.bin")
	writeFile(t, path, 1<<20)
	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:  root,
		Conns: []*bsquic.Conn{rig.ownerConn},
		Index: rig.ownerIndex,
		// Progress intentionally nil.
	}); err != nil {
		t.Fatalf("Prune with nil Progress: %v", err)
	}
}

// TestPrune_StatError asserts a non-ErrNotExist os.Stat error is surfaced as "stat" rather than triggering a delete.
func TestPrune_StatError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	rig := newTestRig(t)
	root := t.TempDir()
	sub := filepath.Join(root, "locked")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatalf("mkdir locked: %v", err)
	}
	path := filepath.Join(sub, "hidden.bin")
	writeFile(t, path, 1<<20)
	if err := rig.ownerIndex.Put(index.FileEntry{
		Path:   filepath.Join("locked", "hidden.bin"),
		Size:   1,
		Chunks: []index.ChunkRef{{CiphertextHash: [32]byte{0xbb}, Size: 10}},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}
	if err := os.Chmod(sub, 0o000); err != nil {
		t.Fatalf("chmod locked: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })

	err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:     root,
		Conns:    []*bsquic.Conn{rig.ownerConn},
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil despite stat EACCES")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("stat")) {
		t.Errorf("err = %q, want 'stat' prefix", err)
	}
}
