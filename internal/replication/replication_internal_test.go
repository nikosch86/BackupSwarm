package replication

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"backupswarm/internal/index"
)

// fakeConn satisfies the Conn interface for tests; carries no transport.
type fakeConn struct{ pub ed25519.PublicKey }

func (f *fakeConn) RemotePub() ed25519.PublicKey { return f.pub }

// pub32 returns a deterministic 32-byte pubkey distinguishable by its first byte.
func pub32(b byte) ed25519.PublicKey {
	p := make(ed25519.PublicKey, 32)
	p[0] = b
	return p
}

func newConn(b byte) *fakeConn { return &fakeConn{pub: pub32(b)} }

// withSendGetChunk replaces sendGetChunkFunc for the duration of t.
func withSendGetChunk(t *testing.T, fake func(ctx context.Context, c Conn, hash [32]byte) ([]byte, error)) {
	t.Helper()
	orig := sendGetChunkFunc
	sendGetChunkFunc = fake
	t.Cleanup(func() { sendGetChunkFunc = orig })
}

func withSendPutChunk(t *testing.T, fake func(ctx context.Context, c Conn, blob []byte) ([32]byte, error)) {
	t.Helper()
	orig := sendPutChunkFunc
	sendPutChunkFunc = fake
	t.Cleanup(func() { sendPutChunkFunc = orig })
}

func withSendGetCapacity(t *testing.T, fake func(ctx context.Context, c Conn) (int64, int64, error)) {
	t.Helper()
	orig := sendGetCapacityFunc
	sendGetCapacityFunc = fake
	t.Cleanup(func() { sendGetCapacityFunc = orig })
}

func withIndexList(t *testing.T, fake func(idx *index.Index) ([]index.FileEntry, error)) {
	t.Helper()
	orig := indexListFunc
	indexListFunc = fake
	t.Cleanup(func() { indexListFunc = orig })
}

// openIndexInTemp creates a fresh bbolt index under t.TempDir().
func openIndexInTemp(t *testing.T) *index.Index {
	t.Helper()
	idx, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	return idx
}

// chunkRefT builds a ChunkRef whose CiphertextHash[0]=tag for assertions.
func chunkRefT(tag byte, size int64, peers ...[]byte) index.ChunkRef {
	var hash [32]byte
	hash[0] = tag
	return index.ChunkRef{
		PlaintextHash:  [32]byte{},
		CiphertextHash: hash,
		Size:           size,
		Peers:          peers,
	}
}

// alwaysCapacity returns a probe seam reporting (used=0, max=0) — unlimited.
func alwaysCapacity() func(ctx context.Context, c Conn) (int64, int64, error) {
	return func(_ context.Context, _ Conn) (int64, int64, error) { return 0, 0, nil }
}

// stubFetcher returns a SendGetChunk seam returning fixed bytes for any hash.
func stubFetcher(blob []byte) func(ctx context.Context, c Conn, hash [32]byte) ([]byte, error) {
	return func(_ context.Context, _ Conn, _ [32]byte) ([]byte, error) { return blob, nil }
}

func TestRun_EmptyIndex_NoOp(t *testing.T) {
	idx := openIndexInTemp(t)
	conns := []Conn{newConn('A'), newConn('B')}
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      conns,
		LostFn:     func([]byte) bool { return false },
		Redundancy: 2,
	}); err != nil {
		t.Errorf("Run = %v, want nil", err)
	}
}

func TestRun_RedundancyZero_NoOp(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	called := false
	withSendGetChunk(t, func(context.Context, Conn, [32]byte) ([]byte, error) {
		called = true
		return nil, nil
	})
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('B')},
		LostFn:     func([]byte) bool { return true },
		Redundancy: 0,
	}); err != nil {
		t.Errorf("Run = %v, want nil", err)
	}
	if called {
		t.Error("Redundancy=0 should not have triggered any I/O")
	}
}

func TestRun_HappyPath_MergesNewPeer(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(7, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	connA := newConn('A')
	connB := newConn('B')
	connC := newConn('C')

	wantBlob := []byte("ciphertext-blob")
	var fetchedFrom atomic.Value
	withSendGetChunk(t, func(_ context.Context, c Conn, _ [32]byte) ([]byte, error) {
		fetchedFrom.Store(c.RemotePub()[0])
		return wantBlob, nil
	})

	withSendGetCapacity(t, alwaysCapacity())

	var putTo atomic.Value
	var wantHash [32]byte
	wantHash[0] = 7
	withSendPutChunk(t, func(_ context.Context, c Conn, blob []byte) ([32]byte, error) {
		putTo.Store(c.RemotePub()[0])
		if string(blob) != string(wantBlob) {
			t.Errorf("put blob = %q, want %q", blob, wantBlob)
		}
		return wantHash, nil
	})

	lostFn := func(p []byte) bool { return p[0] == 'A' }
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{connA, connB, connC},
		LostFn:     lostFn,
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, err := idx.Get("a.txt")
	if err != nil {
		t.Fatalf("idx.Get: %v", err)
	}
	if len(got.Chunks) != 1 {
		t.Fatalf("chunks = %d, want 1", len(got.Chunks))
	}
	peers := got.Chunks[0].Peers
	if len(peers) != 3 {
		t.Fatalf("peers after replication = %d (%v), want 3", len(peers), peers)
	}
	if peers[0][0] != 'A' || peers[1][0] != 'B' {
		t.Errorf("existing peers = %v, want [A,B,...]", peers)
	}
	if peers[2][0] != 'C' {
		t.Errorf("new peer = %v, want C", peers[2])
	}
	if fetchedFrom.Load() != byte('B') {
		t.Errorf("fetched from = %v, want B (only alive source)", fetchedFrom.Load())
	}
	if putTo.Load() != byte('C') {
		t.Errorf("put to = %v, want C (only available target)", putTo.Load())
	}
}

func TestRun_NoSources_Skips(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, func(context.Context, Conn, [32]byte) ([]byte, error) {
		t.Error("SendGetChunk called without a live source")
		return nil, errors.New("unexpected")
	})
	withSendPutChunk(t, func(context.Context, Conn, []byte) ([32]byte, error) {
		t.Error("SendPutChunk called without a live source")
		return [32]byte{}, errors.New("unexpected")
	})
	withSendGetCapacity(t, alwaysCapacity())
	// Both A and B lost; only C is live but it's not a source.
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' || p[0] == 'B' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, _ := idx.Get("a.txt")
	if len(got.Chunks[0].Peers) != 2 {
		t.Errorf("peers = %d, want unchanged 2", len(got.Chunks[0].Peers))
	}
}

func TestRun_SourceFetchFails_Skips(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, func(context.Context, Conn, [32]byte) ([]byte, error) {
		return nil, errors.New("fetch failed")
	})
	putCalled := false
	withSendPutChunk(t, func(context.Context, Conn, []byte) ([32]byte, error) {
		putCalled = true
		return [32]byte{}, nil
	})
	withSendGetCapacity(t, alwaysCapacity())
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if putCalled {
		t.Error("SendPutChunk should not have been called after fetch failed")
	}
	got, _ := idx.Get("a.txt")
	if len(got.Chunks[0].Peers) != 2 {
		t.Errorf("peers = %d, want unchanged 2", len(got.Chunks[0].Peers))
	}
}

func TestRun_TargetPoolEmpty_Skips(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	putCalled := false
	withSendPutChunk(t, func(context.Context, Conn, []byte) ([32]byte, error) {
		putCalled = true
		return [32]byte{}, nil
	})
	withSendGetCapacity(t, alwaysCapacity())
	// Conns = [A,B] — both already in ExistingPeers, no new target available.
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if putCalled {
		t.Error("SendPutChunk should not run when target pool empty")
	}
	got, _ := idx.Get("a.txt")
	if len(got.Chunks[0].Peers) != 2 {
		t.Errorf("peers = %d, want unchanged 2", len(got.Chunks[0].Peers))
	}
}

func TestRun_TargetRejects_ContinuesToNext(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(9, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	withSendGetCapacity(t, alwaysCapacity())

	var (
		mu    sync.Mutex
		calls []byte
	)
	var wantHash [32]byte
	wantHash[0] = 9
	withSendPutChunk(t, func(_ context.Context, c Conn, _ []byte) ([32]byte, error) {
		mu.Lock()
		calls = append(calls, c.RemotePub()[0])
		mu.Unlock()
		if c.RemotePub()[0] == 'C' {
			return [32]byte{}, errors.New("rejected")
		}
		return wantHash, nil
	})
	// R=3, B alive, A lost. Need 2 new from {C, D}; C rejects, expect only D.
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C'), newConn('D')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 3,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	got := append([]byte(nil), calls...)
	mu.Unlock()
	if len(got) != 2 {
		t.Errorf("Put calls = %v, want 2 (one per selected target)", got)
	}
	entry, _ := idx.Get("a.txt")
	peers := entry.Chunks[0].Peers
	// Existing 2 + only successful new (D); C was rejected.
	if len(peers) != 3 {
		t.Errorf("peers after replication = %v, want 3 (A,B,D)", peers)
	}
}

func TestRun_HashMismatch_DropsTarget(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(5, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	withSendGetCapacity(t, alwaysCapacity())
	var bogus [32]byte
	bogus[0] = 0xFF
	withSendPutChunk(t, func(_ context.Context, _ Conn, _ []byte) ([32]byte, error) {
		return bogus, nil
	})
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, _ := idx.Get("a.txt")
	if len(entry.Chunks[0].Peers) != 2 {
		t.Errorf("peers after hash mismatch = %d, want unchanged 2", len(entry.Chunks[0].Peers))
	}
}

func TestRun_IndexListFails_BubblesUp(t *testing.T) {
	idx := openIndexInTemp(t)
	wantErr := errors.New("boom")
	withIndexList(t, func(*index.Index) ([]index.FileEntry, error) { return nil, wantErr })
	err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A')},
		LostFn:     func([]byte) bool { return false },
		Redundancy: 2,
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("Run err = %v, want wraps %v", err, wantErr)
	}
}

func TestRun_CapacityProbeFails_PeerExcluded(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	withSendGetCapacity(t, func(_ context.Context, c Conn) (int64, int64, error) {
		if c.RemotePub()[0] == 'C' {
			return 0, 0, errors.New("probe failed")
		}
		return 0, 0, nil
	})
	putCalled := false
	withSendPutChunk(t, func(context.Context, Conn, []byte) ([32]byte, error) {
		putCalled = true
		return [32]byte{}, nil
	})
	// Only C is a candidate target (A/B excluded as ExistingPeers); C's
	// probe fails, target pool empties, no put issued.
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if putCalled {
		t.Error("SendPutChunk should not run when only target's probe fails")
	}
}

func TestRun_FullCapacityPeerExcluded(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	withSendGetCapacity(t, func(_ context.Context, c Conn) (int64, int64, error) {
		if c.RemotePub()[0] == 'C' {
			return 1000, 1000, nil // full
		}
		return 0, 0, nil
	})
	putCalled := false
	withSendPutChunk(t, func(context.Context, Conn, []byte) ([32]byte, error) {
		putCalled = true
		return [32]byte{}, nil
	})
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if putCalled {
		t.Error("SendPutChunk should not run when only target is at capacity")
	}
}

func TestAvailableFromProbe(t *testing.T) {
	tests := []struct {
		name      string
		used, max int64
		want      int64
	}{
		{"unlimited", 100, 0, unlimitedReplicationWeight},
		{"normal", 100, 1000, 900},
		{"full", 1000, 1000, 0},
		{"used_exceeds_max_clamps_to_zero", 1500, 1000, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := availableFromProbe(tt.used, tt.max); got != tt.want {
				t.Errorf("availableFromProbe(%d,%d) = %d, want %d", tt.used, tt.max, got, tt.want)
			}
		})
	}
}

func TestRun_IndexGetFails_DoesNotAbort(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	withSendGetCapacity(t, alwaysCapacity())
	var wantHash [32]byte
	wantHash[0] = 1
	withSendPutChunk(t, func(_ context.Context, _ Conn, _ []byte) ([32]byte, error) { return wantHash, nil })
	wantErr := errors.New("idx get boom")
	origGet := indexGetFunc
	indexGetFunc = func(*index.Index, string) (index.FileEntry, error) { return index.FileEntry{}, wantErr }
	t.Cleanup(func() { indexGetFunc = origGet })
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Errorf("Run = %v, want nil (per-task error logged, sweep continues)", err)
	}
}

func TestRun_IndexEntryDeleted_BetweenPlanAndMerge(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	withSendGetCapacity(t, alwaysCapacity())
	var wantHash [32]byte
	wantHash[0] = 1
	withSendPutChunk(t, func(_ context.Context, _ Conn, _ []byte) ([32]byte, error) {
		_ = idx.Delete("a.txt")
		return wantHash, nil
	})
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if _, err := idx.Get("a.txt"); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("entry resurrected by merge: %v", err)
	}
}

func TestRun_ChunkIndexOutOfRange_AfterRewrite(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path: "a.txt",
		Size: 100,
		Chunks: []index.ChunkRef{
			chunkRefT(1, 100, pub32('A'), pub32('B')),
			chunkRefT(2, 100, pub32('A'), pub32('B')),
		},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	withSendGetCapacity(t, alwaysCapacity())
	var firstPut atomic.Bool
	withSendPutChunk(t, func(_ context.Context, _ Conn, _ []byte) ([32]byte, error) {
		// First successful put: rewrite the entry to have only one chunk.
		// The second task's ChunkIndex (1) is now out of range.
		if firstPut.CompareAndSwap(false, true) {
			_ = idx.Put(index.FileEntry{
				Path:   "a.txt",
				Size:   100,
				Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'), pub32('Z'))},
			})
		}
		var hash [32]byte
		// Whatever the chunk hash should be — match the second task's hash 2.
		hash[0] = 2
		return hash, nil
	})
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRun_PlacementError_LoggedAndSkipped(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	withSendGetCapacity(t, func(_ context.Context, _ Conn) (int64, int64, error) {
		// Negative weight will be rejected by placement.WeightedRandom.
		return 0, -1, nil
	})
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	got, _ := idx.Get("a.txt")
	if len(got.Chunks[0].Peers) != 2 {
		t.Errorf("peers = %d, want unchanged 2", len(got.Chunks[0].Peers))
	}
}

func TestRun_IndexPutFails_LoggedAndSkipped(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	withSendGetCapacity(t, alwaysCapacity())
	var wantHash [32]byte
	wantHash[0] = 1
	withSendPutChunk(t, func(_ context.Context, _ Conn, _ []byte) ([32]byte, error) { return wantHash, nil })
	wantErr := errors.New("put boom")
	origPut := indexPutFunc
	indexPutFunc = func(*index.Index, index.FileEntry) error { return wantErr }
	t.Cleanup(func() { indexPutFunc = origPut })
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

func TestRun_IndexEntryRewritten_DropsMerge(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendGetChunk(t, stubFetcher([]byte("blob")))
	withSendGetCapacity(t, alwaysCapacity())
	var wantHash [32]byte
	wantHash[0] = 1
	withSendPutChunk(t, func(_ context.Context, _ Conn, _ []byte) ([32]byte, error) {
		// Simulate the index being rewritten under us between Plan and merge.
		_ = idx.Put(index.FileEntry{
			Path:   "a.txt",
			Size:   200,
			Chunks: []index.ChunkRef{chunkRefT(99, 200, pub32('A'))},
		})
		return wantHash, nil
	})
	if err := Run(context.Background(), RunOptions{
		Index:      idx,
		Conns:      []Conn{newConn('A'), newConn('B'), newConn('C')},
		LostFn:     func(p []byte) bool { return p[0] == 'A' },
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, _ := idx.Get("a.txt")
	if entry.Chunks[0].CiphertextHash[0] != 99 {
		t.Errorf("entry rewrite lost: chunk hash = %d, want 99", entry.Chunks[0].CiphertextHash[0])
	}
	if len(entry.Chunks[0].Peers) != 1 {
		t.Errorf("peers = %d, want 1 (rewrite preserved, merge dropped)", len(entry.Chunks[0].Peers))
	}
}
