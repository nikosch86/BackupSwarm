package replication

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"

	"backupswarm/internal/index"
)

func TestPlanCleanup_EmptyEntries_NoTasks(t *testing.T) {
	got := PlanCleanup(nil, pub32('A'), 1)
	if len(got) != 0 {
		t.Errorf("tasks = %d, want 0", len(got))
	}
}

func TestPlanCleanup_RecoveredPubAbsent_NoTasks(t *testing.T) {
	entries := []index.FileEntry{{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('B'), pub32('C'))},
	}}
	got := PlanCleanup(entries, pub32('A'), 1)
	if len(got) != 0 {
		t.Errorf("tasks = %d, want 0; recoveredPub not in any chunk's Peers", len(got))
	}
}

func TestPlanCleanup_AtRedundancy_NoSurplus_NoTasks(t *testing.T) {
	entries := []index.FileEntry{{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}}
	// len(Peers) == 2 == redundancy → no surplus, A's copy is still load-bearing.
	got := PlanCleanup(entries, pub32('A'), 2)
	if len(got) != 0 {
		t.Errorf("tasks = %d, want 0 at len==redundancy", len(got))
	}
}

func TestPlanCleanup_SurplusReplicas_EmitsTask(t *testing.T) {
	entries := []index.FileEntry{{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}}
	// len(Peers) == 2 > redundancy 1 → A is stale (re-rep happened).
	got := PlanCleanup(entries, pub32('A'), 1)
	if len(got) != 1 {
		t.Fatalf("tasks = %d, want 1", len(got))
	}
	if got[0].EntryPath != "a.txt" || got[0].ChunkIndex != 0 {
		t.Errorf("task = %+v", got[0])
	}
	if !bytes.Equal(got[0].StalePub, pub32('A')) {
		t.Errorf("StalePub = %x, want A", got[0].StalePub)
	}
	if got[0].CiphertextHash[0] != 1 {
		t.Errorf("CiphertextHash[0] = %d, want 1", got[0].CiphertextHash[0])
	}
}

func TestPlanCleanup_MixedChunks_OnlyEmitsForMatching(t *testing.T) {
	entries := []index.FileEntry{
		{
			Path: "a.txt",
			Size: 100,
			Chunks: []index.ChunkRef{
				chunkRefT(1, 100, pub32('A'), pub32('B')), // A surplus
				chunkRefT(2, 100, pub32('B'), pub32('C')), // A absent
			},
		},
		{
			Path: "b.txt",
			Size: 50,
			Chunks: []index.ChunkRef{
				chunkRefT(3, 50, pub32('A')), // A is the only holder, no surplus
			},
		},
	}
	got := PlanCleanup(entries, pub32('A'), 1)
	if len(got) != 1 {
		t.Fatalf("tasks = %d, want 1", len(got))
	}
	if got[0].EntryPath != "a.txt" || got[0].ChunkIndex != 0 {
		t.Errorf("task = %+v", got[0])
	}
}

func TestPlanCleanup_RedundancyZero_NoTasks(t *testing.T) {
	entries := []index.FileEntry{{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}}
	got := PlanCleanup(entries, pub32('A'), 0)
	if len(got) != 0 {
		t.Errorf("tasks = %d, want 0 with redundancy=0", len(got))
	}
}

// withSendDeleteChunk replaces sendDeleteChunkFunc for the duration of t.
func withSendDeleteChunk(t *testing.T, fake func(ctx context.Context, c Conn, hash [32]byte) error) {
	t.Helper()
	orig := sendDeleteChunkFunc
	sendDeleteChunkFunc = fake
	t.Cleanup(func() { sendDeleteChunkFunc = orig })
}

func TestRunCleanup_NoTasks_NoIO(t *testing.T) {
	idx := openIndexInTemp(t)
	called := false
	withSendDeleteChunk(t, func(context.Context, Conn, [32]byte) error {
		called = true
		return nil
	})
	if err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       newConn('A'),
		Redundancy: 1,
	}); err != nil {
		t.Fatalf("RunCleanup: %v", err)
	}
	if called {
		t.Error("RunCleanup with empty index should issue no DeleteChunk calls")
	}
}

func TestRunCleanup_SendDeleteAndDropPeer(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(7, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	var deleted [32]byte
	withSendDeleteChunk(t, func(_ context.Context, c Conn, hash [32]byte) error {
		if c.RemotePub()[0] != 'A' {
			t.Errorf("delete sent to %c, want A", c.RemotePub()[0])
		}
		deleted = hash
		return nil
	})

	if err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       newConn('A'),
		Redundancy: 1,
	}); err != nil {
		t.Fatalf("RunCleanup: %v", err)
	}

	if deleted[0] != 7 {
		t.Errorf("delete hash[0] = %d, want 7", deleted[0])
	}
	got, err := idx.Get("a.txt")
	if err != nil {
		t.Fatalf("idx.Get: %v", err)
	}
	peers := got.Chunks[0].Peers
	if len(peers) != 1 || !bytes.Equal(peers[0], pub32('B')) {
		t.Errorf("peers = %x, want [B]", peers)
	}
}

func TestRunCleanup_PeerNotFound_TreatedAsSuccess(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(7, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendDeleteChunk(t, func(context.Context, Conn, [32]byte) error {
		return errors.New("peer rejected delete: not_found xx")
	})
	if err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       newConn('A'),
		Redundancy: 1,
	}); err != nil {
		t.Fatalf("RunCleanup: %v", err)
	}
	got, _ := idx.Get("a.txt")
	if len(got.Chunks[0].Peers) != 1 || !bytes.Equal(got.Chunks[0].Peers[0], pub32('B')) {
		t.Errorf("not_found should have dropped A; peers = %x", got.Chunks[0].Peers)
	}
}

func TestRunCleanup_DeleteFails_KeepsPeerInIndex(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(7, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendDeleteChunk(t, func(context.Context, Conn, [32]byte) error {
		return errors.New("transient network failure")
	})
	if err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       newConn('A'),
		Redundancy: 1,
	}); err != nil {
		t.Fatalf("RunCleanup: %v", err)
	}
	got, _ := idx.Get("a.txt")
	if len(got.Chunks[0].Peers) != 2 {
		t.Errorf("delete failed but peers were updated; peers = %x", got.Chunks[0].Peers)
	}
}

func TestRunCleanup_HashRaceAfterPlan_SkipsIndexUpdate(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(7, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendDeleteChunk(t, func(context.Context, Conn, [32]byte) error {
		// Race: caller rewrites the chunk between Plan and the merge step.
		entry, err := idx.Get("a.txt")
		if err != nil {
			t.Fatalf("idx.Get: %v", err)
		}
		entry.Chunks[0] = chunkRefT(99, 100, pub32('C'))
		if err := idx.Put(entry); err != nil {
			t.Fatalf("idx.Put: %v", err)
		}
		return nil
	})
	if err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       newConn('A'),
		Redundancy: 1,
	}); err != nil {
		t.Fatalf("RunCleanup: %v", err)
	}
	got, _ := idx.Get("a.txt")
	if got.Chunks[0].CiphertextHash[0] != 99 {
		t.Errorf("hash race rewrite was clobbered; chunk[0] = %+v", got.Chunks[0])
	}
	if len(got.Chunks[0].Peers) != 1 || !bytes.Equal(got.Chunks[0].Peers[0], pub32('C')) {
		t.Errorf("peers should reflect the racing rewrite, got %x", got.Chunks[0].Peers)
	}
}

func TestRunCleanup_SecondPassIsNoOp(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(7, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	calls := 0
	withSendDeleteChunk(t, func(context.Context, Conn, [32]byte) error {
		calls++
		return nil
	})
	for range 2 {
		if err := RunCleanup(context.Background(), CleanupOptions{
			Index:      idx,
			Conn:       newConn('A'),
			Redundancy: 1,
		}); err != nil {
			t.Fatalf("RunCleanup: %v", err)
		}
	}
	if calls != 1 {
		t.Errorf("delete calls = %d, want 1 (second pass should plan empty)", calls)
	}
}

// withIndexGet swaps indexGetFunc for the duration of t.
func withIndexGet(t *testing.T, fake func(idx *index.Index, path string) (index.FileEntry, error)) {
	t.Helper()
	orig := indexGetFunc
	indexGetFunc = fake
	t.Cleanup(func() { indexGetFunc = orig })
}

func TestRunCleanup_RedundancyZero_NoOp(t *testing.T) {
	idx := openIndexInTemp(t)
	called := false
	withSendDeleteChunk(t, func(context.Context, Conn, [32]byte) error {
		called = true
		return nil
	})
	if err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       newConn('A'),
		Redundancy: 0,
	}); err != nil {
		t.Fatalf("RunCleanup: %v", err)
	}
	if called {
		t.Error("Redundancy=0 should not have triggered DeleteChunk")
	}
}

func TestRunCleanup_NilConn_NoOp(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(7, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	called := false
	withSendDeleteChunk(t, func(context.Context, Conn, [32]byte) error {
		called = true
		return nil
	})
	if err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       nil,
		Redundancy: 1,
	}); err != nil {
		t.Fatalf("RunCleanup: %v", err)
	}
	if called {
		t.Error("nil Conn should not have triggered DeleteChunk")
	}
}

func TestRunCleanup_EmptyRecoveredPub_NoOp(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(7, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	called := false
	withSendDeleteChunk(t, func(context.Context, Conn, [32]byte) error {
		called = true
		return nil
	})
	emptyConn := &fakeConn{pub: ed25519.PublicKey{}}
	if err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       emptyConn,
		Redundancy: 1,
	}); err != nil {
		t.Fatalf("RunCleanup: %v", err)
	}
	if called {
		t.Error("empty RemotePub should short-circuit before any DeleteChunk")
	}
}

func TestRunCleanup_IndexListFails_BubblesUp(t *testing.T) {
	idx := openIndexInTemp(t)
	wantErr := errors.New("list boom")
	withIndexList(t, func(*index.Index) ([]index.FileEntry, error) { return nil, wantErr })
	err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       newConn('A'),
		Redundancy: 1,
	})
	if !errors.Is(err, wantErr) {
		t.Errorf("RunCleanup err = %v, want wraps %v", err, wantErr)
	}
}

func TestRunCleanup_ProgressEmitsLineOnSuccess(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(7, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendDeleteChunk(t, func(context.Context, Conn, [32]byte) error { return nil })
	var buf bytes.Buffer
	if err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       newConn('A'),
		Redundancy: 1,
		Progress:   &buf,
	}); err != nil {
		t.Fatalf("RunCleanup: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "cleaned up a.txt chunk 0 on peer") {
		t.Errorf("progress output = %q, want a 'cleaned up' line", out)
	}
}

func TestRunCleanup_DropPeerFails_LoggedAndSweepContinues(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(7, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	withSendDeleteChunk(t, func(context.Context, Conn, [32]byte) error { return nil })
	withIndexGet(t, func(*index.Index, string) (index.FileEntry, error) {
		return index.FileEntry{}, errors.New("get boom")
	})
	if err := RunCleanup(context.Background(), CleanupOptions{
		Index:      idx,
		Conn:       newConn('A'),
		Redundancy: 1,
	}); err != nil {
		t.Errorf("RunCleanup = %v, want nil (per-task error logged, sweep continues)", err)
	}
}

func TestDropPeerFromIndex_EntryDeleted_BetweenPlanAndRun(t *testing.T) {
	idx := openIndexInTemp(t)
	task := CleanupTask{
		EntryPath:      "gone.txt",
		ChunkIndex:     0,
		CiphertextHash: [32]byte{1},
		StalePub:       pub32('A'),
	}
	if err := dropPeerFromIndex(idx, task); err != nil {
		t.Errorf("dropPeerFromIndex on missing entry = %v, want nil", err)
	}
}

func TestDropPeerFromIndex_GetReturnsOtherError_Bubbles(t *testing.T) {
	idx := openIndexInTemp(t)
	wantErr := errors.New("get boom")
	withIndexGet(t, func(*index.Index, string) (index.FileEntry, error) {
		return index.FileEntry{}, wantErr
	})
	task := CleanupTask{
		EntryPath:      "a.txt",
		ChunkIndex:     0,
		CiphertextHash: [32]byte{1},
		StalePub:       pub32('A'),
	}
	if err := dropPeerFromIndex(idx, task); !errors.Is(err, wantErr) {
		t.Errorf("dropPeerFromIndex err = %v, want %v", err, wantErr)
	}
}

func TestDropPeerFromIndex_ChunkIndexShrunk_NoOp(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('A'), pub32('B'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	task := CleanupTask{
		EntryPath:      "a.txt",
		ChunkIndex:     5,
		CiphertextHash: [32]byte{1},
		StalePub:       pub32('A'),
	}
	if err := dropPeerFromIndex(idx, task); err != nil {
		t.Errorf("dropPeerFromIndex on out-of-range chunk = %v, want nil", err)
	}
	got, _ := idx.Get("a.txt")
	if len(got.Chunks[0].Peers) != 2 {
		t.Errorf("entry mutated; peers = %x", got.Chunks[0].Peers)
	}
}

func TestDropPeerFromIndex_StalePubAlreadyGone_NoOp(t *testing.T) {
	idx := openIndexInTemp(t)
	if err := idx.Put(index.FileEntry{
		Path:   "a.txt",
		Size:   100,
		Chunks: []index.ChunkRef{chunkRefT(1, 100, pub32('B'), pub32('C'))},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	called := false
	origPut := indexPutFunc
	indexPutFunc = func(idx *index.Index, e index.FileEntry) error {
		called = true
		return origPut(idx, e)
	}
	t.Cleanup(func() { indexPutFunc = origPut })
	task := CleanupTask{
		EntryPath:      "a.txt",
		ChunkIndex:     0,
		CiphertextHash: [32]byte{1},
		StalePub:       pub32('A'),
	}
	if err := dropPeerFromIndex(idx, task); err != nil {
		t.Errorf("dropPeerFromIndex when StalePub absent = %v, want nil", err)
	}
	if called {
		t.Error("indexPut should not be called when nothing changed")
	}
}
