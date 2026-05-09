package verify_test

import (
	"encoding/hex"
	"testing"
	"time"

	"backupswarm/internal/index"
	"backupswarm/internal/verify"
)

func bytesOf(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// reachAll returns a lookup that maps every supplied pubkey to
// "reachable"; pubkeys not in the slice resolve to "" (absent).
func reachAll(pubs ...[]byte) verify.ReachLookup {
	m := make(map[string]string, len(pubs))
	for _, p := range pubs {
		m[hex.EncodeToString(p)] = "reachable"
	}
	return func(hexPub string) (string, bool) {
		s, ok := m[hexPub]
		return s, ok
	}
}

// reachStates returns a lookup keyed by hex(pubkey) → state string.
func reachStates(states map[string]string) verify.ReachLookup {
	return func(hexPub string) (string, bool) {
		s, ok := states[hexPub]
		return s, ok
	}
}

func TestCompute_EmptyIndex_ReportsZeroes(t *testing.T) {
	r := verify.Compute(reachAll(), nil, 1)
	if r.TotalFiles != 0 || r.TotalChunks != 0 {
		t.Errorf("expected zeros, got %+v", r)
	}
	if r.AtTarget != 0 || r.UnderReplicated != 0 || r.OverReplicated != 0 {
		t.Errorf("expected zero state counts, got %+v", r)
	}
	if len(r.UnderReplicatedFiles) != 0 {
		t.Errorf("expected no under-replicated files, got %d", len(r.UnderReplicatedFiles))
	}
	if len(r.MissingPeers) != 0 {
		t.Errorf("expected no missing peers, got %d", len(r.MissingPeers))
	}
}

func TestCompute_FullyReplicated_AllAtTarget(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	entries := []index.FileEntry{{
		Path:    "f1",
		Size:    100,
		ModTime: time.Now(),
		Chunks: []index.ChunkRef{
			{Size: 50, Peers: [][]byte{pubA, pubB}},
			{Size: 50, Peers: [][]byte{pubA, pubB}},
		},
	}}
	r := verify.Compute(reachAll(pubA, pubB), entries, 2)
	if r.TotalFiles != 1 || r.TotalChunks != 2 {
		t.Errorf("totals = files=%d chunks=%d, want 1/2", r.TotalFiles, r.TotalChunks)
	}
	if r.AtTarget != 2 || r.UnderReplicated != 0 || r.OverReplicated != 0 {
		t.Errorf("classification = %+v, want at_target=2", r)
	}
	if len(r.UnderReplicatedFiles) != 0 {
		t.Errorf("expected no under-replicated files, got %v", r.UnderReplicatedFiles)
	}
	if len(r.MissingPeers) != 0 {
		t.Errorf("expected no missing peers, got %v", r.MissingPeers)
	}
}

func TestCompute_PeerNotInSnapshot_CountsAsMissing(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	entries := []index.FileEntry{{
		Path:    "f1",
		Chunks:  []index.ChunkRef{{Size: 50, Peers: [][]byte{pubA, pubB}}},
		ModTime: time.Now(),
	}}
	r := verify.Compute(reachAll(pubA), entries, 2)
	if r.UnderReplicated != 1 || r.AtTarget != 0 {
		t.Errorf("classification = %+v, want under=1", r)
	}
	if got := r.MissingPeers[hex.EncodeToString(pubB)]; got != 1 {
		t.Errorf("MissingPeers[B] = %d, want 1", got)
	}
	if len(r.UnderReplicatedFiles) != 1 {
		t.Fatalf("expected 1 under-replicated file, got %d", len(r.UnderReplicatedFiles))
	}
	f := r.UnderReplicatedFiles[0]
	if f.Path != "f1" || f.UnderReplicatedChunks != 1 || f.MinHealthy != 1 {
		t.Errorf("FileFinding = %+v, want path=f1 under=1 min=1", f)
	}
}

func TestCompute_PeerSnapshotUnreachable_CountsAsMissing(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	entries := []index.FileEntry{{
		Path:    "f1",
		Chunks:  []index.ChunkRef{{Size: 50, Peers: [][]byte{pubA, pubB}}},
		ModTime: time.Now(),
	}}
	lookup := reachStates(map[string]string{
		hex.EncodeToString(pubA): "reachable",
		hex.EncodeToString(pubB): "unreachable",
	})
	r := verify.Compute(lookup, entries, 2)
	if r.UnderReplicated != 1 {
		t.Errorf("UnderReplicated=%d, want 1", r.UnderReplicated)
	}
	if got := r.MissingPeers[hex.EncodeToString(pubB)]; got != 1 {
		t.Errorf("MissingPeers[B]=%d, want 1", got)
	}
}

func TestCompute_PeerSuspect_DoesNotCountAsHealthy(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	entries := []index.FileEntry{{
		Path:    "f1",
		Chunks:  []index.ChunkRef{{Size: 50, Peers: [][]byte{pubA, pubB}}},
		ModTime: time.Now(),
	}}
	lookup := reachStates(map[string]string{
		hex.EncodeToString(pubA): "reachable",
		hex.EncodeToString(pubB): "suspect",
	})
	r := verify.Compute(lookup, entries, 2)
	if r.UnderReplicated != 1 {
		t.Errorf("UnderReplicated=%d, want 1 (B suspect is not healthy)", r.UnderReplicated)
	}
	if got := r.MissingPeers[hex.EncodeToString(pubB)]; got != 1 {
		t.Errorf("MissingPeers[B]=%d, want 1", got)
	}
}

func TestCompute_OverReplicatedWithUnreachableSurplus_StillCountsAsOver(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	pubC := bytesOf(0xc3, 32)
	entries := []index.FileEntry{{
		Path:    "f1",
		Chunks:  []index.ChunkRef{{Size: 50, Peers: [][]byte{pubA, pubB, pubC}}},
		ModTime: time.Now(),
	}}
	lookup := reachStates(map[string]string{
		hex.EncodeToString(pubA): "reachable",
		hex.EncodeToString(pubB): "reachable",
		hex.EncodeToString(pubC): "unreachable",
	})
	r := verify.Compute(lookup, entries, 2)
	if r.OverReplicated != 1 || r.AtTarget != 0 || r.UnderReplicated != 0 {
		t.Errorf("classification = %+v, want over=1", r)
	}
	if got := r.MissingPeers[hex.EncodeToString(pubC)]; got != 1 {
		t.Errorf("MissingPeers[C] = %d, want 1", got)
	}
	if len(r.UnderReplicatedFiles) != 0 {
		t.Errorf("over-replicated chunk should not appear in under-replicated list")
	}
}

func TestCompute_OverReplicated(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	pubC := bytesOf(0xc3, 32)
	entries := []index.FileEntry{{
		Path:    "f1",
		Chunks:  []index.ChunkRef{{Size: 50, Peers: [][]byte{pubA, pubB, pubC}}},
		ModTime: time.Now(),
	}}
	r := verify.Compute(reachAll(pubA, pubB, pubC), entries, 2)
	if r.OverReplicated != 1 || r.AtTarget != 0 || r.UnderReplicated != 0 {
		t.Errorf("classification = %+v, want over=1", r)
	}
	if len(r.UnderReplicatedFiles) != 0 {
		t.Errorf("over-replicated should not appear in under-replicated list")
	}
}

func TestCompute_MixedAcrossOneFile_AggregatesIntoSingleFinding(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	entries := []index.FileEntry{{
		Path: "f1",
		Chunks: []index.ChunkRef{
			{Size: 50, Peers: [][]byte{pubA, pubB}},
			{Size: 50, Peers: [][]byte{pubA}},
			{Size: 50, Peers: [][]byte{pubA}},
		},
		ModTime: time.Now(),
	}}
	r := verify.Compute(reachAll(pubA, pubB), entries, 2)
	if r.AtTarget != 1 || r.UnderReplicated != 2 {
		t.Errorf("classification = %+v, want at=1 under=2", r)
	}
	if len(r.UnderReplicatedFiles) != 1 {
		t.Fatalf("want 1 file finding, got %d", len(r.UnderReplicatedFiles))
	}
	f := r.UnderReplicatedFiles[0]
	if f.Path != "f1" || f.UnderReplicatedChunks != 2 || f.MinHealthy != 1 {
		t.Errorf("FileFinding = %+v, want path=f1 under=2 min=1", f)
	}
}

func TestCompute_RedundancyOne_SinglePeerIsAtTarget(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	entries := []index.FileEntry{{
		Path:    "f1",
		Chunks:  []index.ChunkRef{{Size: 50, Peers: [][]byte{pubA}}},
		ModTime: time.Now(),
	}}
	r := verify.Compute(reachAll(pubA), entries, 1)
	if r.AtTarget != 1 || r.UnderReplicated != 0 {
		t.Errorf("classification = %+v, want at=1", r)
	}
}

func TestCompute_NoHealthyPeers_MinHealthyIsZero(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	entries := []index.FileEntry{{
		Path:    "f1",
		Chunks:  []index.ChunkRef{{Size: 50, Peers: [][]byte{pubA, pubB}}},
		ModTime: time.Now(),
	}}
	r := verify.Compute(reachAll(), entries, 2)
	if r.UnderReplicated != 1 {
		t.Errorf("UnderReplicated=%d, want 1", r.UnderReplicated)
	}
	if r.UnderReplicatedFiles[0].MinHealthy != 0 {
		t.Errorf("MinHealthy=%d, want 0", r.UnderReplicatedFiles[0].MinHealthy)
	}
	if got := r.MissingPeers[hex.EncodeToString(pubA)]; got != 1 {
		t.Errorf("MissingPeers[A]=%d, want 1", got)
	}
	if got := r.MissingPeers[hex.EncodeToString(pubB)]; got != 1 {
		t.Errorf("MissingPeers[B]=%d, want 1", got)
	}
}

func TestCompute_DeterministicFileFindingOrder(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	entries := []index.FileEntry{
		{Path: "z.txt", Chunks: []index.ChunkRef{{Peers: nil}}, ModTime: time.Now()},
		{Path: "a.txt", Chunks: []index.ChunkRef{{Peers: nil}}, ModTime: time.Now()},
		{Path: "m.txt", Chunks: []index.ChunkRef{{Peers: nil}}, ModTime: time.Now()},
	}
	r := verify.Compute(reachAll(pubA), entries, 1)
	if len(r.UnderReplicatedFiles) != 3 {
		t.Fatalf("want 3 findings, got %d", len(r.UnderReplicatedFiles))
	}
	got := []string{r.UnderReplicatedFiles[0].Path, r.UnderReplicatedFiles[1].Path, r.UnderReplicatedFiles[2].Path}
	want := []string{"a.txt", "m.txt", "z.txt"}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("order[%d]=%q, want %q (full=%v)", i, got[i], want[i], got)
		}
	}
}

func TestCompute_NilReach_AllPeersCountAsMissing(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	entries := []index.FileEntry{{
		Path: "f1", ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Peers: [][]byte{pubA}}},
	}}
	r := verify.Compute(nil, entries, 1)
	if r.UnderReplicated != 1 || r.MissingPeers[hex.EncodeToString(pubA)] != 1 {
		t.Errorf("nil reach should treat every peer as missing, got %+v", r)
	}
}

func TestCompute_ChunkWithNoHolders_UnderReplicatedNoMissingPeers(t *testing.T) {
	entries := []index.FileEntry{{
		Path: "orphan", ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Size: 50, Peers: nil}},
	}}
	r := verify.Compute(reachAll(), entries, 1)
	if r.UnderReplicated != 1 || r.AtTarget != 0 {
		t.Fatalf("zero-holder chunk should be under-replicated, got %+v", r)
	}
	if len(r.UnderReplicatedFiles) != 1 || r.UnderReplicatedFiles[0].MinHealthy != 0 {
		t.Errorf("MinHealthy for zero-holder chunk should be 0, got %+v", r.UnderReplicatedFiles)
	}
	if len(r.MissingPeers) != 0 {
		t.Errorf("zero-holder chunk should not populate MissingPeers, got %v", r.MissingPeers)
	}
}

func TestCompute_RedundancyZero_EveryHealthyChunkIsOverReplicated(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	entries := []index.FileEntry{{
		Path: "f1", ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Peers: [][]byte{pubA}}},
	}}
	r := verify.Compute(reachAll(pubA), entries, 0)
	if r.OverReplicated != 1 || r.UnderReplicated != 0 {
		t.Errorf("with redundancy=0, healthy chunks should classify as over, got %+v", r)
	}
}

func TestCompute_DuplicateUnhealthyPeerInChunk_CountsOnce(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	entries := []index.FileEntry{{
		Path: "f1", ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Peers: [][]byte{pubA, pubA}}},
	}}
	r := verify.Compute(reachAll(), entries, 1)
	if got := r.MissingPeers[hex.EncodeToString(pubA)]; got != 1 {
		t.Errorf("MissingPeers[A]=%d, want 1 (dup-in-chunk should not double-count)", got)
	}
}

func TestCompute_DuplicateHealthyPeerInChunk_CountsOnceTowardHealthy(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	entries := []index.FileEntry{{
		Path: "f1", ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Peers: [][]byte{pubA, pubA}}},
	}}
	r := verify.Compute(reachAll(pubA), entries, 2)
	if r.UnderReplicated != 1 || r.AtTarget != 0 {
		t.Errorf("dup peer should not contribute to healthy count twice, got %+v", r)
	}
}

func TestCompute_ReachAbsentTreatedAsMissing(t *testing.T) {
	pubA := bytesOf(0xa1, 32)
	pubB := bytesOf(0xb2, 32)
	entries := []index.FileEntry{{
		Path:    "f1",
		Chunks:  []index.ChunkRef{{Size: 50, Peers: [][]byte{pubA, pubB}}},
		ModTime: time.Now(),
	}}
	r := verify.Compute(reachAll(pubA), entries, 2)
	if r.UnderReplicated != 1 {
		t.Errorf("expected snapshot-absent peer to count as missing, got %+v", r)
	}
}
