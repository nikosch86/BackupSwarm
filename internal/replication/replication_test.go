package replication_test

import (
	"bytes"
	"testing"

	"backupswarm/internal/index"
	"backupswarm/internal/replication"
)

// pub returns a deterministic 32-byte pubkey distinguishable by its first byte.
func pub(b byte) []byte {
	out := make([]byte, 32)
	out[0] = b
	return out
}

func neverLost(_ []byte) bool { return false }

func lostIf(targets ...byte) func([]byte) bool {
	return func(p []byte) bool {
		if len(p) == 0 {
			return false
		}
		for _, t := range targets {
			if p[0] == t {
				return true
			}
		}
		return false
	}
}

func chunkRef(name byte, size int64, peers ...[]byte) index.ChunkRef {
	var hash [32]byte
	hash[0] = name
	return index.ChunkRef{
		PlaintextHash:  [32]byte{},
		CiphertextHash: hash,
		Size:           size,
		Peers:          peers,
	}
}

func TestPlan_EmptyEntries_NoTasks(t *testing.T) {
	tasks := replication.Plan(nil, nil, neverLost, 2)
	if len(tasks) != 0 {
		t.Errorf("Plan(nil) = %d tasks, want 0", len(tasks))
	}
}

func TestPlan_AllReachable_NoTasks(t *testing.T) {
	entries := []index.FileEntry{{
		Path: "a.txt",
		Chunks: []index.ChunkRef{
			chunkRef(1, 100, pub('A'), pub('B')),
		},
	}}
	tasks := replication.Plan(entries, [][]byte{pub('A'), pub('B')}, neverLost, 2)
	if len(tasks) != 0 {
		t.Errorf("Plan = %d tasks, want 0 (well-replicated)", len(tasks))
	}
}

func TestPlan_OneLostOneAlive_OneTask(t *testing.T) {
	entries := []index.FileEntry{{
		Path: "a.txt",
		Chunks: []index.ChunkRef{
			chunkRef(1, 200, pub('A'), pub('B')),
		},
	}}
	tasks := replication.Plan(entries, [][]byte{pub('A')}, lostIf('B'), 2)
	if len(tasks) != 1 {
		t.Fatalf("Plan = %d tasks, want 1", len(tasks))
	}
	got := tasks[0]
	if got.EntryPath != "a.txt" {
		t.Errorf("EntryPath = %q, want a.txt", got.EntryPath)
	}
	if got.ChunkIndex != 0 {
		t.Errorf("ChunkIndex = %d, want 0", got.ChunkIndex)
	}
	if got.NeedCount != 1 {
		t.Errorf("NeedCount = %d, want 1", got.NeedCount)
	}
	if got.Size != 200 {
		t.Errorf("Size = %d, want 200", got.Size)
	}
	if got.CiphertextHash[0] != 1 {
		t.Errorf("CiphertextHash[0] = %d, want 1", got.CiphertextHash[0])
	}
	if !pubsEqual(got.AliveSources, [][]byte{pub('A')}) {
		t.Errorf("AliveSources = %v, want [A]", got.AliveSources)
	}
	if !pubsEqual(got.ExistingPeers, [][]byte{pub('A'), pub('B')}) {
		t.Errorf("ExistingPeers = %v, want [A,B]", got.ExistingPeers)
	}
}

func TestPlan_OneInGracePeriod_NoTask(t *testing.T) {
	entries := []index.FileEntry{{
		Path: "a.txt",
		Chunks: []index.ChunkRef{
			chunkRef(1, 100, pub('A'), pub('B')),
		},
	}}
	tasks := replication.Plan(entries, [][]byte{pub('A')}, neverLost, 2)
	if len(tasks) != 0 {
		t.Errorf("Plan = %d tasks, want 0 (B in grace, not yet lost)", len(tasks))
	}
}

func TestPlan_AllLost_TaskWithEmptySources(t *testing.T) {
	entries := []index.FileEntry{{
		Path: "a.txt",
		Chunks: []index.ChunkRef{
			chunkRef(1, 100, pub('A'), pub('B')),
		},
	}}
	tasks := replication.Plan(entries, nil, lostIf('A', 'B'), 2)
	if len(tasks) != 1 {
		t.Fatalf("Plan = %d tasks, want 1", len(tasks))
	}
	got := tasks[0]
	if got.NeedCount != 2 {
		t.Errorf("NeedCount = %d, want 2", got.NeedCount)
	}
	if len(got.AliveSources) != 0 {
		t.Errorf("AliveSources = %v, want []", got.AliveSources)
	}
}

func TestPlan_AliveButNoLiveConn(t *testing.T) {
	entries := []index.FileEntry{{
		Path: "a.txt",
		Chunks: []index.ChunkRef{
			chunkRef(1, 100, pub('A'), pub('B')),
		},
	}}
	tasks := replication.Plan(entries, nil, lostIf('B'), 2)
	if len(tasks) != 1 {
		t.Fatalf("Plan = %d tasks, want 1", len(tasks))
	}
	got := tasks[0]
	if got.NeedCount != 1 {
		t.Errorf("NeedCount = %d, want 1", got.NeedCount)
	}
	if len(got.AliveSources) != 0 {
		t.Errorf("AliveSources = %v, want [] (A alive but no live conn)", got.AliveSources)
	}
}

func TestPlan_RedundancyBumped_BackFills(t *testing.T) {
	entries := []index.FileEntry{{
		Path: "a.txt",
		Chunks: []index.ChunkRef{
			chunkRef(1, 100, pub('A')),
		},
	}}
	tasks := replication.Plan(entries, [][]byte{pub('A')}, neverLost, 2)
	if len(tasks) != 1 {
		t.Fatalf("Plan = %d tasks, want 1", len(tasks))
	}
	if tasks[0].NeedCount != 1 {
		t.Errorf("NeedCount = %d, want 1", tasks[0].NeedCount)
	}
}

func TestPlan_MultipleChunksAndEntries(t *testing.T) {
	entries := []index.FileEntry{
		{
			Path: "a.txt",
			Chunks: []index.ChunkRef{
				chunkRef(1, 100, pub('A'), pub('B')), // OK
				chunkRef(2, 100, pub('A')),           // need 1
			},
		},
		{
			Path: "b.txt",
			Chunks: []index.ChunkRef{
				chunkRef(3, 100, pub('A'), pub('C')), // need 1 (C lost)
			},
		},
	}
	tasks := replication.Plan(entries, [][]byte{pub('A'), pub('B')}, lostIf('C'), 2)
	if len(tasks) != 2 {
		t.Fatalf("Plan = %d tasks, want 2", len(tasks))
	}
	if tasks[0].EntryPath != "a.txt" || tasks[0].ChunkIndex != 1 {
		t.Errorf("task[0] = %s/%d, want a.txt/1", tasks[0].EntryPath, tasks[0].ChunkIndex)
	}
	if tasks[1].EntryPath != "b.txt" || tasks[1].ChunkIndex != 0 {
		t.Errorf("task[1] = %s/%d, want b.txt/0", tasks[1].EntryPath, tasks[1].ChunkIndex)
	}
}

func TestPlan_RedundancyZero_NoTasks(t *testing.T) {
	entries := []index.FileEntry{{
		Path: "a.txt",
		Chunks: []index.ChunkRef{
			chunkRef(1, 100, pub('A')),
		},
	}}
	tasks := replication.Plan(entries, nil, lostIf('A'), 0)
	if len(tasks) != 0 {
		t.Errorf("Plan with R=0 = %d tasks, want 0", len(tasks))
	}
}

func TestPlan_NilLostFn_TreatedAsNeverLost(t *testing.T) {
	entries := []index.FileEntry{{
		Path: "a.txt",
		Chunks: []index.ChunkRef{
			chunkRef(1, 100, pub('A'), pub('B')),
		},
	}}
	tasks := replication.Plan(entries, [][]byte{pub('A'), pub('B')}, nil, 2)
	if len(tasks) != 0 {
		t.Errorf("Plan(nil lostFn) = %d tasks, want 0", len(tasks))
	}
}

func pubsEqual(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
