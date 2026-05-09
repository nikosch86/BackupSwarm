package metrics_test

import (
	"testing"

	"backupswarm/internal/metrics"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestProm_PerEventCountersIncrementOnAddX(t *testing.T) {
	t.Parallel()

	p := metrics.NewProm()
	c := &metrics.Counters{}
	c.SetProm(p)

	c.AddBytesUp(100)
	c.AddBytesDown(50)
	c.AddFilesBackedUp()
	c.AddFilesBackedUp()
	c.AddChunksStored()

	if got := testutil.ToFloat64(p.BytesUp()); got != 100 {
		t.Errorf("BytesUp prom counter = %v, want 100", got)
	}
	if got := testutil.ToFloat64(p.BytesDown()); got != 50 {
		t.Errorf("BytesDown prom counter = %v, want 50", got)
	}
	if got := testutil.ToFloat64(p.FilesBackedUp()); got != 2 {
		t.Errorf("FilesBackedUp prom counter = %v, want 2", got)
	}
	if got := testutil.ToFloat64(p.ChunksStored()); got != 1 {
		t.Errorf("ChunksStored prom counter = %v, want 1", got)
	}
}

func TestProm_LoadAndResetDoesNotResetPromCounters(t *testing.T) {
	t.Parallel()

	p := metrics.NewProm()
	c := &metrics.Counters{}
	c.SetProm(p)

	c.AddBytesUp(1024)
	c.AddBytesDown(2048)
	c.AddFilesBackedUp()
	c.AddChunksStored()

	snap := c.LoadAndReset()
	if snap.BytesUp != 1024 || snap.BytesDown != 2048 || snap.FilesBackedUp != 1 || snap.ChunksStored != 1 {
		t.Fatalf("first LoadAndReset = %+v, want full deltas", snap)
	}

	if got := testutil.ToFloat64(p.BytesUp()); got != 1024 {
		t.Errorf("prom BytesUp = %v after LoadAndReset, want 1024 (monotonic)", got)
	}
	if got := testutil.ToFloat64(p.BytesDown()); got != 2048 {
		t.Errorf("prom BytesDown = %v after LoadAndReset, want 2048 (monotonic)", got)
	}
	if got := testutil.ToFloat64(p.FilesBackedUp()); got != 1 {
		t.Errorf("prom FilesBackedUp = %v after LoadAndReset, want 1 (monotonic)", got)
	}
	if got := testutil.ToFloat64(p.ChunksStored()); got != 1 {
		t.Errorf("prom ChunksStored = %v after LoadAndReset, want 1 (monotonic)", got)
	}

	c.AddBytesUp(10)
	if got := testutil.ToFloat64(p.BytesUp()); got != 1034 {
		t.Errorf("prom BytesUp after second add = %v, want 1034", got)
	}
}

func TestProm_NilProm_AddXStaysAtomicOnly(t *testing.T) {
	t.Parallel()

	c := &metrics.Counters{}
	c.AddBytesUp(7)
	c.AddBytesDown(11)
	c.AddFilesBackedUp()
	c.AddChunksStored()

	snap := c.LoadAndReset()
	if snap.BytesUp != 7 || snap.BytesDown != 11 || snap.FilesBackedUp != 1 || snap.ChunksStored != 1 {
		t.Errorf("zero-value Counters with no Prom: snap = %+v, want full deltas", snap)
	}
}

func TestProm_UpdateFromSnapshot_PopulatesGauges(t *testing.T) {
	t.Parallel()

	p := metrics.NewProm()

	in := metrics.SnapshotInput{
		PeerStateCounts: map[string]int{
			"reachable":   3,
			"suspect":     1,
			"unreachable": 2,
			"unknown":     0,
		},
		StoreUsed:     1024,
		StoreCapacity: 4096,
		OwnFiles:      5,
		OwnBytes:      2048,
		OwnChunks:     7,
		ReplMin:       1,
		ReplMax:       3,
		ReplAvg:       2.0,
	}
	p.UpdateFromSnapshot(in)

	if got := testutil.ToFloat64(p.PeersByState("reachable")); got != 3 {
		t.Errorf("peers{state=reachable} = %v, want 3", got)
	}
	if got := testutil.ToFloat64(p.PeersByState("suspect")); got != 1 {
		t.Errorf("peers{state=suspect} = %v, want 1", got)
	}
	if got := testutil.ToFloat64(p.PeersByState("unreachable")); got != 2 {
		t.Errorf("peers{state=unreachable} = %v, want 2", got)
	}
	if got := testutil.ToFloat64(p.PeersByState("unknown")); got != 0 {
		t.Errorf("peers{state=unknown} = %v, want 0", got)
	}
	if got := testutil.ToFloat64(p.StoreUsed()); got != 1024 {
		t.Errorf("StoreUsed = %v, want 1024", got)
	}
	if got := testutil.ToFloat64(p.StoreCapacity()); got != 4096 {
		t.Errorf("StoreCapacity = %v, want 4096", got)
	}
	if got := testutil.ToFloat64(p.OwnBackupFiles()); got != 5 {
		t.Errorf("OwnBackupFiles = %v, want 5", got)
	}
	if got := testutil.ToFloat64(p.OwnBackupBytes()); got != 2048 {
		t.Errorf("OwnBackupBytes = %v, want 2048", got)
	}
	if got := testutil.ToFloat64(p.OwnBackupChunks()); got != 7 {
		t.Errorf("OwnBackupChunks = %v, want 7", got)
	}
	if got := testutil.ToFloat64(p.ReplicationMin()); got != 1 {
		t.Errorf("ReplicationMin = %v, want 1", got)
	}
	if got := testutil.ToFloat64(p.ReplicationMax()); got != 3 {
		t.Errorf("ReplicationMax = %v, want 3", got)
	}
	if got := testutil.ToFloat64(p.ReplicationAvg()); got != 2.0 {
		t.Errorf("ReplicationAvg = %v, want 2.0", got)
	}
}

func TestProm_UpdateFromSnapshot_ClearsAbsentPeerStates(t *testing.T) {
	t.Parallel()

	p := metrics.NewProm()

	first := metrics.SnapshotInput{
		PeerStateCounts: map[string]int{"reachable": 5, "suspect": 2},
	}
	p.UpdateFromSnapshot(first)

	second := metrics.SnapshotInput{
		PeerStateCounts: map[string]int{"reachable": 3},
	}
	p.UpdateFromSnapshot(second)

	if got := testutil.ToFloat64(p.PeersByState("reachable")); got != 3 {
		t.Errorf("after second snapshot, peers{state=reachable} = %v, want 3", got)
	}
	if got := testutil.ToFloat64(p.PeersByState("suspect")); got != 0 {
		t.Errorf("after second snapshot, peers{state=suspect} = %v, want 0 (state should be cleared)", got)
	}
}

func TestProm_RegistryGatherProducesAllFamilies(t *testing.T) {
	t.Parallel()

	p := metrics.NewProm()
	c := &metrics.Counters{}
	c.SetProm(p)
	c.AddBytesUp(1)
	p.UpdateFromSnapshot(metrics.SnapshotInput{
		PeerStateCounts: map[string]int{"reachable": 1},
		StoreUsed:       1, StoreCapacity: 2, OwnFiles: 1, OwnBytes: 1, OwnChunks: 1,
		ReplMin: 1, ReplMax: 1, ReplAvg: 1,
	})

	mfs, err := p.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := map[string]bool{}
	for _, mf := range mfs {
		got[mf.GetName()] = true
	}
	want := []string{
		"backupswarm_files_backed_up_total",
		"backupswarm_chunks_stored_total",
		"backupswarm_bytes_up_total",
		"backupswarm_bytes_down_total",
		"backupswarm_peers",
		"backupswarm_store_used_bytes",
		"backupswarm_store_capacity_bytes",
		"backupswarm_own_backup_files",
		"backupswarm_own_backup_bytes",
		"backupswarm_own_backup_chunks",
		"backupswarm_replication_min",
		"backupswarm_replication_max",
		"backupswarm_replication_avg",
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing metric family %s; got %v", name, mapKeys(got))
		}
	}
}

func mapKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestProm_RegistersGoAndProcessCollectors asserts the standard Go runtime
// and process collectors are registered alongside the BackupSwarm metrics
// so operators get goroutine count, memstats, and process CPU/memory
// without extra wiring.
func TestProm_RegistersGoAndProcessCollectors(t *testing.T) {
	t.Parallel()

	p := metrics.NewProm()
	mfs, err := p.Registry().Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	got := map[string]bool{}
	for _, mf := range mfs {
		got[mf.GetName()] = true
	}
	for _, name := range []string{
		"go_goroutines",
		"go_memstats_alloc_bytes",
		"process_cpu_seconds_total",
	} {
		if !got[name] {
			t.Errorf("missing standard collector metric %s; got %v", name, mapKeys(got))
		}
	}
}
