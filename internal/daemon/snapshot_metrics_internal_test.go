package daemon

import (
	"context"
	"testing"
	"time"

	"backupswarm/internal/metrics"
	bsquic "backupswarm/internal/quic"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestSnapshotToMetrics_ProjectsRuntimeSnapshot(t *testing.T) {
	t.Parallel()

	snap := RuntimeSnapshot{
		LocalStore: RuntimeStoreSnapshot{Used: 100, Capacity: 1000},
		OwnBackup:  RuntimeOwnBackupSnapshot{Files: 4, Bytes: 2048, Chunks: 6, ReplMin: 1, ReplMax: 3, ReplAvg: 2.5},
		Peers: []RuntimePeerSnapshot{
			{PubKeyHex: "aa", Reach: "reachable"},
			{PubKeyHex: "bb", Reach: "reachable"},
			{PubKeyHex: "cc", Reach: "suspect"},
			{PubKeyHex: "dd", Reach: "unreachable"},
		},
	}

	in := snapshotToMetrics(snap)

	if in.PeerStateCounts["reachable"] != 2 {
		t.Errorf("reachable count = %d, want 2", in.PeerStateCounts["reachable"])
	}
	if in.PeerStateCounts["suspect"] != 1 {
		t.Errorf("suspect count = %d, want 1", in.PeerStateCounts["suspect"])
	}
	if in.PeerStateCounts["unreachable"] != 1 {
		t.Errorf("unreachable count = %d, want 1", in.PeerStateCounts["unreachable"])
	}
	if in.StoreUsed != 100 {
		t.Errorf("StoreUsed = %d, want 100", in.StoreUsed)
	}
	if in.StoreCapacity != 1000 {
		t.Errorf("StoreCapacity = %d, want 1000", in.StoreCapacity)
	}
	if in.OwnFiles != 4 {
		t.Errorf("OwnFiles = %d, want 4", in.OwnFiles)
	}
	if in.OwnBytes != 2048 {
		t.Errorf("OwnBytes = %d, want 2048", in.OwnBytes)
	}
	if in.OwnChunks != 6 {
		t.Errorf("OwnChunks = %d, want 6", in.OwnChunks)
	}
	if in.ReplMin != 1 {
		t.Errorf("ReplMin = %d, want 1", in.ReplMin)
	}
	if in.ReplMax != 3 {
		t.Errorf("ReplMax = %d, want 3", in.ReplMax)
	}
	if in.ReplAvg != 2.5 {
		t.Errorf("ReplAvg = %v, want 2.5", in.ReplAvg)
	}
}

func TestSnapshotToMetrics_EmptyPeerListProducesEmptyMap(t *testing.T) {
	t.Parallel()

	in := snapshotToMetrics(RuntimeSnapshot{})

	if len(in.PeerStateCounts) != 0 {
		t.Errorf("PeerStateCounts = %v, want empty", in.PeerStateCounts)
	}
}

func TestSnapshotLoop_UpdatesPromGauges(t *testing.T) {
	t.Parallel()

	prom := metrics.NewProm()
	dir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSnapshotLoop(ctx, snapshotLoopOptions{
			dataDir:      dir,
			interval:     time.Hour,
			listenAddr:   "addr",
			modeFn:       func() string { return "reconcile" },
			connsFn:      func() []*bsquic.Conn { return nil },
			lastScanFn:   func() time.Time { return time.Time{} },
			storeStatsFn: func() (int64, int64) { return 7, 11 },
			ownBackupFn: func() RuntimeOwnBackupSnapshot {
				return RuntimeOwnBackupSnapshot{Files: 1, Bytes: 2, Chunks: 3, ReplMin: 1, ReplMax: 1, ReplAvg: 1}
			},
			prom: prom,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		_, err := ReadRuntimeSnapshot(dir)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("snapshot never appeared: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	if got := testutil.ToFloat64(prom.StoreUsed()); got != 7 {
		t.Errorf("store_used = %v, want 7", got)
	}
	if got := testutil.ToFloat64(prom.StoreCapacity()); got != 11 {
		t.Errorf("store_capacity = %v, want 11", got)
	}
	if got := testutil.ToFloat64(prom.OwnBackupFiles()); got != 1 {
		t.Errorf("own_backup_files = %v, want 1", got)
	}
}
