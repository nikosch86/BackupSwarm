package daemon

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

func TestReplicateOnce_RedundancyZero_NoOp(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	reach := swarm.NewReachabilityMapWithGrace(3, time.Hour, nil)
	replicateOnce(context.Background(), idx, nil, reach, 0)
}

func TestReplicateOnce_NilIndex_NoOp(t *testing.T) {
	reach := swarm.NewReachabilityMapWithGrace(3, time.Hour, nil)
	replicateOnce(context.Background(), nil, nil, reach, 2)
}

func TestReplicateOnce_NilReach_NoOp(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	replicateOnce(context.Background(), idx, nil, nil, 2)
}

func TestReplicateOnce_EmptyIndex_NoOp(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	reach := swarm.NewReachabilityMapWithGrace(3, time.Hour, nil)
	replicateOnce(context.Background(), idx, nil, reach, 2)
}

func TestReplicateOnce_ClosedIndex_LogsAndReturns(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("idx.Close: %v", err)
	}
	reach := swarm.NewReachabilityMapWithGrace(3, time.Hour, nil)
	replicateOnce(context.Background(), idx, nil, reach, 2)
}

func TestToReplicationConns(t *testing.T) {
	if got := toReplicationConns(nil); len(got) != 0 {
		t.Errorf("nil input -> len %d, want 0", len(got))
	}
	if got := toReplicationConns([]*bsquic.Conn{}); len(got) != 0 {
		t.Errorf("empty input -> len %d, want 0", len(got))
	}
	in := []*bsquic.Conn{nil, nil}
	got := toReplicationConns(in)
	if len(got) != len(in) {
		t.Fatalf("len = %d, want %d", len(got), len(in))
	}
	for i, c := range got {
		if c.(*bsquic.Conn) != in[i] {
			t.Errorf("got[%d] = %v, want %v", i, c, in[i])
		}
	}
}
