package swarm_test

import (
	"bytes"
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/swarm"
)

func recoverPub(b byte) ed25519.PublicKey {
	p := make(ed25519.PublicKey, 32)
	p[0] = b
	return p
}

func TestSetOnRecover_LostThenReachable_FiresCallback(t *testing.T) {
	clk := newManualClock()
	r := swarm.NewReachabilityMapWithGrace(2, time.Hour, clk.Now)

	var mu sync.Mutex
	var got [][]byte
	r.SetOnRecover(func(pub []byte) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, append([]byte(nil), pub...))
	})

	pub := recoverPub('A')
	r.Mark(pub, swarm.StateUnreachable)
	clk.Advance(2 * time.Hour) // past grace
	if !r.IsLost(pub) {
		t.Fatalf("precondition: peer should be lost")
	}
	r.Mark(pub, swarm.StateReachable)

	mu.Lock()
	defer mu.Unlock()
	if len(got) != 1 {
		t.Fatalf("OnRecover fired %d times, want 1", len(got))
	}
	if !bytes.Equal(got[0], pub) {
		t.Errorf("OnRecover pub = %x, want %x", got[0], pub)
	}
}

func TestSetOnRecover_ShortFlapBelowGrace_DoesNotFire(t *testing.T) {
	clk := newManualClock()
	r := swarm.NewReachabilityMapWithGrace(2, time.Hour, clk.Now)
	fired := false
	r.SetOnRecover(func([]byte) { fired = true })

	pub := recoverPub('B')
	r.Mark(pub, swarm.StateUnreachable)
	clk.Advance(30 * time.Minute) // below grace
	r.Mark(pub, swarm.StateReachable)

	if fired {
		t.Error("OnRecover fired for a sub-grace flap")
	}
}

func TestSetOnRecover_FreshReachable_NeverLost_DoesNotFire(t *testing.T) {
	clk := newManualClock()
	r := swarm.NewReachabilityMapWithGrace(2, time.Hour, clk.Now)
	fired := false
	r.SetOnRecover(func([]byte) { fired = true })

	r.Mark(recoverPub('C'), swarm.StateReachable)

	if fired {
		t.Error("OnRecover fired on first-ever-reachable peer")
	}
}

func TestSetOnRecover_RecordHeartbeatTrue_AfterLost_Fires(t *testing.T) {
	clk := newManualClock()
	r := swarm.NewReachabilityMapWithGrace(2, time.Hour, clk.Now)
	calls := 0
	r.SetOnRecover(func([]byte) { calls++ })

	pub := recoverPub('D')
	r.Mark(pub, swarm.StateUnreachable)
	clk.Advance(2 * time.Hour)
	r.RecordHeartbeat(pub, true)

	if calls != 1 {
		t.Errorf("OnRecover calls = %d, want 1 via RecordHeartbeat", calls)
	}
}

func TestSetOnRecover_NilCallback_NoPanic(t *testing.T) {
	clk := newManualClock()
	r := swarm.NewReachabilityMapWithGrace(2, time.Hour, clk.Now)
	r.SetOnRecover(nil)

	pub := recoverPub('E')
	r.Mark(pub, swarm.StateUnreachable)
	clk.Advance(2 * time.Hour)
	r.Mark(pub, swarm.StateReachable) // must not panic
}

func TestSetOnRecover_NoGraceEnabled_NoFire(t *testing.T) {
	r := swarm.NewReachabilityMap()
	calls := 0
	r.SetOnRecover(func([]byte) { calls++ })

	pub := recoverPub('F')
	r.Mark(pub, swarm.StateUnreachable)
	r.Mark(pub, swarm.StateReachable)

	if calls != 0 {
		t.Errorf("OnRecover calls = %d, want 0 when grace not enabled", calls)
	}
}
