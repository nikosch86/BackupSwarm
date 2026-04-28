package daemon

import (
	"bytes"
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

func TestProbeAllPings_RecordsResults(t *testing.T) {
	okConn, okPub := newProbeConn(t)
	failConn, failPub := newProbeConn(t)

	orig := pingProbeFunc
	t.Cleanup(func() { pingProbeFunc = orig })
	pingProbeFunc = func(_ context.Context, c *bsquic.Conn) error {
		if bytes.Equal(c.RemotePub(), failPub) {
			return errors.New("simulated failure")
		}
		return nil
	}

	reach := swarm.NewReachabilityMap()
	probeAllPings(context.Background(), []*bsquic.Conn{okConn, failConn}, reach, 500*time.Millisecond)

	if got := reach.State(okPub); got != swarm.StateReachable {
		t.Errorf("ok peer: got %v, want StateReachable", got)
	}
	if got := reach.State(failPub); got != swarm.StateSuspect {
		t.Errorf("fail peer (1 miss, threshold=3): got %v, want StateSuspect", got)
	}
}

func TestProbeAllPings_SlowProbeBoundedByTimeout(t *testing.T) {
	slowConn, slowPub := newProbeConn(t)
	fastConn, fastPub := newProbeConn(t)

	timeout := 100 * time.Millisecond
	orig := pingProbeFunc
	t.Cleanup(func() { pingProbeFunc = orig })
	pingProbeFunc = func(ctx context.Context, c *bsquic.Conn) error {
		if bytes.Equal(c.RemotePub(), slowPub) {
			select {
			case <-time.After(10 * time.Second):
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return nil
	}

	reach := swarm.NewReachabilityMap()
	start := time.Now()
	probeAllPings(context.Background(), []*bsquic.Conn{slowConn, fastConn}, reach, timeout)
	elapsed := time.Since(start)

	maxAcceptable := timeout + 500*time.Millisecond
	if elapsed > maxAcceptable {
		t.Fatalf("probeAllPings took %v, want < %v", elapsed, maxAcceptable)
	}
	if got := reach.State(slowPub); got != swarm.StateSuspect {
		t.Errorf("slow peer: got %v, want StateSuspect (1 miss)", got)
	}
	if got := reach.State(fastPub); got != swarm.StateReachable {
		t.Errorf("fast peer: got %v, want StateReachable", got)
	}
}

func TestProbeAllPings_FanOutIsConcurrent(t *testing.T) {
	connA, _ := newProbeConn(t)
	connB, _ := newProbeConn(t)

	probeDelay := 80 * time.Millisecond
	timeout := 500 * time.Millisecond
	orig := pingProbeFunc
	t.Cleanup(func() { pingProbeFunc = orig })
	pingProbeFunc = func(ctx context.Context, _ *bsquic.Conn) error {
		select {
		case <-time.After(probeDelay):
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	reach := swarm.NewReachabilityMap()
	start := time.Now()
	probeAllPings(context.Background(), []*bsquic.Conn{connA, connB}, reach, timeout)
	elapsed := time.Since(start)

	if elapsed >= 2*probeDelay {
		t.Fatalf("probeAllPings took %v with 2 conns × %v; serial behavior detected", elapsed, probeDelay)
	}
}

func TestProbeAllPings_SkipsConnsWithEmptyPub(t *testing.T) {
	orig := pingProbeFunc
	t.Cleanup(func() { pingProbeFunc = orig })
	called := false
	pingProbeFunc = func(_ context.Context, _ *bsquic.Conn) error {
		called = true
		return nil
	}
	probeAllPings(context.Background(), []*bsquic.Conn{nil}, swarm.NewReachabilityMap(), 100*time.Millisecond)
	if called {
		t.Error("pingProbeFunc invoked for nil conn")
	}
}

// Zero-value Conn is non-nil but RemotePub() returns nil, so the
// len(pub) == 0 guard fires before the probe is dispatched.
func TestProbeAllPings_SkipsConnsWithZeroValuePub(t *testing.T) {
	orig := pingProbeFunc
	t.Cleanup(func() { pingProbeFunc = orig })
	called := false
	pingProbeFunc = func(_ context.Context, _ *bsquic.Conn) error {
		called = true
		return nil
	}
	probeAllPings(context.Background(), []*bsquic.Conn{{}}, swarm.NewReachabilityMap(), 100*time.Millisecond)
	if called {
		t.Error("pingProbeFunc invoked for empty-pub conn")
	}
}

func TestRunHeartbeatLoop_TicksAndStopsOnCancel(t *testing.T) {
	conn, _ := newProbeConn(t)

	var calls atomic.Int32
	orig := pingProbeFunc
	t.Cleanup(func() { pingProbeFunc = orig })
	pingProbeFunc = func(_ context.Context, _ *bsquic.Conn) error {
		calls.Add(1)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runHeartbeatLoop(ctx, heartbeatLoopOptions{
			interval: 50 * time.Millisecond,
			connsFn:  func() []*bsquic.Conn { return []*bsquic.Conn{conn} },
			reach:    swarm.NewReachabilityMap(),
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("only %d probe calls fired in 2s with 50ms interval", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runHeartbeatLoop did not exit on ctx cancel")
	}
}
