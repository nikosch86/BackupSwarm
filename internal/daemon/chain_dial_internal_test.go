package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// fakeChainConn is a non-nil sentinel returned by stubbed direct/turn/
// punch seams. The chain only checks for nil, so an empty *bsquic.Conn
// pointer suffices — no test ever dereferences it.
func fakeChainConn() *bsquic.Conn { return &bsquic.Conn{} }

// stubTurnDialer enables the TURN step without standing up a real
// allocation. The chain never invokes DialPeer directly — the
// chainTURNDialFn seam intercepts before reaching the receiver.
type stubTurnDialer struct{}

func (stubTurnDialer) DialPeer(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
	return nil, errors.New("stubTurnDialer: DialPeer should be intercepted by chainTURNDialFn seam")
}

// stubChainSeams swaps chainDirectDialFn, chainPunchFn, and
// chainTURNDialFn for the duration of the test. Each fn closes over
// counters so tests can assert how often it ran.
type chainSeamCounts struct {
	direct atomic.Int32
	punch  atomic.Int32
	turn   atomic.Int32
	relay  atomic.Int32
}

func swapChainSeams(t *testing.T,
	direct func(ctx context.Context, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error),
	punchFn func(ctx context.Context, po *punchOrchestrator, target ed25519.PublicKey, rdv *bsquic.Conn) (*bsquic.Conn, error),
	turn func(ctx context.Context, l turnRelayDialer, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error),
) *chainSeamCounts {
	t.Helper()
	cnt := &chainSeamCounts{}
	prevDirect, prevPunch, prevTURN, prevRelay := chainDirectDialFn, chainPunchFn, chainTURNDialFn, chainRelayDialFn
	chainDirectDialFn = func(ctx context.Context, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error) {
		cnt.direct.Add(1)
		if direct == nil {
			return nil, errors.New("direct: no seam")
		}
		return direct(ctx, addr, priv, expected, trust)
	}
	chainPunchFn = func(ctx context.Context, po *punchOrchestrator, target ed25519.PublicKey, rdv *bsquic.Conn) (*bsquic.Conn, error) {
		cnt.punch.Add(1)
		if punchFn == nil {
			return nil, errors.New("punch: no seam")
		}
		return punchFn(ctx, po, target, rdv)
	}
	chainTURNDialFn = func(ctx context.Context, l turnRelayDialer, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error) {
		cnt.turn.Add(1)
		if turn == nil {
			return nil, errors.New("turn: no seam")
		}
		return turn(ctx, l, addr, priv, expected, trust)
	}
	chainRelayDialFn = func(ctx context.Context, l turnRelayDialer, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error) {
		cnt.relay.Add(1)
		return nil, errors.New("relay: no seam")
	}
	t.Cleanup(func() {
		chainDirectDialFn, chainPunchFn, chainTURNDialFn, chainRelayDialFn = prevDirect, prevPunch, prevTURN, prevRelay
	})
	return cnt
}

// swapChainSeamsWithRelay extends swapChainSeams with an explicit relay
// fn. The four-arg variant defaults the relay seam to a no-op error so
// existing tests that don't exercise the relay rung stay unchanged.
func swapChainSeamsWithRelay(t *testing.T,
	direct func(ctx context.Context, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error),
	punchFn func(ctx context.Context, po *punchOrchestrator, target ed25519.PublicKey, rdv *bsquic.Conn) (*bsquic.Conn, error),
	turn func(ctx context.Context, l turnRelayDialer, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error),
	relay func(ctx context.Context, l turnRelayDialer, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error),
) *chainSeamCounts {
	t.Helper()
	cnt := swapChainSeams(t, direct, punchFn, turn)
	prevRelay := chainRelayDialFn
	chainRelayDialFn = func(ctx context.Context, l turnRelayDialer, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error) {
		cnt.relay.Add(1)
		if relay == nil {
			return nil, errors.New("relay: no seam")
		}
		return relay(ctx, l, addr, priv, expected, trust)
	}
	t.Cleanup(func() { chainRelayDialFn = prevRelay })
	return cnt
}

func chainTestTarget(t *testing.T) peers.Peer {
	t.Helper()
	return peers.Peer{
		PubKey: mustGenPub(t),
		Role:   peers.RoleStorage,
		Addr:   "203.0.113.1:9000",
	}
}

func chainTestOpts(target peers.Peer) chainDialOptions {
	return chainDialOptions{
		target:        target,
		priv:          ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)),
		directTimeout: 30 * time.Second,
		punchTimeout:  5 * time.Second,
		turnTimeout:   15 * time.Second,
		relayTimeout:  15 * time.Second,
	}
}

// Direct succeeds → punch & turn never run, method = "direct".
func TestChainDial_DirectSuccess(t *testing.T) {
	want := fakeChainConn()
	cnt := swapChainSeams(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return want, nil
		},
		nil, nil)

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	conn, method, err := chainDial(context.Background(), opts)
	if err != nil {
		t.Fatalf("chainDial err = %v, want nil", err)
	}
	if conn != want {
		t.Errorf("conn = %p, want %p", conn, want)
	}
	if method != chainMethodDirect {
		t.Errorf("method = %q, want %q", method, chainMethodDirect)
	}
	if cnt.punch.Load() != 0 || cnt.turn.Load() != 0 {
		t.Errorf("punch=%d turn=%d, want 0/0 when direct succeeds", cnt.punch.Load(), cnt.turn.Load())
	}
}

// Direct fails, punch succeeds with a rendezvous → turn never runs,
// method = "hole_punch".
func TestChainDial_DirectFails_PunchSucceeds(t *testing.T) {
	want := fakeChainConn()
	cnt := swapChainSeams(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("direct boom")
		},
		func(context.Context, *punchOrchestrator, ed25519.PublicKey, *bsquic.Conn) (*bsquic.Conn, error) {
			return want, nil
		},
		nil)

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)

	conn, method, err := chainDial(context.Background(), opts)
	if err != nil {
		t.Fatalf("chainDial err = %v, want nil", err)
	}
	if conn != want {
		t.Errorf("conn = %p, want %p", conn, want)
	}
	if method != chainMethodHolePunch {
		t.Errorf("method = %q, want %q", method, chainMethodHolePunch)
	}
	if cnt.turn.Load() != 0 {
		t.Errorf("turn called %d times despite punch success", cnt.turn.Load())
	}
}

// Direct fails, no rendezvous, turn succeeds → punch step is skipped
// (no rendezvous), method = "turn".
func TestChainDial_DirectFails_NoRendezvous_TURNSucceeds(t *testing.T) {
	want := fakeChainConn()
	cnt := swapChainSeams(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("direct boom")
		},
		nil,
		func(context.Context, turnRelayDialer, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return want, nil
		})

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet() // empty → no rendezvous
	opts.turnListener = stubTurnDialer{}

	conn, method, err := chainDial(context.Background(), opts)
	if err != nil {
		t.Fatalf("chainDial err = %v, want nil", err)
	}
	if conn != want {
		t.Errorf("conn = %p, want %p", conn, want)
	}
	if method != chainMethodTURN {
		t.Errorf("method = %q, want %q", method, chainMethodTURN)
	}
	if cnt.punch.Load() != 0 {
		t.Errorf("punch called %d times despite empty connSet", cnt.punch.Load())
	}
}

// Direct fails, punch fails, turn succeeds → method = "turn".
func TestChainDial_FallthroughToTURN(t *testing.T) {
	want := fakeChainConn()
	swapChainSeams(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("direct boom")
		},
		func(context.Context, *punchOrchestrator, ed25519.PublicKey, *bsquic.Conn) (*bsquic.Conn, error) {
			return nil, errors.New("punch boom")
		},
		func(context.Context, turnRelayDialer, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return want, nil
		})

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnListener = stubTurnDialer{}

	conn, method, err := chainDial(context.Background(), opts)
	if err != nil {
		t.Fatalf("chainDial err = %v, want nil", err)
	}
	if conn != want {
		t.Errorf("conn = %p, want %p", conn, want)
	}
	if method != chainMethodTURN {
		t.Errorf("method = %q, want %q", method, chainMethodTURN)
	}
}

// All three steps fail → joined error covers all three; conn nil; method "".
func TestChainDial_AllFail(t *testing.T) {
	directErr := errors.New("direct boom")
	punchErr := errors.New("punch boom")
	turnErr := errors.New("turn boom")
	swapChainSeams(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, directErr
		},
		func(context.Context, *punchOrchestrator, ed25519.PublicKey, *bsquic.Conn) (*bsquic.Conn, error) {
			return nil, punchErr
		},
		func(context.Context, turnRelayDialer, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, turnErr
		})

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnListener = stubTurnDialer{}

	conn, method, err := chainDial(context.Background(), opts)
	if err == nil {
		t.Fatal("chainDial err = nil, want non-nil")
	}
	if conn != nil {
		t.Errorf("conn = %p, want nil on full failure", conn)
	}
	if method != "" {
		t.Errorf("method = %q, want empty on full failure", method)
	}
	if !errors.Is(err, directErr) {
		t.Errorf("err missing directErr: %v", err)
	}
	if !errors.Is(err, punchErr) {
		t.Errorf("err missing punchErr: %v", err)
	}
	if !errors.Is(err, turnErr) {
		t.Errorf("err missing turnErr: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"direct", "hole_punch", "turn"} {
		if !strings.Contains(msg, want) {
			t.Errorf("err.Error() = %q, missing %q", msg, want)
		}
	}
}

// punchOrch nil → punch step skipped, no chainPunchFn call.
func TestChainDial_NilPunchOrch_SkipsPunchStep(t *testing.T) {
	want := fakeChainConn()
	cnt := swapChainSeams(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("direct boom")
		},
		nil,
		func(context.Context, turnRelayDialer, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return want, nil
		})

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.punchOrch = nil // disabled
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnListener = stubTurnDialer{}

	conn, method, err := chainDial(context.Background(), opts)
	if err != nil {
		t.Fatalf("chainDial err = %v, want nil", err)
	}
	if method != chainMethodTURN {
		t.Errorf("method = %q, want %q", method, chainMethodTURN)
	}
	if cnt.punch.Load() != 0 {
		t.Errorf("punch called %d times despite nil punchOrch", cnt.punch.Load())
	}
	_ = conn
}

// turnPC nil → turn step skipped; chain returns the joined direct+punch
// errors and never invokes the turn seam.
func TestChainDial_NilTURNPC_SkipsTURNStep(t *testing.T) {
	cnt := swapChainSeams(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("direct boom")
		},
		func(context.Context, *punchOrchestrator, ed25519.PublicKey, *bsquic.Conn) (*bsquic.Conn, error) {
			return nil, errors.New("punch boom")
		},
		nil)

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnListener = nil

	_, _, err := chainDial(context.Background(), opts)
	if err == nil {
		t.Fatal("chainDial err = nil, want non-nil")
	}
	if cnt.turn.Load() != 0 {
		t.Errorf("turn called %d times despite nil turnListener", cnt.turn.Load())
	}
}

// pickRendezvous skips the target's own conn — punch must use a third
// party as the rendezvous.
func TestChainDial_PickRendezvous_ExcludesTarget(t *testing.T) {
	target := chainTestTarget(t)
	if _, ok := pickRendezvous(nil, target.PubKey); ok {
		t.Fatal("nil connSet returned a rendezvous")
	}
	cs := swarm.NewConnSet()
	if rdv, ok := pickRendezvous(cs, target.PubKey); ok {
		t.Fatalf("empty connSet returned rdv = %v", rdv)
	}
	cs.Add(stubConnWithPub(target.PubKey))
	if _, ok := pickRendezvous(cs, target.PubKey); ok {
		t.Fatal("pickRendezvous returned the target's own conn as rendezvous")
	}
}

// A blocking direct seam is cancelled at directTimeout; the chain moves
// to punch with its own full budget and the parent ctx stays alive.
func TestChainDial_DirectTimeout_DoesNotCancelChain(t *testing.T) {
	wantPunch := fakeChainConn()
	swapChainSeams(t,
		func(ctx context.Context, _ string, _ ed25519.PrivateKey, _ ed25519.PublicKey, _ *bsquic.TrustConfig) (*bsquic.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
		func(ctx context.Context, _ *punchOrchestrator, _ ed25519.PublicKey, _ *bsquic.Conn) (*bsquic.Conn, error) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			return wantPunch, nil
		},
		nil)

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.directTimeout = 50 * time.Millisecond
	opts.punchTimeout = 5 * time.Second
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)

	parentCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	t.Cleanup(cancel)
	start := time.Now()
	conn, method, err := chainDial(parentCtx, opts)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("chainDial err = %v, want nil", err)
	}
	if conn != wantPunch {
		t.Errorf("conn = %p, want %p", conn, wantPunch)
	}
	if method != chainMethodHolePunch {
		t.Errorf("method = %q, want %q", method, chainMethodHolePunch)
	}
	if elapsed > 1*time.Second {
		t.Errorf("chain took %v; direct timeout did not free the chain", elapsed)
	}
	if parentCtx.Err() != nil {
		t.Errorf("parent ctx err = %v, want nil (per-step timeout must not cancel parent)", parentCtx.Err())
	}
}

// stubRendezvousConn registers a non-target conn in cs so the punch
// step's rendezvous picker has something to return. Returns the conn so
// the caller can keep a reference (avoids GC of the live entry).
func stubRendezvousConn(t *testing.T, cs *swarm.ConnSet) *bsquic.Conn {
	t.Helper()
	c := bsquic.NewConnForTest(mustGenPub(t))
	cs.Add(c)
	return c
}

// stubConnWithPub returns a sentinel *bsquic.Conn with only RemotePub
// set — safe for ConnSet membership checks in unit tests.
func stubConnWithPub(pub ed25519.PublicKey) *bsquic.Conn {
	return bsquic.NewConnForTest(pub)
}

// Direct, punch, turn all fail; relay rung dials target.RelayAddr via
// the turnListener and succeeds → method = "relay".
func TestChainDial_RelaySucceeds_WithTURNListener(t *testing.T) {
	want := fakeChainConn()
	var sawAddr atomic.Value
	cnt := swapChainSeamsWithRelay(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("direct boom")
		},
		func(context.Context, *punchOrchestrator, ed25519.PublicKey, *bsquic.Conn) (*bsquic.Conn, error) {
			return nil, errors.New("punch boom")
		},
		func(context.Context, turnRelayDialer, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("turn boom")
		},
		func(_ context.Context, l turnRelayDialer, addr string, _ ed25519.PrivateKey, _ ed25519.PublicKey, _ *bsquic.TrustConfig) (*bsquic.Conn, error) {
			if l == nil {
				return nil, errors.New("relay: turnListener missing")
			}
			sawAddr.Store(addr)
			return want, nil
		})

	target := chainTestTarget(t)
	target.RelayAddr = "203.0.113.5:3478"
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnListener = stubTurnDialer{}

	conn, method, err := chainDial(context.Background(), opts)
	if err != nil {
		t.Fatalf("chainDial err = %v, want nil", err)
	}
	if conn != want {
		t.Errorf("conn = %p, want %p", conn, want)
	}
	if method != chainMethodRelay {
		t.Errorf("method = %q, want %q", method, chainMethodRelay)
	}
	if cnt.relay.Load() != 1 {
		t.Errorf("relay step ran %d times, want 1", cnt.relay.Load())
	}
	if got := sawAddr.Load(); got == nil || got.(string) != target.RelayAddr {
		t.Errorf("relay seam saw addr = %v, want target.RelayAddr %q", got, target.RelayAddr)
	}
}

// Direct, punch fail, no turn listener; relay rung still attempts via
// the direct-fallback path. The seam fires regardless of turnListener
// presence — production code branches inside the seam.
func TestChainDial_RelaySucceeds_WithoutTURNListener(t *testing.T) {
	want := fakeChainConn()
	cnt := swapChainSeamsWithRelay(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("direct boom")
		},
		func(context.Context, *punchOrchestrator, ed25519.PublicKey, *bsquic.Conn) (*bsquic.Conn, error) {
			return nil, errors.New("punch boom")
		},
		nil,
		func(_ context.Context, l turnRelayDialer, addr string, _ ed25519.PrivateKey, _ ed25519.PublicKey, _ *bsquic.TrustConfig) (*bsquic.Conn, error) {
			if l != nil {
				return nil, errors.New("relay: expected turnListener nil for this case")
			}
			if addr != "203.0.113.5:3478" {
				return nil, errors.New("relay: wrong addr " + addr)
			}
			return want, nil
		})

	target := chainTestTarget(t)
	target.RelayAddr = "203.0.113.5:3478"
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnListener = nil // production seam falls back to bsquic.Dial

	conn, method, err := chainDial(context.Background(), opts)
	if err != nil {
		t.Fatalf("chainDial err = %v, want nil", err)
	}
	if conn != want {
		t.Errorf("conn = %p, want %p", conn, want)
	}
	if method != chainMethodRelay {
		t.Errorf("method = %q, want %q", method, chainMethodRelay)
	}
	if cnt.turn.Load() != 0 {
		t.Errorf("turn step ran %d times despite nil turnListener", cnt.turn.Load())
	}
	if cnt.relay.Load() != 1 {
		t.Errorf("relay step ran %d times, want 1", cnt.relay.Load())
	}
}

// All four rungs fail when target.RelayAddr is set → joined error
// includes "relay" alongside the other three step labels.
func TestChainDial_AllFourFail_RelayInJoinedError(t *testing.T) {
	relayErr := errors.New("relay boom")
	swapChainSeamsWithRelay(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("direct boom")
		},
		func(context.Context, *punchOrchestrator, ed25519.PublicKey, *bsquic.Conn) (*bsquic.Conn, error) {
			return nil, errors.New("punch boom")
		},
		func(context.Context, turnRelayDialer, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("turn boom")
		},
		func(context.Context, turnRelayDialer, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, relayErr
		})

	target := chainTestTarget(t)
	target.RelayAddr = "203.0.113.5:3478"
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnListener = stubTurnDialer{}

	conn, method, err := chainDial(context.Background(), opts)
	if err == nil {
		t.Fatal("chainDial err = nil, want non-nil")
	}
	if conn != nil {
		t.Errorf("conn = %p, want nil on full failure", conn)
	}
	if method != "" {
		t.Errorf("method = %q, want empty on full failure", method)
	}
	if !errors.Is(err, relayErr) {
		t.Errorf("err missing relayErr: %v", err)
	}
	if !strings.Contains(err.Error(), "relay") {
		t.Errorf("err.Error() = %q, missing 'relay'", err.Error())
	}
}

// Empty target.RelayAddr → relay rung is skipped, the joined error
// only includes the three other step labels.
func TestChainDial_EmptyRelayAddr_SkipsRelayStep(t *testing.T) {
	cnt := swapChainSeamsWithRelay(t,
		func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("direct boom")
		},
		func(context.Context, *punchOrchestrator, ed25519.PublicKey, *bsquic.Conn) (*bsquic.Conn, error) {
			return nil, errors.New("punch boom")
		},
		func(context.Context, turnRelayDialer, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, errors.New("turn boom")
		},
		func(context.Context, turnRelayDialer, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return fakeChainConn(), nil // would succeed if reached
		})

	target := chainTestTarget(t)
	target.RelayAddr = "" // explicit
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnListener = stubTurnDialer{}

	_, _, err := chainDial(context.Background(), opts)
	if err == nil {
		t.Fatal("chainDial err = nil, want non-nil (relay skipped, all reachable rungs fail)")
	}
	if cnt.relay.Load() != 0 {
		t.Errorf("relay step ran %d times despite empty target.RelayAddr", cnt.relay.Load())
	}
	if strings.Contains(err.Error(), "relay") {
		t.Errorf("err.Error() = %q, must not include 'relay' when rung was skipped", err.Error())
	}
}
