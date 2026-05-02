package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
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

// fakePacketConn is a no-op net.PacketConn used to enable the TURN step
// without standing up a real socket. The chain never reads from it; the
// chainTURNDialFn seam is what tests actually exercise.
type fakePacketConn struct{}

func (f *fakePacketConn) ReadFrom([]byte) (int, net.Addr, error) { return 0, nil, errors.New("noop") }
func (f *fakePacketConn) WriteTo([]byte, net.Addr) (int, error)  { return 0, nil }
func (f *fakePacketConn) Close() error                           { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr                    { return &net.UDPAddr{} }
func (f *fakePacketConn) SetDeadline(time.Time) error            { return nil }
func (f *fakePacketConn) SetReadDeadline(time.Time) error        { return nil }
func (f *fakePacketConn) SetWriteDeadline(time.Time) error       { return nil }

// stubChainSeams swaps chainDirectDialFn, chainPunchFn, and
// chainTURNDialFn for the duration of the test. Each fn closes over
// counters so tests can assert how often it ran.
type chainSeamCounts struct {
	direct atomic.Int32
	punch  atomic.Int32
	turn   atomic.Int32
}

func swapChainSeams(t *testing.T,
	direct func(ctx context.Context, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error),
	punchFn func(ctx context.Context, po *punchOrchestrator, target ed25519.PublicKey, rdv *bsquic.Conn) (*bsquic.Conn, error),
	turn func(ctx context.Context, pc net.PacketConn, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error),
) *chainSeamCounts {
	t.Helper()
	cnt := &chainSeamCounts{}
	prevDirect, prevPunch, prevTURN := chainDirectDialFn, chainPunchFn, chainTURNDialFn
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
	chainTURNDialFn = func(ctx context.Context, pc net.PacketConn, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error) {
		cnt.turn.Add(1)
		if turn == nil {
			return nil, errors.New("turn: no seam")
		}
		return turn(ctx, pc, addr, priv, expected, trust)
	}
	t.Cleanup(func() {
		chainDirectDialFn, chainPunchFn, chainTURNDialFn = prevDirect, prevPunch, prevTURN
	})
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
		func(context.Context, net.PacketConn, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return want, nil
		})

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet() // empty → no rendezvous
	opts.turnPC = &fakePacketConn{}

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
		func(context.Context, net.PacketConn, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return want, nil
		})

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnPC = &fakePacketConn{}

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
		func(context.Context, net.PacketConn, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return nil, turnErr
		})

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.punchOrch = &punchOrchestrator{}
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnPC = &fakePacketConn{}

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
		func(context.Context, net.PacketConn, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
			return want, nil
		})

	target := chainTestTarget(t)
	opts := chainTestOpts(target)
	opts.punchOrch = nil // disabled
	opts.connSet = swarm.NewConnSet()
	stubRendezvousConn(t, opts.connSet)
	opts.turnPC = &fakePacketConn{}

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
	opts.turnPC = nil

	_, _, err := chainDial(context.Background(), opts)
	if err == nil {
		t.Fatal("chainDial err = nil, want non-nil")
	}
	if cnt.turn.Load() != 0 {
		t.Errorf("turn called %d times despite nil turnPC", cnt.turn.Load())
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
