package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// 3-node loopback rig (rendezvous, initiator, target) with the direct
// step forced to fail; outboundDialer.dial routes through chainDial,
// hole-punch succeeds, register emits peer connected method=hole_punch.
func TestChainDial_E2E_DirectFailsFallsThroughToPunch(t *testing.T) {
	// Package-level chainDirectDialFn / punchFireFn forbid t.Parallel
	// alongside other tests that mutate the same vars.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	r := newPunchNode(t, ctx, "rendezvous")
	a := newPunchNode(t, ctx, "initiator")
	b := newPunchNode(t, ctx, "target")

	if err := r.peerStore.Add(peers.Peer{PubKey: a.pub, Role: peers.RoleStorage, Addr: a.addr()}); err != nil {
		t.Fatalf("r.peerStore.Add(A): %v", err)
	}
	if err := r.peerStore.Add(peers.Peer{PubKey: b.pub, Role: peers.RoleStorage, Addr: b.addr()}); err != nil {
		t.Fatalf("r.peerStore.Add(B): %v", err)
	}
	if err := a.peerStore.Add(peers.Peer{PubKey: b.pub, Role: peers.RoleStorage, Addr: b.addr()}); err != nil {
		t.Fatalf("a.peerStore.Add(B): %v", err)
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	t.Cleanup(dialCancel)
	aToR, err := bsquic.Dial(dialCtx, r.addr(), a.priv, r.pub, nil)
	if err != nil {
		t.Fatalf("A → R dial: %v", err)
	}
	t.Cleanup(func() { _ = aToR.Close() })
	go backup.AcceptStreams(ctx, aToR, nil, nil, nil, a.orch.handleRequest, a.orch.handleSignal)

	bToR, err := bsquic.Dial(dialCtx, r.addr(), b.priv, r.pub, nil)
	if err != nil {
		t.Fatalf("B → R dial: %v", err)
	}
	t.Cleanup(func() { _ = bToR.Close() })
	go backup.AcceptStreams(ctx, bToR, nil, nil, nil, b.orch.handleRequest, b.orch.handleSignal)

	waitForConnSet(t, r.connSet, 2, 3*time.Second)

	// A registers the rendezvous conn to R so pickRendezvous has a
	// non-target candidate.
	a.connSet.Add(aToR)

	// Force the direct step to fail so the chain has to fall through.
	prevDirect := chainDirectDialFn
	chainDirectDialFn = func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
		return nil, errors.New("direct: forced failure")
	}
	t.Cleanup(func() { chainDirectDialFn = prevDirect })

	w := &syncWriter{}
	captureSlog(t, w)

	dialer := &outboundDialer{
		ctx:          ctx,
		priv:         a.priv,
		timeout:      200 * time.Millisecond,
		punchTimeout: 5 * time.Second,
		turnTimeout:  1 * time.Second,
		connSet:      a.connSet,
		reach:        swarm.NewReachabilityMap(),
		punchOrch:    a.orch,
	}
	t.Cleanup(dialer.CloseAll)

	target := peers.Peer{PubKey: b.pub, Role: peers.RoleStorage, Addr: b.addr()}
	conn, err := dialer.dial(ctx, target)
	if err != nil {
		t.Fatalf("dialer.dial err = %v, want nil (direct fails, punch should succeed)", err)
	}
	if !conn.RemotePub().Equal(b.pub) {
		t.Errorf("conn.RemotePub mismatch: got %x, want %x", conn.RemotePub(), b.pub)
	}

	b.orch.pendingPunches.Wait()

	logged := w.String()
	if !strings.Contains(logged, "peer connected") {
		t.Errorf("missing 'peer connected' log line; buffer:\n%s", logged)
	}
	if !strings.Contains(logged, `method=hole_punch`) {
		t.Errorf("log line missing method=hole_punch; buffer:\n%s", logged)
	}
	if !strings.Contains(logged, "peer_pub="+hex.EncodeToString(b.pub)) {
		t.Errorf("log line missing target peer_pub; buffer:\n%s", logged)
	}
	for _, want := range []string{
		"chain_dial: start",
		"chain_dial: direct attempt",
		"chain_dial: direct failed",
		"chain_dial: hole_punch attempt",
		"chain_dial: hole_punch succeeded",
	} {
		if !strings.Contains(logged, want) {
			t.Errorf("missing debug breadcrumb %q; buffer:\n%s", want, logged)
		}
	}

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream on dialer-returned conn: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("stream.Close: %v", err)
	}
}

// Confirms outboundDialer.dial routes through chainDial (and not a
// residual direct call). All three step seams stubbed; dialer fails on
// the all-fail path so register's log line never fires.
func TestChainDial_OutboundDialerUsesChain(t *testing.T) {
	directCalled := make(chan struct{}, 1)
	prevDirect := chainDirectDialFn
	chainDirectDialFn = func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
		select {
		case directCalled <- struct{}{}:
		default:
		}
		return nil, errors.New("direct: stubbed")
	}
	t.Cleanup(func() { chainDirectDialFn = prevDirect })

	priv := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	d := &outboundDialer{
		ctx:          context.Background(),
		priv:         priv,
		timeout:      100 * time.Millisecond,
		punchTimeout: 100 * time.Millisecond,
		turnTimeout:  100 * time.Millisecond,
		connSet:      swarm.NewConnSet(),
		reach:        swarm.NewReachabilityMap(),
	}

	target := peers.Peer{PubKey: mustGenPub(t), Role: peers.RoleStorage, Addr: "127.0.0.1:1"}
	conn, err := d.dial(context.Background(), target)
	if err == nil {
		t.Fatalf("dial returned nil err; want error from stubbed chain")
	}
	if conn != nil {
		t.Errorf("dial returned non-nil conn on chain failure")
	}
	select {
	case <-directCalled:
	default:
		t.Errorf("direct seam was never called; outboundDialer is not routing through chainDial")
	}
	if !strings.Contains(err.Error(), "direct: stubbed") {
		t.Errorf("err = %v; want wraps 'direct: stubbed'", err)
	}
}
