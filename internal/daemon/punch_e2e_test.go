package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/nat"
	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// punchNode is one participant in the e2e punch test (rendezvous,
// initiator, or target). It owns a real listener + peer store + conn
// set + orchestrator, all on loopback.
type punchNode struct {
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
	listener  *bsquic.Listener
	peerStore *peers.Store
	connSet   *swarm.ConnSet
	orch      *punchOrchestrator
}

func newPunchNode(t *testing.T, ctx context.Context, name string) *punchNode {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%s gen key: %v", name, err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", priv, nil, nil)
	if err != nil {
		t.Fatalf("%s listen: %v", name, err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	ps, err := peers.Open(filepath.Join(t.TempDir(), name+"-peers.db"))
	if err != nil {
		t.Fatalf("%s peers.Open: %v", name, err)
	}
	t.Cleanup(func() { _ = ps.Close() })

	connSet := swarm.NewConnSet()
	orch := newPunchOrchestrator(ctx, listener, connSet, ps, priv, listener.Addr().String())
	orch.attempts = 2
	orch.interval = 10 * time.Millisecond

	obs := &backup.ConnObserver{
		OnAccept: func(c *bsquic.Conn) { connSet.Add(c) },
		OnClose:  func(c *bsquic.Conn) { connSet.Remove(c) },
	}
	go func() {
		_ = backup.Serve(ctx, listener, nil, nil, nil, orch.handleRequest, orch.handleSignal, obs)
	}()
	return &punchNode{
		pub:       pub,
		priv:      priv,
		listener:  listener,
		peerStore: ps,
		connSet:   connSet,
		orch:      orch,
	}
}

func (n *punchNode) addr() string { return n.listener.Addr().String() }

// waitForConnSet polls the connSet until size reaches `want` or the
// deadline expires.
func waitForConnSet(t *testing.T, cs *swarm.ConnSet, want int, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if len(cs.Snapshot()) >= want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("connSet size never reached %d (got %d)", want, len(cs.Snapshot()))
}

// TestPunch_E2E_RendezvousRelaysAndBothSidesPunch wires up three real
// loopback nodes (rendezvous, initiator, target), drives a punch
// through them, and asserts both sides fired their UDP probes and the
// initiator ended up with a usable conn to the target.
func TestPunch_E2E_RendezvousRelaysAndBothSidesPunch(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	r := newPunchNode(t, ctx, "rendezvous")
	a := newPunchNode(t, ctx, "initiator")
	b := newPunchNode(t, ctx, "target")

	// R knows A and B (so R can validate punch requests' targets).
	if err := r.peerStore.Add(peers.Peer{PubKey: a.pub, Role: peers.RoleStorage, Addr: a.addr()}); err != nil {
		t.Fatalf("r.peerStore.Add(A): %v", err)
	}
	if err := r.peerStore.Add(peers.Peer{PubKey: b.pub, Role: peers.RoleStorage, Addr: b.addr()}); err != nil {
		t.Fatalf("r.peerStore.Add(B): %v", err)
	}
	// A knows B (so RequestPunch can resolve B's addr).
	if err := a.peerStore.Add(peers.Peer{PubKey: b.pub, Role: peers.RoleStorage, Addr: b.addr()}); err != nil {
		t.Fatalf("a.peerStore.Add(B): %v", err)
	}

	// A and B both dial R so R's connSet populates with both.
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

	// Wrap punchFireFn so we can assert both sides fired without losing
	// the real punch behavior.
	var punchCount atomic.Int32
	prev := punchFireFn
	punchFireFn = func(ctx context.Context, pc nat.PacketWriter, target *net.UDPAddr, attempts int, interval time.Duration) error {
		punchCount.Add(1)
		return prev(ctx, pc, target, attempts, interval)
	}
	t.Cleanup(func() { punchFireFn = prev })

	// Drive the punch from A → B via R as the rendezvous.
	punchCtx, punchCancel := context.WithTimeout(ctx, 5*time.Second)
	t.Cleanup(punchCancel)
	conn, err := a.orch.RequestPunch(punchCtx, b.pub, aToR)
	if err != nil {
		t.Fatalf("RequestPunch: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Wait for B's target-side punch goroutine.
	b.orch.pendingPunches.Wait()

	if got := punchCount.Load(); got < 2 {
		t.Errorf("punchFireFn fired %d times, want >= 2 (initiator + target)", got)
	}

	// Sanity: the punched conn is real — opening a stream succeeds.
	stream, err := conn.OpenStream(punchCtx)
	if err != nil {
		t.Fatalf("OpenStream on punched conn: %v", err)
	}
	if err := protocol.WriteMessageType(stream, protocol.MsgPing); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	if err := stream.Close(); err != nil {
		t.Fatalf("stream Close: %v", err)
	}
	if appErr, err := protocol.ReadPingResponse(stream); err != nil || appErr != "" {
		t.Fatalf("ping over punched conn: appErr=%q err=%v", appErr, err)
	}

	// Confirm initiator's pubkey is what the conn reports.
	if !conn.RemotePub().Equal(b.pub) {
		t.Errorf("conn.RemotePub mismatch: got %x, want %x", conn.RemotePub(), b.pub)
	}
}
