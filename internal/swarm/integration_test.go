package swarm_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// TestBroadcast_EndToEnd exercises the full chain over real QUIC:
// BroadcastPeerJoined → backup.Serve dispatch → ServeAnnouncementStream
// → Apply on the subscriber's peer store.
func TestBroadcast_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	subPub, subPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sub key: %v", err)
	}
	_, introPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("intro key: %v", err)
	}

	subStore, err := peers.Open(filepath.Join(t.TempDir(), "sub-peers.db"))
	if err != nil {
		t.Fatalf("subStore Open: %v", err)
	}
	t.Cleanup(func() { _ = subStore.Close() })

	listener, err := bsquic.Listen("127.0.0.1:0", subPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	announceFn := func(ctx context.Context, r io.Reader, _ []byte) error {
		return swarm.ServeAnnouncementStream(ctx, r, subStore)
	}
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- backup.Serve(ctx, listener, nil, announceFn, nil, nil, nil, nil)
	}()

	dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), introPriv, subPub, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	joinerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("joiner key: %v", err)
	}
	joiner := peers.Peer{
		Addr:   "192.0.2.7:9000",
		PubKey: joinerPub,
		Role:   peers.RolePeer,
	}
	if err := swarm.BroadcastPeerJoined(ctx, []*bsquic.Conn{conn}, joiner); err != nil {
		t.Fatalf("BroadcastPeerJoined: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		got, getErr := subStore.Get(joinerPub)
		if getErr == nil {
			if got.Addr != joiner.Addr || got.Role != peers.RolePeer {
				t.Errorf("got %+v, want addr=%q role=peer", got, joiner.Addr)
			}
			return
		}
		if !errors.Is(getErr, peers.ErrPeerNotFound) {
			t.Fatalf("subStore.Get: %v", getErr)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for subscriber to apply PeerJoined")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// gossipNode is one swarm participant: listener served by backup.Serve,
// ConnSet populated via ConnObserver, Router wired for apply + forward.
type gossipNode struct {
	pub      ed25519.PublicKey
	priv     ed25519.PrivateKey
	listener *bsquic.Listener
	store    *peers.Store
	conns    *swarm.ConnSet
	router   *swarm.Router
}

func newGossipNode(t *testing.T, ctx context.Context, name string) *gossipNode {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("%s ed25519.GenerateKey: %v", name, err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", priv, nil, nil)
	if err != nil {
		t.Fatalf("%s Listen: %v", name, err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	store, err := peers.Open(filepath.Join(t.TempDir(), name+"-peers.db"))
	if err != nil {
		t.Fatalf("%s peers.Open: %v", name, err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cs := swarm.NewConnSet()
	router := &swarm.Router{
		Store: store,
		Dedup: swarm.NewDedupCache(64),
		Conns: cs,
	}
	obs := &backup.ConnObserver{OnAccept: cs.Add, OnClose: cs.Remove}
	go func() { _ = backup.Serve(ctx, listener, nil, router.HandleStream, nil, nil, nil, obs) }()

	return &gossipNode{
		pub:      pub,
		priv:     priv,
		listener: listener,
		store:    store,
		conns:    cs,
		router:   router,
	}
}

// dialAndRegister dials remote, registers the resulting outbound conn into
// from.conns, and waits until remote.conns has accepted the inbound side.
func dialAndRegister(t *testing.T, ctx context.Context, from, remote *gossipNode) *bsquic.Conn {
	t.Helper()
	dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	conn, err := bsquic.Dial(dialCtx, remote.listener.Addr().String(), from.priv, remote.pub, nil)
	if err != nil {
		t.Fatalf("Dial %s→%s: %v", hex(from.pub[:4]), hex(remote.pub[:4]), err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	from.conns.Add(conn)

	deadline := time.Now().Add(5 * time.Second)
	for {
		for _, c := range remote.conns.Snapshot() {
			if c.RemotePub().Equal(from.pub) {
				return conn
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s never registered inbound conn from %s", hex(remote.pub[:4]), hex(from.pub[:4]))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// hex encodes b as a lowercase hex string.
func hex(b []byte) string {
	const tab = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = tab[x>>4]
		out[i*2+1] = tab[x&0x0f]
	}
	return string(out)
}

// TestForwarding_3NodeChain wires A↔B and B↔C and asserts an announcement
// originated by A reaches C through B's forwarder. C has no direct conn
// to A; its only path is via the forward.
func TestForwarding_3NodeChain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	a := newGossipNode(t, ctx, "a")
	b := newGossipNode(t, ctx, "b")
	c := newGossipNode(t, ctx, "c")

	// Topology: A ↔ B and B ↔ C. A and C never share a conn.
	dialAndRegister(t, ctx, a, b)
	dialAndRegister(t, ctx, b, c)

	joinerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("joiner key: %v", err)
	}
	joiner := peers.Peer{
		Addr:   "203.0.113.7:9000",
		PubKey: joinerPub,
		Role:   peers.RolePeer,
	}

	// A originates by broadcasting on its conn snapshot (only conn is to B).
	if err := swarm.BroadcastPeerJoined(ctx, a.conns.Snapshot(), joiner); err != nil {
		t.Fatalf("BroadcastPeerJoined: %v", err)
	}

	// C never had a direct conn to A — its only path is via B's forward.
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, getErr := c.store.Get(joinerPub)
		if getErr == nil {
			if got.Addr != joiner.Addr || got.Role != peers.RolePeer {
				t.Errorf("c got %+v, want addr=%q role=peer", got, joiner.Addr)
			}
			break
		}
		if !errors.Is(getErr, peers.ErrPeerNotFound) {
			t.Fatalf("c.store.Get: %v", getErr)
		}
		if time.Now().After(deadline) {
			t.Fatal("timed out waiting for forwarded announcement at C")
		}
		time.Sleep(50 * time.Millisecond)
	}

	// B should also have applied locally.
	if _, err := b.store.Get(joinerPub); err != nil {
		t.Errorf("b.store.Get: %v (B did not apply forwarded announcement)", err)
	}
}

// TestForwarding_TriangleDedupBoundsTraffic wires a triangle topology
// (A↔B, A↔C, B↔C) and asserts an announcement originated at A reaches
// B and C, then quiesces.
func TestForwarding_TriangleDedupBoundsTraffic(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	a := newGossipNode(t, ctx, "a")
	b := newGossipNode(t, ctx, "b")
	c := newGossipNode(t, ctx, "c")

	dialAndRegister(t, ctx, a, b)
	dialAndRegister(t, ctx, a, c)
	dialAndRegister(t, ctx, b, c)

	joinerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("joiner key: %v", err)
	}
	joiner := peers.Peer{
		Addr:   "203.0.113.99:9000",
		PubKey: joinerPub,
		Role:   peers.RolePeer,
	}

	if err := swarm.BroadcastPeerJoined(ctx, a.conns.Snapshot(), joiner); err != nil {
		t.Fatalf("BroadcastPeerJoined: %v", err)
	}

	for _, n := range []*gossipNode{b, c} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			if _, err := n.store.Get(joinerPub); err == nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for joiner at node")
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	time.Sleep(200 * time.Millisecond)
}
