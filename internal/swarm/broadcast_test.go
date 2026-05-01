package swarm_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// quicPair wires up an introducer-style listener and N subscriber dials,
// returning the introducer-side conns (for broadcasting) and the
// subscriber-side conns (for inbound stream reads). All resources are
// cleaned up via t.Cleanup.
type quicPair struct {
	introPub  ed25519.PublicKey
	introPriv ed25519.PrivateKey
	listener  *bsquic.Listener
	// introSide[i] / subSide[i] are the two ends of subscriber i's connection.
	introSide []*bsquic.Conn
	subSide   []*bsquic.Conn
}

func setupQuicPair(t *testing.T, n int) *quicPair {
	t.Helper()
	introPub, introPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("intro key: %v", err)
	}
	l, err := bsquic.Listen("127.0.0.1:0", introPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	rig := &quicPair{
		introPub:  introPub,
		introPriv: introPriv,
		listener:  l,
		introSide: make([]*bsquic.Conn, n),
		subSide:   make([]*bsquic.Conn, n),
	}

	for i := 0; i < n; i++ {
		_, subPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("sub %d key: %v", i, err)
		}

		dialedCh := make(chan *bsquic.Conn, 1)
		dialErrCh := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := bsquic.Dial(ctx, l.Addr().String(), subPriv, introPub, nil)
			if err != nil {
				dialErrCh <- err
				return
			}
			dialedCh <- c
		}()
		acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 5*time.Second)
		introConn, err := l.Accept(acceptCtx)
		acceptCancel()
		if err != nil {
			t.Fatalf("Accept sub %d: %v", i, err)
		}
		var subConn *bsquic.Conn
		select {
		case subConn = <-dialedCh:
		case err := <-dialErrCh:
			t.Fatalf("Dial sub %d: %v", i, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("Dial sub %d timed out", i)
		}
		rig.introSide[i] = introConn
		rig.subSide[i] = subConn
		t.Cleanup(func() {
			_ = introConn.Close()
			_ = subConn.Close()
		})
	}
	return rig
}

func TestBroadcastPeerJoined_FansOutToAllConns(t *testing.T) {
	rig := setupQuicPair(t, 3)
	joinerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("joiner key: %v", err)
	}
	joiner := peers.Peer{
		Addr:   "192.0.2.7:9000",
		PubKey: joinerPub,
		Role:   peers.RolePeer,
	}

	// Each subscriber accepts an inbound stream, reads the message type +
	// announcement frame, and reports what it saw.
	type recv struct {
		ann protocol.PeerAnnouncement
		err error
	}
	results := make(chan recv, len(rig.subSide))
	var wg sync.WaitGroup
	for _, sub := range rig.subSide {
		sub := sub
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s, err := sub.AcceptStream(ctx)
			if err != nil {
				results <- recv{err: err}
				return
			}
			defer func() { _ = s.Close() }()
			mt, err := protocol.ReadMessageType(s)
			if err != nil {
				results <- recv{err: err}
				return
			}
			if mt != protocol.MsgPeerAnnouncement {
				results <- recv{err: errFromString("unexpected message type")}
				return
			}
			ann, err := protocol.ReadPeerAnnouncement(s, 1<<10)
			results <- recv{ann: ann, err: err}
		}()
	}

	if err := swarm.BroadcastPeerJoined(context.Background(), rig.introSide, joiner); err != nil {
		t.Fatalf("BroadcastPeerJoined: %v", err)
	}
	wg.Wait()
	close(results)

	for r := range results {
		if r.err != nil {
			t.Errorf("subscriber recv: %v", r.err)
			continue
		}
		if r.ann.Kind != protocol.AnnouncePeerJoined {
			t.Errorf("kind = %v, want PeerJoined", r.ann.Kind)
		}
		if r.ann.Addr != joiner.Addr {
			t.Errorf("addr = %q, want %q", r.ann.Addr, joiner.Addr)
		}
		if r.ann.Role != byte(joiner.Role) {
			t.Errorf("role = %d, want %d", r.ann.Role, joiner.Role)
		}
		var wantPub [32]byte
		copy(wantPub[:], joinerPub)
		if r.ann.PubKey != wantPub {
			t.Errorf("pubkey mismatch")
		}
	}
}

func TestBroadcastPeerJoined_FillsRandomID(t *testing.T) {
	rig := setupQuicPair(t, 1)
	joinerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("joiner key: %v", err)
	}
	joiner := peers.Peer{
		Addr:   "192.0.2.7:9000",
		PubKey: joinerPub,
		Role:   peers.RolePeer,
	}

	// Capture the announcement received over the wire across two broadcasts;
	// IDs must be non-zero and distinct between calls.
	receive := func() protocol.PeerAnnouncement {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := rig.subSide[0].AcceptStream(ctx)
		if err != nil {
			t.Fatalf("AcceptStream: %v", err)
		}
		defer func() { _ = s.Close() }()
		if _, err := protocol.ReadMessageType(s); err != nil {
			t.Fatalf("ReadMessageType: %v", err)
		}
		ann, err := protocol.ReadPeerAnnouncement(s, 1<<10)
		if err != nil {
			t.Fatalf("ReadPeerAnnouncement: %v", err)
		}
		return ann
	}

	got := make([]protocol.PeerAnnouncement, 2)
	for i := range got {
		ch := make(chan protocol.PeerAnnouncement, 1)
		go func() { ch <- receive() }()
		if err := swarm.BroadcastPeerJoined(context.Background(), rig.introSide, joiner); err != nil {
			t.Fatalf("BroadcastPeerJoined %d: %v", i, err)
		}
		got[i] = <-ch
	}
	for i, ann := range got {
		var zero [protocol.AnnouncementIDSize]byte
		if ann.ID == zero {
			t.Errorf("broadcast %d: ID is zero", i)
		}
	}
	if got[0].ID == got[1].ID {
		t.Error("two broadcasts emitted the same ID")
	}
}

func TestBroadcastPeerJoined_ContinuesPastDeadConn(t *testing.T) {
	rig := setupQuicPair(t, 2)
	joinerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("joiner key: %v", err)
	}
	joiner := peers.Peer{
		Addr:   "192.0.2.8:9000",
		PubKey: joinerPub,
		Role:   peers.RolePeer,
	}

	// Kill the first subscriber's connection so OpenStream fails on
	// rig.introSide[0]. The broadcast must still deliver to subscriber 1.
	if err := rig.introSide[0].Close(); err != nil {
		t.Fatalf("Close introSide[0]: %v", err)
	}
	_ = rig.subSide[0].Close()

	resultCh := make(chan protocol.PeerAnnouncement, 1)
	errCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := rig.subSide[1].AcceptStream(ctx)
		if err != nil {
			errCh <- err
			return
		}
		defer func() { _ = s.Close() }()
		if _, err := protocol.ReadMessageType(s); err != nil {
			errCh <- err
			return
		}
		ann, err := protocol.ReadPeerAnnouncement(s, 1<<10)
		if err != nil {
			errCh <- err
			return
		}
		resultCh <- ann
	}()

	if err := swarm.BroadcastPeerJoined(context.Background(), rig.introSide, joiner); err != nil {
		t.Fatalf("BroadcastPeerJoined: %v", err)
	}
	select {
	case ann := <-resultCh:
		if ann.Addr != joiner.Addr {
			t.Errorf("addr = %q, want %q", ann.Addr, joiner.Addr)
		}
	case err := <-errCh:
		t.Fatalf("subscriber 1 recv: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber 1 timed out — broadcast aborted on dead conn?")
	}
}

func TestBroadcastAddressChanged_FansOutToAllConns(t *testing.T) {
	rig := setupQuicPair(t, 3)
	subjPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("subject key: %v", err)
	}

	type recv struct {
		ann protocol.PeerAnnouncement
		err error
	}
	results := make(chan recv, len(rig.subSide))
	var wg sync.WaitGroup
	for _, sub := range rig.subSide {
		sub := sub
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			s, err := sub.AcceptStream(ctx)
			if err != nil {
				results <- recv{err: err}
				return
			}
			defer func() { _ = s.Close() }()
			mt, err := protocol.ReadMessageType(s)
			if err != nil {
				results <- recv{err: err}
				return
			}
			if mt != protocol.MsgPeerAnnouncement {
				results <- recv{err: errFromString("unexpected message type")}
				return
			}
			ann, err := protocol.ReadPeerAnnouncement(s, 1<<10)
			results <- recv{ann: ann, err: err}
		}()
	}

	if err := swarm.BroadcastAddressChanged(context.Background(), rig.introSide, subjPub, "203.0.113.7:9001"); err != nil {
		t.Fatalf("BroadcastAddressChanged: %v", err)
	}
	wg.Wait()
	close(results)

	for r := range results {
		if r.err != nil {
			t.Errorf("subscriber recv: %v", r.err)
			continue
		}
		if r.ann.Kind != protocol.AnnounceAddressChanged {
			t.Errorf("kind = %v, want AddressChanged", r.ann.Kind)
		}
		if r.ann.Addr != "203.0.113.7:9001" {
			t.Errorf("addr = %q, want %q", r.ann.Addr, "203.0.113.7:9001")
		}
		var wantPub [32]byte
		copy(wantPub[:], subjPub)
		if r.ann.PubKey != wantPub {
			t.Errorf("pubkey mismatch")
		}
	}
}

func TestBroadcastAddressChanged_RejectsEmptyAddr(t *testing.T) {
	subjPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("subject key: %v", err)
	}
	if err := swarm.BroadcastAddressChanged(context.Background(), nil, subjPub, ""); err == nil {
		t.Fatal("BroadcastAddressChanged accepted empty addr")
	}
}

func TestBroadcastAddressChanged_RejectsBadPubkey(t *testing.T) {
	if err := swarm.BroadcastAddressChanged(context.Background(), nil, ed25519.PublicKey{0x01, 0x02}, "203.0.113.7:9001"); err == nil {
		t.Fatal("BroadcastAddressChanged accepted short pubkey")
	}
}

func TestBroadcastAddressChanged_FillsRandomID(t *testing.T) {
	rig := setupQuicPair(t, 1)
	subjPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("subject key: %v", err)
	}

	receive := func() protocol.PeerAnnouncement {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := rig.subSide[0].AcceptStream(ctx)
		if err != nil {
			t.Fatalf("AcceptStream: %v", err)
		}
		defer func() { _ = s.Close() }()
		if _, err := protocol.ReadMessageType(s); err != nil {
			t.Fatalf("ReadMessageType: %v", err)
		}
		ann, err := protocol.ReadPeerAnnouncement(s, 1<<10)
		if err != nil {
			t.Fatalf("ReadPeerAnnouncement: %v", err)
		}
		return ann
	}

	got := make([]protocol.PeerAnnouncement, 2)
	for i := range got {
		ch := make(chan protocol.PeerAnnouncement, 1)
		go func() { ch <- receive() }()
		if err := swarm.BroadcastAddressChanged(context.Background(), rig.introSide, subjPub, "203.0.113.7:9001"); err != nil {
			t.Fatalf("BroadcastAddressChanged %d: %v", i, err)
		}
		got[i] = <-ch
	}
	for i, ann := range got {
		var zero [protocol.AnnouncementIDSize]byte
		if ann.ID == zero {
			t.Errorf("broadcast %d: ID is zero", i)
		}
	}
	if got[0].ID == got[1].ID {
		t.Error("two broadcasts emitted the same ID")
	}
}

func errFromString(s string) error { return &simpleErr{s} }

type simpleErr struct{ s string }

func (e *simpleErr) Error() string { return e.s }
