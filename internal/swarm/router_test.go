package swarm_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	"backupswarm/internal/swarm"
)

func mustRouterStore(t *testing.T) *peers.Store {
	t.Helper()
	s, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func encodedAnnouncement(t *testing.T, ann protocol.PeerAnnouncement) *bytes.Reader {
	t.Helper()
	var buf bytes.Buffer
	if err := protocol.WritePeerAnnouncement(&buf, ann); err != nil {
		t.Fatalf("WritePeerAnnouncement: %v", err)
	}
	return bytes.NewReader(buf.Bytes())
}

func TestRouter_HandleStream_AppliesLocally(t *testing.T) {
	store := mustRouterStore(t)
	r := &swarm.Router{Store: store, Dedup: swarm.NewDedupCache(8), Conns: swarm.NewConnSet()}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     id(0xa1),
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}
	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), nil); err != nil {
		t.Fatalf("HandleStream: %v", err)
	}
	got, err := store.Get(pub)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if got.Addr != ann.Addr {
		t.Errorf("addr = %q, want %q", got.Addr, ann.Addr)
	}
}

func TestRouter_HandleStream_DedupSilencesDuplicate(t *testing.T) {
	store := mustRouterStore(t)
	cache := swarm.NewDedupCache(8)
	r := &swarm.Router{Store: store, Dedup: cache, Conns: swarm.NewConnSet()}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     id(0xa2),
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}

	// First call applies and remembers.
	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), nil); err != nil {
		t.Fatalf("HandleStream first: %v", err)
	}
	if err := store.Remove(pub); err != nil {
		t.Fatalf("store.Remove: %v", err)
	}
	// Second call must NOT re-apply (we deleted the record; if dedup
	// short-circuits the call, the store stays empty).
	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), nil); err != nil {
		t.Fatalf("HandleStream second: %v", err)
	}
	if _, err := store.Get(pub); !errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("dedup did not short-circuit second call: store.Get err = %v, want ErrPeerNotFound", err)
	}
}

func TestRouter_HandleStream_ForwardsToOtherConns(t *testing.T) {
	rig := setupQuicPair(t, 2)
	store := mustRouterStore(t)
	cs := swarm.NewConnSet()
	for _, c := range rig.introSide {
		cs.Add(c)
	}
	r := &swarm.Router{Store: store, Dedup: swarm.NewDedupCache(8), Conns: cs}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     id(0xa3),
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}

	// Both subscribers should receive the forwarded announcement.
	results := make(chan protocol.PeerAnnouncement, 2)
	errCh := make(chan error, 2)
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
				errCh <- err
				return
			}
			defer func() { _ = s.Close() }()
			if _, err := protocol.ReadMessageType(s); err != nil {
				errCh <- err
				return
			}
			recv, err := protocol.ReadPeerAnnouncement(s, 1<<10)
			if err != nil {
				errCh <- err
				return
			}
			results <- recv
		}()
	}

	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), nil); err != nil {
		t.Fatalf("HandleStream: %v", err)
	}

	wg.Wait()
	close(results)
	close(errCh)
	for e := range errCh {
		t.Errorf("subscriber recv: %v", e)
	}
	gotCount := 0
	for recv := range results {
		gotCount++
		if recv.ID != ann.ID {
			t.Errorf("forwarded ID mismatch: got %x, want %x", recv.ID, ann.ID)
		}
	}
	if gotCount != 2 {
		t.Errorf("forwarded count = %d, want 2", gotCount)
	}
}

func TestRouter_HandleStream_SkipsSender(t *testing.T) {
	rig := setupQuicPair(t, 2)
	store := mustRouterStore(t)
	cs := swarm.NewConnSet()
	for _, c := range rig.introSide {
		cs.Add(c)
	}
	r := &swarm.Router{Store: store, Dedup: swarm.NewDedupCache(8), Conns: cs}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     id(0xa4),
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}

	// Pretend conn 0 was the sender. We expect ONLY conn 1 to receive.
	senderPub := rig.introSide[0].RemotePub()
	excludedPub := rig.introSide[0].RemotePub()
	receivedPub := rig.introSide[1].RemotePub()

	type recv struct {
		ann protocol.PeerAnnouncement
		err error
	}
	resultCh := make(chan recv, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := rig.subSide[1].AcceptStream(ctx)
		if err != nil {
			resultCh <- recv{err: err}
			return
		}
		defer func() { _ = s.Close() }()
		if _, err := protocol.ReadMessageType(s); err != nil {
			resultCh <- recv{err: err}
			return
		}
		got, err := protocol.ReadPeerAnnouncement(s, 1<<10)
		resultCh <- recv{ann: got, err: err}
	}()

	// Excluded subscriber must NOT see anything; check after a short window.
	excludedCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		_, err := rig.subSide[0].AcceptStream(ctx)
		excludedCh <- err
	}()

	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), senderPub); err != nil {
		t.Fatalf("HandleStream: %v", err)
	}

	select {
	case r := <-resultCh:
		if r.err != nil {
			t.Fatalf("subscriber 1 recv: %v", r.err)
		}
		if r.ann.ID != ann.ID {
			t.Errorf("forwarded ID mismatch: got %x, want %x", r.ann.ID, ann.ID)
		}
		_ = receivedPub
	case <-time.After(5 * time.Second):
		t.Fatal("subscriber 1 did not receive forwarded announcement")
	}

	select {
	case err := <-excludedCh:
		if err == nil {
			t.Errorf("sender's conn (%x) received a forward — must have been excluded", excludedPub[:8])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("excluded probe timed out")
	}
}

func TestRouter_HandleStream_ReadErrorPropagates(t *testing.T) {
	store := mustRouterStore(t)
	r := &swarm.Router{Store: store, Dedup: swarm.NewDedupCache(8), Conns: swarm.NewConnSet()}
	if err := r.HandleStream(context.Background(), bytes.NewReader([]byte{1, 2, 3}), nil); err == nil {
		t.Error("HandleStream accepted truncated frame")
	}
}

func TestRouter_HandleStream_ApplyErrorPropagates(t *testing.T) {
	store := closedStore(t)
	r := &swarm.Router{Store: store, Dedup: swarm.NewDedupCache(8), Conns: swarm.NewConnSet()}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     id(0xa5),
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}
	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), nil); err == nil {
		t.Error("HandleStream succeeded against closed store")
	}
}

func TestRouter_HandleStream_OnAppliedFiresAfterApply(t *testing.T) {
	store := mustRouterStore(t)
	var (
		mu     sync.Mutex
		called []protocol.PeerAnnouncement
	)
	r := &swarm.Router{
		Store: store,
		Dedup: swarm.NewDedupCache(8),
		Conns: swarm.NewConnSet(),
		OnApplied: func(_ context.Context, ann protocol.PeerAnnouncement) {
			mu.Lock()
			defer mu.Unlock()
			called = append(called, ann)
		},
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     id(0xb1),
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.7:9999",
	}
	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), nil); err != nil {
		t.Fatalf("HandleStream: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(called) != 1 {
		t.Fatalf("OnApplied called %d times, want 1", len(called))
	}
	if called[0].ID != ann.ID || called[0].Addr != ann.Addr {
		t.Errorf("OnApplied got ann %+v, want %+v", called[0], ann)
	}
}

func TestRouter_HandleStream_OnAppliedSkippedOnDedup(t *testing.T) {
	store := mustRouterStore(t)
	var calls int32
	cache := swarm.NewDedupCache(8)
	r := &swarm.Router{
		Store: store,
		Dedup: cache,
		Conns: swarm.NewConnSet(),
		OnApplied: func(_ context.Context, _ protocol.PeerAnnouncement) {
			calls++
		},
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     id(0xb2),
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.7:9999",
	}
	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), nil); err != nil {
		t.Fatalf("HandleStream first: %v", err)
	}
	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), nil); err != nil {
		t.Fatalf("HandleStream second: %v", err)
	}
	if calls != 1 {
		t.Errorf("OnApplied called %d times, want 1 (dedup must skip second)", calls)
	}
}

func TestRouter_HandleStream_OnAppliedSkippedOnApplyError(t *testing.T) {
	store := closedStore(t)
	var calls int32
	r := &swarm.Router{
		Store: store,
		Dedup: swarm.NewDedupCache(8),
		Conns: swarm.NewConnSet(),
		OnApplied: func(_ context.Context, _ protocol.PeerAnnouncement) {
			calls++
		},
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     id(0xb3),
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.7:9999",
	}
	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), nil); err == nil {
		t.Fatal("HandleStream succeeded against closed store")
	}
	if calls != 0 {
		t.Errorf("OnApplied called %d times, want 0 on Apply error", calls)
	}
}

func TestRouter_HandleStream_NilConnsSkipsForward(t *testing.T) {
	store := mustRouterStore(t)
	r := &swarm.Router{Store: store, Dedup: swarm.NewDedupCache(8)}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     id(0xa6),
		PubKey: pubArray(pub),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}
	if err := r.HandleStream(context.Background(), encodedAnnouncement(t, ann), nil); err != nil {
		t.Fatalf("HandleStream with nil Conns: %v", err)
	}
}
