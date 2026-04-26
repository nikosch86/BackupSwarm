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

	announceFn := func(ctx context.Context, r io.Reader) error {
		return swarm.ServeAnnouncementStream(ctx, r, subStore)
	}
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- backup.Serve(ctx, listener, nil, announceFn)
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
