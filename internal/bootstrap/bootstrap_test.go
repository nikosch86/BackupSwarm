package bootstrap_test

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

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/pkg/token"
)

// Matches the unexported maxAdvertisedAddrLen used inside the bootstrap
// package. Kept local to the test so the test doesn't need to be in the
// internal test file.
const maxAdvertisedAddrLenForTest = 1 << 10

type twoSides struct {
	introducerPub      ed25519.PublicKey
	introducerPriv     ed25519.PrivateKey
	joinerPub          ed25519.PublicKey
	joinerPriv         ed25519.PrivateKey
	listener           *bsquic.Listener
	introducerPeerList *peers.Store
	joinerPeerList     *peers.Store
}

func setupTwoSides(t *testing.T) *twoSides {
	t.Helper()
	introPub, introPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("intro key: %v", err)
	}
	joinPub, joinPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("join key: %v", err)
	}
	l, err := bsquic.Listen("127.0.0.1:0", introPriv)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	introStore, err := peers.Open(filepath.Join(t.TempDir(), "intro-peers.db"))
	if err != nil {
		t.Fatalf("intro peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = introStore.Close() })

	joinStore, err := peers.Open(filepath.Join(t.TempDir(), "join-peers.db"))
	if err != nil {
		t.Fatalf("join peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = joinStore.Close() })

	return &twoSides{
		introducerPub:      introPub,
		introducerPriv:     introPriv,
		joinerPub:          joinPub,
		joinerPriv:         joinPriv,
		listener:           l,
		introducerPeerList: introStore,
		joinerPeerList:     joinStore,
	}
}

func TestBootstrap_EndToEnd(t *testing.T) {
	rig := setupTwoSides(t)
	const joinerListen = "192.0.2.1:9000"
	const inviteTimeout = 5 * time.Second

	tok, err := token.Encode(rig.listener.Addr().String(), rig.introducerPub)
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}

	var wg sync.WaitGroup
	var acceptedPeer peers.Peer
	var acceptErr error

	ctx, cancel := context.WithTimeout(context.Background(), inviteTimeout)
	defer cancel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptedPeer, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	introducerPeer, err := bootstrap.DoJoin(dialCtx, tok, rig.joinerPriv, joinerListen, rig.joinerPeerList)
	if err != nil {
		t.Fatalf("DoJoin: %v", err)
	}

	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptJoin: %v", acceptErr)
	}

	// Introducer should now know the joiner (pubkey from TLS + addr from hello).
	if !bytes.Equal(acceptedPeer.PubKey, rig.joinerPub) {
		t.Error("AcceptJoin returned wrong pubkey")
	}
	if acceptedPeer.Addr != joinerListen {
		t.Errorf("AcceptJoin addr = %q, want %q", acceptedPeer.Addr, joinerListen)
	}
	got, err := rig.introducerPeerList.Get(rig.joinerPub)
	if err != nil {
		t.Fatalf("introducer's peer store missing joiner: %v", err)
	}
	if got.Addr != joinerListen {
		t.Errorf("introducer saw joiner addr %q, want %q", got.Addr, joinerListen)
	}

	// Joiner should know the introducer.
	if !bytes.Equal(introducerPeer.PubKey, rig.introducerPub) {
		t.Error("DoJoin returned wrong pubkey")
	}
	if introducerPeer.Addr != rig.listener.Addr().String() {
		t.Errorf("DoJoin addr = %q, want %q", introducerPeer.Addr, rig.listener.Addr().String())
	}
	got, err = rig.joinerPeerList.Get(rig.introducerPub)
	if err != nil {
		t.Fatalf("joiner's peer store missing introducer: %v", err)
	}
	if got.Addr != rig.listener.Addr().String() {
		t.Errorf("joiner saw introducer addr %q, want %q", got.Addr, rig.listener.Addr().String())
	}
}

func TestBootstrap_WrongPubkeyTokenFailsTLSPin(t *testing.T) {
	rig := setupTwoSides(t)

	// Token encodes the correct addr but a random other pubkey — TLS pin
	// must reject the introducer's real cert.
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	tok, err := token.Encode(rig.listener.Addr().String(), otherPub)
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Keep an AcceptJoin goroutine running so the dial actually reaches
	// the TLS handshake layer (rather than a connection-refused).
	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer acceptCancel()
	go func() {
		_, _ = bootstrap.AcceptJoin(acceptCtx, rig.listener, rig.introducerPeerList)
	}()

	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "127.0.0.1:1", rig.joinerPeerList)
	if err == nil {
		t.Fatal("DoJoin succeeded despite wrong pubkey in token")
	}
	// Peer store must not have been mutated.
	list, _ := rig.joinerPeerList.List()
	if len(list) != 0 {
		t.Errorf("joiner peer store mutated after failed join: %d entries", len(list))
	}
}

func TestBootstrap_MalformedTokenRejected(t *testing.T) {
	rig := setupTwoSides(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err := bootstrap.DoJoin(ctx, "!!!not-a-token!!!", rig.joinerPriv, "x:1", rig.joinerPeerList)
	if err == nil {
		t.Error("DoJoin accepted a malformed token")
	}
}

func TestBootstrap_DeadAddrFailsDial(t *testing.T) {
	rig := setupTwoSides(t)
	// Craft a token pointing at an unused port.
	tok, err := token.Encode("127.0.0.1:1", rig.introducerPub)
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "x:1", rig.joinerPeerList)
	if err == nil {
		t.Error("DoJoin succeeded against dead address")
	}
}

func TestBootstrap_AcceptJoin_CtxCancelReturns(t *testing.T) {
	rig := setupTwoSides(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("AcceptJoin returned nil after ctx cancel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("AcceptJoin did not return within 3s of ctx cancel")
	}
}

func TestBootstrap_JoinerWithEmptyListenAddr(t *testing.T) {
	rig := setupTwoSides(t)
	tok, err := token.Encode(rig.listener.Addr().String(), rig.introducerPub)
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptedPeer peers.Peer
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptedPeer, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList)
	}()

	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "", rig.joinerPeerList)
	if err != nil {
		t.Fatalf("DoJoin with empty listen: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptJoin: %v", acceptErr)
	}
	if acceptedPeer.Addr != "" {
		t.Errorf("accepted addr = %q, want empty", acceptedPeer.Addr)
	}
	// Joiner's pubkey should still be persisted even with no addr.
	got, err := rig.introducerPeerList.Get(rig.joinerPub)
	if err != nil {
		t.Fatalf("Get joiner: %v", err)
	}
	if got.Addr != "" {
		t.Errorf("stored addr = %q, want empty", got.Addr)
	}
}

// When AcceptJoin's peer-store write fails, the introducer should reply
// with an application-level error instead of a plain OK ack, and the
// joiner's DoJoin should surface that error without mutating its own
// peer store. Exercises both the "store error" ack branch in AcceptJoin
// and the appErr != "" branch in DoJoin.
func TestBootstrap_IntroducerStoreError_PropagatesAppErr(t *testing.T) {
	rig := setupTwoSides(t)
	// Close the peer store before AcceptJoin so the Add call fails.
	_ = rig.introducerPeerList.Close()

	tok, err := token.Encode(rig.listener.Addr().String(), rig.introducerPub)
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList)
	}()

	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "", rig.joinerPeerList)
	wg.Wait()

	if err == nil {
		t.Fatal("DoJoin returned nil despite introducer app error")
	}
	if acceptErr == nil {
		t.Error("AcceptJoin returned nil despite store failure")
	}
	// Joiner must not have persisted the introducer after an app error.
	list, _ := rig.joinerPeerList.List()
	if len(list) != 0 {
		t.Errorf("joiner peer list contains %d entries after app-error; want 0", len(list))
	}
}

// ensure we don't silently ignore useful comparators
var _ = errors.Is

// TestAcceptJoin_ClientClosesWithoutStream exercises the conn.AcceptStream
// error wrap in AcceptJoin. The joiner completes the TLS handshake but
// closes the connection without opening a stream, so AcceptStream unblocks
// with an error. This hits the "accept stream: %w" wrap.
func TestAcceptJoin_ClientClosesWithoutStream(t *testing.T) {
	rig := setupTwoSides(t)
	// Short ctx so AcceptStream unblocks within the test window — closing
	// the conn from the joiner side should make AcceptStream fail more
	// promptly but we cap the wait to keep the suite snappy.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList)
	}()

	conn, err := bsquic.Dial(dialCtx, rig.listener.Addr().String(), rig.joinerPriv, rig.introducerPub)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	// Close the connection without ever opening a stream — the introducer's
	// AcceptStream call returns an error (eventually: QUIC close is
	// asynchronous, hence the 2s budget above).
	_ = conn.Close()

	wg.Wait()
	if acceptErr == nil {
		t.Fatal("AcceptJoin returned nil when client closed before opening stream")
	}
	// Peer store must not have been mutated.
	list, _ := rig.introducerPeerList.List()
	if len(list) != 0 {
		t.Errorf("introducer peer list has %d entries; want 0", len(list))
	}
}

// TestAcceptJoin_ListenerClosed exercises the l.Accept error wrap in
// AcceptJoin. Closing the listener before Accept forces the underlying
// qgo.Accept to return an error, which must be wrapped as "accept: ...".
func TestAcceptJoin_ListenerClosed(t *testing.T) {
	rig := setupTwoSides(t)
	// Close listener so Accept returns immediately with an error.
	_ = rig.listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList)
	if err == nil {
		t.Fatal("AcceptJoin returned nil on closed listener")
	}
}

// TestAcceptJoin_MalformedHello exercises the ReadJoinHello error wrap in
// AcceptJoin: the joiner opens a stream but half-closes it before sending
// a well-formed hello, so ReadJoinHello fails on the truncated header.
// This also covers the "malformed hello" WriteJoinAck call that follows.
func TestAcceptJoin_MalformedHello(t *testing.T) {
	rig := setupTwoSides(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList)
	}()

	// Dial with the right pubkey (TLS pin passes) but never write a proper
	// hello frame — just open a stream and close it immediately.
	conn, err := bsquic.Dial(ctx, rig.listener.Addr().String(), rig.joinerPriv, rig.introducerPub)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	// Close without writing — introducer's ReadJoinHello header read fails.
	_ = stream.Close()

	wg.Wait()
	if acceptErr == nil {
		t.Fatal("AcceptJoin returned nil on malformed hello")
	}
	// Peer store must not have been mutated.
	list, _ := rig.introducerPeerList.List()
	if len(list) != 0 {
		t.Errorf("introducer peer list mutated on malformed hello: %d entries", len(list))
	}
}

// TestDoJoin_IntroducerDropsBeforeAck exercises the ReadJoinAck error wrap
// in DoJoin: the introducer accepts the stream, reads the hello, then
// closes the connection before writing any ack bytes. The joiner's
// ReadJoinAck must fail with a wrapped "read ack" error and the peer
// store must not be mutated.
func TestDoJoin_IntroducerDropsBeforeAck(t *testing.T) {
	rig := setupTwoSides(t)
	tok, err := token.Encode(rig.listener.Addr().String(), rig.introducerPub)
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Custom, minimal introducer: accept, read hello, hang up without ack.
		conn, err := rig.listener.Accept(ctx)
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			_ = conn.Close()
			return
		}
		// Consume the hello bytes so the joiner's write completes, then
		// close the conn without sending the ack.
		_, _ = protocol.ReadJoinHello(stream, maxAdvertisedAddrLenForTest)
		_ = conn.Close()
	}()

	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	if err == nil {
		t.Fatal("DoJoin returned nil when introducer dropped before ack")
	}
	wg.Wait()
	list, _ := rig.joinerPeerList.List()
	if len(list) != 0 {
		t.Errorf("joiner peer list has %d entries after failed ack read; want 0", len(list))
	}
}

// TestDoJoin_JoinerStoreClosed_PropagatesErr exercises the joiner-side
// store.Add error wrap in DoJoin (after a successful ack was received).
// The joiner's peer store is closed before DoJoin is called, so Add
// fails once the ack has been processed.
func TestDoJoin_JoinerStoreClosed_PropagatesErr(t *testing.T) {
	rig := setupTwoSides(t)
	tok, err := token.Encode(rig.listener.Addr().String(), rig.introducerPub)
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList)
	}()

	// Close the joiner's peer store before DoJoin so Add fails after ack.
	_ = rig.joinerPeerList.Close()

	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	if err == nil {
		t.Fatal("DoJoin returned nil when joiner store.Add should fail")
	}
	wg.Wait()
}
