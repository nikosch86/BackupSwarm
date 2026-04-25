package quic_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	bsw "backupswarm/internal/quic"
)

func newKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub, priv
}

// TestListen_AssignsAddr ensures Listen on :0 returns a usable bound address.
func TestListen_AssignsAddr(t *testing.T) {
	t.Parallel()
	_, priv := newKeyPair(t)
	l, err := bsw.Listen("127.0.0.1:0", priv, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	if l.Addr() == nil || l.Addr().String() == "" {
		t.Fatalf("expected non-empty listen addr")
	}
}

// TestRoundTrip exercises the full mTLS handshake and a chunk-sized stream
// echo, verifying both sides observe the peer's verified Ed25519 pubkey.
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	serverPub, serverPriv := newKeyPair(t)
	clientPub, clientPriv := newKeyPair(t)

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	payload := make([]byte, 1<<20) // 1 MiB — chunk-sized
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("rand: %v", err)
	}

	type result struct {
		data []byte
		pub  ed25519.PublicKey
		err  error
	}
	done := make(chan result, 1)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		conn, err := l.Accept(ctx)
		if err != nil {
			done <- result{err: err}
			return
		}
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			_ = conn.Close()
			done <- result{err: err}
			return
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(s, buf); err != nil {
			_ = conn.Close()
			done <- result{err: err}
			return
		}
		if _, err := s.Write(buf); err != nil {
			_ = conn.Close()
			done <- result{err: err}
			return
		}
		_ = s.Close()
		// Wait for client to close its send side before tearing down the
		// connection — otherwise conn.Close aborts pending writes mid-flight.
		if _, err := io.Copy(io.Discard, s); err != nil {
			_ = conn.Close()
			done <- result{err: err}
			return
		}
		_ = conn.Close()
		done <- result{data: buf, pub: conn.RemotePub()}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if !conn.RemotePub().Equal(serverPub) {
		t.Fatalf("client RemotePub mismatch")
	}

	s, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, len(payload))
	if _, err := io.ReadFull(s, echo); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	_ = s.Close()

	if !bytes.Equal(echo, payload) {
		t.Fatalf("echo mismatch (len client=%d)", len(echo))
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("server: %v", r.err)
	}
	if !r.pub.Equal(clientPub) {
		t.Fatalf("server RemotePub mismatch")
	}
	if !bytes.Equal(r.data, payload) {
		t.Fatalf("server received bytes mismatch")
	}
}

// TestDial_RejectsWrongPeerPubkey: dialer pins a key the server doesn't
// hold; the handshake must fail with ErrPeerPubkeyMismatch in the chain.
func TestDial_RejectsWrongPeerPubkey(t *testing.T) {
	t.Parallel()
	_, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)
	wrongPub, _ := newKeyPair(t)

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Drain accept so the server doesn't block on the failed handshake.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if c, err := l.Accept(ctx); err == nil {
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = bsw.Dial(ctx, l.Addr().String(), clientPriv, wrongPub)
	if err == nil {
		t.Fatalf("expected dial failure with wrong peer pubkey")
	}
	if !errors.Is(err, bsw.ErrPeerPubkeyMismatch) {
		t.Fatalf("expected ErrPeerPubkeyMismatch in chain, got: %v", err)
	}
}

// TestListen_InvalidAddr covers the bind-error path.
func TestListen_InvalidAddr(t *testing.T) {
	t.Parallel()
	_, priv := newKeyPair(t)
	if _, err := bsw.Listen("not:a:valid:addr", priv, nil); err == nil {
		t.Fatalf("expected error for invalid addr")
	}
}

// TestDial_ContextCancel covers the dial-error path without needing a server.
func TestDial_ContextCancel(t *testing.T) {
	t.Parallel()
	_, priv := newKeyPair(t)
	pub, _ := newKeyPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := bsw.Dial(ctx, "127.0.0.1:1", priv, pub); err == nil {
		t.Fatalf("expected error from cancelled context")
	}
}

// TestListen_NilVerifyPeerAdmitsAny covers the bootstrap mode where Listen
// is given a nil predicate — the listener accepts any Ed25519 peer (used
// during invite's AcceptJoin before the joiner's pubkey is in peers.db).
func TestListen_NilVerifyPeerAdmitsAny(t *testing.T) {
	t.Parallel()
	serverPub, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := l.Accept(ctx)
		if err == nil {
			// Hold the connection open so the client doesn't tear down
			// before we've finished accepting; closes when the test exits.
			t.Cleanup(func() { _ = c.Close() })
		}
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = conn.Close()
}

// TestListen_VerifyPeerRejectsUnknown covers membership enforcement — a
// client whose pubkey is rejected by the predicate cannot use the
// connection. This is the F-01 fix: unknown peers' streams never reach
// the server's dispatcher.
//
// In TLS 1.3 mTLS the client considers its own handshake complete after
// sending its Finished message, so quic-go's Dial may return successfully
// before the server has validated the client cert. The server-side
// rejection surfaces on the first wire round-trip as a CRYPTO_ERROR; the
// server-side Accept never returns the connection.
//
// We assert two invariants that together prove the rejection: (a) the
// server never accepted the connection, and (b) any stream we tried to use
// fails on a write/read round-trip.
func TestListen_VerifyPeerRejectsUnknown(t *testing.T) {
	t.Parallel()
	serverPub, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)
	allowed, _ := newKeyPair(t)

	verify := func(pub ed25519.PublicKey) error {
		if !pub.Equal(allowed) {
			return errors.New("not a known peer")
		}
		return nil
	}

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, verify)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Server should never see an accepted connection from a rejected peer.
	accepted := make(chan struct{}, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if c, err := l.Accept(ctx); err == nil {
			_ = c.Close()
			accepted <- struct{}{}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub)
	if err == nil {
		// Force a round-trip — opening + writing + reading exercises the
		// closed connection state set by the server's TLS rejection.
		defer func() { _ = conn.Close() }()
		s, sErr := conn.OpenStream(ctx)
		if sErr == nil {
			_, _ = s.Write([]byte("ping"))
			_ = s.Close()
			if _, rErr := io.Copy(io.Discard, s); rErr == nil {
				t.Fatalf("expected stream round-trip to fail when client pubkey is not in the predicate allowlist")
			}
		}
	}

	// Listener never saw the rejected peer as an accepted connection.
	select {
	case <-accepted:
		t.Fatalf("server accepted a connection that should have failed VerifyPeer")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestListen_VerifyPeerAdmitsKnown covers the steady-state case — a client
// whose pubkey passes the predicate handshakes successfully.
func TestListen_VerifyPeerAdmitsKnown(t *testing.T) {
	t.Parallel()
	serverPub, serverPriv := newKeyPair(t)
	clientPub, clientPriv := newKeyPair(t)

	verify := func(pub ed25519.PublicKey) error {
		if !pub.Equal(clientPub) {
			return errors.New("not a known peer")
		}
		return nil
	}

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, verify)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := l.Accept(ctx)
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
		done <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = conn.Close()
}

// TestListener_SetVerifyPeer covers the invite→daemon handoff: the listener
// is bound in bootstrap mode (nil predicate, accept any Ed25519) so AcceptJoin
// works for a peer not yet in peers.db; after AcceptJoin, the caller flips
// the predicate to a membership check before starting the steady-state serve
// loop. Subsequent handshakes must use the new predicate.
func TestListener_SetVerifyPeer(t *testing.T) {
	t.Parallel()
	serverPub, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	// Drain accepts in a loop — the first dial succeeds, the second will
	// fail at the TLS handshake so no further connection surfaces to Accept.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	// First dial: bootstrap mode (nil predicate) admits any Ed25519 client.
	ctx1, cancel1 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel1()
	conn1, err := bsw.Dial(ctx1, l.Addr().String(), clientPriv, serverPub)
	if err != nil {
		t.Fatalf("bootstrap dial: %v", err)
	}
	_ = conn1.Close()

	// Swap in a predicate that rejects everything.
	l.SetVerifyPeer(func(_ ed25519.PublicKey) error {
		return errors.New("membership check: rejected")
	})

	// Second dial: the new predicate applies. As with TestListen_VerifyPeerRejectsUnknown,
	// the server-side rejection surfaces on the first wire round-trip
	// rather than at Dial time (TLS 1.3 timing).
	ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel2()
	conn2, err := bsw.Dial(ctx2, l.Addr().String(), clientPriv, serverPub)
	if err == nil {
		defer func() { _ = conn2.Close() }()
		s, sErr := conn2.OpenStream(ctx2)
		if sErr == nil {
			_, _ = s.Write([]byte("ping"))
			_ = s.Close()
			if _, rErr := io.Copy(io.Discard, s); rErr == nil {
				t.Fatalf("expected stream round-trip to fail after SetVerifyPeer(reject-all)")
			}
		}
	}
}
