package quic_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"backupswarm/internal/ca"
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

// signedLeafFor builds a CA-signed TLS leaf for priv via swarmCA.
func signedLeafFor(t *testing.T, swarmCA *ca.CA, priv ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	csrDER, err := ca.CreateCSR(priv)
	if err != nil {
		t.Fatalf("create csr: %v", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("priv.Public() not Ed25519")
	}
	leafDER, err := ca.SignNodeCert(swarmCA, csrDER, pub, ca.DefaultLeafValidity)
	if err != nil {
		t.Fatalf("sign node cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{leafDER},
		PrivateKey:  priv,
	}
}

// caPool builds an x509 cert pool containing swarmCA's root.
func caPool(t *testing.T, swarmCA *ca.CA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	pool.AddCert(swarmCA.Cert)
	return pool
}

// TestListen_AssignsAddr asserts Listen on :0 returns a usable bound address.
func TestListen_AssignsAddr(t *testing.T) {
	t.Parallel()
	_, priv := newKeyPair(t)
	l, err := bsw.Listen("127.0.0.1:0", priv, nil, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()
	if l.Addr() == nil || l.Addr().String() == "" {
		t.Fatalf("expected non-empty listen addr")
	}
}

// TestRoundTrip exercises an mTLS handshake and chunk-sized stream echo and asserts both sides observe the peer's verified Ed25519 pubkey.
func TestRoundTrip(t *testing.T) {
	t.Parallel()
	serverPub, serverPriv := newKeyPair(t)
	clientPub, clientPriv := newKeyPair(t)

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	payload := make([]byte, 1<<20)
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
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub, nil)
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

// TestDial_RejectsWrongPeerPubkey asserts a dial pinned to a wrong server pubkey fails with ErrPeerPubkeyMismatch.
func TestDial_RejectsWrongPeerPubkey(t *testing.T) {
	t.Parallel()
	_, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)
	wrongPub, _ := newKeyPair(t)

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if c, err := l.Accept(ctx); err == nil {
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err = bsw.Dial(ctx, l.Addr().String(), clientPriv, wrongPub, nil)
	if err == nil {
		t.Fatalf("expected dial failure with wrong peer pubkey")
	}
	if !errors.Is(err, bsw.ErrPeerPubkeyMismatch) {
		t.Fatalf("expected ErrPeerPubkeyMismatch in chain, got: %v", err)
	}
}

// TestListen_InvalidAddr asserts Listen errors on an invalid bind address.
func TestListen_InvalidAddr(t *testing.T) {
	t.Parallel()
	_, priv := newKeyPair(t)
	if _, err := bsw.Listen("not:a:valid:addr", priv, nil, nil); err == nil {
		t.Fatalf("expected error for invalid addr")
	}
}

// TestDial_ContextCancel asserts Dial returns an error when its context is already cancelled.
func TestDial_ContextCancel(t *testing.T) {
	t.Parallel()
	_, priv := newKeyPair(t)
	pub, _ := newKeyPair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := bsw.Dial(ctx, "127.0.0.1:1", priv, pub, nil); err == nil {
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

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, nil)
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
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if err := <-done; err != nil {
		t.Fatalf("accept: %v", err)
	}
	_ = conn.Close()
}

// TestListen_VerifyPeerRejectsUnknown covers membership enforcement: a
// client whose pubkey is rejected by the predicate cannot use the connection.
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

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, verify, nil)
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
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub, nil)
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

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, verify, nil)
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
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub, nil)
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

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, nil)
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
	conn1, err := bsw.Dial(ctx1, l.Addr().String(), clientPriv, serverPub, nil)
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
	conn2, err := bsw.Dial(ctx2, l.Addr().String(), clientPriv, serverPub, nil)
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

// TestRoundTrip_CAMode exercises a CA-mode handshake: both sides present a
// leaf signed by the swarm CA and chain-verify the peer against the shared
// pool, with the Ed25519 pubkey check still running on top.
func TestRoundTrip_CAMode(t *testing.T) {
	t.Parallel()
	swarmCA, err := ca.Generate()
	if err != nil {
		t.Fatalf("generate ca: %v", err)
	}
	pool := caPool(t, swarmCA)

	serverPub, serverPriv := newKeyPair(t)
	clientPub, clientPriv := newKeyPair(t)
	serverCert := signedLeafFor(t, swarmCA, serverPriv)
	clientCert := signedLeafFor(t, swarmCA, clientPriv)
	serverTrust := &bsw.TrustConfig{Cert: &serverCert, Pool: pool}
	clientTrust := &bsw.TrustConfig{Cert: &clientCert, Pool: pool}

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, serverTrust)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	payload := []byte("ping-ca-mode")
	type result struct {
		pub  ed25519.PublicKey
		data []byte
		err  error
	}
	done := make(chan result, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := l.Accept(ctx)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer func() { _ = c.Close() }()
		s, err := c.AcceptStream(ctx)
		if err != nil {
			done <- result{err: err}
			return
		}
		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(s, buf); err != nil {
			done <- result{err: err}
			return
		}
		if _, err := s.Write(buf); err != nil {
			done <- result{err: err}
			return
		}
		_ = s.Close()
		if _, err := io.Copy(io.Discard, s); err != nil {
			done <- result{err: err}
			return
		}
		done <- result{pub: c.RemotePub(), data: buf}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub, clientTrust)
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
		t.Fatalf("echo mismatch")
	}

	r := <-done
	if r.err != nil {
		t.Fatalf("server: %v", r.err)
	}
	if !r.pub.Equal(clientPub) {
		t.Fatalf("server RemotePub mismatch")
	}
	if !bytes.Equal(r.data, payload) {
		t.Fatalf("server data mismatch")
	}
}

// TestDial_RejectsServerLeafFromDifferentCA exercises dial-side chain
// verification: a server leaf signed by an untrusted CA is rejected
// before the pubkey check runs.
func TestDial_RejectsServerLeafFromDifferentCA(t *testing.T) {
	t.Parallel()
	serverCA, err := ca.Generate()
	if err != nil {
		t.Fatalf("server ca: %v", err)
	}
	clientCA, err := ca.Generate()
	if err != nil {
		t.Fatalf("client ca: %v", err)
	}

	serverPub, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)
	serverLeaf := signedLeafFor(t, serverCA, serverPriv)
	clientLeaf := signedLeafFor(t, clientCA, clientPriv)
	serverTrust := &bsw.TrustConfig{Cert: &serverLeaf, Pool: caPool(t, serverCA)}
	clientTrust := &bsw.TrustConfig{Cert: &clientLeaf, Pool: caPool(t, clientCA)}

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, serverTrust)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if c, err := l.Accept(ctx); err == nil {
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub, clientTrust); err == nil {
		t.Fatalf("expected dial to fail when server leaf does not chain to client's pool")
	}
}

// TestListen_RejectsClientLeafFromDifferentCA exercises listener-side
// chain verification: a client leaf signed by an untrusted CA fails on
// the first wire round-trip and the listener never accepts.
func TestListen_RejectsClientLeafFromDifferentCA(t *testing.T) {
	t.Parallel()
	serverCA, err := ca.Generate()
	if err != nil {
		t.Fatalf("server ca: %v", err)
	}
	clientCA, err := ca.Generate()
	if err != nil {
		t.Fatalf("client ca: %v", err)
	}

	serverPub, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)
	serverLeaf := signedLeafFor(t, serverCA, serverPriv)
	clientLeaf := signedLeafFor(t, clientCA, clientPriv)
	// Client trusts the server's CA, so the dial-side chain verify passes;
	// the failure surfaces only on the server side.
	serverTrust := &bsw.TrustConfig{Cert: &serverLeaf, Pool: caPool(t, serverCA)}
	clientTrust := &bsw.TrustConfig{Cert: &clientLeaf, Pool: caPool(t, serverCA)}

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, serverTrust)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

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
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub, clientTrust)
	if err == nil {
		defer func() { _ = conn.Close() }()
		s, sErr := conn.OpenStream(ctx)
		if sErr == nil {
			_, _ = s.Write([]byte("ping"))
			_ = s.Close()
			if _, rErr := io.Copy(io.Discard, s); rErr == nil {
				t.Fatalf("expected stream round-trip to fail when client leaf does not chain to server's ClientCAs")
			}
		}
	}

	select {
	case <-accepted:
		t.Fatalf("server accepted a connection whose client leaf does not chain to ClientCAs")
	case <-time.After(100 * time.Millisecond):
	}
}

// TestDial_RejectsCASignedLeafForWrongPubkey covers the stolen-CA-key
// threat: a chain-valid leaf that binds to a different Ed25519 identity
// is rejected by the dial-side pubkey pin.
func TestDial_RejectsCASignedLeafForWrongPubkey(t *testing.T) {
	t.Parallel()
	swarmCA, err := ca.Generate()
	if err != nil {
		t.Fatalf("generate ca: %v", err)
	}
	pool := caPool(t, swarmCA)

	// serverPub is what the client expects; impostor is what it reaches.
	serverPub, _ := newKeyPair(t)
	impostorPub, impostorPriv := newKeyPair(t)
	impostorCSR, err := ca.CreateCSR(impostorPriv)
	if err != nil {
		t.Fatalf("impostor csr: %v", err)
	}
	impostorLeafDER, err := ca.SignNodeCert(swarmCA, impostorCSR, impostorPub, ca.DefaultLeafValidity)
	if err != nil {
		t.Fatalf("sign impostor: %v", err)
	}
	impostorLeaf := tls.Certificate{
		Certificate: [][]byte{impostorLeafDER},
		PrivateKey:  impostorPriv,
	}
	_, clientPriv := newKeyPair(t)
	clientLeaf := signedLeafFor(t, swarmCA, clientPriv)
	serverTrust := &bsw.TrustConfig{Cert: &impostorLeaf, Pool: pool}
	clientTrust := &bsw.TrustConfig{Cert: &clientLeaf, Pool: pool}

	l, err := bsw.Listen("127.0.0.1:0", impostorPriv, nil, serverTrust)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if c, err := l.Accept(ctx); err == nil {
			_ = c.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub, clientTrust)
	if err == nil {
		t.Fatalf("expected dial to fail when CA-signed leaf binds to the wrong pubkey")
	}
	if !errors.Is(err, bsw.ErrPeerPubkeyMismatch) {
		t.Fatalf("expected ErrPeerPubkeyMismatch, got: %v", err)
	}
}

// TestListen_TrustConfigValidation asserts a half-populated TrustConfig
// is rejected up-front instead of nil-panicking at handshake time.
func TestListen_TrustConfigValidation(t *testing.T) {
	t.Parallel()
	_, priv := newKeyPair(t)
	if _, err := bsw.Listen("127.0.0.1:0", priv, nil, &bsw.TrustConfig{}); err == nil {
		t.Fatal("expected Listen to error on TrustConfig{} (both fields nil)")
	}
}

// TestDial_TrustConfigValidation mirrors the Listen-side validation check.
func TestDial_TrustConfigValidation(t *testing.T) {
	t.Parallel()
	_, priv := newKeyPair(t)
	pub, _ := newKeyPair(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	if _, err := bsw.Dial(ctx, "127.0.0.1:1", priv, pub, &bsw.TrustConfig{}); err == nil {
		t.Fatal("expected Dial to error on TrustConfig{} (both fields nil)")
	}
}

// signedLeafViaIntermediate builds a 2-link chain rooted at swarmCA: an
// intermediate CA signed by swarmCA, then a leaf for priv signed by the
// intermediate. The returned chain is [leafDER, intermediateDER].
func signedLeafViaIntermediate(t *testing.T, swarmCA *ca.CA, priv ed25519.PrivateKey) tls.Certificate {
	t.Helper()
	intPub, intPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate intermediate key: %v", err)
	}
	intSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("intermediate serial: %v", err)
	}
	intTemplate := &x509.Certificate{
		SerialNumber:          intSerial,
		Subject:               pkix.Name{CommonName: "BackupSwarm Test Intermediate"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, swarmCA.Cert, intPub, swarmCA.PrivateKey)
	if err != nil {
		t.Fatalf("create intermediate: %v", err)
	}
	intCert, err := x509.ParseCertificate(intDER)
	if err != nil {
		t.Fatalf("parse intermediate: %v", err)
	}

	leafPub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("priv.Public() not Ed25519")
	}
	leafSerial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("leaf serial: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: "backupswarm-leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, intCert, leafPub, intPriv)
	if err != nil {
		t.Fatalf("create leaf: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{leafDER, intDER},
		PrivateKey:  priv,
	}
}

// TestRoundTrip_CAMode_WithIntermediate exercises verifyChain's intermediates
// loop: both sides present leaf+intermediate, and the verifier must walk the
// intermediate to reach the trusted root.
func TestRoundTrip_CAMode_WithIntermediate(t *testing.T) {
	t.Parallel()
	swarmCA, err := ca.Generate()
	if err != nil {
		t.Fatalf("generate ca: %v", err)
	}
	pool := caPool(t, swarmCA)

	serverPub, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)
	serverCert := signedLeafViaIntermediate(t, swarmCA, serverPriv)
	clientCert := signedLeafViaIntermediate(t, swarmCA, clientPriv)
	serverTrust := &bsw.TrustConfig{Cert: &serverCert, Pool: pool}
	clientTrust := &bsw.TrustConfig{Cert: &clientCert, Pool: pool}

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, serverTrust)
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
	conn, err := bsw.Dial(ctx, l.Addr().String(), clientPriv, serverPub, clientTrust)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if !conn.RemotePub().Equal(serverPub) {
		t.Fatalf("client RemotePub mismatch")
	}
	if err := <-done; err != nil {
		t.Fatalf("accept: %v", err)
	}
}
