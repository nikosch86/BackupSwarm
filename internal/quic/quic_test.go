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

// TestListen_AssignsAddr asserts Listen on :0 returns a usable bound address.
func TestListen_AssignsAddr(t *testing.T) {
	t.Parallel()
	_, priv := newKeyPair(t)
	l, err := bsw.Listen("127.0.0.1:0", priv)
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

	l, err := bsw.Listen("127.0.0.1:0", serverPriv)
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

// TestDial_RejectsWrongPeerPubkey asserts a dial pinned to a wrong server pubkey fails with ErrPeerPubkeyMismatch.
func TestDial_RejectsWrongPeerPubkey(t *testing.T) {
	t.Parallel()
	_, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)
	wrongPub, _ := newKeyPair(t)

	l, err := bsw.Listen("127.0.0.1:0", serverPriv)
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
	_, err = bsw.Dial(ctx, l.Addr().String(), clientPriv, wrongPub)
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
	if _, err := bsw.Listen("not:a:valid:addr", priv); err == nil {
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
	if _, err := bsw.Dial(ctx, "127.0.0.1:1", priv, pub); err == nil {
		t.Fatalf("expected error from cancelled context")
	}
}
