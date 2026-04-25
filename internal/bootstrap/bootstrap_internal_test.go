package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/pkg/token"
)

// TestEd25519PubCopy_Nil asserts ed25519PubCopy(nil) returns nil.
func TestEd25519PubCopy_Nil(t *testing.T) {
	if got := ed25519PubCopy(nil); got != nil {
		t.Errorf("ed25519PubCopy(nil) = %v, want nil", got)
	}
}

// withWriteJoinAckFunc swaps writeJoinAckFunc for the duration of a test.
func withWriteJoinAckFunc(t *testing.T, fn func(w io.Writer, appErr string) error) {
	t.Helper()
	prev := writeJoinAckFunc
	writeJoinAckFunc = fn
	t.Cleanup(func() { writeJoinAckFunc = prev })
}

// withWriteJoinHelloFunc swaps writeJoinHelloFunc for the duration of a test.
func withWriteJoinHelloFunc(t *testing.T, fn func(w io.Writer, listenAddr string) error) {
	t.Helper()
	prev := writeJoinHelloFunc
	writeJoinHelloFunc = fn
	t.Cleanup(func() { writeJoinHelloFunc = prev })
}

// withStreamCloseFunc swaps streamCloseFunc for the duration of a test.
func withStreamCloseFunc(t *testing.T, fn func(s io.Closer) error) {
	t.Helper()
	prev := streamCloseFunc
	streamCloseFunc = fn
	t.Cleanup(func() { streamCloseFunc = prev })
}

type internalRig struct {
	introPub, joinerPub   ed25519.PublicKey
	introPriv, joinerPriv ed25519.PrivateKey
	listener              *bsquic.Listener
	introStore            *peers.Store
	joinerStore           *peers.Store
}

func newInternalRig(t *testing.T) *internalRig {
	t.Helper()
	ip, iPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("intro key: %v", err)
	}
	jp, jPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("join key: %v", err)
	}
	l, err := bsquic.Listen("127.0.0.1:0", iPriv, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	is, err := peers.Open(filepath.Join(t.TempDir(), "intro.db"))
	if err != nil {
		t.Fatalf("intro store: %v", err)
	}
	t.Cleanup(func() { _ = is.Close() })
	js, err := peers.Open(filepath.Join(t.TempDir(), "join.db"))
	if err != nil {
		t.Fatalf("join store: %v", err)
	}
	t.Cleanup(func() { _ = js.Close() })
	return &internalRig{
		introPub: ip, introPriv: iPriv,
		joinerPub: jp, joinerPriv: jPriv,
		listener:    l,
		introStore:  is,
		joinerStore: js,
	}
}

// TestAcceptJoin_WriteJoinAckFailure asserts AcceptJoin wraps a WriteJoinAck failure as "write ack".
func TestAcceptJoin_WriteJoinAckFailure(t *testing.T) {
	rig := newInternalRig(t)
	sentinel := errors.New("forced ack write failure")
	withWriteJoinAckFunc(t, func(w io.Writer, appErr string) error {
		if appErr == "" {
			if c, ok := w.(io.Closer); ok {
				_ = c.Close()
			}
			return sentinel
		}
		return protocol.WriteJoinAck(w, appErr)
	})

	tok, err := token.Encode(token.Token{Addr: rig.listener.Addr().String(), Pub: rig.introPub})
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
		_, acceptErr = AcceptJoin(ctx, rig.listener, rig.introStore)
	}()

	_, _ = DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerStore)

	wg.Wait()
	if acceptErr == nil {
		t.Fatal("AcceptJoin returned nil despite injected ack-write failure")
	}
	if !errors.Is(acceptErr, sentinel) {
		t.Errorf("AcceptJoin err = %v, want wraps sentinel", acceptErr)
	}
}

// TestDoJoin_WriteJoinHelloFailure asserts DoJoin wraps a WriteJoinHello failure as "write hello".
func TestDoJoin_WriteJoinHelloFailure(t *testing.T) {
	rig := newInternalRig(t)
	sentinel := errors.New("forced hello write failure")
	withWriteJoinHelloFunc(t, func(w io.Writer, addr string) error {
		return sentinel
	})

	tok, err := token.Encode(token.Token{Addr: rig.listener.Addr().String(), Pub: rig.introPub})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = AcceptJoin(ctx, rig.listener, rig.introStore)
	}()

	_, err = DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerStore)
	if err == nil {
		t.Fatal("DoJoin returned nil despite injected hello-write failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("DoJoin err = %v, want wraps sentinel", err)
	}
	cancel()
	wg.Wait()
}

// TestDoJoin_StreamCloseFailure asserts DoJoin wraps a half-close failure as "close hello send".
func TestDoJoin_StreamCloseFailure(t *testing.T) {
	rig := newInternalRig(t)
	sentinel := errors.New("forced stream close failure")
	withStreamCloseFunc(t, func(s io.Closer) error {
		return sentinel
	})

	tok, err := token.Encode(token.Token{Addr: rig.listener.Addr().String(), Pub: rig.introPub})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer acceptCancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = AcceptJoin(acceptCtx, rig.listener, rig.introStore)
	}()

	_, err = DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerStore)
	if err == nil {
		t.Fatal("DoJoin returned nil despite injected stream-close failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("DoJoin err = %v, want wraps sentinel", err)
	}
	cancel()
	wg.Wait()
}
