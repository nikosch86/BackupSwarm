package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/invites"
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

// TestEntriesToPeers_RejectsUnknownRole feeds entriesToPeers a non-zero
// out-of-range role byte and asserts a non-nil error.
func TestEntriesToPeers_RejectsUnknownRole(t *testing.T) {
	in := []protocol.PeerEntry{{PubKey: [32]byte{0x11}, Role: 99, Addr: "x:1"}}
	out, err := entriesToPeers(in)
	if err == nil {
		t.Fatalf("entriesToPeers accepted unknown role; out=%v", out)
	}
}

// TestJoinResponseError_UnknownCode asserts an unrecognized wire code
// produces an error that is none of the typed sentinels.
func TestJoinResponseError_UnknownCode(t *testing.T) {
	err := joinResponseError("future_code_42")
	if err == nil {
		t.Fatal("joinResponseError returned nil for unknown code")
	}
	if errors.Is(err, ErrSwarmMismatch) || errors.Is(err, ErrBadSecret) || errors.Is(err, ErrIntroducerInternal) {
		t.Errorf("unknown code matched a typed sentinel: %v", err)
	}
}

func withWriteJoinResponseFunc(t *testing.T, fn func(w io.Writer, appErr string) error) {
	t.Helper()
	prev := writeJoinResponseFunc
	writeJoinResponseFunc = fn
	t.Cleanup(func() { writeJoinResponseFunc = prev })
}

func withWriteJoinRequestFunc(t *testing.T, fn func(w io.Writer, swarmID, secret [32]byte, addr string) error) {
	t.Helper()
	prev := writeJoinRequestFunc
	writeJoinRequestFunc = fn
	t.Cleanup(func() { writeJoinRequestFunc = prev })
}

func withWritePeerListFunc(t *testing.T, fn func(w io.Writer, entries []protocol.PeerEntry) error) {
	t.Helper()
	prev := writePeerListFunc
	writePeerListFunc = fn
	t.Cleanup(func() { writePeerListFunc = prev })
}

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
	swarmID               [token.SwarmIDSize]byte
	secret                [token.SecretSize]byte
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

	var swarmID [token.SwarmIDSize]byte
	if _, err := rand.Read(swarmID[:]); err != nil {
		t.Fatalf("rand swarm: %v", err)
	}
	var secret [token.SecretSize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatalf("rand secret: %v", err)
	}

	return &internalRig{
		introPub: ip, introPriv: iPriv,
		joinerPub: jp, joinerPriv: jPriv,
		listener:    l,
		introStore:  is,
		joinerStore: js,
		swarmID:     swarmID,
		secret:      secret,
	}
}

// validator returns a one-shot SecretValidator backed by the rig's
// known secret/swarmID; the second matching call returns ErrAlreadyUsed.
func (r *internalRig) validator() SecretValidator {
	used := false
	return func(got [token.SecretSize]byte) ([token.SwarmIDSize]byte, error) {
		if subtle.ConstantTimeCompare(got[:], r.secret[:]) != 1 {
			return [token.SwarmIDSize]byte{}, invites.ErrUnknown
		}
		if used {
			return [token.SwarmIDSize]byte{}, invites.ErrAlreadyUsed
		}
		used = true
		return r.swarmID, nil
	}
}

func (r *internalRig) tokenStr(t *testing.T) string {
	t.Helper()
	tok, err := token.Encode(token.Token{
		Addr:    r.listener.Addr().String(),
		Pub:     r.introPub,
		SwarmID: r.swarmID,
		Secret:  r.secret,
	})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}
	return tok
}

// TestAcceptJoin_WriteResponseFailure asserts AcceptJoin wraps a
// WriteJoinResponse failure as "write response".
func TestAcceptJoin_WriteResponseFailure(t *testing.T) {
	rig := newInternalRig(t)
	sentinel := errors.New("forced response write failure")
	withWriteJoinResponseFunc(t, func(w io.Writer, appErr string) error {
		if appErr == "" {
			if c, ok := w.(io.Closer); ok {
				_ = c.Close()
			}
			return sentinel
		}
		return protocol.WriteJoinResponse(w, appErr)
	})

	tok := rig.tokenStr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = AcceptJoin(ctx, rig.listener, rig.introStore, rig.validator())
	}()

	_, _ = DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerStore)

	wg.Wait()
	if acceptErr == nil {
		t.Fatal("AcceptJoin returned nil despite injected response-write failure")
	}
	if !errors.Is(acceptErr, sentinel) {
		t.Errorf("AcceptJoin err = %v, want wraps sentinel", acceptErr)
	}
}

// TestAcceptJoin_WritePeerListFailure covers a failure on the trailing
// peer-list write after the success response.
func TestAcceptJoin_WritePeerListFailure(t *testing.T) {
	rig := newInternalRig(t)
	sentinel := errors.New("forced peer list write failure")
	withWritePeerListFunc(t, func(w io.Writer, entries []protocol.PeerEntry) error {
		return sentinel
	})

	tok := rig.tokenStr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = AcceptJoin(ctx, rig.listener, rig.introStore, rig.validator())
	}()

	_, _ = DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerStore)

	wg.Wait()
	if acceptErr == nil {
		t.Fatal("AcceptJoin returned nil despite injected peer-list write failure")
	}
	if !errors.Is(acceptErr, sentinel) {
		t.Errorf("AcceptJoin err = %v, want wraps sentinel", acceptErr)
	}
}

// TestDoJoin_WriteRequestFailure asserts DoJoin wraps a WriteJoinRequest
// failure as "write request".
func TestDoJoin_WriteRequestFailure(t *testing.T) {
	rig := newInternalRig(t)
	sentinel := errors.New("forced request write failure")
	withWriteJoinRequestFunc(t, func(w io.Writer, swarmID, secret [32]byte, addr string) error {
		return sentinel
	})

	tok := rig.tokenStr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = AcceptJoin(ctx, rig.listener, rig.introStore, rig.validator())
	}()

	_, err := DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerStore)
	if err == nil {
		t.Fatal("DoJoin returned nil despite injected request-write failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("DoJoin err = %v, want wraps sentinel", err)
	}
	cancel()
	wg.Wait()
}

// TestDoJoin_StreamCloseFailure asserts DoJoin wraps a half-close failure
// as "close request send".
func TestDoJoin_StreamCloseFailure(t *testing.T) {
	rig := newInternalRig(t)
	sentinel := errors.New("forced stream close failure")
	withStreamCloseFunc(t, func(s io.Closer) error {
		return sentinel
	})

	tok := rig.tokenStr(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer acceptCancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = AcceptJoin(acceptCtx, rig.listener, rig.introStore, rig.validator())
	}()

	_, err := DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerStore)
	if err == nil {
		t.Fatal("DoJoin returned nil despite injected stream-close failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("DoJoin err = %v, want wraps sentinel", err)
	}
	cancel()
	wg.Wait()
}
