package quic

import (
	"context"
	"crypto/ed25519"
	"io"

	"golang.org/x/time/rate"
)

// NewConnForTest constructs a *Conn carrying only remotePub. The inner
// *qgo.Conn is nil; OpenStream / AcceptStream / Close panic.
// Test-only sentinel for ConnSet membership logic.
func NewConnForTest(pub ed25519.PublicKey) *Conn {
	return &Conn{remotePub: pub}
}

// NewStreamForTest wraps rwc as a *Stream with the given limiters.
// Test-only; embedded *qgo.Stream is nil so promoted methods panic.
func NewStreamForTest(rwc io.ReadWriteCloser, up, down *rate.Limiter) *Stream {
	return &Stream{rwc: rwc, up: up, down: down}
}

// NewStreamForTestWithContext is NewStreamForTest with a caller-supplied
// context for WaitN. Test-only; production paths take ctx from the
// underlying *qgo.Stream.
func NewStreamForTestWithContext(rwc io.ReadWriteCloser, up, down *rate.Limiter, ctx context.Context) *Stream {
	return &Stream{rwc: rwc, up: up, down: down, ctx: ctx}
}
