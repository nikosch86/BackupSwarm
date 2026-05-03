package quic_test

import (
	"context"
	"io"
	"testing"
	"time"

	"golang.org/x/time/rate"

	bsw "backupswarm/internal/quic"
)

// throttledRoundTripRig holds the (server, client) Conn pair used by the
// SetLimiters end-to-end tests so each test can pick which side installs
// limiters and drive a stream over the established connection.
type throttledRoundTripRig struct {
	clientConn *bsw.Conn
	serverConn *bsw.Conn
}

// newThrottledRoundTripRig listens on 127.0.0.1:0, dials it back, and
// returns the matched Conn pair. Listener and both Conns are torn down via
// t.Cleanup.
func newThrottledRoundTripRig(t *testing.T) *throttledRoundTripRig {
	t.Helper()
	serverPub, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	type acceptResult struct {
		conn *bsw.Conn
		err  error
	}
	accepted := make(chan acceptResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := l.Accept(ctx)
		accepted <- acceptResult{conn: c, err: err}
	}()

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	clientConn, err := bsw.Dial(dialCtx, l.Addr().String(), clientPriv, serverPub, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	res := <-accepted
	if res.err != nil {
		t.Fatalf("accept: %v", res.err)
	}
	t.Cleanup(func() { _ = res.conn.Close() })

	return &throttledRoundTripRig{
		clientConn: clientConn,
		serverConn: res.conn,
	}
}

// TestListener_SetLimiters_AppliesToAcceptedConnStreams asserts the down
// limiter installed via Listener.SetLimiters before Accept throttles reads
// on streams accepted by the server-side Conn it returns.
func TestListener_SetLimiters_AppliesToAcceptedConnStreams(t *testing.T) {
	t.Parallel()

	const ratePerSec = 64 * 1024
	const burst = 8 * 1024
	const payloadBytes = 64 * 1024

	serverPub, serverPriv := newKeyPair(t)
	_, clientPriv := newKeyPair(t)

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	downLim := rate.NewLimiter(rate.Limit(ratePerSec), burst)
	downLim.AllowN(time.Now(), burst)
	l.SetLimiters(bsw.Limiters{Down: downLim})

	type readResult struct {
		got     int
		elapsed time.Duration
		err     error
	}
	serverDone := make(chan readResult, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		c, aerr := l.Accept(ctx)
		if aerr != nil {
			serverDone <- readResult{err: aerr}
			return
		}
		defer func() { _ = c.Close() }()
		s, sErr := c.AcceptStream(ctx)
		if sErr != nil {
			serverDone <- readResult{err: sErr}
			return
		}
		start := time.Now()
		buf, rerr := io.ReadAll(s)
		serverDone <- readResult{got: len(buf), elapsed: time.Since(start), err: rerr}
	}()

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := bsw.Dial(dialCtx, l.Addr().String(), clientPriv, serverPub, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	s, err := conn.OpenStream(dialCtx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	payload := make([]byte, payloadBytes)
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if cerr := s.Close(); cerr != nil {
		t.Fatalf("client close: %v", cerr)
	}

	res := <-serverDone
	if res.err != nil {
		t.Fatalf("server read: %v", res.err)
	}
	if res.got != payloadBytes {
		t.Fatalf("server read %d bytes, want %d", res.got, payloadBytes)
	}
	expected := time.Duration(float64(time.Second) * float64(payloadBytes) / float64(ratePerSec))
	if res.elapsed < expected*7/10 {
		t.Fatalf("server read elapsed %v: want >= %v (Listener.SetLimiters down limiter not applied)", res.elapsed, expected*7/10)
	}
}

// TestConn_SetLimiters_AppliesToSubsequentlyOpenedStreams asserts an up
// limiter installed via Conn.SetLimiters after Dial throttles writes on
// streams opened from that Conn afterwards.
func TestConn_SetLimiters_AppliesToSubsequentlyOpenedStreams(t *testing.T) {
	t.Parallel()

	const ratePerSec = 64 * 1024
	const burst = 8 * 1024
	const payloadBytes = 64 * 1024

	rig := newThrottledRoundTripRig(t)

	upLim := rate.NewLimiter(rate.Limit(ratePerSec), burst)
	upLim.AllowN(time.Now(), burst)
	rig.clientConn.SetLimiters(bsw.Limiters{Up: upLim})

	serverErr := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		s, err := rig.serverConn.AcceptStream(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		_, err = io.ReadAll(s)
		serverErr <- err
	}()

	openCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := rig.clientConn.OpenStream(openCtx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}

	payload := make([]byte, payloadBytes)
	start := time.Now()
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = s.Close()
	elapsed := time.Since(start)

	if err := <-serverErr; err != nil {
		t.Fatalf("server: %v", err)
	}

	expected := time.Duration(float64(time.Second) * float64(payloadBytes) / float64(ratePerSec))
	if elapsed < expected*7/10 {
		t.Fatalf("client write elapsed %v: want >= %v (Conn.SetLimiters limiter not applied)", elapsed, expected*7/10)
	}
}

// TestStream_Close_RealQUICStreamPath asserts Stream.Close drives the
// underlying *qgo.Stream when no rwc test seam is set, returning a nil
// error in the happy-path roundtrip.
func TestStream_Close_RealQUICStreamPath(t *testing.T) {
	t.Parallel()

	rig := newThrottledRoundTripRig(t)

	serverDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := rig.serverConn.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		_, _ = io.ReadAll(s)
		serverDone <- nil
	}()

	openCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s, err := rig.clientConn.OpenStream(openCtx)
	if err != nil {
		t.Fatalf("open stream: %v", err)
	}
	if _, err := s.Write([]byte("hello")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if cerr := s.Close(); cerr != nil {
		t.Fatalf("close (embedded *qgo.Stream path): %v", cerr)
	}

	if err := <-serverDone; err != nil {
		t.Fatalf("server: %v", err)
	}
}

// TestConn_OpenStream_AfterCloseReturnsError asserts OpenStream propagates
// the error quic-go returns when the underlying connection has been closed.
func TestConn_OpenStream_AfterCloseReturnsError(t *testing.T) {
	t.Parallel()

	rig := newThrottledRoundTripRig(t)
	if err := rig.clientConn.Close(); err != nil {
		t.Fatalf("close client conn: %v", err)
	}

	openCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := rig.clientConn.OpenStream(openCtx)
	if err == nil {
		t.Fatalf("OpenStream on closed conn returned nil error")
	}
}

// TestConn_AcceptStream_AfterCloseReturnsError asserts AcceptStream
// propagates the error quic-go returns when the underlying connection has
// been closed.
func TestConn_AcceptStream_AfterCloseReturnsError(t *testing.T) {
	t.Parallel()

	rig := newThrottledRoundTripRig(t)
	if err := rig.serverConn.Close(); err != nil {
		t.Fatalf("close server conn: %v", err)
	}

	acceptCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := rig.serverConn.AcceptStream(acceptCtx)
	if err == nil {
		t.Fatalf("AcceptStream on closed conn returned nil error")
	}
}
