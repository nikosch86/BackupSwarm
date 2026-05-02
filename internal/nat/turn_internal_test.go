package nat

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	pturn "github.com/pion/turn/v4"
)

// errPacketConn is a net.PacketConn whose Close always returns errClosed.
type errPacketConn struct {
	mu     sync.Mutex
	closed bool
	addr   net.Addr
}

var errClosed = errors.New("forced close error")

func (e *errPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) {
	return 0, nil, errClosed
}
func (e *errPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) { return len(p), nil }
func (e *errPacketConn) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	return errClosed
}
func (e *errPacketConn) LocalAddr() net.Addr                { return e.addr }
func (e *errPacketConn) SetDeadline(_ time.Time) error      { return nil }
func (e *errPacketConn) SetReadDeadline(_ time.Time) error  { return nil }
func (e *errPacketConn) SetWriteDeadline(_ time.Time) error { return nil }

// TestAllocate_ListenPacketFailure covers the local-listen error branch.
func TestAllocate_ListenPacketFailure(t *testing.T) {
	prev := listenPacketFunc
	listenPacketFunc = func(_, _ string) (net.PacketConn, error) {
		return nil, errors.New("forced listen failure")
	}
	t.Cleanup(func() { listenPacketFunc = prev })

	_, err := Allocate(context.Background(), TURNConfig{
		Server:   "127.0.0.1:1",
		Username: "u",
		Password: "p",
		Realm:    "r",
	})
	if err == nil {
		t.Fatal("expected listen failure")
	}
}

// TestAllocate_NewClientFailure covers the pion NewClient error branch and
// asserts the local conn is closed on the failure path.
func TestAllocate_NewClientFailure(t *testing.T) {
	pc := &errPacketConn{addr: &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}}
	prevListen := listenPacketFunc
	listenPacketFunc = func(_, _ string) (net.PacketConn, error) { return pc, nil }
	t.Cleanup(func() { listenPacketFunc = prevListen })

	prevNew := newTURNClient
	newTURNClient = func(_ *pturn.ClientConfig) (*pturn.Client, error) {
		return nil, errors.New("forced new-client failure")
	}
	t.Cleanup(func() { newTURNClient = prevNew })

	_, err := Allocate(context.Background(), TURNConfig{
		Server:   "127.0.0.1:1",
		Username: "u",
		Password: "p",
		Realm:    "r",
	})
	if err == nil {
		t.Fatal("expected NewClient failure")
	}
}

// TestAllocationClose_PropagatesRelayAndLocalErrors asserts Close surfaces
// the relay-close error and ignores subsequent local-close errors when the
// relay error already populated closeErr.
func TestAllocationClose_PropagatesRelayError(t *testing.T) {
	relay := &errPacketConn{}
	local := &errPacketConn{}
	a := &Allocation{relay: relay, local: local}
	if err := a.Close(); !errors.Is(err, errClosed) {
		t.Fatalf("Close error = %v, want errClosed", err)
	}
}

// TestAllocationClose_PropagatesLocalError covers the local-close branch
// when relay closes cleanly but local errors.
func TestAllocationClose_PropagatesLocalError(t *testing.T) {
	relay := okPacketConn{}
	local := &errPacketConn{}
	a := &Allocation{relay: relay, local: local}
	if err := a.Close(); !errors.Is(err, errClosed) {
		t.Fatalf("Close error = %v, want errClosed", err)
	}
}

// okPacketConn is a net.PacketConn whose Close returns nil.
type okPacketConn struct{}

func (okPacketConn) ReadFrom(_ []byte) (int, net.Addr, error) { return 0, nil, errClosed }
func (okPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return len(p), nil
}
func (okPacketConn) Close() error                      { return nil }
func (okPacketConn) LocalAddr() net.Addr               { return &net.UDPAddr{} }
func (okPacketConn) SetDeadline(_ time.Time) error     { return nil }
func (okPacketConn) SetReadDeadline(_ time.Time) error { return nil }
func (okPacketConn) SetWriteDeadline(_ time.Time) error {
	return nil
}
