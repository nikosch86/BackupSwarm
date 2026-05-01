package nat_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v3"

	"backupswarm/internal/nat"
)

// fakeTransactor responds with a canned STUN frame on the first Recv after
// a Send (or with sendErr / recvErr if non-nil).
type fakeTransactor struct {
	mu       sync.Mutex
	resp     []byte
	sendErr  error
	recvErr  error
	closed   bool
	sendN    int
	recvN    int
	holdRecv chan struct{} // when set, Recv blocks until close
}

func (f *fakeTransactor) Send(_ []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sendN++
	return f.sendErr
}

func (f *fakeTransactor) Recv(buf []byte, _ time.Time) (int, error) {
	f.mu.Lock()
	hold := f.holdRecv
	closed := f.closed
	rerr := f.recvErr
	resp := f.resp
	f.recvN++
	f.mu.Unlock()
	if hold != nil {
		<-hold
		f.mu.Lock()
		closed = f.closed
		f.mu.Unlock()
		if closed {
			return 0, net.ErrClosed
		}
	}
	if rerr != nil {
		return 0, rerr
	}
	n := copy(buf, resp)
	return n, nil
}

func (f *fakeTransactor) Close() error {
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		if f.holdRecv != nil {
			close(f.holdRecv)
		}
	}
	f.mu.Unlock()
	return nil
}

func withDial(t *testing.T, fn func(ctx context.Context, network, address string) (nat.Transactor, error)) {
	t.Helper()
	prev := nat.DialFunc
	nat.DialFunc = fn
	t.Cleanup(func() { nat.DialFunc = prev })
}

func encodeXORResponse(t *testing.T, ip net.IP, port int) []byte {
	t.Helper()
	m := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
	if err := (&stun.XORMappedAddress{IP: ip, Port: port}).AddTo(m); err != nil {
		t.Fatalf("addto: %v", err)
	}
	m.Encode()
	return append([]byte(nil), m.Raw...)
}

func TestDiscover_EmptyServer(t *testing.T) {
	if _, err := nat.Discover(context.Background(), ""); !errors.Is(err, nat.ErrEmptyServer) {
		t.Fatalf("err = %v, want ErrEmptyServer", err)
	}
}

func TestDiscover_ReturnsHostFromXORMappedAddress(t *testing.T) {
	ft := &fakeTransactor{resp: encodeXORResponse(t, net.ParseIP("203.0.113.7"), 51820)}
	withDial(t, func(_ context.Context, _, _ string) (nat.Transactor, error) { return ft, nil })

	host, err := nat.Discover(context.Background(), "stun.example:3478")
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if host != "203.0.113.7" {
		t.Errorf("host = %q, want %q", host, "203.0.113.7")
	}
	if !ft.closed {
		t.Errorf("transactor was not closed")
	}
	if ft.sendN != 1 || ft.recvN != 1 {
		t.Errorf("send=%d recv=%d, want 1/1", ft.sendN, ft.recvN)
	}
}

func TestDiscover_DialError(t *testing.T) {
	wantErr := errors.New("boom")
	withDial(t, func(_ context.Context, _, _ string) (nat.Transactor, error) { return nil, wantErr })
	_, err := nat.Discover(context.Background(), "stun.example:3478")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want wraps %v", err, wantErr)
	}
}

func TestDiscover_SendError(t *testing.T) {
	wantErr := errors.New("send fail")
	ft := &fakeTransactor{sendErr: wantErr}
	withDial(t, func(_ context.Context, _, _ string) (nat.Transactor, error) { return ft, nil })
	_, err := nat.Discover(context.Background(), "stun.example:3478")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want wraps %v", err, wantErr)
	}
	if !ft.closed {
		t.Errorf("transactor was not closed after send error")
	}
}

func TestDiscover_RecvError(t *testing.T) {
	wantErr := errors.New("read fail")
	ft := &fakeTransactor{recvErr: wantErr}
	withDial(t, func(_ context.Context, _, _ string) (nat.Transactor, error) { return ft, nil })
	_, err := nat.Discover(context.Background(), "stun.example:3478")
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want wraps %v", err, wantErr)
	}
}

func TestDiscover_NoXORMappedAddress(t *testing.T) {
	resp := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
	resp.Encode()
	ft := &fakeTransactor{resp: append([]byte(nil), resp.Raw...)}
	withDial(t, func(_ context.Context, _, _ string) (nat.Transactor, error) { return ft, nil })
	_, err := nat.Discover(context.Background(), "stun.example:3478")
	if err == nil {
		t.Fatalf("Discover returned nil error on response without XOR-MAPPED-ADDRESS")
	}
}

func TestDiscover_RealUDPTransactor_AgainstLocalSTUN(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })

	mappedIP := net.ParseIP("198.51.100.42").To4()
	const mappedPort = 40404

	serverDone := make(chan error, 1)
	go func() {
		buf := make([]byte, nat.MaxResponseSize)
		_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, addr, rerr := pc.ReadFrom(buf)
		if rerr != nil {
			serverDone <- rerr
			return
		}
		req := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
		if derr := req.Decode(); derr != nil {
			serverDone <- derr
			return
		}
		resp := stun.MustBuild(stun.TransactionID, stun.BindingSuccess)
		if aerr := (&stun.XORMappedAddress{IP: mappedIP, Port: mappedPort}).AddTo(resp); aerr != nil {
			serverDone <- aerr
			return
		}
		resp.Encode()
		_, werr := pc.WriteTo(resp.Raw, addr)
		serverDone <- werr
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	host, err := nat.Discover(ctx, pc.LocalAddr().String())
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if host != mappedIP.String() {
		t.Errorf("host = %q, want %q", host, mappedIP.String())
	}
	if serr := <-serverDone; serr != nil {
		t.Errorf("stun server: %v", serr)
	}
}

func TestDiscover_ContextCancelClosesTransactorAndReturnsCtxErr(t *testing.T) {
	ft := &fakeTransactor{holdRecv: make(chan struct{})}
	withDial(t, func(_ context.Context, _, _ string) (nat.Transactor, error) { return ft, nil })

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := nat.Discover(ctx, "stun.example:3478")
		done <- err
	}()

	time.Sleep(20 * time.Millisecond) // let Recv park
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Discover did not return after ctx cancel")
	}
}
