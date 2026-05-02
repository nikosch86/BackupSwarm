package nat_test

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/nat"
)

// fakeWriter is a nat.PacketWriter that records every WriteTo call.
type fakeWriter struct {
	mu      sync.Mutex
	writes  []writeRecord
	writeFn func([]byte, net.Addr) (int, error)
}

type writeRecord struct {
	payload []byte
	addr    net.Addr
}

func (f *fakeWriter) WriteTo(b []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, writeRecord{
		payload: append([]byte(nil), b...),
		addr:    addr,
	})
	if f.writeFn != nil {
		return f.writeFn(b, addr)
	}
	return len(b), nil
}

func (f *fakeWriter) calls() []writeRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]writeRecord(nil), f.writes...)
}

func mustResolveUDP(t *testing.T, host string) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", host)
	if err != nil {
		t.Fatalf("ResolveUDPAddr %q: %v", host, err)
	}
	return addr
}

func TestPunch_FiresExpectedAttempts(t *testing.T) {
	w := &fakeWriter{}
	target := mustResolveUDP(t, "203.0.113.7:51820")
	if err := nat.Punch(context.Background(), w, target, 4, time.Microsecond); err != nil {
		t.Fatalf("Punch: %v", err)
	}
	calls := w.calls()
	if len(calls) != 4 {
		t.Fatalf("len(calls) = %d, want 4", len(calls))
	}
	for i, c := range calls {
		if c.addr.String() != target.String() {
			t.Errorf("call %d addr = %q, want %q", i, c.addr, target)
		}
		if len(c.payload) == 0 {
			t.Errorf("call %d payload empty", i)
		}
	}
}

func TestPunch_RejectsNonPositiveAttempts(t *testing.T) {
	w := &fakeWriter{}
	target := mustResolveUDP(t, "203.0.113.7:51820")
	for _, n := range []int{0, -1} {
		if err := nat.Punch(context.Background(), w, target, n, time.Microsecond); err == nil {
			t.Errorf("Punch(attempts=%d) returned nil, want error", n)
		}
	}
	if got := len(w.calls()); got != 0 {
		t.Errorf("len(calls) = %d, want 0 (rejected before any send)", got)
	}
}

func TestPunch_PropagatesSendError(t *testing.T) {
	sentinel := errors.New("write boom")
	w := &fakeWriter{writeFn: func([]byte, net.Addr) (int, error) { return 0, sentinel }}
	target := mustResolveUDP(t, "203.0.113.7:51820")
	err := nat.Punch(context.Background(), w, target, 5, time.Microsecond)
	if !errors.Is(err, sentinel) {
		t.Fatalf("Punch err = %v, want wraps sentinel", err)
	}
	if got := len(w.calls()); got != 1 {
		t.Errorf("len(calls) = %d, want 1 (aborted after first failure)", got)
	}
}

func TestPunch_RespectsCtxCancel(t *testing.T) {
	w := &fakeWriter{}
	target := mustResolveUDP(t, "203.0.113.7:51820")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancelled before first sleep returns
	err := nat.Punch(ctx, w, target, 5, time.Hour)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Punch err = %v, want context.Canceled", err)
	}
	if got := len(w.calls()); got != 1 {
		t.Errorf("len(calls) = %d, want exactly one send before cancel", got)
	}
}

func TestPunch_RejectsNilTarget(t *testing.T) {
	w := &fakeWriter{}
	if err := nat.Punch(context.Background(), w, nil, 3, time.Microsecond); err == nil {
		t.Error("Punch accepted nil target")
	}
}
