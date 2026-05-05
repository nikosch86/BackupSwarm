package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/nat"
	bsquic "backupswarm/internal/quic"
)

// fakePortMapper records Map and Unmap calls for tests.
type fakePortMapper struct {
	mu      sync.Mutex
	mapErr  error
	unmap   bool
	results []nat.Mapping
	calls   int
}

func (f *fakePortMapper) Map(_ context.Context, _ int) (nat.Mapping, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.mapErr != nil {
		return nat.Mapping{}, f.mapErr
	}
	if len(f.results) == 0 {
		return nat.Mapping{}, errors.New("fake: no scripted result")
	}
	out := f.results[0]
	if len(f.results) > 1 {
		f.results = f.results[1:]
	}
	return out, nil
}

func (f *fakePortMapper) Unmap(_ context.Context, _ nat.Mapping) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.unmap = true
	return nil
}

func TestNextPortMapRefresh_BoundsAndJitter(t *testing.T) {
	prev := portmapJitterFn
	t.Cleanup(func() { portmapJitterFn = prev })
	portmapJitterFn = func() float64 { return 1.0 }

	cases := []struct {
		name       string
		lease      int
		wantApprox time.Duration
	}{
		{"zero-lease-uses-default", 0, defaultPortMapRefresh},
		{"lease/2-bounded-min", 1, minPortMapRefresh},
		{"lease/2-typical", 7200, 3600 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := nextPortMapRefresh(tc.lease)
			if got != tc.wantApprox {
				t.Errorf("got %v, want %v", got, tc.wantApprox)
			}
		})
	}
}

func TestNextPortMapRefresh_CapsAtMax(t *testing.T) {
	prev := portmapJitterFn
	t.Cleanup(func() { portmapJitterFn = prev })
	portmapJitterFn = func() float64 { return 1.0 }
	got := nextPortMapRefresh(1 << 25)
	if got != maxPortMapRefresh {
		t.Errorf("got %v, want %v", got, maxPortMapRefresh)
	}
}

// withFastRefresh shrinks the loop's refresh bounds so tests don't wait
// for the production 30-second floor.
func withFastRefresh(t *testing.T) {
	t.Helper()
	prevMin := minPortMapRefresh
	prevDefault := defaultPortMapRefresh
	prevMax := maxPortMapRefresh
	minPortMapRefresh = time.Millisecond
	defaultPortMapRefresh = 5 * time.Millisecond
	maxPortMapRefresh = 50 * time.Millisecond
	t.Cleanup(func() {
		minPortMapRefresh = prevMin
		defaultPortMapRefresh = prevDefault
		maxPortMapRefresh = prevMax
	})
}

// TestRunPortMapLoop_BroadcastsRelayAddr asserts opts.relayAddr is
// shipped alongside the new mapped addr on every emit.
func TestRunPortMapLoop_BroadcastsRelayAddr(t *testing.T) {
	prevBroadcast := broadcastAddressChangedFunc
	prevMap := portmapMapFunc
	prevJitter := portmapJitterFn
	t.Cleanup(func() {
		broadcastAddressChangedFunc = prevBroadcast
		portmapMapFunc = prevMap
		portmapJitterFn = prevJitter
	})
	portmapJitterFn = func() float64 { return 1.0 }
	withFastRefresh(t)

	type bc struct{ addr, relay string }
	bcCh := make(chan bc, 4)
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, addr, relay string) error {
		bcCh <- bc{addr: addr, relay: relay}
		return nil
	}

	mapper := &fakePortMapper{
		results: []nat.Mapping{
			{ExternalIP: net.IPv4(203, 0, 113, 22), ExternalPort: 7777, InternalPort: 7777, Protocol: "upnp", LeaseSeconds: 0},
		},
	}
	portmapMapFunc = func(_ context.Context, _ nat.PortMapper, _ int) (nat.Mapping, error) {
		return mapper.Map(context.Background(), 0)
	}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPortMapLoop(ctx, portmapLoopOptions{
			mapper:       mapper,
			initial:      nat.Mapping{ExternalIP: net.IPv4(198, 51, 100, 1), ExternalPort: 7777, InternalPort: 7777, Protocol: "upnp", LeaseSeconds: 60},
			internalPort: 7777,
			pub:          pub,
			relayAddr:    "203.0.113.5:3478",
			connsFn:      func() []*bsquic.Conn { return nil },
		})
	}()

	select {
	case got := <-bcCh:
		if got.addr != "203.0.113.22:7777" {
			t.Errorf("addr = %q, want 203.0.113.22:7777", got.addr)
		}
		if got.relay != "203.0.113.5:3478" {
			t.Errorf("relay = %q, want 203.0.113.5:3478", got.relay)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AddressChanged not broadcast within 2s")
	}
	cancel()
	<-done
}

func TestRunPortMapLoop_BroadcastsOnAddressChange(t *testing.T) {
	prevBroadcast := broadcastAddressChangedFunc
	prevMap := portmapMapFunc
	prevJitter := portmapJitterFn
	t.Cleanup(func() {
		broadcastAddressChangedFunc = prevBroadcast
		portmapMapFunc = prevMap
		portmapJitterFn = prevJitter
	})
	portmapJitterFn = func() float64 { return 1.0 }
	withFastRefresh(t)

	gotAddrCh := make(chan string, 4)
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, addr, _ string) error {
		gotAddrCh <- addr
		return nil
	}

	mapper := &fakePortMapper{
		results: []nat.Mapping{
			{ExternalIP: net.IPv4(203, 0, 113, 22), ExternalPort: 7777, InternalPort: 7777, Protocol: "upnp", LeaseSeconds: 0},
		},
	}
	portmapMapFunc = func(_ context.Context, _ nat.PortMapper, _ int) (nat.Mapping, error) {
		return mapper.Map(context.Background(), 0)
	}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPortMapLoop(ctx, portmapLoopOptions{
			mapper:       mapper,
			initial:      nat.Mapping{ExternalIP: net.IPv4(198, 51, 100, 1), ExternalPort: 7777, InternalPort: 7777, Protocol: "upnp", LeaseSeconds: 60},
			internalPort: 7777,
			pub:          pub,
			connsFn:      func() []*bsquic.Conn { return nil },
		})
	}()

	select {
	case got := <-gotAddrCh:
		if got != "203.0.113.22:7777" {
			t.Errorf("addr = %q, want %q", got, "203.0.113.22:7777")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("AddressChanged not broadcast within 2s")
	}
	cancel()
	<-done
}

func TestRunPortMapLoop_NoBroadcastWhenAddressUnchanged(t *testing.T) {
	prevBroadcast := broadcastAddressChangedFunc
	prevMap := portmapMapFunc
	prevJitter := portmapJitterFn
	t.Cleanup(func() {
		broadcastAddressChangedFunc = prevBroadcast
		portmapMapFunc = prevMap
		portmapJitterFn = prevJitter
	})
	portmapJitterFn = func() float64 { return 1.0 }
	withFastRefresh(t)

	var broadcasts int
	var mu sync.Mutex
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, _, _ string) error {
		mu.Lock()
		defer mu.Unlock()
		broadcasts++
		return nil
	}

	initial := nat.Mapping{ExternalIP: net.IPv4(203, 0, 113, 5), ExternalPort: 7777, InternalPort: 7777, LeaseSeconds: 1}
	portmapMapFunc = func(_ context.Context, _ nat.PortMapper, _ int) (nat.Mapping, error) {
		return initial, nil
	}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPortMapLoop(ctx, portmapLoopOptions{
			mapper:       &fakePortMapper{},
			initial:      initial,
			internalPort: 7777,
			pub:          pub,
			connsFn:      func() []*bsquic.Conn { return nil },
		})
	}()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if broadcasts != 0 {
		t.Errorf("broadcasts = %d, want 0", broadcasts)
	}
}

func TestRunPortMapLoop_RefreshFailureLogsAndContinues(t *testing.T) {
	prevMap := portmapMapFunc
	prevJitter := portmapJitterFn
	prevBroadcast := broadcastAddressChangedFunc
	t.Cleanup(func() {
		portmapMapFunc = prevMap
		portmapJitterFn = prevJitter
		broadcastAddressChangedFunc = prevBroadcast
	})
	portmapJitterFn = func() float64 { return 1.0 }
	withFastRefresh(t)
	broadcastAddressChangedFunc = func(context.Context, []*bsquic.Conn, ed25519.PublicKey, string, string) error {
		t.Fatal("broadcast should not run on refresh failure")
		return nil
	}

	calls := make(chan int, 8)
	var mu sync.Mutex
	var n int
	portmapMapFunc = func(_ context.Context, _ nat.PortMapper, _ int) (nat.Mapping, error) {
		mu.Lock()
		n++
		c := n
		mu.Unlock()
		select {
		case calls <- c:
		default:
		}
		return nat.Mapping{}, errors.New("forced refresh failure")
	}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPortMapLoop(ctx, portmapLoopOptions{
			mapper:       &fakePortMapper{mapErr: errors.New("ignored")},
			initial:      nat.Mapping{ExternalIP: net.IPv4(1, 2, 3, 4), ExternalPort: 7777, LeaseSeconds: 1},
			internalPort: 7777,
			pub:          pub,
			connsFn:      func() []*bsquic.Conn { return nil },
		})
	}()

	select {
	case <-calls:
	case <-time.After(2 * time.Second):
		t.Fatal("refresh map call did not fire within 2s")
	}
	cancel()
	<-done
}

func TestRunPortMapLoop_ContextCancelExits(t *testing.T) {
	prevJitter := portmapJitterFn
	t.Cleanup(func() { portmapJitterFn = prevJitter })
	portmapJitterFn = func() float64 { return 1.0 }

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPortMapLoop(ctx, portmapLoopOptions{
			mapper:       &fakePortMapper{},
			initial:      nat.Mapping{ExternalIP: net.IPv4(1, 2, 3, 4), ExternalPort: 7777, LeaseSeconds: 100},
			internalPort: 7777,
			pub:          pub,
			connsFn:      func() []*bsquic.Conn { return nil },
		})
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("loop did not exit within 1s of cancel")
	}
}

func TestPortFromListenerAddr(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		want    int
		wantErr bool
	}{
		{"valid-host-port", "127.0.0.1:7777", 7777, false},
		{"valid-zero-host", "0.0.0.0:65535", 65535, false},
		{"missing-port", "127.0.0.1", 0, true},
		{"non-numeric-port", "127.0.0.1:abcd", 0, true},
		{"empty", "", 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := portFromListenerAddr(tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected err: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %d, want %d", got, tc.want)
			}
		})
	}
}

func TestPortMapAddrEqual(t *testing.T) {
	a := nat.Mapping{ExternalIP: net.IPv4(1, 2, 3, 4), ExternalPort: 7777}
	b := nat.Mapping{ExternalIP: net.IPv4(1, 2, 3, 4), ExternalPort: 7777}
	c := nat.Mapping{ExternalIP: net.IPv4(1, 2, 3, 5), ExternalPort: 7777}
	d := nat.Mapping{ExternalIP: net.IPv4(1, 2, 3, 4), ExternalPort: 7778}
	if !portMapAddrEqual(a, b) {
		t.Error("a==b should be true")
	}
	if portMapAddrEqual(a, c) {
		t.Error("differing IP should not equal")
	}
	if portMapAddrEqual(a, d) {
		t.Error("differing port should not equal")
	}
}

func TestRunPortMapLoop_BroadcastFailureLogsAndContinues(t *testing.T) {
	prevBroadcast := broadcastAddressChangedFunc
	prevMap := portmapMapFunc
	prevJitter := portmapJitterFn
	t.Cleanup(func() {
		broadcastAddressChangedFunc = prevBroadcast
		portmapMapFunc = prevMap
		portmapJitterFn = prevJitter
	})
	portmapJitterFn = func() float64 { return 1.0 }
	withFastRefresh(t)

	broadcastAddressChangedFunc = func(context.Context, []*bsquic.Conn, ed25519.PublicKey, string, string) error {
		return errors.New("forced broadcast failure")
	}
	portmapMapFunc = func(_ context.Context, _ nat.PortMapper, _ int) (nat.Mapping, error) {
		return nat.Mapping{ExternalIP: net.IPv4(203, 0, 113, 99), ExternalPort: 7777, LeaseSeconds: 0}, nil
	}

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		runPortMapLoop(ctx, portmapLoopOptions{
			mapper:       &fakePortMapper{},
			initial:      nat.Mapping{ExternalIP: net.IPv4(1, 2, 3, 4), ExternalPort: 7777, LeaseSeconds: 1},
			internalPort: 7777,
			pub:          pub,
			connsFn:      func() []*bsquic.Conn { return nil },
		})
	}()
	<-done
}
