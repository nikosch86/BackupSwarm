package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	bsquic "backupswarm/internal/quic"
)

func TestRunNATLoop_NoBroadcastWhenHostUnchanged(t *testing.T) {
	var discoverCalls atomic.Int32
	var broadcastCalls atomic.Int32

	orig := natDiscoverFunc
	t.Cleanup(func() { natDiscoverFunc = orig })
	natDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		discoverCalls.Add(1)
		return "203.0.113.7", nil
	}

	origB := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = origB })
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, _, _ string) error {
		broadcastCalls.Add(1)
		return nil
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runNATLoop(ctx, natLoopOptions{
			server:      "stun.example:3478",
			interval:    20 * time.Millisecond,
			perProbe:    50 * time.Millisecond,
			port:        "7777",
			pub:         pub,
			initialHost: "203.0.113.7",
			connsFn:     func() []*bsquic.Conn { return nil },
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && discoverCalls.Load() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runNATLoop did not exit on ctx cancel")
	}
	if got := discoverCalls.Load(); got < 3 {
		t.Fatalf("discover calls = %d, want >= 3", got)
	}
	if got := broadcastCalls.Load(); got != 0 {
		t.Errorf("broadcast called %d times, want 0 (host matched initialHost)", got)
	}
}

// TestRunNATLoop_BroadcastsRelayAddr asserts opts.relayAddr is shipped
// alongside the new direct addr on every emit, so receivers learn the
// peer's TURN endpoint in the same announcement.
func TestRunNATLoop_BroadcastsRelayAddr(t *testing.T) {
	var hostMu sync.Mutex
	host := "203.0.113.7"
	getHost := func() string { hostMu.Lock(); defer hostMu.Unlock(); return host }
	setHost := func(h string) { hostMu.Lock(); defer hostMu.Unlock(); host = h }

	orig := natDiscoverFunc
	t.Cleanup(func() { natDiscoverFunc = orig })
	natDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return getHost(), nil
	}

	type bc struct{ addr, relay string }
	bcCh := make(chan bc, 4)
	origB := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = origB })
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, addr, relay string) error {
		bcCh <- bc{addr: addr, relay: relay}
		return nil
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runNATLoop(ctx, natLoopOptions{
		server:      "stun.example:3478",
		interval:    20 * time.Millisecond,
		perProbe:    50 * time.Millisecond,
		port:        "7777",
		pub:         pub,
		initialHost: "203.0.113.7",
		relayAddr:   "203.0.113.5:3478",
		connsFn:     func() []*bsquic.Conn { return nil },
	})

	setHost("198.51.100.42")
	select {
	case got := <-bcCh:
		if got.addr != "198.51.100.42:7777" {
			t.Errorf("addr = %q, want 198.51.100.42:7777", got.addr)
		}
		if got.relay != "203.0.113.5:3478" {
			t.Errorf("relay = %q, want 203.0.113.5:3478", got.relay)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no broadcast received after host change")
	}
}

func TestRunNATLoop_BroadcastsOnHostChange(t *testing.T) {
	var hostMu sync.Mutex
	host := "203.0.113.7"
	getHost := func() string { hostMu.Lock(); defer hostMu.Unlock(); return host }
	setHost := func(h string) { hostMu.Lock(); defer hostMu.Unlock(); host = h }

	orig := natDiscoverFunc
	t.Cleanup(func() { natDiscoverFunc = orig })
	natDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return getHost(), nil
	}

	type bc struct {
		addr string
		pub  ed25519.PublicKey
	}
	bcCh := make(chan bc, 4)
	origB := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = origB })
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, p ed25519.PublicKey, addr, _ string) error {
		bcCh <- bc{addr: addr, pub: p}
		return nil
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runNATLoop(ctx, natLoopOptions{
		server:      "stun.example:3478",
		interval:    20 * time.Millisecond,
		perProbe:    50 * time.Millisecond,
		port:        "7777",
		pub:         pub,
		initialHost: "203.0.113.7",
		connsFn:     func() []*bsquic.Conn { return nil },
	})

	// Drain any zero broadcasts during baseline period.
	time.Sleep(80 * time.Millisecond)
	select {
	case <-bcCh:
		t.Fatal("unexpected broadcast during baseline period")
	default:
	}

	setHost("198.51.100.42")
	select {
	case got := <-bcCh:
		if got.addr != "198.51.100.42:7777" {
			t.Errorf("addr = %q, want 198.51.100.42:7777", got.addr)
		}
		if !got.pub.Equal(pub) {
			t.Error("broadcast pub != daemon pub")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no broadcast received after host change")
	}
}

// TestRunNATLoop_BroadcastErrorIsLoggedAndLoopContinues asserts a
// failing AddressChanged broadcast does not abort the loop and the
// next host change still triggers another emit attempt.
func TestRunNATLoop_BroadcastErrorIsLoggedAndLoopContinues(t *testing.T) {
	var hostMu sync.Mutex
	host := "203.0.113.7"
	getHost := func() string { hostMu.Lock(); defer hostMu.Unlock(); return host }
	setHost := func(h string) { hostMu.Lock(); defer hostMu.Unlock(); host = h }

	orig := natDiscoverFunc
	t.Cleanup(func() { natDiscoverFunc = orig })
	natDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return getHost(), nil
	}

	var broadcastCalls atomic.Int32
	origB := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = origB })
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, _, _ string) error {
		broadcastCalls.Add(1)
		return errors.New("broadcast boom")
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runNATLoop(ctx, natLoopOptions{
		server:      "stun.example:3478",
		interval:    20 * time.Millisecond,
		perProbe:    50 * time.Millisecond,
		port:        "7777",
		pub:         pub,
		initialHost: "203.0.113.7",
		connsFn:     func() []*bsquic.Conn { return nil },
	})

	setHost("198.51.100.42")
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && broadcastCalls.Load() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := broadcastCalls.Load(); got < 1 {
		t.Fatalf("broadcast calls = %d, want >= 1 after host change", got)
	}
	// Loop must keep ticking after the broadcast error.
	setHost("198.51.100.43")
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && broadcastCalls.Load() < 2 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := broadcastCalls.Load(); got < 2 {
		t.Errorf("broadcast calls = %d after second host change, want loop to continue", got)
	}
}

func TestRunNATLoop_DiscoverErrorIsLoggedAndLoopContinues(t *testing.T) {
	var discoverCalls atomic.Int32
	var broadcastCalls atomic.Int32

	orig := natDiscoverFunc
	t.Cleanup(func() { natDiscoverFunc = orig })
	natDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		discoverCalls.Add(1)
		return "", errors.New("network down")
	}
	origB := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = origB })
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, _, _ string) error {
		broadcastCalls.Add(1)
		return nil
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go runNATLoop(ctx, natLoopOptions{
		server:      "stun.example:3478",
		interval:    20 * time.Millisecond,
		perProbe:    50 * time.Millisecond,
		port:        "7777",
		pub:         pub,
		initialHost: "203.0.113.7",
		connsFn:     func() []*bsquic.Conn { return nil },
	})
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && discoverCalls.Load() < 3 {
		time.Sleep(10 * time.Millisecond)
	}
	if got := discoverCalls.Load(); got < 3 {
		t.Errorf("discover calls = %d, want loop to continue past first err", got)
	}
	if got := broadcastCalls.Load(); got != 0 {
		t.Errorf("broadcast called %d times despite discover errors", got)
	}
}

// TestResolveTURNServerIP_LiteralIPv4 returns the parsed IP without a DNS
// lookup when the host portion is already an IPv4 literal.
func TestResolveTURNServerIP_LiteralIPv4(t *testing.T) {
	got, err := resolveTURNServerIP("198.51.100.7:3478")
	if err != nil {
		t.Fatalf("resolveTURNServerIP: %v", err)
	}
	want := net.ParseIP("198.51.100.7").To4()
	if !got.Equal(want) {
		t.Errorf("ip = %v, want %v", got, want)
	}
}

// TestResolveTURNServerIP_NoColon rejects a host string with no port
// separator; the wrapper surfaces "split host:port".
func TestResolveTURNServerIP_NoColon(t *testing.T) {
	_, err := resolveTURNServerIP("not-a-hostport")
	if err == nil {
		t.Fatal("resolveTURNServerIP accepted host without port")
	}
	if !strings.Contains(err.Error(), "split host:port") {
		t.Errorf("err = %q, want 'split host:port' substring", err)
	}
}

// TestResolveTURNServerIP_LoopbackHostname exercises the DNS-lookup
// branch with "localhost" (or 127.0.0.1 fallback), which resolves
// without external network access on supported systems.
func TestResolveTURNServerIP_LoopbackHostname(t *testing.T) {
	got, err := resolveTURNServerIP("localhost:3478")
	if err != nil {
		t.Skipf("localhost not resolvable in this environment: %v", err)
	}
	if got == nil || !got.IsLoopback() {
		t.Errorf("ip = %v, want loopback", got)
	}
}

// TestResolveTURNServerIP_UnresolvableHost asserts the resolver branch
// surfaces "resolve" when net.ResolveIPAddr fails.
func TestResolveTURNServerIP_UnresolvableHost(t *testing.T) {
	_, err := resolveTURNServerIP("definitely-not-a-real-host.invalid:3478")
	if err == nil {
		t.Fatal("resolveTURNServerIP accepted unresolvable host")
	}
	if !strings.Contains(err.Error(), "resolve") {
		t.Errorf("err = %q, want 'resolve' substring", err)
	}
}

func TestRunNATLoop_StopsOnCtxCancel(t *testing.T) {
	orig := natDiscoverFunc
	t.Cleanup(func() { natDiscoverFunc = orig })
	natDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return "203.0.113.7", nil
	}
	origB := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = origB })
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, _, _ string) error {
		return nil
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runNATLoop(ctx, natLoopOptions{
			server:      "stun.example:3478",
			interval:    50 * time.Millisecond,
			perProbe:    50 * time.Millisecond,
			port:        "7777",
			pub:         pub,
			initialHost: "203.0.113.7",
			connsFn:     func() []*bsquic.Conn { return nil },
		})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runNATLoop did not exit on ctx cancel")
	}
}
