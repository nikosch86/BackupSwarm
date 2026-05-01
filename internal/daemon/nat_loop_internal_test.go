package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
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
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, _ string) error {
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
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, p ed25519.PublicKey, addr string) error {
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
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, _ string) error {
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

func TestRunNATLoop_StopsOnCtxCancel(t *testing.T) {
	orig := natDiscoverFunc
	t.Cleanup(func() { natDiscoverFunc = orig })
	natDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return "203.0.113.7", nil
	}
	origB := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = origB })
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, _ string) error {
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
