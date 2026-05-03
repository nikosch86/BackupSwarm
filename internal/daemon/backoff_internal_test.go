package daemon

import (
	"encoding/hex"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// makeClock returns a now-func backed by an atomic clock and a Set function.
func makeClock(start time.Time) (func() time.Time, func(time.Time)) {
	var c atomic.Int64
	c.Store(start.UnixNano())
	now := func() time.Time { return time.Unix(0, c.Load()) }
	set := func(t time.Time) { c.Store(t.UnixNano()) }
	return now, set
}

func TestPeerBackoff_AllowFreshPeer(t *testing.T) {
	t.Parallel()
	now, _ := makeClock(time.Unix(0, 0))
	b := newPeerBackoff(time.Second, time.Minute, false, now, func() float64 { return 0 })
	if !b.Allow([]byte{1, 2, 3}) {
		t.Fatal("fresh peer must be allowed")
	}
}

func TestPeerBackoff_MarkFailureBlocksUntilNextAt(t *testing.T) {
	t.Parallel()
	start := time.Unix(0, 0)
	now, set := makeClock(start)
	b := newPeerBackoff(time.Second, time.Minute, false, now, func() float64 { return 1 })
	pub := []byte{0xab, 0xcd}

	b.MarkFailure(pub)
	if b.Allow(pub) {
		t.Fatal("peer must be in backoff immediately after MarkFailure")
	}
	set(start.Add(999 * time.Millisecond))
	if b.Allow(pub) {
		t.Fatal("peer must still be blocked just before next_at")
	}
	set(start.Add(time.Second))
	if !b.Allow(pub) {
		t.Fatal("peer must be allowed at exactly the next-eligible time")
	}
}

func TestPeerBackoff_ExponentialGrowth(t *testing.T) {
	t.Parallel()
	start := time.Unix(0, 0)
	now, set := makeClock(start)
	b := newPeerBackoff(time.Second, time.Minute, false, now, func() float64 { return 1 })
	pub := []byte{1}

	expected := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
	for i, want := range expected {
		set(start)
		b.MarkFailure(pub)
		set(start.Add(want - time.Millisecond))
		if b.Allow(pub) {
			t.Fatalf("attempt %d: peer must be blocked just before %v", i+1, want)
		}
		set(start.Add(want))
		if !b.Allow(pub) {
			t.Fatalf("attempt %d: peer must be allowed at delay=%v", i+1, want)
		}
	}
}

func TestPeerBackoff_CapsAtMax(t *testing.T) {
	t.Parallel()
	start := time.Unix(0, 0)
	now, set := makeClock(start)
	b := newPeerBackoff(time.Second, 5*time.Second, false, now, func() float64 { return 1 })
	pub := []byte{1}

	// Drive enough failures that base * 2^(n-1) far exceeds the cap.
	for i := 0; i < 20; i++ {
		set(start.Add(time.Duration(i) * time.Hour))
		b.MarkFailure(pub)
	}
	last := start.Add(19 * time.Hour)
	set(last.Add(4 * time.Second))
	if b.Allow(pub) {
		t.Fatal("peer must remain blocked until the max-cap delay")
	}
	set(last.Add(5 * time.Second))
	if !b.Allow(pub) {
		t.Fatal("peer must be allowed at the max-cap delay")
	}
}

func TestPeerBackoff_JitterScalesDelay(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		rand      float64
		wantDelay time.Duration
	}{
		{"r=0 -> half delay", 0, 500 * time.Millisecond},
		{"r=1 -> full delay", 1, 1 * time.Second},
		{"r=0.5 -> 0.75 delay", 0.5, 750 * time.Millisecond},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			start := time.Unix(0, 0)
			now, set := makeClock(start)
			b := newPeerBackoff(time.Second, time.Minute, true, now, func() float64 { return tc.rand })
			pub := []byte{1}
			b.MarkFailure(pub)
			set(start.Add(tc.wantDelay - time.Millisecond))
			if b.Allow(pub) {
				t.Fatalf("must be blocked just before %v", tc.wantDelay)
			}
			set(start.Add(tc.wantDelay))
			if !b.Allow(pub) {
				t.Fatalf("must be allowed at %v", tc.wantDelay)
			}
		})
	}
}

func TestPeerBackoff_MarkSuccessClearsState(t *testing.T) {
	t.Parallel()
	start := time.Unix(0, 0)
	now, _ := makeClock(start)
	b := newPeerBackoff(time.Second, time.Minute, false, now, func() float64 { return 1 })
	pub := []byte{1}
	b.MarkFailure(pub)
	b.MarkFailure(pub)
	if b.Allow(pub) {
		t.Fatal("blocked after MarkFailure")
	}
	b.MarkSuccess(pub)
	if !b.Allow(pub) {
		t.Fatal("MarkSuccess must clear state and allow immediately")
	}
	if got := b.attempts[hex.EncodeToString(pub)]; got != 0 {
		t.Fatalf("attempts after MarkSuccess = %d, want 0", got)
	}
	b.MarkFailure(pub)
	if got := b.attempts[hex.EncodeToString(pub)]; got != 1 {
		t.Fatalf("attempts after reset+failure = %d, want 1", got)
	}
}

func TestPeerBackoff_DisabledAlwaysAllows(t *testing.T) {
	t.Parallel()
	start := time.Unix(0, 0)
	now, _ := makeClock(start)
	b := newPeerBackoff(0, time.Minute, true, now, func() float64 { return 1 })
	pub := []byte{1}
	b.MarkFailure(pub)
	b.MarkFailure(pub)
	if !b.Allow(pub) {
		t.Fatal("disabled backoff (base<=0) must always allow")
	}
	if got := len(b.attempts); got != 0 {
		t.Fatalf("attempts after disabled MarkFailure = %d, want 0", got)
	}
}

func TestPeerBackoff_EmptyPubKeyNoop(t *testing.T) {
	t.Parallel()
	start := time.Unix(0, 0)
	now, _ := makeClock(start)
	b := newPeerBackoff(time.Second, time.Minute, false, now, func() float64 { return 1 })
	if !b.Allow(nil) {
		t.Fatal("nil pubkey must be allowed")
	}
	b.MarkFailure(nil)
	b.MarkSuccess(nil)
	if got := len(b.attempts); got != 0 {
		t.Fatalf("attempts after nil failure = %d, want 0", got)
	}
}

func TestPeerBackoff_NilReceiverSafe(t *testing.T) {
	t.Parallel()
	var b *peerBackoff
	if !b.Allow([]byte{1}) {
		t.Fatal("nil backoff must always allow")
	}
	b.MarkFailure([]byte{1})
	b.MarkSuccess([]byte{1})
}

func TestPeerBackoff_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	start := time.Unix(0, 0)
	now, _ := makeClock(start)
	b := newPeerBackoff(time.Millisecond, time.Second, true, now, func() float64 { return 0.5 })
	const peers = 16
	const iters = 32
	var wg sync.WaitGroup
	for i := 0; i < peers; i++ {
		pub := []byte{byte(i)}
		wg.Add(3)
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				b.MarkFailure(pub)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_ = b.Allow(pub)
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				b.MarkSuccess(pub)
			}
		}()
	}
	wg.Wait()
}

func TestPeerBackoff_NoOverflowAtHighAttempts(t *testing.T) {
	t.Parallel()
	start := time.Unix(0, 0)
	now, _ := makeClock(start)
	// base 1s, max 30m -> attempts past ~11 hit the cap; ensure 1000 attempts
	// don't overflow into a negative duration.
	b := newPeerBackoff(time.Second, 30*time.Minute, false, now, func() float64 { return 1 })
	pub := []byte{1}
	for i := 0; i < 1000; i++ {
		b.MarkFailure(pub)
	}
	delay := b.delayFor(b.attempts[hex.EncodeToString(pub)])
	if delay != 30*time.Minute {
		t.Fatalf("delay at 1000 attempts = %v, want 30m (capped)", delay)
	}
}
