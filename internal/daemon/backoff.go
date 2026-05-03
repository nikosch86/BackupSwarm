package daemon

import (
	"encoding/hex"
	"math"
	mrand "math/rand/v2"
	"sync"
	"time"
)

// peerBackoff tracks consecutive dial failures per peer and enforces an
// exponential delay before the next eligible dial. MarkSuccess clears
// state. base ≤ 0 disables the gate (Allow always returns true).
type peerBackoff struct {
	mu       sync.Mutex
	attempts map[string]int
	nextAt   map[string]time.Time

	base   time.Duration
	max    time.Duration
	jitter bool

	now      func() time.Time
	randFunc func() float64
}

// newPeerBackoff returns a peerBackoff with the given parameters. nowFn
// defaults to time.Now; randFn defaults to math/rand/v2's global Float64.
func newPeerBackoff(base, max time.Duration, jitter bool, nowFn func() time.Time, randFn func() float64) *peerBackoff {
	if nowFn == nil {
		nowFn = time.Now
	}
	if randFn == nil {
		randFn = mrand.Float64
	}
	return &peerBackoff{
		attempts: make(map[string]int),
		nextAt:   make(map[string]time.Time),
		base:     base,
		max:      max,
		jitter:   jitter,
		now:      nowFn,
		randFunc: randFn,
	}
}

// Allow reports whether pub is eligible for a dial attempt right now.
// Disabled backoff (base ≤ 0), nil receiver, and unknown peers always allow.
func (b *peerBackoff) Allow(pub []byte) bool {
	if b == nil || b.base <= 0 || len(pub) == 0 {
		return true
	}
	key := hex.EncodeToString(pub)
	b.mu.Lock()
	defer b.mu.Unlock()
	next, ok := b.nextAt[key]
	if !ok {
		return true
	}
	return !b.now().Before(next)
}

// MarkFailure increments the attempt count for pub and schedules the
// next eligible time. No-op when backoff is disabled or pub is empty.
func (b *peerBackoff) MarkFailure(pub []byte) {
	if b == nil || b.base <= 0 || len(pub) == 0 {
		return
	}
	key := hex.EncodeToString(pub)
	b.mu.Lock()
	defer b.mu.Unlock()
	b.attempts[key]++
	delay := b.delayFor(b.attempts[key])
	b.nextAt[key] = b.now().Add(delay)
}

// MarkSuccess clears any backoff state for pub. Safe on nil receiver.
func (b *peerBackoff) MarkSuccess(pub []byte) {
	if b == nil || len(pub) == 0 {
		return
	}
	key := hex.EncodeToString(pub)
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.attempts, key)
	delete(b.nextAt, key)
}

// delayFor returns base * 2^(attempts-1), capped at max, optionally
// scaled by a random factor in [0.5, 1.0]. Caller must hold b.mu.
func (b *peerBackoff) delayFor(attempts int) time.Duration {
	factor := math.Pow(2, float64(attempts-1))
	delay := time.Duration(float64(b.base) * factor)
	if delay <= 0 || delay > b.max {
		delay = b.max
	}
	if b.jitter {
		delay = time.Duration(float64(delay) * (0.5 + 0.5*b.randFunc()))
	}
	return delay
}
