package swarm

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	bsquic "backupswarm/internal/quic"
)

// State is the reachability classification of a known peer.
type State int

const (
	// StateUnknown is the zero value; no state recorded for the peer.
	StateUnknown State = iota
	// StateReachable indicates the most recent connection event was a success.
	StateReachable
	// StateSuspect indicates one or more consecutive missed heartbeats
	// have been recorded but the miss threshold has not yet been reached.
	StateSuspect
	// StateUnreachable indicates the most recent connection event was a failure.
	StateUnreachable
)

// DefaultMissThreshold is the number of consecutive missed heartbeats
// required to flip a peer from StateSuspect to StateUnreachable.
const DefaultMissThreshold = 3

// String returns a short human label for the state.
func (s State) String() string {
	switch s {
	case StateUnknown:
		return "unknown"
	case StateReachable:
		return "reachable"
	case StateSuspect:
		return "suspect"
	case StateUnreachable:
		return "unreachable"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// ReachabilityMap is the in-memory reachability state per known peer,
// keyed by hex(pubkey). Safe for concurrent use.
type ReachabilityMap struct {
	mu               sync.Mutex
	states           map[string]State
	misses           map[string]int
	missThreshold    int
	gracePeriod      time.Duration
	now              func() time.Time
	unreachableSince map[string]time.Time
	lostEnabled      bool
}

// NewReachabilityMap returns a map using DefaultMissThreshold; IsLost
// always returns false.
func NewReachabilityMap() *ReachabilityMap {
	return NewReachabilityMapWithThreshold(DefaultMissThreshold)
}

// NewReachabilityMapWithThreshold returns a map using n as the
// suspect→unreachable miss count; IsLost always returns false. n must
// be positive; non-positive values panic.
func NewReachabilityMapWithThreshold(n int) *ReachabilityMap {
	if n <= 0 {
		panic(fmt.Sprintf("swarm: miss threshold must be positive, got %d", n))
	}
	return &ReachabilityMap{
		states:        make(map[string]State),
		misses:        make(map[string]int),
		missThreshold: n,
	}
}

// NewReachabilityMapWithGrace returns a map where IsLost flips true
// once a peer has been continuously StateUnreachable for grace; now nil
// defaults to time.Now. missThreshold>0 and grace>=0 or panic.
func NewReachabilityMapWithGrace(missThreshold int, grace time.Duration, now func() time.Time) *ReachabilityMap {
	if missThreshold <= 0 {
		panic(fmt.Sprintf("swarm: miss threshold must be positive, got %d", missThreshold))
	}
	if grace < 0 {
		panic(fmt.Sprintf("swarm: grace must be non-negative, got %v", grace))
	}
	if now == nil {
		now = time.Now
	}
	return &ReachabilityMap{
		states:           make(map[string]State),
		misses:           make(map[string]int),
		missThreshold:    missThreshold,
		gracePeriod:      grace,
		now:              now,
		unreachableSince: make(map[string]time.Time),
		lostEnabled:      true,
	}
}

// Mark records s for pub, resets the per-peer miss counter, stamps or
// clears the grace timer on transitions into/out of StateUnreachable,
// and is a no-op for nil/empty pub. StateUnknown removes the entry.
func (r *ReachabilityMap) Mark(pub []byte, s State) {
	if len(pub) == 0 {
		return
	}
	key := hex.EncodeToString(pub)
	r.mu.Lock()
	defer r.mu.Unlock()
	if s == StateUnknown {
		delete(r.states, key)
		delete(r.misses, key)
		r.clearUnreachableSince(key)
		return
	}
	prev := r.states[key]
	r.states[key] = s
	delete(r.misses, key)
	r.maintainUnreachableSince(key, prev, s)
}

// RecordHeartbeat sets StateReachable on ok=true (resets misses) and
// StateSuspect→StateUnreachable as consecutive misses cross
// missThreshold. Stamps and clears the grace timer like Mark.
func (r *ReachabilityMap) RecordHeartbeat(pub []byte, ok bool) {
	if len(pub) == 0 {
		return
	}
	key := hex.EncodeToString(pub)
	r.mu.Lock()
	defer r.mu.Unlock()
	prev := r.states[key]
	if ok {
		r.states[key] = StateReachable
		delete(r.misses, key)
		r.maintainUnreachableSince(key, prev, StateReachable)
		return
	}
	r.misses[key]++
	if r.misses[key] >= r.missThreshold {
		r.states[key] = StateUnreachable
		r.maintainUnreachableSince(key, prev, StateUnreachable)
		return
	}
	r.states[key] = StateSuspect
	r.maintainUnreachableSince(key, prev, StateSuspect)
}

// maintainUnreachableSince stamps or clears the grace timer based on the
// state transition. Caller holds r.mu.
func (r *ReachabilityMap) maintainUnreachableSince(key string, prev, next State) {
	if !r.lostEnabled {
		return
	}
	if next == StateUnreachable {
		if prev != StateUnreachable {
			r.unreachableSince[key] = r.now()
		}
		return
	}
	delete(r.unreachableSince, key)
}

// clearUnreachableSince drops the grace timer entry for key. Caller
// holds r.mu.
func (r *ReachabilityMap) clearUnreachableSince(key string) {
	if !r.lostEnabled {
		return
	}
	delete(r.unreachableSince, key)
}

// IsLost reports whether pub has been continuously StateUnreachable
// for at least the configured grace period. Always false for nil/empty
// pub, non-Unreachable peers, and maps without grace machinery.
func (r *ReachabilityMap) IsLost(pub []byte) bool {
	if len(pub) == 0 {
		return false
	}
	key := hex.EncodeToString(pub)
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.lostEnabled {
		return false
	}
	if r.states[key] != StateUnreachable {
		return false
	}
	since := r.unreachableSince[key]
	return r.now().Sub(since) >= r.gracePeriod
}

// LostPubs returns a fresh copy of every pubkey for which IsLost is
// currently true. Returns an empty slice on maps without grace-period
// machinery.
func (r *ReachabilityMap) LostPubs() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.lostEnabled {
		return nil
	}
	now := r.now()
	out := make([][]byte, 0, len(r.unreachableSince))
	for k, since := range r.unreachableSince {
		if now.Sub(since) < r.gracePeriod {
			continue
		}
		raw, err := hex.DecodeString(k)
		if err != nil {
			continue
		}
		out = append(out, bytes.Clone(raw))
	}
	return out
}

// MarkConn records s for conn.RemotePub(). A nil conn or empty remote
// pubkey is silently ignored.
func (r *ReachabilityMap) MarkConn(conn *bsquic.Conn, s State) {
	if conn == nil {
		return
	}
	r.Mark(conn.RemotePub(), s)
}

// State returns the recorded state for pub, or StateUnknown when absent.
func (r *ReachabilityMap) State(pub []byte) State {
	if len(pub) == 0 {
		return StateUnknown
	}
	key := hex.EncodeToString(pub)
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.states[key]
}

// IsReachable reports whether pub's most recent state is StateReachable.
func (r *ReachabilityMap) IsReachable(pub []byte) bool {
	return r.State(pub) == StateReachable
}

// ReachablePubs returns a fresh copy of every pubkey currently in
// StateReachable.
func (r *ReachabilityMap) ReachablePubs() [][]byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([][]byte, 0, len(r.states))
	for k, s := range r.states {
		if s != StateReachable {
			continue
		}
		raw, err := hex.DecodeString(k)
		if err != nil {
			continue
		}
		out = append(out, bytes.Clone(raw))
	}
	return out
}

// Snapshot returns a copy of the internal state map keyed by hex(pubkey).
func (r *ReachabilityMap) Snapshot() map[string]State {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]State, len(r.states))
	for k, v := range r.states {
		out[k] = v
	}
	return out
}
