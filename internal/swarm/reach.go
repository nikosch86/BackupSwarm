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
	// StateUnknown is the zero value.
	StateUnknown State = iota
	// StateReachable: the most recent event was a success.
	StateReachable
	// StateSuspect: one or more consecutive missed heartbeats below threshold.
	StateSuspect
	// StateUnreachable: the most recent event was a failure.
	StateUnreachable
)

// DefaultMissThreshold flips Suspect to Unreachable.
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

// ReachabilityMap is the per-peer reachability state, keyed by hex(pubkey).
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

// NewReachabilityMap returns a map using DefaultMissThreshold.
func NewReachabilityMap() *ReachabilityMap {
	return NewReachabilityMapWithThreshold(DefaultMissThreshold)
}

// NewReachabilityMapWithThreshold returns a map using n as the miss threshold.
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

// NewReachabilityMapWithGrace enables IsLost after grace of continuous Unreachable.
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

// Mark records s for pub. StateUnknown removes the entry.
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

// RecordHeartbeat updates state on heartbeat outcome.
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

// maintainUnreachableSince updates the grace timer; caller holds r.mu.
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

// clearUnreachableSince drops the grace timer entry; caller holds r.mu.
func (r *ReachabilityMap) clearUnreachableSince(key string) {
	if !r.lostEnabled {
		return
	}
	delete(r.unreachableSince, key)
}

// IsLost reports whether pub has been Unreachable for at least the grace period.
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

// LostPubs returns a fresh copy of every pubkey for which IsLost is true.
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

// MarkConn records s for conn.RemotePub().
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
