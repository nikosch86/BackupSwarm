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

// OnRecoverFunc is invoked when a peer transitions from a lost state
// (StateUnreachable past grace) back to StateReachable.
type OnRecoverFunc func(pub []byte)

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
	onRecover        OnRecoverFunc
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

// SetOnRecover installs the lost→reachable callback. Pass nil to clear.
// The callback fires after the state transition, outside the map's lock.
func (r *ReachabilityMap) SetOnRecover(fn OnRecoverFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.onRecover = fn
}

// Mark records s for pub. StateUnknown removes the entry.
func (r *ReachabilityMap) Mark(pub []byte, s State) {
	if len(pub) == 0 {
		return
	}
	key := hex.EncodeToString(pub)
	r.mu.Lock()
	if s == StateUnknown {
		delete(r.states, key)
		delete(r.misses, key)
		r.clearUnreachableSince(key)
		r.mu.Unlock()
		return
	}
	prev := r.states[key]
	cb := r.captureRecoverCallback(key, prev, s)
	r.states[key] = s
	delete(r.misses, key)
	r.maintainUnreachableSince(key, prev, s)
	r.mu.Unlock()
	fireRecover(cb, pub)
}

// RecordHeartbeat updates state on heartbeat outcome.
func (r *ReachabilityMap) RecordHeartbeat(pub []byte, ok bool) {
	if len(pub) == 0 {
		return
	}
	key := hex.EncodeToString(pub)
	r.mu.Lock()
	prev := r.states[key]
	var cb OnRecoverFunc
	if ok {
		cb = r.captureRecoverCallback(key, prev, StateReachable)
		r.states[key] = StateReachable
		delete(r.misses, key)
		r.maintainUnreachableSince(key, prev, StateReachable)
		r.mu.Unlock()
		fireRecover(cb, pub)
		return
	}
	r.misses[key]++
	if r.misses[key] >= r.missThreshold {
		r.states[key] = StateUnreachable
		r.maintainUnreachableSince(key, prev, StateUnreachable)
		r.mu.Unlock()
		return
	}
	r.states[key] = StateSuspect
	r.maintainUnreachableSince(key, prev, StateSuspect)
	r.mu.Unlock()
}

// captureRecoverCallback returns r.onRecover when the transition exits a
// lost state (Unreachable past grace) into Reachable; nil otherwise.
// Caller holds r.mu.
func (r *ReachabilityMap) captureRecoverCallback(key string, prev, next State) OnRecoverFunc {
	if !r.lostEnabled || r.onRecover == nil {
		return nil
	}
	if next != StateReachable || prev != StateUnreachable {
		return nil
	}
	since, ok := r.unreachableSince[key]
	if !ok {
		return nil
	}
	if r.now().Sub(since) < r.gracePeriod {
		return nil
	}
	return r.onRecover
}

// fireRecover dispatches cb with a defensive copy of pub. nil cb is a no-op.
func fireRecover(cb OnRecoverFunc, pub []byte) {
	if cb == nil {
		return
	}
	cb(bytes.Clone(pub))
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
