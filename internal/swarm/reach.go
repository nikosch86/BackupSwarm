package swarm

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sync"

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
	mu            sync.Mutex
	states        map[string]State
	misses        map[string]int
	missThreshold int
}

// NewReachabilityMap returns a map using DefaultMissThreshold.
func NewReachabilityMap() *ReachabilityMap {
	return NewReachabilityMapWithThreshold(DefaultMissThreshold)
}

// NewReachabilityMapWithThreshold returns a map using n as the consecutive
// miss count required for the StateSuspect → StateUnreachable transition.
// n must be positive; non-positive values panic.
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

// Mark records s as the latest state for pub and resets the per-peer
// miss counter. Marking StateUnknown removes the entry. A nil or empty
// pub is silently ignored.
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
		return
	}
	r.states[key] = s
	delete(r.misses, key)
}

// RecordHeartbeat updates pub's state from a single heartbeat outcome.
// ok=true sets StateReachable and resets the miss counter; consecutive
// misses set StateSuspect, then StateUnreachable at missThreshold.
func (r *ReachabilityMap) RecordHeartbeat(pub []byte, ok bool) {
	if len(pub) == 0 {
		return
	}
	key := hex.EncodeToString(pub)
	r.mu.Lock()
	defer r.mu.Unlock()
	if ok {
		r.states[key] = StateReachable
		delete(r.misses, key)
		return
	}
	r.misses[key]++
	if r.misses[key] >= r.missThreshold {
		r.states[key] = StateUnreachable
		return
	}
	r.states[key] = StateSuspect
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
