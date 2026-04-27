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
	// StateUnreachable indicates the most recent connection event was a failure.
	StateUnreachable
)

// String returns a short human label for the state.
func (s State) String() string {
	switch s {
	case StateUnknown:
		return "unknown"
	case StateReachable:
		return "reachable"
	case StateUnreachable:
		return "unreachable"
	default:
		return fmt.Sprintf("unknown(%d)", int(s))
	}
}

// ReachabilityMap is the in-memory reachability state per known peer,
// keyed by hex(pubkey). Safe for concurrent use.
type ReachabilityMap struct {
	mu     sync.Mutex
	states map[string]State
}

// NewReachabilityMap returns an empty map.
func NewReachabilityMap() *ReachabilityMap {
	return &ReachabilityMap{states: make(map[string]State)}
}

// Mark records s as the latest state for pub. Marking StateUnknown
// removes the entry. A nil or empty pub is silently ignored.
func (r *ReachabilityMap) Mark(pub []byte, s State) {
	if len(pub) == 0 {
		return
	}
	key := hex.EncodeToString(pub)
	r.mu.Lock()
	defer r.mu.Unlock()
	if s == StateUnknown {
		delete(r.states, key)
		return
	}
	r.states[key] = s
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
