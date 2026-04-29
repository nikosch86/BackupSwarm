package swarm

import (
	"encoding/hex"
	"sync"

	bsquic "backupswarm/internal/quic"
)

// ConnSet is a registry of live QUIC connections keyed by hex(remote pubkey).
type ConnSet struct {
	mu    sync.Mutex
	conns map[string]*bsquic.Conn
}

// NewConnSet returns an empty ConnSet.
func NewConnSet() *ConnSet {
	return &ConnSet{conns: make(map[string]*bsquic.Conn)}
}

// Add registers conn under its RemotePub.
func (s *ConnSet) Add(conn *bsquic.Conn) {
	if conn == nil {
		return
	}
	pub := conn.RemotePub()
	if len(pub) == 0 {
		return
	}
	key := hex.EncodeToString(pub)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.conns[key] = conn
}

// Remove unregisters conn when the stored pointer matches.
func (s *ConnSet) Remove(conn *bsquic.Conn) {
	if conn == nil {
		return
	}
	pub := conn.RemotePub()
	if len(pub) == 0 {
		return
	}
	key := hex.EncodeToString(pub)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.conns[key]; ok && existing == conn {
		delete(s.conns, key)
	}
}

// Snapshot returns a copy of the current conn slice for safe iteration.
func (s *ConnSet) Snapshot() []*bsquic.Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*bsquic.Conn, 0, len(s.conns))
	for _, c := range s.conns {
		out = append(out, c)
	}
	return out
}

// SnapshotExcept returns the snapshot minus the conn whose RemotePub equals exclude.
func (s *ConnSet) SnapshotExcept(exclude []byte) []*bsquic.Conn {
	if len(exclude) == 0 {
		return s.Snapshot()
	}
	excludeKey := hex.EncodeToString(exclude)
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*bsquic.Conn, 0, len(s.conns))
	for k, c := range s.conns {
		if k == excludeKey {
			continue
		}
		out = append(out, c)
	}
	return out
}
