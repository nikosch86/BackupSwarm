package swarm_test

import (
	"crypto/ed25519"
	"testing"

	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// containsPub reports whether snapshot has a conn whose RemotePub matches pub.
func containsPub(snapshot []*bsquic.Conn, pub ed25519.PublicKey) bool {
	for _, c := range snapshot {
		if c.RemotePub().Equal(pub) {
			return true
		}
	}
	return false
}

func TestConnSet_AddSnapshotIncludes(t *testing.T) {
	rig := setupQuicPair(t, 2)
	cs := swarm.NewConnSet()
	for _, c := range rig.introSide {
		cs.Add(c)
	}
	snap := cs.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot len = %d, want 2", len(snap))
	}
	for _, c := range rig.introSide {
		if !containsPub(snap, c.RemotePub()) {
			t.Errorf("snapshot missing conn for pub %x", c.RemotePub()[:8])
		}
	}
}

func TestConnSet_RemoveExcludes(t *testing.T) {
	rig := setupQuicPair(t, 2)
	cs := swarm.NewConnSet()
	cs.Add(rig.introSide[0])
	cs.Add(rig.introSide[1])
	cs.Remove(rig.introSide[0])
	snap := cs.Snapshot()
	if len(snap) != 1 {
		t.Fatalf("Snapshot len = %d, want 1", len(snap))
	}
	if containsPub(snap, rig.introSide[0].RemotePub()) {
		t.Error("removed conn still present in snapshot")
	}
	if !containsPub(snap, rig.introSide[1].RemotePub()) {
		t.Error("non-removed conn missing from snapshot")
	}
}

func TestConnSet_SnapshotExceptSkipsSender(t *testing.T) {
	rig := setupQuicPair(t, 3)
	cs := swarm.NewConnSet()
	for _, c := range rig.introSide {
		cs.Add(c)
	}
	sender := rig.introSide[1].RemotePub()
	snap := cs.SnapshotExcept(sender)
	if len(snap) != 2 {
		t.Fatalf("SnapshotExcept len = %d, want 2", len(snap))
	}
	if containsPub(snap, sender) {
		t.Error("SnapshotExcept included the sender's conn")
	}
}

func TestConnSet_AddDedupesSamePubKey(t *testing.T) {
	rig := setupQuicPair(t, 1)
	cs := swarm.NewConnSet()
	cs.Add(rig.introSide[0])
	cs.Add(rig.introSide[0]) // re-Add same conn — must not duplicate
	if len(cs.Snapshot()) != 1 {
		t.Errorf("Snapshot len = %d, want 1 after duplicate Add", len(cs.Snapshot()))
	}
}

func TestConnSet_RemoveUnknownIsNoOp(t *testing.T) {
	rig := setupQuicPair(t, 1)
	cs := swarm.NewConnSet()
	cs.Remove(rig.introSide[0])
	if len(cs.Snapshot()) != 0 {
		t.Errorf("Snapshot len = %d, want 0", len(cs.Snapshot()))
	}
}

func TestConnSet_AddNilConnIsNoOp(t *testing.T) {
	cs := swarm.NewConnSet()
	cs.Add(nil)
	if got := len(cs.Snapshot()); got != 0 {
		t.Errorf("Snapshot len = %d after Add(nil), want 0", got)
	}
}

func TestConnSet_RemoveNilConnIsNoOp(t *testing.T) {
	cs := swarm.NewConnSet()
	cs.Remove(nil) // must not panic
}

func TestConnSet_SnapshotExceptEmptyExcludeReturnsAll(t *testing.T) {
	rig := setupQuicPair(t, 2)
	cs := swarm.NewConnSet()
	for _, c := range rig.introSide {
		cs.Add(c)
	}
	if got := len(cs.SnapshotExcept(nil)); got != 2 {
		t.Errorf("SnapshotExcept(nil) len = %d, want 2", got)
	}
}
