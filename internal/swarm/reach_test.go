package swarm_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"

	"backupswarm/internal/swarm"
)

func mustEd25519Pub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return pub
}

func TestReachabilityMap_InitialStateUnknown(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	if got := rm.State(pub); got != swarm.StateUnknown {
		t.Errorf("fresh map State = %v, want StateUnknown", got)
	}
	if rm.IsReachable(pub) {
		t.Error("fresh map IsReachable = true, want false")
	}
}

func TestReachabilityMap_MarkReachable(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateReachable)
	if got := rm.State(pub); got != swarm.StateReachable {
		t.Errorf("State after MarkReachable = %v, want StateReachable", got)
	}
	if !rm.IsReachable(pub) {
		t.Error("IsReachable = false after MarkReachable")
	}
}

func TestReachabilityMap_MarkUnreachable(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateUnreachable)
	if got := rm.State(pub); got != swarm.StateUnreachable {
		t.Errorf("State after MarkUnreachable = %v, want StateUnreachable", got)
	}
	if rm.IsReachable(pub) {
		t.Error("IsReachable = true after MarkUnreachable")
	}
}

func TestReachabilityMap_StateTransitions(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)

	steps := []struct {
		set  swarm.State
		want swarm.State
	}{
		{swarm.StateReachable, swarm.StateReachable},
		{swarm.StateUnreachable, swarm.StateUnreachable},
		{swarm.StateReachable, swarm.StateReachable},
	}
	for i, step := range steps {
		rm.Mark(pub, step.set)
		if got := rm.State(pub); got != step.want {
			t.Errorf("step %d: State = %v, want %v", i, got, step.want)
		}
	}
}

func TestReachabilityMap_MarkUnknownClears(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateReachable)
	rm.Mark(pub, swarm.StateUnknown)
	if got := rm.State(pub); got != swarm.StateUnknown {
		t.Errorf("State after Mark Unknown = %v, want StateUnknown", got)
	}
	if got := rm.Snapshot(); len(got) != 0 {
		t.Errorf("Snapshot len = %d after Mark Unknown, want 0", len(got))
	}
}

func TestReachabilityMap_NilPubKeyIsNoOp(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	rm.Mark(nil, swarm.StateReachable) // must not panic
	if got := rm.State(nil); got != swarm.StateUnknown {
		t.Errorf("State(nil) = %v, want StateUnknown", got)
	}
	if rm.IsReachable(nil) {
		t.Error("IsReachable(nil) = true, want false")
	}
	if got := rm.Snapshot(); len(got) != 0 {
		t.Errorf("Snapshot len = %d after Mark(nil), want 0", len(got))
	}
}

func TestReachabilityMap_EmptyPubKeyIsNoOp(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	rm.Mark([]byte{}, swarm.StateReachable)
	if got := rm.Snapshot(); len(got) != 0 {
		t.Errorf("Snapshot len = %d after Mark(empty), want 0", len(got))
	}
}

func TestReachabilityMap_ReachablePubsFiltersByState(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pubA := mustEd25519Pub(t)
	pubB := mustEd25519Pub(t)
	pubC := mustEd25519Pub(t)
	rm.Mark(pubA, swarm.StateReachable)
	rm.Mark(pubB, swarm.StateUnreachable)
	rm.Mark(pubC, swarm.StateReachable)

	got := rm.ReachablePubs()
	if len(got) != 2 {
		t.Fatalf("ReachablePubs len = %d, want 2", len(got))
	}
	hasA := false
	hasC := false
	for _, p := range got {
		if bytes.Equal(p, pubA) {
			hasA = true
		}
		if bytes.Equal(p, pubC) {
			hasC = true
		}
		if bytes.Equal(p, pubB) {
			t.Error("ReachablePubs included unreachable peer")
		}
	}
	if !hasA || !hasC {
		t.Errorf("ReachablePubs missing entries: hasA=%v hasC=%v", hasA, hasC)
	}
}

func TestReachabilityMap_ReachablePubsAreCopies(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateReachable)

	got := rm.ReachablePubs()
	if len(got) != 1 {
		t.Fatalf("ReachablePubs len = %d, want 1", len(got))
	}
	// Mutating the returned slice must not affect internal state.
	for i := range got[0] {
		got[0][i] = 0
	}
	if !rm.IsReachable(pub) {
		t.Error("internal state corrupted by mutating ReachablePubs result")
	}
}

func TestReachabilityMap_Snapshot(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pubA := mustEd25519Pub(t)
	pubB := mustEd25519Pub(t)
	rm.Mark(pubA, swarm.StateReachable)
	rm.Mark(pubB, swarm.StateUnreachable)

	snap := rm.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot len = %d, want 2", len(snap))
	}
	// Mutating the snapshot must not bleed back.
	for k := range snap {
		snap[k] = swarm.StateUnknown
	}
	if !rm.IsReachable(pubA) {
		t.Error("internal state corrupted by mutating Snapshot")
	}
	if rm.State(pubB) != swarm.StateUnreachable {
		t.Error("internal state corrupted by mutating Snapshot")
	}
}

func TestReachabilityMap_MarkConn(t *testing.T) {
	rig := setupQuicPair(t, 1)
	rm := swarm.NewReachabilityMap()

	conn := rig.introSide[0]
	rm.MarkConn(conn, swarm.StateReachable)
	if !rm.IsReachable(conn.RemotePub()) {
		t.Error("MarkConn StateReachable did not record peer as reachable")
	}
	rm.MarkConn(conn, swarm.StateUnreachable)
	if rm.IsReachable(conn.RemotePub()) {
		t.Error("MarkConn StateUnreachable did not flip peer to unreachable")
	}
}

func TestReachabilityMap_MarkConnNilIsNoOp(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	rm.MarkConn(nil, swarm.StateReachable) // must not panic
	if got := rm.Snapshot(); len(got) != 0 {
		t.Errorf("Snapshot len = %d after MarkConn(nil), want 0", len(got))
	}
}

func TestReachabilityMap_StateString(t *testing.T) {
	cases := []struct {
		s    swarm.State
		want string
	}{
		{swarm.StateUnknown, "unknown"},
		{swarm.StateReachable, "reachable"},
		{swarm.StateUnreachable, "unreachable"},
	}
	for _, c := range cases {
		if got := c.s.String(); got != c.want {
			t.Errorf("State(%d).String() = %q, want %q", c.s, got, c.want)
		}
	}
	if got := swarm.State(99).String(); got == "" {
		t.Error("State(99).String() = empty; want unknown(...) fallback")
	}
}

func TestReachabilityMap_Concurrent(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pubs := make([]ed25519.PublicKey, 16)
	for i := range pubs {
		pubs[i] = mustEd25519Pub(t)
	}

	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			pub := pubs[idx%len(pubs)]
			state := swarm.StateReachable
			if idx%2 == 0 {
				state = swarm.StateUnreachable
			}
			rm.Mark(pub, state)
			_ = rm.State(pub)
			_ = rm.IsReachable(pub)
			_ = rm.ReachablePubs()
			_ = rm.Snapshot()
		}(i)
	}
	wg.Wait()
}
