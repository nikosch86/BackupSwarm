package swarm_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/swarm"
)

// manualClock is a test-only time source for grace-period arithmetic.
type manualClock struct{ t time.Time }

func newManualClock() *manualClock             { return &manualClock{t: time.Unix(1_000_000, 0)} }
func (c *manualClock) Now() time.Time          { return c.t }
func (c *manualClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

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

func TestStateSuspect_String(t *testing.T) {
	if got := swarm.StateSuspect.String(); got != "suspect" {
		t.Errorf("StateSuspect.String() = %q, want %q", got, "suspect")
	}
}

func TestRecordHeartbeat_SuccessSetsReachable(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	rm.RecordHeartbeat(pub, true)
	if got := rm.State(pub); got != swarm.StateReachable {
		t.Errorf("after success got %v, want StateReachable", got)
	}
}

func TestRecordHeartbeat_FirstMissTransitionsToSuspect(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	rm.RecordHeartbeat(pub, false)
	if got := rm.State(pub); got != swarm.StateSuspect {
		t.Errorf("after first miss got %v, want StateSuspect", got)
	}
}

func TestRecordHeartbeat_DefaultThresholdMissesGoUnreachable(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	for i := 0; i < swarm.DefaultMissThreshold; i++ {
		rm.RecordHeartbeat(pub, false)
	}
	if got := rm.State(pub); got != swarm.StateUnreachable {
		t.Errorf("after %d misses got %v, want StateUnreachable", swarm.DefaultMissThreshold, got)
	}
}

func TestRecordHeartbeat_RecoveryResetsCounter(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	for i := 0; i < swarm.DefaultMissThreshold; i++ {
		rm.RecordHeartbeat(pub, false)
	}
	if got := rm.State(pub); got != swarm.StateUnreachable {
		t.Fatalf("setup: got %v, want StateUnreachable", got)
	}
	rm.RecordHeartbeat(pub, true)
	if got := rm.State(pub); got != swarm.StateReachable {
		t.Errorf("after recovery got %v, want StateReachable", got)
	}
	rm.RecordHeartbeat(pub, false)
	if got := rm.State(pub); got != swarm.StateSuspect {
		t.Errorf("recovery+1 miss got %v, want StateSuspect (counter must reset on success)", got)
	}
}

func TestRecordHeartbeat_RecoveryFromSuspectResets(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	rm.RecordHeartbeat(pub, false)
	if got := rm.State(pub); got != swarm.StateSuspect {
		t.Fatalf("setup: got %v, want StateSuspect", got)
	}
	rm.RecordHeartbeat(pub, true)
	if got := rm.State(pub); got != swarm.StateReachable {
		t.Errorf("recovery from suspect got %v, want StateReachable", got)
	}
}

func TestRecordHeartbeat_NilPubIgnored(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	rm.RecordHeartbeat(nil, true)
	rm.RecordHeartbeat([]byte{}, false)
	if got := rm.Snapshot(); len(got) != 0 {
		t.Errorf("Snapshot len = %d after nil/empty heartbeat, want 0", len(got))
	}
}

func TestRecordHeartbeat_CustomThreshold(t *testing.T) {
	rm := swarm.NewReachabilityMapWithThreshold(2)
	pub := mustEd25519Pub(t)
	rm.RecordHeartbeat(pub, false)
	if got := rm.State(pub); got != swarm.StateSuspect {
		t.Errorf("first miss got %v, want StateSuspect", got)
	}
	rm.RecordHeartbeat(pub, false)
	if got := rm.State(pub); got != swarm.StateUnreachable {
		t.Errorf("second miss (threshold=2) got %v, want StateUnreachable", got)
	}
}

func TestNewReachabilityMapWithThreshold_PanicsOnNonPositive(t *testing.T) {
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("threshold=%d: expected panic", n)
				}
			}()
			swarm.NewReachabilityMapWithThreshold(n)
		}()
	}
}

func TestMark_ResetsHeartbeatCounter(t *testing.T) {
	rm := swarm.NewReachabilityMap()
	pub := mustEd25519Pub(t)
	rm.RecordHeartbeat(pub, false)
	if got := rm.State(pub); got != swarm.StateSuspect {
		t.Fatalf("setup: got %v, want StateSuspect", got)
	}
	rm.Mark(pub, swarm.StateReachable)
	rm.RecordHeartbeat(pub, false)
	if got := rm.State(pub); got != swarm.StateSuspect {
		t.Errorf("after Mark+miss got %v, want StateSuspect (Mark must reset counter)", got)
	}
}

func TestNewReachabilityMapWithGrace_PanicsOnNonPositiveThreshold(t *testing.T) {
	clock := newManualClock()
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				if r := recover(); r == nil {
					t.Errorf("threshold=%d: expected panic", n)
				}
			}()
			swarm.NewReachabilityMapWithGrace(n, time.Hour, clock.Now)
		}()
	}
}

func TestNewReachabilityMapWithGrace_PanicsOnNegativeGrace(t *testing.T) {
	clock := newManualClock()
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("grace=-1s: expected panic")
		}
	}()
	swarm.NewReachabilityMapWithGrace(3, -1*time.Second, clock.Now)
}

func TestNewReachabilityMapWithGrace_NilNowDefaultsToTimeNow(t *testing.T) {
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, nil)
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateUnreachable)
	// IsLost must not panic with nil now; by default the freshly-stamped
	// timestamp is now() so IsLost is false until grace elapses.
	if rm.IsLost(pub) {
		t.Error("IsLost with nil now and grace=1h returned true on fresh transition")
	}
}

func TestIsLost_StateUnknownReturnsFalse(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	pub := mustEd25519Pub(t)
	if rm.IsLost(pub) {
		t.Error("IsLost on Unknown peer = true, want false")
	}
}

func TestIsLost_StateReachableReturnsFalse(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateReachable)
	clock.Advance(48 * time.Hour)
	if rm.IsLost(pub) {
		t.Error("IsLost on Reachable peer = true, want false")
	}
}

func TestIsLost_StateSuspectReturnsFalse(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	pub := mustEd25519Pub(t)
	rm.RecordHeartbeat(pub, false)
	if got := rm.State(pub); got != swarm.StateSuspect {
		t.Fatalf("setup: state = %v, want StateSuspect", got)
	}
	clock.Advance(48 * time.Hour)
	if rm.IsLost(pub) {
		t.Error("IsLost on Suspect peer = true, want false")
	}
}

func TestIsLost_UnreachableBeforeGraceReturnsFalse(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateUnreachable)
	clock.Advance(30 * time.Minute)
	if rm.IsLost(pub) {
		t.Error("IsLost before grace elapsed = true, want false")
	}
}

func TestIsLost_UnreachableAtGraceBoundaryReturnsTrue(t *testing.T) {
	clock := newManualClock()
	grace := time.Hour
	rm := swarm.NewReachabilityMapWithGrace(3, grace, clock.Now)
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateUnreachable)
	clock.Advance(grace) // exactly at the boundary
	if !rm.IsLost(pub) {
		t.Error("IsLost at grace boundary = false, want true")
	}
}

func TestIsLost_UnreachablePastGraceReturnsTrue(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateUnreachable)
	clock.Advance(2 * time.Hour)
	if !rm.IsLost(pub) {
		t.Error("IsLost past grace = false, want true")
	}
}

func TestIsLost_RecoveryClearsTimer(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateUnreachable)
	clock.Advance(30 * time.Minute)
	rm.Mark(pub, swarm.StateReachable)
	clock.Advance(2 * time.Hour) // would be past grace if timer hadn't cleared
	if rm.IsLost(pub) {
		t.Error("IsLost after recovery = true, want false (timer must clear on transition out)")
	}
}

func TestIsLost_RecoveryViaHeartbeatClearsTimer(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateUnreachable)
	rm.RecordHeartbeat(pub, true) // ok=true → StateReachable
	clock.Advance(2 * time.Hour)
	if rm.IsLost(pub) {
		t.Error("IsLost after heartbeat recovery = true, want false")
	}
}

func TestIsLost_ReflapResetsTimer(t *testing.T) {
	clock := newManualClock()
	grace := time.Hour
	rm := swarm.NewReachabilityMapWithGrace(3, grace, clock.Now)
	pub := mustEd25519Pub(t)

	rm.Mark(pub, swarm.StateUnreachable)
	clock.Advance(50 * time.Minute)
	rm.Mark(pub, swarm.StateReachable) // clears timer
	clock.Advance(50 * time.Minute)
	rm.Mark(pub, swarm.StateUnreachable) // fresh timer at t = +100m
	clock.Advance(30 * time.Minute)      // timer at +30m relative to fresh start
	if rm.IsLost(pub) {
		t.Error("IsLost after reflap before fresh grace = true, want false")
	}
	clock.Advance(31 * time.Minute) // total elapsed since fresh start = 61m > grace
	if !rm.IsLost(pub) {
		t.Error("IsLost after reflap past fresh grace = false, want true")
	}
}

func TestIsLost_RepeatedUnreachableMarkPreservesOriginalTimer(t *testing.T) {
	clock := newManualClock()
	grace := time.Hour
	rm := swarm.NewReachabilityMapWithGrace(3, grace, clock.Now)
	pub := mustEd25519Pub(t)

	rm.Mark(pub, swarm.StateUnreachable) // since = t0
	clock.Advance(50 * time.Minute)
	rm.Mark(pub, swarm.StateUnreachable) // must NOT reset since-time
	clock.Advance(11 * time.Minute)      // 61m total > grace
	if !rm.IsLost(pub) {
		t.Error("IsLost: repeated Unreachable mark reset the timer; want preserved")
	}
}

func TestIsLost_HeartbeatTransitionToUnreachableStartsTimer(t *testing.T) {
	clock := newManualClock()
	grace := time.Hour
	rm := swarm.NewReachabilityMapWithGrace(3, grace, clock.Now)
	pub := mustEd25519Pub(t)

	for i := 0; i < swarm.DefaultMissThreshold; i++ {
		rm.RecordHeartbeat(pub, false)
	}
	if got := rm.State(pub); got != swarm.StateUnreachable {
		t.Fatalf("setup: state = %v, want StateUnreachable", got)
	}
	clock.Advance(30 * time.Minute)
	if rm.IsLost(pub) {
		t.Error("IsLost before grace = true, want false")
	}
	clock.Advance(31 * time.Minute) // total 61m > grace
	if !rm.IsLost(pub) {
		t.Error("IsLost past grace via heartbeat path = false, want true")
	}
}

func TestIsLost_HeartbeatRepeatedFailurePreservesOriginalTimer(t *testing.T) {
	clock := newManualClock()
	grace := time.Hour
	rm := swarm.NewReachabilityMapWithGrace(3, grace, clock.Now)
	pub := mustEd25519Pub(t)

	for i := 0; i < swarm.DefaultMissThreshold; i++ {
		rm.RecordHeartbeat(pub, false)
	}
	clock.Advance(50 * time.Minute)
	rm.RecordHeartbeat(pub, false) // already Unreachable; further misses must not reset since-time
	clock.Advance(11 * time.Minute)
	if !rm.IsLost(pub) {
		t.Error("IsLost: extra failed heartbeats reset the timer; want preserved")
	}
}

func TestIsLost_GraceZeroTreatsUnreachableAsLostImmediately(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, 0, clock.Now)
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateUnreachable)
	if !rm.IsLost(pub) {
		t.Error("IsLost with grace=0 immediately after transition = false, want true")
	}
}

func TestIsLost_NilPubReturnsFalse(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	if rm.IsLost(nil) || rm.IsLost([]byte{}) {
		t.Error("IsLost(nil/empty) = true, want false")
	}
}

func TestIsLost_LegacyConstructorAlwaysReturnsFalse(t *testing.T) {
	// NewReachabilityMap and NewReachabilityMapWithThreshold do not enable
	// the grace-period machinery; IsLost must remain false even for an
	// Unreachable peer (callers that need lost-detection must opt in via
	// NewReachabilityMapWithGrace).
	for _, rm := range []*swarm.ReachabilityMap{
		swarm.NewReachabilityMap(),
		swarm.NewReachabilityMapWithThreshold(2),
	} {
		pub := mustEd25519Pub(t)
		rm.Mark(pub, swarm.StateUnreachable)
		if rm.IsLost(pub) {
			t.Error("IsLost on map without grace enabled = true, want false")
		}
	}
}

func TestLostPubs_LegacyConstructorReturnsNil(t *testing.T) {
	for _, rm := range []*swarm.ReachabilityMap{
		swarm.NewReachabilityMap(),
		swarm.NewReachabilityMapWithThreshold(2),
	} {
		pub := mustEd25519Pub(t)
		rm.Mark(pub, swarm.StateUnreachable)
		if got := rm.LostPubs(); got != nil {
			t.Errorf("LostPubs on map without grace enabled = %v, want nil", got)
		}
	}
}

func TestLostPubs_FiltersByGrace(t *testing.T) {
	clock := newManualClock()
	grace := time.Hour
	rm := swarm.NewReachabilityMapWithGrace(3, grace, clock.Now)
	pubReachable := mustEd25519Pub(t)
	pubFresh := mustEd25519Pub(t)
	pubLost1 := mustEd25519Pub(t)
	pubLost2 := mustEd25519Pub(t)

	rm.Mark(pubLost1, swarm.StateUnreachable) // since = t=0
	clock.Advance(90 * time.Minute)           // Lost1 elapsed = 90m
	rm.Mark(pubLost2, swarm.StateUnreachable) // since = t=90m
	clock.Advance(70 * time.Minute)           // Lost1 = 160m, Lost2 = 70m (both > grace)
	rm.Mark(pubReachable, swarm.StateReachable)
	rm.Mark(pubFresh, swarm.StateUnreachable) // since = t=160m, elapsed = 0

	got := rm.LostPubs()
	if len(got) != 2 {
		t.Fatalf("LostPubs len = %d, want 2", len(got))
	}
	hasLost1 := false
	hasLost2 := false
	for _, p := range got {
		if bytes.Equal(p, pubLost1) {
			hasLost1 = true
		}
		if bytes.Equal(p, pubLost2) {
			hasLost2 = true
		}
		if bytes.Equal(p, pubReachable) || bytes.Equal(p, pubFresh) {
			t.Errorf("LostPubs included a non-lost peer")
		}
	}
	if !hasLost1 || !hasLost2 {
		t.Errorf("LostPubs missing entries: hasLost1=%v hasLost2=%v", hasLost1, hasLost2)
	}
}

func TestLostPubs_AreCopies(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateUnreachable)
	clock.Advance(2 * time.Hour)
	got := rm.LostPubs()
	if len(got) != 1 {
		t.Fatalf("LostPubs len = %d, want 1", len(got))
	}
	for i := range got[0] {
		got[0][i] = 0
	}
	again := rm.LostPubs()
	if len(again) != 1 || bytes.Equal(again[0], make([]byte, len(again[0]))) {
		t.Error("internal state corrupted by mutating LostPubs result")
	}
}

func TestMarkUnknown_ClearsLostTimer(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	pub := mustEd25519Pub(t)
	rm.Mark(pub, swarm.StateUnreachable)
	clock.Advance(2 * time.Hour)
	rm.Mark(pub, swarm.StateUnknown) // delete entry
	if rm.IsLost(pub) {
		t.Error("IsLost after Mark(Unknown) = true, want false (entry deleted)")
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

func TestReachabilityMap_GraceConcurrent(t *testing.T) {
	clock := newManualClock()
	rm := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
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
			rm.RecordHeartbeat(pub, idx%3 == 0)
			_ = rm.IsLost(pub)
			_ = rm.LostPubs()
		}(i)
	}
	wg.Wait()
}
