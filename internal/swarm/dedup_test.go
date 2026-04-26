package swarm_test

import (
	"sync"
	"testing"

	"backupswarm/internal/protocol"
	"backupswarm/internal/swarm"
)

func id(seed byte) [protocol.AnnouncementIDSize]byte {
	var out [protocol.AnnouncementIDSize]byte
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	return out
}

func TestDedupCache_FirstSeenReturnsFalse(t *testing.T) {
	c := swarm.NewDedupCache(8)
	if c.Seen(id(0x01)) {
		t.Error("first call to Seen reported already-seen")
	}
}

func TestDedupCache_RepeatedReturnsTrue(t *testing.T) {
	c := swarm.NewDedupCache(8)
	want := id(0x02)
	c.Seen(want)
	if !c.Seen(want) {
		t.Error("repeated call to Seen reported not-seen")
	}
}

func TestDedupCache_EvictsOldestPastCap(t *testing.T) {
	c := swarm.NewDedupCache(2)
	first := id(0x10)
	c.Seen(first)
	c.Seen(id(0x20))
	c.Seen(id(0x30)) // first should now be evicted
	if c.Seen(first) {
		t.Error("evicted entry still reported as seen")
	}
}

func TestDedupCache_SecondInsertAfterEvictionDoesNotDoubleEvict(t *testing.T) {
	c := swarm.NewDedupCache(2)
	a, b, x := id(0xa0), id(0xb0), id(0xff)
	c.Seen(a)
	c.Seen(b)
	c.Seen(x) // evicts a, ring now [b, x]
	if !c.Seen(b) {
		t.Error("b evicted after a single eviction; ring wraparound is wrong")
	}
	if !c.Seen(x) {
		t.Error("x evicted after a single eviction; ring wraparound is wrong")
	}
}

func TestDedupCache_ZeroCapacityRejectsAll(t *testing.T) {
	c := swarm.NewDedupCache(0)
	c.Seen(id(0x01))
	if c.Seen(id(0x01)) {
		t.Error("cap=0 cache reported already-seen for second call")
	}
}

func TestDedupCache_NegativeCapacityClampsToZero(t *testing.T) {
	c := swarm.NewDedupCache(-1)
	c.Seen(id(0x01))
	if c.Seen(id(0x01)) {
		t.Error("negative-cap cache reported already-seen — should clamp to zero (no-op)")
	}
}

func TestDedupCache_ConcurrentAccessSafe(t *testing.T) {
	c := swarm.NewDedupCache(1024)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 64; j++ {
				c.Seen(id(byte(i*64 + j)))
			}
		}()
	}
	wg.Wait()
}
