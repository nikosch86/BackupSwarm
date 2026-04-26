package swarm

import (
	"sync"

	"backupswarm/internal/protocol"
)

// DefaultDedupCapacity is the cache size used when daemon callers don't
// override it.
const DefaultDedupCapacity = 1024

// DedupCache is a fixed-size FIFO of seen announcement IDs. Capacity 0
// disables caching; every Seen call returns false. Safe for concurrent use.
type DedupCache struct {
	mu     sync.Mutex
	cap    int
	ring   [][protocol.AnnouncementIDSize]byte
	next   int
	filled bool
	set    map[[protocol.AnnouncementIDSize]byte]struct{}
}

// NewDedupCache returns a cache that holds up to cap entries. cap must be
// non-negative; cap == 0 produces a no-op cache.
func NewDedupCache(cap int) *DedupCache {
	if cap < 0 {
		cap = 0
	}
	return &DedupCache{
		cap:  cap,
		ring: make([][protocol.AnnouncementIDSize]byte, cap),
		set:  make(map[[protocol.AnnouncementIDSize]byte]struct{}, cap),
	}
}

// Seen reports whether id was already in the cache, recording it on the
// first call. Returns false (and records) when capacity is zero.
func (c *DedupCache) Seen(id [protocol.AnnouncementIDSize]byte) bool {
	if c.cap == 0 {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.set[id]; ok {
		return true
	}
	if c.filled {
		evicted := c.ring[c.next]
		delete(c.set, evicted)
	}
	c.ring[c.next] = id
	c.set[id] = struct{}{}
	c.next++
	if c.next == c.cap {
		c.next = 0
		c.filled = true
	}
	return false
}
