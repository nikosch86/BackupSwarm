// Package metrics holds the per-process activity counters surfaced by
// the daemon's periodic activity-log line. Counters are race-free and
// reset to zero on each LoadAndReset.
package metrics

import "sync/atomic"

// Counters aggregates per-process activity. The zero value is ready to
// use; copying a non-zero value is unsafe.
type Counters struct {
	filesBackedUp atomic.Int64
	chunksStored  atomic.Int64
	bytesUp       atomic.Int64
	bytesDown     atomic.Int64

	prom *Prom
}

// SetProm wires a Prom registry to receive the same per-event increments
// that flow into the atomic counters. Call once at startup before any AddX
// goroutine spawns; concurrent SetProm + AddX is a data race.
func (c *Counters) SetProm(p *Prom) { c.prom = p }

// Snapshot is the deltas captured by LoadAndReset.
type Snapshot struct {
	FilesBackedUp int64
	ChunksStored  int64
	BytesUp       int64
	BytesDown     int64
}

// AddFilesBackedUp increments the files-backed-up counter by one.
func (c *Counters) AddFilesBackedUp() {
	c.filesBackedUp.Add(1)
	if c.prom != nil {
		c.prom.filesBackedUp.Inc()
	}
}

// AddChunksStored increments the chunks-stored counter by one.
func (c *Counters) AddChunksStored() {
	c.chunksStored.Add(1)
	if c.prom != nil {
		c.prom.chunksStored.Inc()
	}
}

// AddBytesUp adds n to the upload byte counter.
func (c *Counters) AddBytesUp(n int) {
	if n > 0 {
		c.bytesUp.Add(int64(n))
		if c.prom != nil {
			c.prom.bytesUp.Add(float64(n))
		}
	}
}

// AddBytesDown adds n to the download byte counter.
func (c *Counters) AddBytesDown(n int) {
	if n > 0 {
		c.bytesDown.Add(int64(n))
		if c.prom != nil {
			c.prom.bytesDown.Add(float64(n))
		}
	}
}

// LoadAndReset atomically reads each counter and resets it to zero.
func (c *Counters) LoadAndReset() Snapshot {
	return Snapshot{
		FilesBackedUp: c.filesBackedUp.Swap(0),
		ChunksStored:  c.chunksStored.Swap(0),
		BytesUp:       c.bytesUp.Swap(0),
		BytesDown:     c.bytesDown.Swap(0),
	}
}
