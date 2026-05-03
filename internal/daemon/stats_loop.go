package daemon

import (
	"context"
	"log/slog"
	"time"

	"backupswarm/internal/metrics"
)

// defaultStatsInterval is the default cadence for the activity stats line.
const defaultStatsInterval = 2 * time.Minute

// statsLoopOptions configures runStatsLoop.
type statsLoopOptions struct {
	interval time.Duration
	counters *metrics.Counters
	nowFn    func() time.Time
}

// runStatsLoop emits one INFO "activity" line per opts.interval with the
// counts of files backed up, chunks stored, and average bandwidth used
// up/down since the previous tick. Counter values are reset each tick so
// the deltas are independent.
func runStatsLoop(ctx context.Context, opts statsLoopOptions) {
	if opts.counters == nil {
		<-ctx.Done()
		return
	}
	if opts.interval <= 0 {
		<-ctx.Done()
		return
	}
	if opts.nowFn == nil {
		opts.nowFn = time.Now
	}
	last := opts.nowFn()
	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := opts.nowFn()
			elapsed := now.Sub(last)
			last = now
			snap := opts.counters.LoadAndReset()
			emitActivity(ctx, snap, elapsed)
		}
	}
}

// emitActivity logs a single INFO "activity" line summarising one tick.
func emitActivity(ctx context.Context, snap metrics.Snapshot, elapsed time.Duration) {
	upPerSec := bytesPerSec(snap.BytesUp, elapsed)
	downPerSec := bytesPerSec(snap.BytesDown, elapsed)
	slog.InfoContext(ctx, "activity",
		"files_backed_up", snap.FilesBackedUp,
		"chunks_stored", snap.ChunksStored,
		"bytes_up", snap.BytesUp,
		"bytes_down", snap.BytesDown,
		"up_bytes_per_sec", upPerSec,
		"down_bytes_per_sec", downPerSec,
		"interval_seconds", elapsed.Round(time.Second).Seconds(),
	)
}

// bytesPerSec rounds bytes/elapsed to whole bytes per second; non-positive
// elapsed yields 0 (no division by zero, no negative averages).
func bytesPerSec(bytes int64, elapsed time.Duration) int64 {
	if elapsed <= 0 {
		return 0
	}
	return int64(float64(bytes) / elapsed.Seconds())
}
