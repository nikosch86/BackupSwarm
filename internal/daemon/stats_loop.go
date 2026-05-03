package daemon

import (
	"context"
	"fmt"
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
	slog.InfoContext(ctx, "activity",
		"files_backed_up", snap.FilesBackedUp,
		"chunks_stored", snap.ChunksStored,
		"up", formatBytes(snap.BytesUp),
		"down", formatBytes(snap.BytesDown),
		"up_rate", formatBytesPerSec(bytesPerSec(snap.BytesUp, elapsed)),
		"down_rate", formatBytesPerSec(bytesPerSec(snap.BytesDown, elapsed)),
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

// formatBytes returns n in 1024-based units. Sub-KB values render as
// raw integer bytes ("823 B"); larger values use one decimal place
// with a KB/MB/GB/TB/PB suffix.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for nn := n / unit; nn >= unit; nn /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTP"[exp])
}

// formatBytesPerSec is formatBytes with a "/s" suffix.
func formatBytesPerSec(n int64) string {
	return formatBytes(n) + "/s"
}
