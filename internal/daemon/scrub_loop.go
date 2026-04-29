package daemon

import (
	"context"
	"log/slog"
	"time"

	"backupswarm/internal/store"
)

// scrubLoopOptions configures runScrubLoop.
type scrubLoopOptions struct {
	interval time.Duration
	scrubFn  func(ctx context.Context) (store.ScrubResult, error)
}

// runScrubLoop runs scrubFn on entry and once per opts.interval.
func runScrubLoop(ctx context.Context, opts scrubLoopOptions) {
	tick := func() {
		res, err := opts.scrubFn(ctx)
		if err != nil {
			slog.WarnContext(ctx, "scrub failed", "err", err)
			return
		}
		if res.Corrupt > 0 {
			slog.WarnContext(ctx, "scrub removed corrupt blobs",
				"scanned", res.Scanned,
				"corrupt", res.Corrupt,
			)
			return
		}
		slog.DebugContext(ctx, "scrub clean", "scanned", res.Scanned)
	}
	tick()
	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}
