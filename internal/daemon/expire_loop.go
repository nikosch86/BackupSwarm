package daemon

import (
	"context"
	"log/slog"
	"time"

	"backupswarm/internal/store"
)

// expireLoopOptions configures runExpireLoop.
type expireLoopOptions struct {
	interval time.Duration
	expireFn func(ctx context.Context) (store.ExpireResult, error)
}

// runExpireLoop runs expireFn on entry, then once per opts.interval until
// ctx is cancelled.
func runExpireLoop(ctx context.Context, opts expireLoopOptions) {
	tick := func() {
		res, err := opts.expireFn(ctx)
		if err != nil {
			slog.WarnContext(ctx, "expire sweep failed", "err", err)
			return
		}
		if res.Expired > 0 {
			slog.WarnContext(ctx, "expire sweep removed blobs",
				"scanned", res.Scanned,
				"expired", res.Expired,
			)
			return
		}
		slog.DebugContext(ctx, "expire sweep clean", "scanned", res.Scanned)
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
