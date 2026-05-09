package cli

import (
	"io"
	"os"
	"time"

	"backupswarm/internal/cliprogress"
	"backupswarm/internal/daemon"
)

// progressOptions captures the user-facing flags that shape the tracker
// constructed for the one-shot phase commands and daemon phases.
type progressOptions struct {
	stderr     io.Writer
	noProgress bool
	interval   time.Duration
}

// buildProgressFactory returns a daemon.ProgressTrackerFactory that
// constructs a cliprogress.Tracker per phase. When stderr is nil, the
// factory is nil (progress disabled).
func buildProgressFactory(opts progressOptions) daemon.ProgressTrackerFactory {
	if opts.stderr == nil {
		return nil
	}
	stderr := opts.stderr
	noProgress := opts.noProgress
	interval := opts.interval
	return func(phase string, totals cliprogress.Totals) cliprogress.Tracker {
		return cliprogress.New(cliprogress.Options{
			Phase:    phase,
			Totals:   totals,
			Stderr:   stderr,
			Interval: interval,
			NoTTY:    noProgress,
		})
	}
}

// resolveStderr returns w unless it is nil, in which case os.Stderr.
func resolveStderr(w io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return os.Stderr
}
