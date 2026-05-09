// Package signalctx wraps signal.NotifyContext with a second-signal
// hard exit. The first signal cancels the context; the second calls
// exit(130).
package signalctx

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"sync"
)

// HardExitCode is the exit code passed to exit on the second signal,
// matching the shell convention for Ctrl-C after a stuck shutdown.
const HardExitCode = 130

// exit is the package's exit hook. Tests swap it; production wires it
// to os.Exit.
var exit = os.Exit

// WithSignalCancel returns a context cancelled on the first delivery of
// any signals; a second delivery calls exit(HardExitCode). stop() must
// be called (typically deferred) and is idempotent.
func WithSignalCancel(parent context.Context, signals ...os.Signal) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, signals...)

	stopCh := make(chan struct{})
	done := make(chan struct{})
	go watch(ctx, cancel, sigCh, stopCh, done)

	var stopOnce sync.Once
	stop := func() {
		stopOnce.Do(func() {
			signal.Stop(sigCh)
			close(stopCh)
			cancel()
			<-done
		})
	}
	return ctx, stop
}

// watch translates signal deliveries into cancel and, on the second
// delivery, exit. It returns when stopCh closes or ctx ends.
func watch(ctx context.Context, cancel context.CancelFunc, sigCh <-chan os.Signal, stopCh, done chan struct{}) {
	defer close(done)

	var first os.Signal
	select {
	case first = <-sigCh:
		slog.InfoContext(ctx, "received signal, shutting down", "signal", first.String())
		cancel()
	case <-stopCh:
		return
	case <-ctx.Done():
		return
	}

	select {
	case second := <-sigCh:
		slog.WarnContext(ctx, "received second signal, hard exit", "signal", second.String(), "code", HardExitCode)
		exit(HardExitCode)
	case <-stopCh:
		return
	}
}
