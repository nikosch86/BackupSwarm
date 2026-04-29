package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/store"
)

func TestRunScrubLoop_TicksAndStopsOnCancel(t *testing.T) {
	var calls atomic.Int32
	scrubFn := func(_ context.Context) (store.ScrubResult, error) {
		calls.Add(1)
		return store.ScrubResult{Scanned: 3}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runScrubLoop(ctx, scrubLoopOptions{
			interval: 50 * time.Millisecond,
			scrubFn:  scrubFn,
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("only %d scrub calls fired in 2s with 50ms interval", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runScrubLoop did not exit on ctx cancel")
	}
}

func TestRunScrubLoop_ContinuesAfterScrubFnError(t *testing.T) {
	var calls atomic.Int32
	scrubFn := func(_ context.Context) (store.ScrubResult, error) {
		calls.Add(1)
		return store.ScrubResult{}, errors.New("scrub blew up")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runScrubLoop(ctx, scrubLoopOptions{
			interval: 30 * time.Millisecond,
			scrubFn:  scrubFn,
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := calls.Load(); got < 3 {
		t.Fatalf("only %d scrub calls fired despite errors; loop should continue, got %d", got, got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runScrubLoop did not exit on ctx cancel")
	}
}

func TestRunScrubLoop_FirstTickIsSynchronous(t *testing.T) {
	gate := make(chan struct{})
	scrubFn := func(_ context.Context) (store.ScrubResult, error) {
		select {
		case <-gate:
		case <-time.After(2 * time.Second):
		}
		return store.ScrubResult{}, nil
	}

	// Ensure runScrubLoop blocks the goroutine on the first tick before
	// the ticker has a chance to fire.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		runScrubLoop(ctx, scrubLoopOptions{
			interval: 1 * time.Hour,
			scrubFn:  scrubFn,
		})
		close(done)
	}()

	// If the first tick is synchronous, the goroutine is parked inside
	// scrubFn and runScrubLoop has not returned. Cancel must not unblock
	// it until the gate is released.
	select {
	case <-done:
		t.Fatal("runScrubLoop returned before scrubFn finished")
	case <-time.After(100 * time.Millisecond):
	}

	close(gate)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runScrubLoop did not exit after gate + cancel")
	}
}
