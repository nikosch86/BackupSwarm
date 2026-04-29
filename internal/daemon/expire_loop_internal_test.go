package daemon

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/store"
)

func TestRunExpireLoop_TicksAndStopsOnCancel(t *testing.T) {
	var calls atomic.Int32
	expireFn := func(_ context.Context) (store.ExpireResult, error) {
		calls.Add(1)
		return store.ExpireResult{Scanned: 4}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runExpireLoop(ctx, expireLoopOptions{
			interval: 50 * time.Millisecond,
			expireFn: expireFn,
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("only %d expire calls fired in 2s with 50ms interval", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runExpireLoop did not exit on ctx cancel")
	}
}

func TestRunExpireLoop_ContinuesAfterError(t *testing.T) {
	var calls atomic.Int32
	expireFn := func(_ context.Context) (store.ExpireResult, error) {
		calls.Add(1)
		return store.ExpireResult{}, errors.New("expire boom")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runExpireLoop(ctx, expireLoopOptions{
			interval: 30 * time.Millisecond,
			expireFn: expireFn,
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := calls.Load(); got < 3 {
		t.Fatalf("only %d expire calls fired despite errors; got %d", got, got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runExpireLoop did not exit on ctx cancel")
	}
}

func TestRunExpireLoop_LogsExpiredResults(t *testing.T) {
	var calls atomic.Int32
	expireFn := func(_ context.Context) (store.ExpireResult, error) {
		calls.Add(1)
		return store.ExpireResult{Scanned: 5, Expired: 2}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runExpireLoop(ctx, expireLoopOptions{
			interval: 30 * time.Millisecond,
			expireFn: expireFn,
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("expire fired %d times with expired results; want >= 2", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runExpireLoop did not exit on ctx cancel")
	}
}

func TestRunExpireLoop_FirstTickIsSynchronous(t *testing.T) {
	gate := make(chan struct{})
	expireFn := func(_ context.Context) (store.ExpireResult, error) {
		select {
		case <-gate:
		case <-time.After(2 * time.Second):
		}
		return store.ExpireResult{}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		runExpireLoop(ctx, expireLoopOptions{
			interval: 1 * time.Hour,
			expireFn: expireFn,
		})
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("runExpireLoop returned before expireFn finished")
	case <-time.After(100 * time.Millisecond):
	}
	close(gate)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runExpireLoop did not exit after gate + cancel")
	}
}
