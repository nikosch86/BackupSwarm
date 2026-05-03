package daemon

import (
	"context"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/metrics"
)

// TestRunStatsLoop_EmitsActivityWithDeltasAndResets asserts each tick
// emits an INFO line with the per-counter deltas and that subsequent
// ticks see fresh counters (LoadAndReset behaviour).
func TestRunStatsLoop_EmitsActivityWithDeltasAndResets(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	c := &metrics.Counters{}
	c.AddFilesBackedUp()
	c.AddFilesBackedUp()
	c.AddChunksStored()
	c.AddBytesUp(2_000_000)
	c.AddBytesDown(500_000)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runStatsLoop(ctx, statsLoopOptions{
			interval: 50 * time.Millisecond,
			counters: c,
		})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(w.String(), "files_backed_up=2") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	out := w.String()
	if !strings.Contains(out, "msg=activity") {
		t.Errorf("slog capture missing 'msg=activity'; got: %s", out)
	}
	if !strings.Contains(out, "files_backed_up=2") {
		t.Errorf("slog capture missing 'files_backed_up=2'; got: %s", out)
	}
	if !strings.Contains(out, "chunks_stored=1") {
		t.Errorf("slog capture missing 'chunks_stored=1'; got: %s", out)
	}
	if !strings.Contains(out, "bytes_up=2000000") {
		t.Errorf("slog capture missing 'bytes_up=2000000'; got: %s", out)
	}
	if !strings.Contains(out, "bytes_down=500000") {
		t.Errorf("slog capture missing 'bytes_down=500000'; got: %s", out)
	}

	if got := c.LoadAndReset(); got != (metrics.Snapshot{}) {
		t.Errorf("counters not reset after first tick: %+v", got)
	}
}

// TestRunStatsLoop_NilCountersBlocksUntilCtxDone asserts a nil counters
// disables the loop and returns on context cancel without panicking.
func TestRunStatsLoop_NilCountersBlocksUntilCtxDone(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	runStatsLoop(ctx, statsLoopOptions{interval: time.Hour, counters: nil})
}

// TestRunStatsLoop_ZeroIntervalDisables asserts interval <= 0 disables
// the loop without scheduling a ticker.
func TestRunStatsLoop_ZeroIntervalDisables(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	runStatsLoop(ctx, statsLoopOptions{interval: 0, counters: &metrics.Counters{}})
}

// TestBytesPerSec covers the bytes/elapsed division and the zero-elapsed
// guard.
func TestBytesPerSec(t *testing.T) {
	cases := []struct {
		bytes   int64
		elapsed time.Duration
		want    int64
	}{
		{1_000_000, 1 * time.Second, 1_000_000},
		{1_000_000, 2 * time.Second, 500_000},
		{0, time.Second, 0},
		{1_000_000, 0, 0},
		{1_000_000, -time.Second, 0},
	}
	for _, tc := range cases {
		if got := bytesPerSec(tc.bytes, tc.elapsed); got != tc.want {
			t.Errorf("bytesPerSec(%d, %v) = %d, want %d", tc.bytes, tc.elapsed, got, tc.want)
		}
	}
}

// TestEmitActivity_LogsRoundedInterval asserts the emitted slog line
// carries an interval_seconds attr derived from the elapsed duration.
func TestEmitActivity_LogsRoundedInterval(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	emitActivity(context.Background(), metrics.Snapshot{
		FilesBackedUp: 5,
		ChunksStored:  10,
		BytesUp:       30,
		BytesDown:     45,
	}, 120*time.Second)

	out := w.String()
	if !strings.Contains(out, "interval_seconds=120") {
		t.Errorf("slog capture missing 'interval_seconds=120'; got: %s", out)
	}
}
