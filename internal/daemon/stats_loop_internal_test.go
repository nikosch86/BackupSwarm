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
	c.AddBytesUp(2 * 1024 * 1024) // 2.0 MB
	c.AddBytesDown(512 * 1024)    // 512.0 KB

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
	if !strings.Contains(out, `up="2.0 MB"`) {
		t.Errorf(`slog capture missing 'up="2.0 MB"'; got: %s`, out)
	}
	if !strings.Contains(out, `down="512.0 KB"`) {
		t.Errorf(`slog capture missing 'down="512.0 KB"'; got: %s`, out)
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

// TestFormatBytes covers the 1024-based unit boundaries and the sub-KB
// integer-byte branch. Values at exact KB/MB/... boundaries render as
// "1.0 KB" etc.; sub-KB values render as raw "<n> B".
func TestFormatBytes(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{1, "1 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1024 * 1024, "1.0 MB"},
		{2621440, "2.5 MB"},
		{1024 * 1024 * 1024, "1.0 GB"},
		{1024 * 1024 * 1024 * 1024, "1.0 TB"},
		{1024 * 1024 * 1024 * 1024 * 1024, "1.0 PB"},
	}
	for _, tc := range cases {
		if got := formatBytes(tc.in); got != tc.want {
			t.Errorf("formatBytes(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestFormatBytesPerSec asserts the rate formatter appends "/s" to the
// byte-format result, including the sub-KB branch.
func TestFormatBytesPerSec(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B/s"},
		{500, "500 B/s"},
		{1024, "1.0 KB/s"},
		{1024 * 1024, "1.0 MB/s"},
	}
	for _, tc := range cases {
		if got := formatBytesPerSec(tc.in); got != tc.want {
			t.Errorf("formatBytesPerSec(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestEmitActivity_FormattedBandwidthAttrs asserts the slog line emits
// human-readable up/down (totals) and up_rate/down_rate (per-second)
// attrs derived from the snapshot, replacing the raw byte counters.
func TestEmitActivity_FormattedBandwidthAttrs(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	emitActivity(context.Background(), metrics.Snapshot{
		FilesBackedUp: 1,
		ChunksStored:  1,
		BytesUp:       2 * 1024 * 1024, // 2.0 MB
		BytesDown:     512 * 1024,      // 512.0 KB
	}, 10*time.Second)

	out := w.String()
	for _, want := range []string{
		`up="2.0 MB"`,
		`down="512.0 KB"`,
		`up_rate="204.8 KB/s"`,
		`down_rate="51.2 KB/s"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("slog capture missing %q; got: %s", want, out)
		}
	}
	for _, gone := range []string{"bytes_up=", "bytes_down=", "up_bytes_per_sec=", "down_bytes_per_sec="} {
		if strings.Contains(out, gone) {
			t.Errorf("slog capture still contains legacy attr %q; got: %s", gone, out)
		}
	}
}
