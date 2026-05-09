package cliprogress

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"
)

// captureSlog redirects the default logger to w for the test's lifetime.
func captureSlog(t *testing.T, w *syncWriter) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

type syncWriter struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// TestNew_NoTTYForcesNonTTYImpl asserts NoTTY=true picks the non-TTY emitter
// even when IsTTY() returns true.
func TestNew_NoTTYForcesNonTTYImpl(t *testing.T) {
	tr := New(Options{
		Phase:    "restore",
		Totals:   Totals{Files: 3, Bytes: 300},
		Stderr:   &bytes.Buffer{},
		Interval: time.Hour,
		NoTTY:    true,
		IsTTY:    func() bool { return true },
	})
	if _, ok := tr.(*nonTTYTracker); !ok {
		t.Fatalf("NoTTY=true should pick nonTTYTracker, got %T", tr)
	}
}

// TestNew_IsTTYFalsePicksNonTTYImpl asserts a non-TTY stderr selects the
// slog emitter.
func TestNew_IsTTYFalsePicksNonTTYImpl(t *testing.T) {
	tr := New(Options{
		Phase:  "restore",
		Stderr: &bytes.Buffer{},
		IsTTY:  func() bool { return false },
	})
	if _, ok := tr.(*nonTTYTracker); !ok {
		t.Fatalf("IsTTY=false should pick nonTTYTracker, got %T", tr)
	}
}

// TestNew_IsTTYTruePicksTTYImpl asserts a TTY stderr selects the bar.
func TestNew_IsTTYTruePicksTTYImpl(t *testing.T) {
	tr := New(Options{
		Phase:  "restore",
		Totals: Totals{Files: 1, Bytes: 100},
		Stderr: &bytes.Buffer{},
		IsTTY:  func() bool { return true },
	})
	if _, ok := tr.(*ttyTracker); !ok {
		t.Fatalf("IsTTY=true should pick ttyTracker, got %T", tr)
	}
}

// TestNonTTY_AddDoesNotEmitBeforeInterval asserts no slog line is written
// until the interval has elapsed since the last emit.
func TestNonTTY_AddDoesNotEmitBeforeInterval(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	now := time.Unix(1_000_000, 0)
	tr := New(Options{
		Phase:    "restore",
		Totals:   Totals{Files: 10, Bytes: 1000},
		Stderr:   &bytes.Buffer{},
		Interval: 10 * time.Second,
		Now:      func() time.Time { return now },
		NoTTY:    true,
	}).(*nonTTYTracker)

	tr.Add(100, 1)
	now = now.Add(5 * time.Second)
	tr.Add(100, 1)

	if got := w.String(); got != "" {
		t.Fatalf("expected no emit before interval, got: %s", got)
	}
}

// TestNonTTY_AddEmitsOnIntervalElapsed asserts an Add at-or-past the
// interval triggers exactly one slog line with the expected attrs.
func TestNonTTY_AddEmitsOnIntervalElapsed(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	now := time.Unix(1_000_000, 0)
	tr := New(Options{
		Phase:    "restore",
		Totals:   Totals{Files: 10, Bytes: 1000},
		Stderr:   &bytes.Buffer{},
		Interval: 10 * time.Second,
		Now:      func() time.Time { return now },
		NoTTY:    true,
	}).(*nonTTYTracker)

	tr.Add(500, 5)
	now = now.Add(10 * time.Second)
	tr.Add(0, 0)

	out := w.String()
	for _, want := range []string{
		"msg=progress",
		"phase=restore",
		"files_done=5",
		"files_total=10",
		"bytes_done=500",
		"bytes_total=1000",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("emit missing %q; got: %s", want, out)
		}
	}
}

// TestNonTTY_DoneEmitsFinalLine asserts Done emits even if the interval
// has not elapsed.
func TestNonTTY_DoneEmitsFinalLine(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	now := time.Unix(1_000_000, 0)
	tr := New(Options{
		Phase:    "purge",
		Totals:   Totals{Files: 2, Bytes: 0},
		Stderr:   &bytes.Buffer{},
		Interval: time.Hour,
		Now:      func() time.Time { return now },
		NoTTY:    true,
	}).(*nonTTYTracker)

	tr.Add(0, 1)
	tr.Add(0, 1)
	now = now.Add(50 * time.Millisecond)
	tr.Done()

	out := w.String()
	for _, want := range []string{
		"msg=progress",
		"phase=purge",
		"files_done=2",
		"files_total=2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("done emit missing %q; got: %s", want, out)
		}
	}
}

// TestNonTTY_DoneWithFrozenClockEmitsWithoutDivByZero asserts Done with
// elapsed==0 since the last emit (frozen clock) records no rate sample
// but still emits the final summary line.
func TestNonTTY_DoneWithFrozenClockEmitsWithoutDivByZero(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	now := time.Unix(1_000_000, 0)
	tr := New(Options{
		Phase:    "purge",
		Totals:   Totals{Files: 1, Bytes: 100},
		Stderr:   &bytes.Buffer{},
		Interval: time.Hour,
		Now:      func() time.Time { return now },
		NoTTY:    true,
	}).(*nonTTYTracker)

	tr.Add(50, 1)
	tr.Done() // elapsed==0 since lastEmit was set in newNonTTY at the same now

	out := w.String()
	if !strings.Contains(out, "msg=progress") {
		t.Errorf("Done with frozen clock should still emit; got: %s", out)
	}
}

// TestNonTTY_DoneTwiceIsNoop asserts a second Done does not emit.
func TestNonTTY_DoneTwiceIsNoop(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	now := time.Unix(1_000_000, 0)
	tr := New(Options{
		Phase:    "restore",
		Totals:   Totals{Files: 1, Bytes: 100},
		Stderr:   &bytes.Buffer{},
		Interval: time.Hour,
		Now:      func() time.Time { return now },
		NoTTY:    true,
	}).(*nonTTYTracker)

	tr.Add(100, 1)
	tr.Done()
	first := w.String()

	tr.Done()
	second := w.String()

	if first != second {
		t.Errorf("second Done() emitted; first=%q second=%q", first, second)
	}
	if !strings.Contains(first, "files_done=1") {
		t.Errorf("first Done emit missing files_done=1; got: %s", first)
	}
}

// TestNonTTY_AddAfterDoneIsNoop asserts Add after Done does not record.
func TestNonTTY_AddAfterDoneIsNoop(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	now := time.Unix(1_000_000, 0)
	tr := New(Options{
		Phase:    "restore",
		Totals:   Totals{Files: 5, Bytes: 500},
		Stderr:   &bytes.Buffer{},
		Interval: time.Hour,
		Now:      func() time.Time { return now },
		NoTTY:    true,
	}).(*nonTTYTracker)

	tr.Add(100, 1)
	tr.Done()
	tr.Add(400, 4)

	if got := tr.bytes; got != 100 {
		t.Errorf("Add after Done changed bytes: got %d, want 100", got)
	}
	if got := tr.files; got != 1 {
		t.Errorf("Add after Done changed files: got %d, want 1", got)
	}
}

// TestNonTTY_ZeroIntervalDisablesPeriodicEmit asserts that interval=0
// suppresses periodic Add emits but Done still flushes one final line.
func TestNonTTY_ZeroIntervalDisablesPeriodicEmit(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	now := time.Unix(1_000_000, 0)
	tr := New(Options{
		Phase:    "first-backup",
		Totals:   Totals{Files: 5, Bytes: 500},
		Stderr:   &bytes.Buffer{},
		Interval: 0,
		Now:      func() time.Time { return now },
		NoTTY:    true,
	}).(*nonTTYTracker)

	tr.Add(100, 1)
	now = now.Add(time.Hour)
	tr.Add(400, 4)

	if got := w.String(); got != "" {
		t.Errorf("interval=0 should suppress Add emits; got: %s", got)
	}

	tr.Done()
	if !strings.Contains(w.String(), "msg=progress") {
		t.Errorf("Done with interval=0 should still emit; got: %s", w.String())
	}
}

// TestNonTTY_RateAndETA asserts the rate field reflects the EWMA of
// observed bytes/sec and ETA is computed from remaining bytes / rate.
func TestNonTTY_RateAndETA(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	now := time.Unix(1_000_000, 0)
	tr := New(Options{
		Phase:    "restore",
		Totals:   Totals{Files: 100, Bytes: 10_240},
		Stderr:   &bytes.Buffer{},
		Interval: 1 * time.Second,
		Now:      func() time.Time { return now },
		NoTTY:    true,
	}).(*nonTTYTracker)

	now = now.Add(1 * time.Second)
	tr.Add(1024, 10)

	out := w.String()
	if !strings.Contains(out, `rate="1.0 KB/s"`) {
		t.Errorf("expected rate=\"1.0 KB/s\"; got: %s", out)
	}
	if !strings.Contains(out, "eta_seconds=9") {
		t.Errorf("expected eta_seconds=9 (9 KB remaining @ 1 KB/s); got: %s", out)
	}
}

// TestEWMA_FirstSampleSeedsValue asserts the first Add seeds the EWMA
// without weighting.
func TestEWMA_FirstSampleSeedsValue(t *testing.T) {
	e := newEWMA(0.3)
	e.Add(100)
	if got, want := e.Value(), 100.0; got != want {
		t.Errorf("first sample: got %v, want %v", got, want)
	}
}

// TestEWMA_BlendsSubsequentSamples asserts each Add applies alpha to the
// new sample and (1-alpha) to the prior value.
func TestEWMA_BlendsSubsequentSamples(t *testing.T) {
	e := newEWMA(0.5)
	e.Add(100)
	e.Add(200)
	if got, want := e.Value(), 150.0; got != want {
		t.Errorf("second sample: got %v, want %v", got, want)
	}
}

// TestEWMA_TransientStallDoesNotZero asserts a single zero sample is
// smoothed and does not collapse the estimate to zero.
func TestEWMA_TransientStallDoesNotZero(t *testing.T) {
	e := newEWMA(0.3)
	e.Add(100)
	e.Add(0)
	if got := e.Value(); got <= 0 {
		t.Errorf("transient stall should not collapse to zero; got %v", got)
	}
}

// TestEWMA_ConvergesToConstantSamples asserts repeated identical samples
// converge to that value.
func TestEWMA_ConvergesToConstantSamples(t *testing.T) {
	e := newEWMA(0.3)
	for i := 0; i < 100; i++ {
		e.Add(50)
	}
	if got, want := e.Value(), 50.0; got != want {
		t.Errorf("constant sample convergence: got %v, want %v", got, want)
	}
}

// TestNonTTY_ConcurrentAdd asserts mutex protects internal state under
// concurrent Add calls.
func TestNonTTY_ConcurrentAdd(t *testing.T) {
	tr := New(Options{
		Phase:    "restore",
		Totals:   Totals{Files: 1000, Bytes: 100_000},
		Stderr:   &bytes.Buffer{},
		Interval: time.Hour,
		Now:      func() time.Time { return time.Unix(1, 0) },
		NoTTY:    true,
	}).(*nonTTYTracker)

	const workers = 50
	const each = 20
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				tr.Add(100, 1)
			}
		}()
	}
	wg.Wait()

	if tr.files != int64(workers*each) {
		t.Errorf("files: got %d, want %d", tr.files, workers*each)
	}
	if tr.bytes != int64(workers*each*100) {
		t.Errorf("bytes: got %d, want %d", tr.bytes, workers*each*100)
	}
}

// TestTTY_AddDoneNoPanic asserts the TTY impl handles Add and Done
// without panicking even when the underlying buffer is not a TTY.
func TestTTY_AddDoneNoPanic(t *testing.T) {
	tr := New(Options{
		Phase:  "restore",
		Totals: Totals{Files: 5, Bytes: 500},
		Stderr: &bytes.Buffer{},
		IsTTY:  func() bool { return true },
	}).(*ttyTracker)

	tr.Add(100, 1)
	tr.Add(400, 4)
	tr.Done()
	tr.Done()    // second Done is no-op
	tr.Add(0, 0) // Add after Done is no-op
}

// TestFormatBytesPerSec covers the 1024-based unit formatter used by the
// non-TTY emitter for rate strings.
func TestFormatBytesPerSec(t *testing.T) {
	cases := []struct {
		in   int64
		want string
	}{
		{0, "0 B/s"},
		{500, "500 B/s"},
		{1024, "1.0 KB/s"},
		{1024 * 1024, "1.0 MB/s"},
		{1024 * 1024 * 1024, "1.0 GB/s"},
	}
	for _, tc := range cases {
		if got := formatBytesPerSec(tc.in); got != tc.want {
			t.Errorf("formatBytesPerSec(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNew_DefaultsApplied asserts zero-value Options receive a working
// Now func (no panics on Add/Done). Interval==0 explicitly disables
// periodic emission and is honored as-is.
func TestNew_DefaultsApplied(t *testing.T) {
	tr := New(Options{
		Phase:  "restore",
		Totals: Totals{Files: 1, Bytes: 100},
		NoTTY:  true,
	}).(*nonTTYTracker)
	if tr.now == nil {
		t.Errorf("Now default not applied")
	}
	if tr.interval != 0 {
		t.Errorf("explicit Interval=0 should pass through; got %v", tr.interval)
	}
}

// TestDefaultIsTTY_NonFileFalse asserts a non-*os.File writer is reported
// as a non-TTY (e.g. bytes.Buffer in tests).
func TestDefaultIsTTY_NonFileFalse(t *testing.T) {
	if defaultIsTTY(&bytes.Buffer{}) {
		t.Errorf("bytes.Buffer should not be a TTY")
	}
}

// TestNew_NilIsTTYUsesDefaultDetector asserts that omitting IsTTY wires
// the default detector, which classifies a non-file Stderr as non-TTY
// and selects the slog emitter.
func TestNew_NilIsTTYUsesDefaultDetector(t *testing.T) {
	tr := New(Options{
		Phase:  "restore",
		Totals: Totals{Files: 1, Bytes: 100},
		Stderr: &bytes.Buffer{},
	})
	if _, ok := tr.(*nonTTYTracker); !ok {
		t.Fatalf("nil IsTTY with non-file Stderr should pick nonTTYTracker, got %T", tr)
	}
}
