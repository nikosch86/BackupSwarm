// Package cliprogress provides one-shot progress display for daemon and
// CLI phases (restore, first-backup, purge). New picks a TTY progress bar
// or a structured-log emitter based on stderr's tty status.
package cliprogress

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"golang.org/x/term"
)

// Tracker reports incremental progress for a phase. Add increments the
// counters with the bytes/files just completed; Done finalises the
// bar/log emission. Implementations are safe for concurrent use.
type Tracker interface {
	Add(bytes int64, files int)
	Done()
}

// Totals are the upfront file/byte counts for a phase.
type Totals struct {
	Files int64
	Bytes int64
}

// Options configures a Tracker. Interval == 0 disables periodic emission
// in the non-TTY impl; Done still flushes a final line.
type Options struct {
	Phase    string
	Totals   Totals
	Stderr   io.Writer
	Interval time.Duration
	Now      func() time.Time
	IsTTY    func() bool
	NoTTY    bool
}

// DefaultInterval is the recommended cadence the CLI applies when the
// operator does not pass --progress-interval.
const DefaultInterval = 10 * time.Second

// ewmaAlpha is the smoothing factor on the throughput estimate. ~0.3
// rejects single-interval stalls without lagging far behind sustained
// throughput shifts.
const ewmaAlpha = 0.3

// New constructs a Tracker. NoTTY=true or IsTTY()=false picks the slog
// emitter; otherwise a schollz/progressbar instance is returned.
func New(opts Options) Tracker {
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.IsTTY == nil {
		opts.IsTTY = func() bool { return defaultIsTTY(opts.Stderr) }
	}
	if !opts.NoTTY && opts.IsTTY() {
		return newTTY(opts)
	}
	return newNonTTY(opts)
}

// defaultIsTTY reports whether w is a terminal-attached file.
func defaultIsTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// ttyTracker wraps a schollz/progressbar instance.
type ttyTracker struct {
	bar *progressbar.ProgressBar

	mu   sync.Mutex
	done bool
}

func newTTY(opts Options) *ttyTracker {
	bar := progressbar.NewOptions64(
		opts.Totals.Bytes,
		progressbar.OptionSetDescription(opts.Phase),
		progressbar.OptionSetWriter(opts.Stderr),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetPredictTime(true),
	)
	return &ttyTracker{bar: bar}
}

func (t *ttyTracker) Add(bytes int64, _ int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return
	}
	_ = t.bar.Add64(bytes)
}

func (t *ttyTracker) Done() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return
	}
	_ = t.bar.Finish()
	t.done = true
}

// ewma is a single-channel exponentially weighted moving average.
type ewma struct {
	alpha  float64
	value  float64
	seeded bool
}

func newEWMA(alpha float64) *ewma {
	return &ewma{alpha: alpha}
}

// Add folds sample into the running average. The first sample seeds the
// value verbatim; subsequent samples are blended via alpha.
func (e *ewma) Add(sample float64) {
	if !e.seeded {
		e.value = sample
		e.seeded = true
		return
	}
	e.value = e.alpha*sample + (1-e.alpha)*e.value
}

// Value returns the current smoothed estimate.
func (e *ewma) Value() float64 { return e.value }

// nonTTYTracker emits one slog INFO "progress" line per interval and one
// final line on Done. Rate is the EWMA of bytes/sec across emit boundaries.
type nonTTYTracker struct {
	phase    string
	totals   Totals
	interval time.Duration
	now      func() time.Time

	mu        sync.Mutex
	files     int64
	bytes     int64
	lastEmit  time.Time
	lastBytes int64
	rate      *ewma
	done      bool
}

func newNonTTY(opts Options) *nonTTYTracker {
	return &nonTTYTracker{
		phase:    opts.Phase,
		totals:   opts.Totals,
		interval: opts.Interval,
		now:      opts.Now,
		lastEmit: opts.Now(),
		rate:     newEWMA(ewmaAlpha),
	}
}

func (t *nonTTYTracker) Add(bytes int64, files int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return
	}
	t.bytes += bytes
	t.files += int64(files)
	if t.interval <= 0 {
		return
	}
	n := t.now()
	elapsed := n.Sub(t.lastEmit)
	if elapsed < t.interval {
		return
	}
	t.recordRate(elapsed)
	t.emit()
	t.lastEmit = n
	t.lastBytes = t.bytes
}

func (t *nonTTYTracker) Done() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.done {
		return
	}
	t.recordRate(t.now().Sub(t.lastEmit))
	t.emit()
	t.done = true
}

func (t *nonTTYTracker) recordRate(elapsed time.Duration) {
	if elapsed <= 0 {
		return
	}
	bytesDelta := t.bytes - t.lastBytes
	rate := float64(bytesDelta) / elapsed.Seconds()
	t.rate.Add(rate)
}

func (t *nonTTYTracker) emit() {
	rate := t.rate.Value()
	var etaSec int64
	if rate > 0 && t.totals.Bytes > t.bytes {
		etaSec = int64(float64(t.totals.Bytes-t.bytes) / rate)
	}
	slog.Info("progress",
		"phase", t.phase,
		"files_done", t.files,
		"files_total", t.totals.Files,
		"bytes_done", t.bytes,
		"bytes_total", t.totals.Bytes,
		"rate", formatBytesPerSec(int64(rate)),
		"eta_seconds", etaSec,
	)
}

// formatBytes returns n in 1024-based units; sub-KB values are integer
// bytes ("823 B"), larger values use one decimal with a KB/MB/GB suffix.
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
