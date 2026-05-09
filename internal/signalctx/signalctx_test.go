package signalctx

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// withExit swaps the package-level exit hook for the duration of the
// test and restores it on cleanup. Returns a getter for the recorded
// exit code (-1 if exit was never called).
func withExit(t *testing.T) func() int {
	t.Helper()
	var code atomic.Int64
	code.Store(-1)
	prev := exit
	exit = func(c int) { code.Store(int64(c)) }
	t.Cleanup(func() { exit = prev })
	return func() int { return int(code.Load()) }
}

// signalSelf delivers sig to the current process. Used to drive the
// signal-handling code under test from inside the test process.
func signalSelf(t *testing.T, sig os.Signal) {
	t.Helper()
	proc, err := os.FindProcess(os.Getpid())
	if err != nil {
		t.Fatalf("find self process: %v", err)
	}
	if err := proc.Signal(sig); err != nil {
		t.Fatalf("signal self: %v", err)
	}
}

// waitDone blocks up to d for ctx to be cancelled. Reports a fatal
// error with msg if the deadline expires first.
func waitDone(t *testing.T, ctx context.Context, d time.Duration, msg string) {
	t.Helper()
	select {
	case <-ctx.Done():
	case <-time.After(d):
		t.Fatalf("timeout waiting for %s", msg)
	}
}

func TestWithSignalCancel_FirstSignalCancels(t *testing.T) {
	getExit := withExit(t)

	ctx, stop := WithSignalCancel(context.Background(), syscall.SIGUSR1)
	defer stop()

	signalSelf(t, syscall.SIGUSR1)
	waitDone(t, ctx, 2*time.Second, "ctx cancellation on first signal")

	// First signal must not trigger the hard-exit.
	if got := getExit(); got != -1 {
		t.Fatalf("exit hook fired on first signal (code %d), want no fire", got)
	}
}

func TestWithSignalCancel_SecondSignalHardExits(t *testing.T) {
	getExit := withExit(t)

	ctx, stop := WithSignalCancel(context.Background(), syscall.SIGUSR1)
	defer stop()

	signalSelf(t, syscall.SIGUSR1)
	waitDone(t, ctx, 2*time.Second, "ctx cancellation on first signal")

	// Second signal: poll briefly because exit is recorded asynchronously.
	signalSelf(t, syscall.SIGUSR1)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if getExit() == HardExitCode {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("exit hook not called with code %d (got %d)", HardExitCode, getExit())
}

func TestWithSignalCancel_StopWithoutSignalCancelsCtx(t *testing.T) {
	withExit(t)

	ctx, stop := WithSignalCancel(context.Background(), syscall.SIGUSR1)
	stop()

	if ctx.Err() == nil {
		t.Fatalf("ctx not cancelled after stop")
	}
}

func TestWithSignalCancel_StopIsIdempotent(t *testing.T) {
	withExit(t)

	_, stop := WithSignalCancel(context.Background(), syscall.SIGUSR1)
	stop()
	stop() // must not panic
}

func TestWithSignalCancel_StopReleasesGoroutine(t *testing.T) {
	withExit(t)

	before := runtime.NumGoroutine()
	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, stop := WithSignalCancel(context.Background(), syscall.SIGUSR1)
			stop()
		}()
	}
	wg.Wait()

	// Allow scheduled goroutines to wind down.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if runtime.NumGoroutine() <= before+2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("goroutine count grew %d → %d after %d stop()s",
		before, runtime.NumGoroutine(), n)
}

func TestWithSignalCancel_ParentCancelPropagates(t *testing.T) {
	withExit(t)

	parent, parentCancel := context.WithCancel(context.Background())
	ctx, stop := WithSignalCancel(parent, syscall.SIGUSR1)
	defer stop()

	parentCancel()
	waitDone(t, ctx, time.Second, "ctx propagation from parent cancel")
}

// safeBuf is bytes.Buffer with mutex-guarded Write/String for
// concurrent access.
type safeBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// captureSlog redirects slog.Default to a JSON buffer for the duration
// of the test and returns a getter for the captured bytes.
func captureSlog(t *testing.T) func() string {
	t.Helper()
	buf := &safeBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return func() string { return buf.String() }
}

func TestWithSignalCancel_FirstSignalLogsAttribution(t *testing.T) {
	withExit(t)
	logs := captureSlog(t)

	ctx, stop := WithSignalCancel(context.Background(), syscall.SIGUSR1)
	defer stop()

	signalSelf(t, syscall.SIGUSR1)
	waitDone(t, ctx, 2*time.Second, "ctx cancellation on first signal")

	// Poll briefly because the goroutine logs after the cancel.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		out := logs()
		if strings.Contains(out, `"msg":"received signal, shutting down"`) &&
			strings.Contains(out, `"signal":"user defined signal 1"`) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("missing first-signal log; got: %s", logs())
}

func TestWithSignalCancel_SecondSignalLogsHardExit(t *testing.T) {
	withExit(t)
	logs := captureSlog(t)

	ctx, stop := WithSignalCancel(context.Background(), syscall.SIGUSR1)
	defer stop()

	signalSelf(t, syscall.SIGUSR1)
	waitDone(t, ctx, 2*time.Second, "ctx cancellation on first signal")

	signalSelf(t, syscall.SIGUSR1)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(logs(), `"msg":"received second signal, hard exit"`) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("missing second-signal log; got: %s", logs())
}

func TestWithSignalCancel_StopAfterFirstSignalSilencesSecond(t *testing.T) {
	getExit := withExit(t)

	// SIGUSR1's default action is terminate. Pre-install a no-op
	// absorber so a USR1 sent after stop() releases its handler does
	// not kill the test process.
	absorbCh := make(chan os.Signal, 2)
	signal.Notify(absorbCh, syscall.SIGUSR1)
	defer signal.Stop(absorbCh)

	ctx, stop := WithSignalCancel(context.Background(), syscall.SIGUSR1)

	signalSelf(t, syscall.SIGUSR1)
	waitDone(t, ctx, 2*time.Second, "ctx cancellation on first signal")

	stop()
	// Drain whatever the absorber caught from the first signal.
	select {
	case <-absorbCh:
	default:
	}

	signalSelf(t, syscall.SIGUSR1)
	select {
	case <-absorbCh:
	case <-time.After(time.Second):
		t.Fatalf("second SIGUSR1 not delivered")
	}

	if got := getExit(); got != -1 {
		t.Fatalf("exit hook fired after stop() (code %d), want no fire", got)
	}
}
