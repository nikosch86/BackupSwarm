package quic_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"golang.org/x/time/rate"

	bsw "backupswarm/internal/quic"
)

// byteRWC adapts a Reader+Writer pair into an io.ReadWriteCloser for tests.
type byteRWC struct {
	r io.Reader
	w io.Writer
}

func (b byteRWC) Read(p []byte) (int, error)  { return b.r.Read(p) }
func (b byteRWC) Write(p []byte) (int, error) { return b.w.Write(p) }
func (b byteRWC) Close() error                { return nil }

// TestStream_Write_ThrottlesToUploadRate asserts a Stream wrapper with an
// up limiter takes elapsed time matching the configured byte rate.
func TestStream_Write_ThrottlesToUploadRate(t *testing.T) {
	t.Parallel()

	const ratePerSec = 64 * 1024 // 64 KiB/s
	const burst = 8 * 1024
	const payloadBytes = 32 * 1024

	lim := rate.NewLimiter(rate.Limit(ratePerSec), burst)
	// Drain the initial burst so the first Write must wait.
	lim.AllowN(time.Now(), burst)

	var sink bytes.Buffer
	s := bsw.NewStreamForTest(byteRWC{w: &sink}, lim, nil)

	payload := bytes.Repeat([]byte("a"), payloadBytes)

	start := time.Now()
	n, err := s.Write(payload)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("write: %v", err)
	}
	if n != payloadBytes {
		t.Fatalf("wrote %d bytes, want %d", n, payloadBytes)
	}
	if got := sink.Len(); got != payloadBytes {
		t.Fatalf("sink %d bytes, want %d", got, payloadBytes)
	}

	expected := time.Duration(float64(time.Second) * float64(payloadBytes) / float64(ratePerSec))
	if elapsed < expected*7/10 {
		t.Fatalf("elapsed %v: want ≥ %v (70%% of %v)", elapsed, expected*7/10, expected)
	}
	if elapsed > expected*15/10 {
		t.Fatalf("elapsed %v: want ≤ %v (150%% of %v)", elapsed, expected*15/10, expected)
	}
}

// TestStream_Read_ThrottlesToDownloadRate asserts a Stream wrapper with a
// down limiter takes elapsed time matching the configured byte rate.
func TestStream_Read_ThrottlesToDownloadRate(t *testing.T) {
	t.Parallel()

	const ratePerSec = 64 * 1024
	const burst = 8 * 1024
	const payloadBytes = 32 * 1024

	lim := rate.NewLimiter(rate.Limit(ratePerSec), burst)
	lim.AllowN(time.Now(), burst)

	src := bytes.NewReader(bytes.Repeat([]byte("a"), payloadBytes))
	s := bsw.NewStreamForTest(byteRWC{r: src}, nil, lim)

	start := time.Now()
	n, err := io.Copy(io.Discard, s)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	if n != int64(payloadBytes) {
		t.Fatalf("copied %d bytes, want %d", n, payloadBytes)
	}

	expected := time.Duration(float64(time.Second) * float64(payloadBytes) / float64(ratePerSec))
	if elapsed < expected*7/10 {
		t.Fatalf("elapsed %v: want ≥ %v (70%% of %v)", elapsed, expected*7/10, expected)
	}
	if elapsed > expected*15/10 {
		t.Fatalf("elapsed %v: want ≤ %v (150%% of %v)", elapsed, expected*15/10, expected)
	}
}

// TestStream_NilLimiters_NoThrottle asserts a Stream with both limiters nil
// passes through Read/Write to the underlying RW with no added latency.
func TestStream_NilLimiters_NoThrottle(t *testing.T) {
	t.Parallel()

	const payloadBytes = 256 * 1024
	var sink bytes.Buffer
	s := bsw.NewStreamForTest(byteRWC{w: &sink}, nil, nil)

	payload := bytes.Repeat([]byte("z"), payloadBytes)
	start := time.Now()
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("nil limiter added %v latency; want pass-through", elapsed)
	}
	if got := sink.Len(); got != payloadBytes {
		t.Fatalf("sink %d bytes, want %d", got, payloadBytes)
	}
}

// TestStream_SharedUpLimiter_BoundsCombinedThroughput asserts two Streams
// sharing one upload limiter consume from one budget — combined elapsed
// matches the per-budget rate, not 2x it.
func TestStream_SharedUpLimiter_BoundsCombinedThroughput(t *testing.T) {
	t.Parallel()

	const ratePerSec = 64 * 1024
	const burst = 8 * 1024
	const perStream = 32 * 1024 // combined 64 KiB → expected ~1s elapsed

	lim := rate.NewLimiter(rate.Limit(ratePerSec), burst)
	lim.AllowN(time.Now(), burst)

	var sink1, sink2 bytes.Buffer
	s1 := bsw.NewStreamForTest(byteRWC{w: &sink1}, lim, nil)
	s2 := bsw.NewStreamForTest(byteRWC{w: &sink2}, lim, nil)

	payload := bytes.Repeat([]byte("a"), perStream)

	var wg sync.WaitGroup
	wg.Add(2)
	start := time.Now()
	go func() {
		defer wg.Done()
		if _, err := s1.Write(payload); err != nil {
			t.Errorf("s1 write: %v", err)
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := s2.Write(payload); err != nil {
			t.Errorf("s2 write: %v", err)
		}
	}()
	wg.Wait()
	elapsed := time.Since(start)

	expected := time.Duration(float64(time.Second) * float64(2*perStream) / float64(ratePerSec))
	if elapsed < expected*7/10 {
		t.Fatalf("elapsed %v: want ≥ %v (70%% of %v)", elapsed, expected*7/10, expected)
	}
	if elapsed > expected*15/10 {
		t.Fatalf("elapsed %v: want ≤ %v (150%% of %v) — limiters may not be shared", elapsed, expected*15/10, expected)
	}
	if sink1.Len() != perStream || sink2.Len() != perStream {
		t.Fatalf("sinks: got %d / %d, want %d each", sink1.Len(), sink2.Len(), perStream)
	}
}

// TestStream_Write_HonorsContextCancel asserts a Write blocked on a slow
// limiter returns the context error when the stream's context is cancelled.
func TestStream_Write_HonorsContextCancel(t *testing.T) {
	t.Parallel()

	// Slow limiter: 1 byte/sec, burst 1. After draining burst, every byte
	// requires ~1s wait; we cancel before the first sleep returns.
	lim := rate.NewLimiter(rate.Limit(1), 1)
	lim.AllowN(time.Now(), 1)

	var sink bytes.Buffer
	ctx, cancel := context.WithCancel(context.Background())
	s := bsw.NewStreamForTestWithContext(byteRWC{w: &sink}, lim, nil, ctx)

	done := make(chan error, 1)
	go func() {
		_, err := s.Write([]byte("hello"))
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Write returned nil after cancel")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Write err = %v; want context.Canceled in chain", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Write did not return after ctx cancel")
	}
}

// TestStream_Read_HonorsContextCancel asserts a Read whose post-read
// waitTokens parks on a slow down limiter returns the canceled error in
// place of the read-side success when the stream's context is cancelled.
func TestStream_Read_HonorsContextCancel(t *testing.T) {
	t.Parallel()

	lim := rate.NewLimiter(rate.Limit(1), 1)
	lim.AllowN(time.Now(), 1)

	src := bytes.NewReader([]byte("hello"))
	ctx, cancel := context.WithCancel(context.Background())
	s := bsw.NewStreamForTestWithContext(byteRWC{r: src}, nil, lim, ctx)

	done := make(chan error, 1)
	go func() {
		_, err := io.Copy(io.Discard, s)
		done <- err
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read returned nil after cancel")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Read err = %v; want context.Canceled in chain", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not return after ctx cancel")
	}
}

// TestStream_Write_BurstZero_PassesThrough asserts a Stream whose up
// limiter has burst <= 0 falls through directly to writeInner without
// parking on WaitN.
func TestStream_Write_BurstZero_PassesThrough(t *testing.T) {
	t.Parallel()

	lim := rate.NewLimiter(rate.Limit(0), 0)
	var sink bytes.Buffer
	s := bsw.NewStreamForTest(byteRWC{w: &sink}, lim, nil)

	payload := []byte("hello-burst-zero")
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err := s.Write(payload)
		if err != nil {
			t.Errorf("Write: %v", err)
			return
		}
		if n != len(payload) {
			t.Errorf("Write n = %d, want %d", n, len(payload))
		}
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Write parked despite burst <= 0; expected pass-through")
	}
	if got := sink.String(); got != string(payload) {
		t.Fatalf("sink = %q, want %q", got, payload)
	}
}

// closeTrackingRWC records whether Close was called and surfaces a sentinel
// error so the test can assert Stream.Close routed through the rwc seam.
type closeTrackingRWC struct {
	closed bool
	err    error
}

func (c *closeTrackingRWC) Read(p []byte) (int, error)  { return 0, io.EOF }
func (c *closeTrackingRWC) Write(p []byte) (int, error) { return len(p), nil }
func (c *closeTrackingRWC) Close() error {
	c.closed = true
	return c.err
}

// TestStream_Close_RWCSeam asserts Stream.Close routes through the rwc test
// seam and propagates its return value when the embedded *qgo.Stream is nil.
func TestStream_Close_RWCSeam(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("rwc-close-sentinel")
	rwc := &closeTrackingRWC{err: sentinel}
	s := bsw.NewStreamForTest(rwc, nil, nil)

	if err := s.Close(); !errors.Is(err, sentinel) {
		t.Fatalf("Close err = %v, want %v", err, sentinel)
	}
	if !rwc.closed {
		t.Fatal("Close did not invoke rwc.Close")
	}
}

// TestStream_Read_BurstZero_PassesThrough exercises waitTokens' burst <= 0
// branch by reading through a Stream whose down limiter has burst 0; the
// post-read wait must fall through and the bytes must surface to the caller.
func TestStream_Read_BurstZero_PassesThrough(t *testing.T) {
	t.Parallel()

	lim := rate.NewLimiter(rate.Limit(0), 0)
	src := bytes.NewReader([]byte("hello-burst-zero"))
	s := bsw.NewStreamForTest(byteRWC{r: src}, nil, lim)

	done := make(chan []byte, 1)
	errCh := make(chan error, 1)
	go func() {
		buf, err := io.ReadAll(s)
		if err != nil {
			errCh <- err
			return
		}
		done <- buf
	}()

	select {
	case got := <-done:
		if string(got) != "hello-burst-zero" {
			t.Fatalf("Read returned %q, want %q", got, "hello-burst-zero")
		}
	case err := <-errCh:
		t.Fatalf("Read: %v", err)
	case <-time.After(time.Second):
		t.Fatal("Read parked despite burst <= 0; expected pass-through")
	}
}
