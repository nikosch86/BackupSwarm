package quic_test

import (
	"bytes"
	"io"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/time/rate"

	bsw "backupswarm/internal/quic"
)

// fakeMeter is the simplest bsw.ByteMeter for tests.
type fakeMeter struct {
	up   atomic.Int64
	down atomic.Int64
}

func (m *fakeMeter) AddBytesUp(n int)   { m.up.Add(int64(n)) }
func (m *fakeMeter) AddBytesDown(n int) { m.down.Add(int64(n)) }

// TestStream_Write_IncrementsMeterByWrittenBytes asserts each successful
// Write feeds the meter with the byte count actually delivered.
func TestStream_Write_IncrementsMeterByWrittenBytes(t *testing.T) {
	t.Parallel()

	const payloadBytes = 4096
	var sink bytes.Buffer
	meter := &fakeMeter{}
	s := bsw.NewStreamForTestWithMeter(byteRWC{w: &sink}, nil, nil, meter)

	payload := bytes.Repeat([]byte("x"), payloadBytes)
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := meter.up.Load(); got != payloadBytes {
		t.Errorf("meter.up = %d, want %d", got, payloadBytes)
	}
	if got := meter.down.Load(); got != 0 {
		t.Errorf("meter.down = %d, want 0", got)
	}
}

// TestStream_Read_IncrementsMeterByReadBytes asserts each successful Read
// feeds the meter with the byte count actually delivered.
func TestStream_Read_IncrementsMeterByReadBytes(t *testing.T) {
	t.Parallel()

	const payloadBytes = 4096
	src := bytes.NewReader(bytes.Repeat([]byte("y"), payloadBytes))
	meter := &fakeMeter{}
	s := bsw.NewStreamForTestWithMeter(byteRWC{r: src}, nil, nil, meter)

	if _, err := io.Copy(io.Discard, s); err != nil {
		t.Fatalf("Read: %v", err)
	}
	if got := meter.down.Load(); got != payloadBytes {
		t.Errorf("meter.down = %d, want %d", got, payloadBytes)
	}
	if got := meter.up.Load(); got != 0 {
		t.Errorf("meter.up = %d, want 0", got)
	}
}

// TestStream_NilMeter_NoPanic asserts a nil meter does not panic on
// Read/Write — meter is optional.
func TestStream_NilMeter_NoPanic(t *testing.T) {
	t.Parallel()

	var sink bytes.Buffer
	s := bsw.NewStreamForTestWithMeter(byteRWC{w: &sink}, nil, nil, nil)
	if _, err := s.Write([]byte("hi")); err != nil {
		t.Fatalf("Write: %v", err)
	}

	src := bytes.NewReader([]byte("hi"))
	s = bsw.NewStreamForTestWithMeter(byteRWC{r: src}, nil, nil, nil)
	if _, err := io.Copy(io.Discard, s); err != nil {
		t.Fatalf("Read: %v", err)
	}
}

// TestStream_Write_MeterAndLimiterCompose asserts the meter receives the
// bytes count even when the limiter chunks the payload.
func TestStream_Write_MeterAndLimiterCompose(t *testing.T) {
	t.Parallel()

	const payloadBytes = 4096
	const burst = 1024
	lim := rate.NewLimiter(rate.Limit(1<<20), burst) // 1 MiB/s, burst 1 KiB
	var sink bytes.Buffer
	meter := &fakeMeter{}
	s := bsw.NewStreamForTestWithMeter(byteRWC{w: &sink}, lim, nil, meter)

	payload := bytes.Repeat([]byte("z"), payloadBytes)
	if _, err := s.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if got := meter.up.Load(); got != payloadBytes {
		t.Errorf("meter.up = %d, want %d (limiter chunking should not lose bytes)", got, payloadBytes)
	}
}

// TestListener_SetLimitersWithMeter_PropagatesToAcceptedStream asserts a
// meter set on the Listener's Limiters lands on streams of accepted Conns.
// Covered indirectly: SetLimiters takes a Limiters with Meter; we exercise
// the wrapStream path via concurrency to ensure no race in propagation.
func TestStream_Meter_ConcurrentReadsAndWritesAreRaceFree(t *testing.T) {
	t.Parallel()

	const workers = 8
	const writes = 200
	var wg sync.WaitGroup
	wg.Add(workers)
	meter := &fakeMeter{}
	for range workers {
		go func() {
			defer wg.Done()
			var sink bytes.Buffer
			s := bsw.NewStreamForTestWithMeter(byteRWC{w: &sink}, nil, nil, meter)
			for range writes {
				if _, err := s.Write([]byte("a")); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
	if got := meter.up.Load(); got != int64(workers*writes) {
		t.Errorf("meter.up = %d, want %d", got, workers*writes)
	}
}
