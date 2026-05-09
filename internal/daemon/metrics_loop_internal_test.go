package daemon

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/metrics"
)

func TestRunMetricsLoop_ServesMetricsEndpoint(t *testing.T) {
	t.Parallel()

	prom := metrics.NewProm()
	c := &metrics.Counters{}
	c.SetProm(prom)
	c.AddBytesUp(123)
	c.AddFilesBackedUp()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		runMetricsLoop(ctx, metricsLoopOptions{
			listener: ln,
			prom:     prom,
		})
	}()

	body := pollGet(t, "http://"+addr+"/metrics", 2*time.Second)
	if !strings.Contains(body, "backupswarm_bytes_up_total 123") {
		t.Errorf("body missing bytes_up sample; got: %s", body)
	}
	if !strings.Contains(body, "backupswarm_files_backed_up_total 1") {
		t.Errorf("body missing files_backed_up sample; got: %s", body)
	}

	cancel()
	wg.Wait()
}

func TestRunMetricsLoop_ShutdownOnContextDone(t *testing.T) {
	t.Parallel()

	prom := metrics.NewProm()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		runMetricsLoop(ctx, metricsLoopOptions{
			listener: ln,
			prom:     prom,
		})
	}()
	pollGet(t, "http://"+addr+"/metrics", 2*time.Second)

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runMetricsLoop did not return after ctx cancel")
	}

	// After shutdown the listener must be closed so the address is reusable.
	conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		t.Errorf("expected port %s to be free after shutdown, but dial succeeded", addr)
	}
}

func TestRunMetricsLoop_NilListener_BlocksUntilCtxDone(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	runMetricsLoop(ctx, metricsLoopOptions{listener: nil, prom: metrics.NewProm()})
}

func TestRunMetricsLoop_NilProm_BlocksUntilCtxDone(t *testing.T) {
	t.Parallel()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	runMetricsLoop(ctx, metricsLoopOptions{listener: ln, prom: nil})
}

func TestRunMetricsLoop_ExitsWhenListenerClosedExternally(t *testing.T) {
	t.Parallel()

	prom := metrics.NewProm()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		defer close(done)
		runMetricsLoop(ctx, metricsLoopOptions{listener: ln, prom: prom})
	}()

	pollGet(t, "http://"+ln.Addr().String()+"/metrics", 2*time.Second)
	_ = ln.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runMetricsLoop did not return after external listener close")
	}
}

func TestRunMetricsLoop_ShortShutdownTimeoutStillReturns(t *testing.T) {
	t.Parallel()

	prom := metrics.NewProm()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	addr := ln.Addr().String()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		runMetricsLoop(ctx, metricsLoopOptions{
			listener:        ln,
			prom:            prom,
			shutdownTimeout: time.Nanosecond,
		})
	}()
	pollGet(t, "http://"+addr+"/metrics", 2*time.Second)

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runMetricsLoop did not return after ctx cancel with tight shutdown timeout")
	}
}

func pollGet(t *testing.T, url string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err != nil {
			lastErr = err
			time.Sleep(20 * time.Millisecond)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == 200 {
			return string(body)
		}
		lastErr = nil
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("GET %s did not return 200 within %v: %v", url, timeout, lastErr)
	return ""
}
