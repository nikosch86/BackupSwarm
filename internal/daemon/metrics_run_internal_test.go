package daemon

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRun_MetricsAddrBindFailureLogsWarning(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:     t.TempDir(),
			ListenAddr:  "127.0.0.1:0",
			MetricsAddr: "127.0.0.1:not-a-port",
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(w.String(), "metrics endpoint disabled") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}

	if !strings.Contains(w.String(), "metrics endpoint disabled") {
		t.Errorf("expected slog WARN 'metrics endpoint disabled'; got: %s", w.String())
	}
}

func TestRun_MetricsAddrEnabledServesEndpoint(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:     t.TempDir(),
			ListenAddr:  "127.0.0.1:0",
			MetricsAddr: "127.0.0.1:0",
		})
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}
}
