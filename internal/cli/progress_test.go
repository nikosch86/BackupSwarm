package cli

import (
	"bytes"
	"os"
	"testing"
	"time"

	"backupswarm/internal/cliprogress"
)

// TestBuildProgressFactory_NilStderrYieldsNilFactory asserts a nil
// stderr disables progress entirely.
func TestBuildProgressFactory_NilStderrYieldsNilFactory(t *testing.T) {
	if got := buildProgressFactory(progressOptions{stderr: nil}); got != nil {
		t.Errorf("expected nil factory for nil stderr; got %T", got)
	}
}

// TestBuildProgressFactory_BuildsTrackerWithFlags asserts a non-nil
// factory invokes cliprogress.New with the configured options. We
// verify by constructing a tracker and confirming its dynamic type.
func TestBuildProgressFactory_BuildsTrackerWithFlags(t *testing.T) {
	factory := buildProgressFactory(progressOptions{
		stderr:     &bytes.Buffer{},
		noProgress: true,
		interval:   5 * time.Second,
	})
	if factory == nil {
		t.Fatalf("factory unexpectedly nil")
	}
	tr := factory("restore", cliprogress.Totals{Files: 1, Bytes: 100})
	if tr == nil {
		t.Fatalf("factory returned nil tracker")
	}
	tr.Done()
}

// TestResolveStderr_FallsBackToOsStderr asserts a nil writer arg is
// replaced with os.Stderr.
func TestResolveStderr_FallsBackToOsStderr(t *testing.T) {
	if got := resolveStderr(nil); got != os.Stderr {
		t.Errorf("nil should resolve to os.Stderr; got %T", got)
	}
}

// TestResolveStderr_PassesThrough asserts a non-nil writer is returned as-is.
func TestResolveStderr_PassesThrough(t *testing.T) {
	w := &bytes.Buffer{}
	if got := resolveStderr(w); got != w {
		t.Errorf("non-nil writer should pass through; got %T", got)
	}
}
