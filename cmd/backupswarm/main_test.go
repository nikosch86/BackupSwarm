package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRun_HelpReturnsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(--help) exit code = %d, want 0 (stderr=%q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "init") {
		t.Errorf("help output missing 'init' subcommand:\n%s", stdout.String())
	}
}

func TestRun_InitReturnsZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--data-dir", t.TempDir(), "init"}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("run(init) exit code = %d, want 0 (stderr=%q)", code, stderr.String())
	}
}

func TestRun_UnknownCommandReturnsNonZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"does-not-exist"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run(unknown) exit code = 0, want non-zero")
	}
	// The CLI contract is: errors go to stderr as structured JSON logs.
	// Verify the failure was actually logged (not silently swallowed) and
	// that it reached stderr rather than stdout.
	if !strings.Contains(stderr.String(), "command failed") {
		t.Errorf("expected 'command failed' log on stderr, got: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), `"level":"ERROR"`) {
		t.Errorf("expected JSON-formatted ERROR log on stderr, got: %q", stderr.String())
	}
}
