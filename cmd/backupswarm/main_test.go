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
	for _, sub := range []string{"invite", "join", "run"} {
		if !strings.Contains(stdout.String(), sub) {
			t.Errorf("help output missing %q subcommand:\n%s", sub, stdout.String())
		}
	}
}

func TestRun_UnknownCommandReturnsNonZero(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"does-not-exist"}, &stdout, &stderr)
	if code == 0 {
		t.Fatalf("run(unknown) exit code = 0, want non-zero")
	}
	if !strings.Contains(stderr.String(), "command failed") {
		t.Errorf("expected 'command failed' log on stderr, got: %q", stderr.String())
	}
	if !strings.Contains(stderr.String(), `"level":"ERROR"`) {
		t.Errorf("expected JSON-formatted ERROR log on stderr, got: %q", stderr.String())
	}
}
