package cli

import (
	"bytes"
	"log/slog"
	"testing"
)

func TestParseLogLevel(t *testing.T) {
	cases := []struct {
		in   string
		want slog.Level
	}{
		{"", slog.LevelInfo},
		{"info", slog.LevelInfo},
		{"INFO", slog.LevelInfo},
		{"debug", slog.LevelDebug},
		{"Debug", slog.LevelDebug},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{" error ", slog.LevelError},
	}
	for _, tc := range cases {
		got, err := parseLogLevel(tc.in)
		if err != nil {
			t.Errorf("parseLogLevel(%q) unexpected err: %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseLogLevel(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestParseLogLevel_Invalid(t *testing.T) {
	if _, err := parseLogLevel("trace"); err == nil {
		t.Fatal("expected error for invalid level")
	}
}

func TestResolveLogLevel_FlagOverridesEnv(t *testing.T) {
	got, err := resolveLogLevel("debug", "error")
	if err != nil {
		t.Fatal(err)
	}
	if got != slog.LevelDebug {
		t.Fatalf("flag should win: got %v", got)
	}
}

func TestResolveLogLevel_EnvFallback(t *testing.T) {
	got, err := resolveLogLevel("", "warn")
	if err != nil {
		t.Fatal(err)
	}
	if got != slog.LevelWarn {
		t.Fatalf("env fallback failed: got %v", got)
	}
}

func TestResolveLogLevel_DefaultInfo(t *testing.T) {
	got, err := resolveLogLevel("", "")
	if err != nil {
		t.Fatal(err)
	}
	if got != slog.LevelInfo {
		t.Fatalf("default should be info: got %v", got)
	}
}

func TestInstallLogger_RespectsLevel(t *testing.T) {
	prev := slog.Default()
	t.Cleanup(func() { slog.SetDefault(prev) })

	var buf bytes.Buffer
	installLogger(&buf, slog.LevelWarn)
	slog.Info("should-not-appear")
	slog.Warn("should-appear")
	out := buf.String()
	if bytes.Contains([]byte(out), []byte("should-not-appear")) {
		t.Error("info log leaked at warn level")
	}
	if !bytes.Contains([]byte(out), []byte("should-appear")) {
		t.Error("warn log missing at warn level")
	}
}
