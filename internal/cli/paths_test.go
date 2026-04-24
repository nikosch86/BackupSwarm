package cli

import "testing"

func TestResolveDataDir_ExplicitTakesPrecedence(t *testing.T) {
	t.Setenv("BACKUPSWARM_DATA_DIR", "/from/env")
	got, err := resolveDataDir("/from/flag")
	if err != nil {
		t.Fatalf("resolveDataDir: %v", err)
	}
	if got != "/from/flag" {
		t.Errorf("resolveDataDir = %q, want /from/flag", got)
	}
}

func TestResolveDataDir_EnvFallback(t *testing.T) {
	t.Setenv("BACKUPSWARM_DATA_DIR", "/from/env")
	got, err := resolveDataDir("")
	if err != nil {
		t.Fatalf("resolveDataDir: %v", err)
	}
	if got != "/from/env" {
		t.Errorf("resolveDataDir = %q, want /from/env", got)
	}
}

func TestResolveDataDir_HomeFallback(t *testing.T) {
	t.Setenv("BACKUPSWARM_DATA_DIR", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "/some/home")
	got, err := resolveDataDir("")
	if err != nil {
		t.Fatalf("resolveDataDir: %v", err)
	}
	want := "/some/home/.local/share/backupswarm"
	if got != want {
		t.Errorf("resolveDataDir = %q, want %q", got, want)
	}
}

func TestResolveDataDir_XDGFallback(t *testing.T) {
	t.Setenv("BACKUPSWARM_DATA_DIR", "")
	t.Setenv("XDG_DATA_HOME", "/xdg/data")
	got, err := resolveDataDir("")
	if err != nil {
		t.Fatalf("resolveDataDir: %v", err)
	}
	want := "/xdg/data/backupswarm"
	if got != want {
		t.Errorf("resolveDataDir = %q, want %q", got, want)
	}
}

func TestResolveDataDir_ErrorsWhenAllUnset(t *testing.T) {
	t.Setenv("BACKUPSWARM_DATA_DIR", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "")
	// UserHomeDir also reads XDG_CONFIG_HOME-style fallbacks on non-Linux,
	// but on the primary Linux target an empty HOME produces an error.
	if _, err := resolveDataDir(""); err == nil {
		t.Error("resolveDataDir returned nil error when no inputs set")
	}
}
