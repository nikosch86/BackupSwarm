package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"backupswarm/internal/node"
)

func TestRootCmd_HasDataDirFlag(t *testing.T) {
	root := NewRootCmd()
	f := root.PersistentFlags().Lookup("data-dir")
	if f == nil {
		t.Fatal("root command missing --data-dir persistent flag")
	}
	if f.Usage == "" {
		t.Error("--data-dir flag has empty usage string")
	}
}

func TestInitCmd_CreatesIdentityOnFreshDir(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "node")
	root := NewRootCmd()

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", dataDir, "init"})

	if err := root.Execute(); err != nil {
		t.Fatalf("init failed: %v (stderr=%q)", err, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(dataDir, "node.key")); err != nil {
		t.Errorf("private key not created: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "node.pub")); err != nil {
		t.Errorf("public key not created: %v", err)
	}
}

func TestInitCmd_IdempotentAcrossRuns(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "node")

	r1 := NewRootCmd()
	var out1, err1 bytes.Buffer
	r1.SetOut(&out1)
	r1.SetErr(&err1)
	r1.SetArgs([]string{"--data-dir", dataDir, "init"})
	if err := r1.Execute(); err != nil {
		t.Fatalf("first init: %v (stderr=%q)", err, err1.String())
	}
	id1, err := node.Load(dataDir)
	if err != nil {
		t.Fatalf("load after first init: %v", err)
	}

	r2 := NewRootCmd()
	var out2, err2 bytes.Buffer
	r2.SetOut(&out2)
	r2.SetErr(&err2)
	r2.SetArgs([]string{"--data-dir", dataDir, "init"})
	if err := r2.Execute(); err != nil {
		t.Fatalf("second init: %v (stderr=%q)", err, err2.String())
	}
	id2, err := node.Load(dataDir)
	if err != nil {
		t.Fatalf("load after second init: %v", err)
	}

	if !id1.PublicKey.Equal(id2.PublicKey) {
		t.Error("node ID changed between init runs — not idempotent")
	}
}

func TestInitCmd_ReportsEnsureError(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	// `blocker/node` can't be created because its parent is a file.
	bad := filepath.Join(blocker, "node")

	cmd := NewRootCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"--data-dir", bad, "init"})

	if err := cmd.Execute(); err == nil {
		t.Error("init returned nil error despite un-creatable data dir")
	}
}

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

func TestInitCmd_ReportsResolveError(t *testing.T) {
	t.Setenv("BACKUPSWARM_DATA_DIR", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("HOME", "")

	cmd := NewRootCmd()
	var stdout, stderr bytes.Buffer
	cmd.SetOut(&stdout)
	cmd.SetErr(&stderr)
	cmd.SetArgs([]string{"init"})

	if err := cmd.Execute(); err == nil {
		t.Error("init returned nil error when data-dir can't be resolved")
	}
}
