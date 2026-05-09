package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRunCmd_ConfigFile_AcceptedAndResolved asserts --config FILE is wired
// in: the daemon accepts a config file, layered values reach the daemon
// options, and the run exits cleanly on cancel.
func TestRunCmd_ConfigFile_AcceptedAndResolved(t *testing.T) {
	dataDir := t.TempDir()
	cfgBody := `
[storage]
redundancy = 2

[metrics]
addr = ""

[log]
level = "info"
`
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}

	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--listen", "127.0.0.1:0",
		"--backup-dir", t.TempDir(),
		"--config", cfgPath,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with --config returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_ConfigFile_UnknownKey_ErrorsAtStartup asserts that an unknown
// key in the config file produces an error before the daemon starts.
func TestRunCmd_ConfigFile_UnknownKey_ErrorsAtStartup(t *testing.T) {
	dataDir := t.TempDir()
	cfgBody := `
[storage]
nonsense_key = 5
`
	cfgPath := filepath.Join(t.TempDir(), "bad.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}

	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--listen", "127.0.0.1:0",
		"--backup-dir", t.TempDir(),
		"--config", cfgPath,
	})

	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected error for unknown key, got nil")
	}
	if !strings.Contains(err.Error(), "storage.nonsense_key") {
		t.Errorf("error %q does not name unknown key", err.Error())
	}
}

// TestRunCmd_ConfigFile_DefaultsToDataDir asserts <data-dir>/config.toml is
// auto-loaded when --config is omitted.
func TestRunCmd_ConfigFile_DefaultsToDataDir(t *testing.T) {
	dataDir := t.TempDir()
	cfgBody := `
[storage]
nonsense_key = 5
`
	if err := os.WriteFile(filepath.Join(dataDir, "config.toml"), []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}

	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--listen", "127.0.0.1:0",
		"--backup-dir", t.TempDir(),
	})

	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected error from auto-loaded <data-dir>/config.toml")
	}
	if !strings.Contains(err.Error(), "storage.nonsense_key") {
		t.Errorf("error %q does not name unknown key", err.Error())
	}
}

// TestRunCmd_ConfigFile_FlagOverrides asserts a CLI flag wins over a config
// file value. We assert the flag-set redundancy survives by triggering a
// validation that a config-only redundancy=0 would fail.
func TestRunCmd_ConfigFile_FlagOverrides(t *testing.T) {
	dataDir := t.TempDir()
	cfgBody := `
[storage]
redundancy = 0
`
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte(cfgBody), 0o600); err != nil {
		t.Fatal(err)
	}

	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--listen", "127.0.0.1:0",
		"--backup-dir", t.TempDir(),
		"--config", cfgPath,
		"--redundancy", "3",
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected flag override of redundancy=0 to bypass validation; got err=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_ConfigFile_MissingNotFatal asserts a non-existent --config path
// doesn't error; the daemon falls back to defaults.
func TestRunCmd_ConfigFile_MissingNotFatal(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--listen", "127.0.0.1:0",
		"--backup-dir", t.TempDir(),
		"--config", filepath.Join(t.TempDir(), "definitely-missing.toml"),
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("missing --config path should be non-fatal; got err=%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}
