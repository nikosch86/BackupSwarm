package cli

import (
	"bytes"
	"testing"
)

func TestNewRootCmd_HasNameAndShortDescription(t *testing.T) {
	root := NewRootCmd()

	if root.Use != "backupswarm" {
		t.Errorf("root Use = %q, want %q", root.Use, "backupswarm")
	}
	if root.Short == "" {
		t.Error("root Short description is empty")
	}
}

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

// TestRootCmd_NoInitSubcommand: identity is auto-ensured by
// invite/join/run, so a standalone `init` is redundant and was dropped
// in M1.9's cleanup. This test pins the removal so a future
// well-meaning refactor doesn't resurrect it by accident.
func TestRootCmd_NoInitSubcommand(t *testing.T) {
	root := NewRootCmd()
	for _, sub := range root.Commands() {
		if sub.Name() == "init" {
			t.Error("root command has `init` subcommand; should be dropped (identity is auto-ensured)")
		}
	}
}

// TestRootCmd_SilencesUsageAndErrors verifies the CLI contract that errors
// are surfaced via structured logs (from run()), not via cobra's default
// usage/error dump. These flags are user-facing behavior worth pinning.
func TestRootCmd_SilencesUsageAndErrors(t *testing.T) {
	root := NewRootCmd()

	if !root.SilenceUsage {
		t.Error("root SilenceUsage = false, want true (usage dump is handled elsewhere)")
	}
	if !root.SilenceErrors {
		t.Error("root SilenceErrors = false, want true (errors logged via slog)")
	}
}

func TestRootCmd_HelpRuns(t *testing.T) {
	root := NewRootCmd()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stdout)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("--help failed: %v", err)
	}
	if stdout.Len() == 0 {
		t.Error("--help produced no output")
	}
}
