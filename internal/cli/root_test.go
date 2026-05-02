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

// TestRootCmd_NoInitSubcommand pins that no `init` subcommand exists.
// Identity and per-swarm CA are both auto-ensured on first invite (CA by
// default, --no-ca opts in to pubkey-pin trust).
func TestRootCmd_NoInitSubcommand(t *testing.T) {
	root := NewRootCmd()
	for _, sub := range root.Commands() {
		if sub.Name() == "init" {
			t.Error("root command has `init` subcommand; should be dropped (auto-ensured via invite)")
		}
	}
}

// TestRootCmd_SilencesUsageAndErrors asserts the root command sets SilenceUsage and SilenceErrors.
func TestRootCmd_SilencesUsageAndErrors(t *testing.T) {
	root := NewRootCmd()

	if !root.SilenceUsage {
		t.Error("root SilenceUsage = false, want true (usage dump is handled elsewhere)")
	}
	if !root.SilenceErrors {
		t.Error("root SilenceErrors = false, want true (errors logged via slog)")
	}
}

func TestRootCmd_HasLogLevelFlag(t *testing.T) {
	root := NewRootCmd()
	f := root.PersistentFlags().Lookup("log-level")
	if f == nil {
		t.Fatal("root command missing --log-level persistent flag")
	}
	if f.Usage == "" {
		t.Error("--log-level flag has empty usage string")
	}
}

func TestRootCmd_LogLevelInvalidErrors(t *testing.T) {
	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"--log-level", "trace", "peers"})
	if err := root.Execute(); err == nil {
		t.Fatal("expected error for invalid --log-level")
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
