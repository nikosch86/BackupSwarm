package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
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

func TestNewRootCmd_HasInitSubcommand(t *testing.T) {
	root := NewRootCmd()

	var found bool
	for _, sub := range root.Commands() {
		if sub.Name() == "init" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected root command to have an 'init' subcommand")
	}
}

func TestInitCmd_RunsSuccessfully(t *testing.T) {
	root := NewRootCmd()

	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", t.TempDir(), "init"})

	if err := root.Execute(); err != nil {
		t.Fatalf("executing 'init' failed: %v (stderr=%q)", err, stderr.String())
	}
}

// TestInitCmd_HasRunE pins the invariant that 'init' is actually wired to a
// handler. Without this, a future refactor that drops RunE would still let
// TestInitCmd_RunsSuccessfully pass (cobra treats no-op commands as success).
func TestInitCmd_HasRunE(t *testing.T) {
	root := NewRootCmd()

	var initCmd *cobra.Command
	for _, sub := range root.Commands() {
		if sub.Name() == "init" {
			initCmd = sub
			break
		}
	}
	if initCmd == nil {
		t.Fatal("init subcommand not found")
	}
	if initCmd.RunE == nil && initCmd.Run == nil {
		t.Error("init subcommand has neither RunE nor Run handler")
	}
	if initCmd.Short == "" {
		t.Error("init subcommand is missing Short description")
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

func TestRootCmd_HelpListsInit(t *testing.T) {
	root := NewRootCmd()

	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stdout)
	root.SetArgs([]string{"--help"})

	if err := root.Execute(); err != nil {
		t.Fatalf("executing --help failed: %v", err)
	}
	if !strings.Contains(stdout.String(), "init") {
		t.Errorf("help output does not mention 'init' subcommand:\n%s", stdout.String())
	}
}
