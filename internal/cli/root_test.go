package cli

import (
	"bytes"
	"strings"
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
	root.SetArgs([]string{"init"})

	if err := root.Execute(); err != nil {
		t.Fatalf("executing 'init' failed: %v (stderr=%q)", err, stderr.String())
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
