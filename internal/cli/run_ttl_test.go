package cli

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func findRunCmd(t *testing.T) *cobra.Command {
	t.Helper()
	root := NewRootCmd()
	for _, c := range root.Commands() {
		if c.Name() == "run" {
			return c
		}
	}
	t.Fatal("run subcommand missing")
	return nil
}

func TestRunCmd_RegistersChunkTTLFlag(t *testing.T) {
	run := findRunCmd(t)
	f := run.Flags().Lookup("chunk-ttl")
	if f == nil {
		t.Fatal("run is missing --chunk-ttl flag")
	}
	if f.DefValue != "720h0m0s" {
		t.Errorf("--chunk-ttl default = %q, want 720h0m0s", f.DefValue)
	}
}

func TestRunCmd_RegistersChunkRenewIntervalFlag(t *testing.T) {
	run := findRunCmd(t)
	f := run.Flags().Lookup("chunk-renew-interval")
	if f == nil {
		t.Fatal("run is missing --chunk-renew-interval flag")
	}
	if f.DefValue != "144h0m0s" {
		t.Errorf("--chunk-renew-interval default = %q, want 144h0m0s", f.DefValue)
	}
}

func TestRunCmd_RegistersChunkExpireIntervalFlag(t *testing.T) {
	run := findRunCmd(t)
	f := run.Flags().Lookup("chunk-expire-interval")
	if f == nil {
		t.Fatal("run is missing --chunk-expire-interval flag")
	}
	if f.DefValue != "1h0m0s" {
		t.Errorf("--chunk-expire-interval default = %q, want 1h0m0s", f.DefValue)
	}
}

func TestRunCmd_RejectsNegativeChunkTTL(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--chunk-ttl", "-1h",
	})
	if err := root.Execute(); err == nil {
		t.Error("run accepted --chunk-ttl -1h")
	}
}

func TestRunCmd_RejectsNegativeChunkRenewInterval(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--chunk-renew-interval", "-5m",
	})
	if err := root.Execute(); err == nil {
		t.Error("run accepted --chunk-renew-interval -5m")
	}
}

func TestRunCmd_AcceptsCustomChunkTTL(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--chunk-ttl", "1h",
		"--chunk-renew-interval", "5m",
		"--chunk-expire-interval", "10m",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with custom chunk TTL flags returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}
