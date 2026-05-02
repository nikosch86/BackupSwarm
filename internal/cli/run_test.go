package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/daemon"
	"backupswarm/internal/index"
)

func TestRunCmd_RegisteredOnRoot(t *testing.T) {
	root := NewRootCmd()
	var found bool
	for _, c := range root.Commands() {
		if c.Name() == "run" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("root command missing `run` subcommand")
	}
}

// TestRunCmd_AcceptsMissingBackupDir asserts run starts and exits cleanly when --backup-dir is omitted.
func TestRunCmd_AcceptsMissingBackupDir(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", t.TempDir(), "run", "--listen", "127.0.0.1:0"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run without --backup-dir returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

func TestRunCmd_RequiresListen(t *testing.T) {
	t.Setenv("BACKUPSWARM_LISTEN", "")
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", t.TempDir(), "run", "--backup-dir", t.TempDir()})
	if err := root.Execute(); err == nil {
		t.Error("run accepted missing --listen")
	}
}

// TestRunCmd_AcceptsListenFromEnv asserts BACKUPSWARM_LISTEN supplies the
// listen address when --listen is omitted.
func TestRunCmd_AcceptsListenFromEnv(t *testing.T) {
	t.Setenv("BACKUPSWARM_LISTEN", "127.0.0.1:0")

	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", t.TempDir(), "run", "--backup-dir", t.TempDir()})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with BACKUPSWARM_LISTEN env returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_ListenFlagOverridesEnv asserts an explicit --listen wins over
// BACKUPSWARM_LISTEN.
func TestRunCmd_ListenFlagOverridesEnv(t *testing.T) {
	t.Setenv("BACKUPSWARM_LISTEN", "999.999.999.999:7777")

	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--backup-dir", t.TempDir(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with --listen + invalid env returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_NoPeerFlag asserts the run subcommand does not expose --peer or --peer-pubkey flags.
func TestRunCmd_NoPeerFlag(t *testing.T) {
	root := NewRootCmd()
	var run *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "run" {
			run = c
			break
		}
	}
	if run == nil {
		t.Fatal("run subcommand missing")
	}
	if f := run.Flags().Lookup("peer"); f != nil {
		t.Error("run has --peer flag; should read from peers.db instead")
	}
	if f := run.Flags().Lookup("peer-pubkey"); f != nil {
		t.Error("run has --peer-pubkey flag; should read from peers.db instead")
	}
}

// TestRunCmd_IdleStorageOnly_ExitsOnCancel asserts run exits cleanly when cancelled while idle as a storage-only peer.
func TestRunCmd_IdleStorageOnly_ExitsOnCancel(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()

	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--backup-dir", backupDir,
		"--listen", "127.0.0.1:0",
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_RegistersMaxStorageFlag asserts the --max-storage flag is
// exposed on the run subcommand so users can cap the local store.
func TestRunCmd_RegistersMaxStorageFlag(t *testing.T) {
	root := NewRootCmd()
	var run *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "run" {
			run = c
			break
		}
	}
	if run == nil {
		t.Fatal("run subcommand missing")
	}
	if f := run.Flags().Lookup("max-storage"); f == nil {
		t.Fatal("run is missing --max-storage flag")
	}
}

// TestRunCmd_RejectsInvalidMaxStorage asserts a malformed --max-storage
// value surfaces as a flag error before the daemon even starts.
func TestRunCmd_RejectsInvalidMaxStorage(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--max-storage", "garbage",
	})
	if err := root.Execute(); err == nil {
		t.Error("run accepted invalid --max-storage")
	}
}

// TestRunCmd_AcceptsHumanMaxStorage asserts a valid --max-storage value
// (e.g. "1m") parses and the daemon starts cleanly.
func TestRunCmd_AcceptsHumanMaxStorage(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--max-storage", "1m",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with --max-storage 1m returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_AcceptsMaxStorageZero: --max-storage 0 passes flag validation.
func TestRunCmd_AcceptsMaxStorageZero(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--max-storage", "0",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with --max-storage 0 returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_AcceptsMaxStorageUnlimited: explicit "unlimited" literal is accepted.
func TestRunCmd_AcceptsMaxStorageUnlimited(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--max-storage", "unlimited",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with --max-storage unlimited returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_RegistersRedundancyFlag asserts the --redundancy flag is
// exposed on the run subcommand so users can configure per-chunk peer count.
func TestRunCmd_RegistersRedundancyFlag(t *testing.T) {
	root := NewRootCmd()
	var run *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "run" {
			run = c
			break
		}
	}
	if run == nil {
		t.Fatal("run subcommand missing")
	}
	if f := run.Flags().Lookup("redundancy"); f == nil {
		t.Fatal("run is missing --redundancy flag")
	}
}

// TestRunCmd_RejectsZeroRedundancy asserts --redundancy 0 fails fast.
func TestRunCmd_RejectsZeroRedundancy(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--redundancy", "0",
	})
	if err := root.Execute(); err == nil {
		t.Error("run accepted --redundancy 0")
	}
}

// TestRunCmd_RejectsNegativeRedundancy asserts --redundancy -1 fails fast.
func TestRunCmd_RejectsNegativeRedundancy(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--redundancy", "-1",
	})
	if err := root.Execute(); err == nil {
		t.Error("run accepted --redundancy -1")
	}
}

// TestRunCmd_AcceptsRedundancy asserts a valid --redundancy value parses
// and the daemon starts cleanly.
func TestRunCmd_AcceptsRedundancy(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--redundancy", "3",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with --redundancy 3 returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_RegistersHeartbeatFlags asserts --heartbeat-interval and
// --heartbeat-misses are exposed on the run subcommand.
func TestRunCmd_RegistersHeartbeatFlags(t *testing.T) {
	root := NewRootCmd()
	var run *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "run" {
			run = c
			break
		}
	}
	if run == nil {
		t.Fatal("run subcommand missing")
	}
	if f := run.Flags().Lookup("heartbeat-interval"); f == nil {
		t.Error("run is missing --heartbeat-interval flag")
	}
	if f := run.Flags().Lookup("heartbeat-misses"); f == nil {
		t.Error("run is missing --heartbeat-misses flag")
	}
}

// TestRunCmd_RejectsZeroHeartbeatMisses asserts --heartbeat-misses 0 fails fast.
func TestRunCmd_RejectsZeroHeartbeatMisses(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--heartbeat-misses", "0",
	})
	if err := root.Execute(); err == nil {
		t.Error("run accepted --heartbeat-misses 0")
	}
}

// TestRunCmd_RegistersGracePeriodFlag asserts --grace-period is exposed
// on the run subcommand.
func TestRunCmd_RegistersGracePeriodFlag(t *testing.T) {
	root := NewRootCmd()
	var run *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "run" {
			run = c
			break
		}
	}
	if run == nil {
		t.Fatal("run subcommand missing")
	}
	f := run.Flags().Lookup("grace-period")
	if f == nil {
		t.Fatal("run is missing --grace-period flag")
	}
	if f.DefValue != "24h0m0s" {
		t.Errorf("--grace-period default = %q, want 24h0m0s", f.DefValue)
	}
}

// TestRunCmd_RejectsNegativeGracePeriod asserts --grace-period -1m fails fast.
func TestRunCmd_RejectsNegativeGracePeriod(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--grace-period", "-1m",
	})
	if err := root.Execute(); err == nil {
		t.Error("run accepted --grace-period -1m")
	}
}

// TestRunCmd_AcceptsZeroGracePeriod asserts --grace-period 0 (lost-immediately) is allowed.
func TestRunCmd_AcceptsZeroGracePeriod(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--grace-period", "0",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with --grace-period 0 returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_RegistersScrubIntervalFlag asserts --scrub-interval is
// exposed on the run subcommand with a 6h default.
func TestRunCmd_RegistersScrubIntervalFlag(t *testing.T) {
	root := NewRootCmd()
	var run *cobra.Command
	for _, c := range root.Commands() {
		if c.Name() == "run" {
			run = c
			break
		}
	}
	if run == nil {
		t.Fatal("run subcommand missing")
	}
	f := run.Flags().Lookup("scrub-interval")
	if f == nil {
		t.Fatal("run is missing --scrub-interval flag")
	}
	if f.DefValue != "6h0m0s" {
		t.Errorf("--scrub-interval default = %q, want 6h0m0s", f.DefValue)
	}
}

// TestRunCmd_AcceptsScrubInterval asserts a custom --scrub-interval value
// parses and the daemon starts cleanly.
func TestRunCmd_AcceptsScrubInterval(t *testing.T) {
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--scrub-interval", "2h",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(100*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with --scrub-interval 2h returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}

// TestRunCmd_RefusesWhenIndexedFilesMissing asserts run wraps daemon.ErrRefuseStart when indexed files are absent on disk and no flag has been provided.
func TestRunCmd_RefusesWhenIndexedFilesMissing(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()

	ix, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("seed index open: %v", err)
	}
	if err := ix.Put(index.FileEntry{Path: "gone.bin", Size: 1}); err != nil {
		t.Fatalf("seed index put: %v", err)
	}
	if err := ix.Close(); err != nil {
		t.Fatalf("seed index close: %v", err)
	}

	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--backup-dir", backupDir,
		"--listen", "127.0.0.1:0",
	})
	err = root.Execute()
	if err == nil {
		t.Error("run accepted indexed-but-missing file without --restore/--purge/--acknowledge-deletes")
	}
	if !errors.Is(err, daemon.ErrRefuseStart) {
		t.Errorf("err = %v, want wraps daemon.ErrRefuseStart", err)
	}
}

// TestRunCmd_AcknowledgeDeletesBypassesGate asserts --acknowledge-deletes lets the daemon proceed past the gate (it then enters the scan loop, which we cancel).
func TestRunCmd_AcknowledgeDeletesBypassesGate(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(backupDir, "still-here.txt"), []byte("x"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	ix, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("seed index open: %v", err)
	}
	if err := ix.Put(index.FileEntry{Path: "gone.bin", Size: 1}); err != nil {
		t.Fatalf("seed index put: %v", err)
	}
	if err := ix.Close(); err != nil {
		t.Fatalf("seed index close: %v", err)
	}

	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--backup-dir", backupDir,
		"--listen", "127.0.0.1:0",
		"--acknowledge-deletes",
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- root.ExecuteContext(ctx) }()
	time.AfterFunc(200*time.Millisecond, cancel)

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("run with --acknowledge-deletes returned err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("run did not exit within 5s of cancel")
	}
}
