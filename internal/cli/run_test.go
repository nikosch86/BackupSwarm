package cli

import (
	"bytes"
	"context"
	"errors"
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
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", t.TempDir(), "run", "--backup-dir", t.TempDir()})
	if err := root.Execute(); err == nil {
		t.Error("run accepted missing --listen")
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

// TestRunCmd_RefusesWhenLocalEmptyIndexPopulated asserts run wraps daemon.ErrRefuseStart for an empty local with a populated index.
func TestRunCmd_RefusesWhenLocalEmptyIndexPopulated(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()

	ix, err := index.Open(filepath.Join(dataDir, "index.db"))
	if err != nil {
		t.Fatalf("seed index open: %v", err)
	}
	if err := ix.Put(index.FileEntry{Path: "/irrelevant", Size: 1}); err != nil {
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
		t.Error("run accepted empty-local + populated-index without --restore/--purge")
	}
	if !errors.Is(err, daemon.ErrRefuseStart) {
		t.Errorf("err = %v, want wraps daemon.ErrRefuseStart", err)
	}
}
