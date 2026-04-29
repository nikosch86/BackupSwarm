package cli

import (
	"context"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/peers"
)

// TestRunCmd_AutoJoinFromEnvVar boots a founder, sets the joiner's
// BACKUPSWARM_INVITE_TOKEN env, runs the joiner via plain `run`, and
// asserts the introducer lands in peers.db without an explicit `join`.
func TestRunCmd_AutoJoinFromEnvVar(t *testing.T) {
	dataB := filepath.Join(t.TempDir(), "node-b")
	dataA := filepath.Join(t.TempDir(), "node-a")
	addrB := reserveLocalUDPAddr(t)

	overallCtx, cancelOverall := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelOverall()

	bCtx, cancelB := context.WithCancel(overallCtx)
	bDone := make(chan error, 1)
	bCmd := NewRootCmd()
	bOut := &syncBuffer{}
	bCmd.SetOut(bOut)
	bCmd.SetErr(io.Discard)
	bCmd.SetArgs([]string{
		"--data-dir", dataB,
		"run",
		"--listen", addrB,
		"--invite",
	})
	go func() { bDone <- bCmd.ExecuteContext(bCtx) }()
	tokStr := waitForToken(t, bOut, 10*time.Second)

	t.Setenv("BACKUPSWARM_INVITE_TOKEN", tokStr)

	addrA := reserveLocalUDPAddr(t)
	aCtx, cancelA := context.WithCancel(overallCtx)
	aDone := make(chan error, 1)
	aCmd := NewRootCmd()
	aOut := &syncBuffer{}
	aCmd.SetOut(aOut)
	aCmd.SetErr(io.Discard)
	aCmd.SetArgs([]string{
		"--data-dir", dataA,
		"run",
		"--listen", addrA,
	})
	go func() { aDone <- aCmd.ExecuteContext(aCtx) }()

	waitForPeerStorePopulated(t, filepath.Join(dataA, "peers.db"), 15*time.Second)

	cancelA()
	if err := awaitDone(aDone, 10*time.Second); err != nil {
		t.Fatalf("node A run: %v", err)
	}
	cancelB()
	if err := awaitDone(bDone, 10*time.Second); err != nil {
		t.Fatalf("node B run: %v", err)
	}
}

// TestRunCmd_AutoJoinSkippedWhenAlreadyJoined asserts the env-var path is
// idempotent: a second run with peers.db already populated does not error
// and does not double-join.
func TestRunCmd_AutoJoinSkippedWhenAlreadyJoined(t *testing.T) {
	dataB := filepath.Join(t.TempDir(), "node-b")
	dataA := filepath.Join(t.TempDir(), "node-a")
	addrB := reserveLocalUDPAddr(t)

	overallCtx, cancelOverall := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelOverall()

	bCtx, cancelB := context.WithCancel(overallCtx)
	bDone := make(chan error, 1)
	bCmd := NewRootCmd()
	bOut := &syncBuffer{}
	bCmd.SetOut(bOut)
	bCmd.SetErr(io.Discard)
	bCmd.SetArgs([]string{
		"--data-dir", dataB,
		"run",
		"--listen", addrB,
		"--invite",
	})
	go func() { bDone <- bCmd.ExecuteContext(bCtx) }()
	tokStr := waitForToken(t, bOut, 10*time.Second)
	defer func() {
		cancelB()
		_ = awaitDone(bDone, 10*time.Second)
	}()

	joinCmd := NewRootCmd()
	joinCmd.SetOut(io.Discard)
	joinCmd.SetErr(io.Discard)
	joinCmd.SetArgs([]string{"--data-dir", dataA, "join", tokStr})
	if err := joinCmd.ExecuteContext(overallCtx); err != nil {
		t.Fatalf("seed join: %v", err)
	}

	t.Setenv("BACKUPSWARM_INVITE_TOKEN", tokStr)

	addrA := reserveLocalUDPAddr(t)
	aCtx, cancelA := context.WithCancel(overallCtx)
	aDone := make(chan error, 1)
	aCmd := NewRootCmd()
	aOut := &syncBuffer{}
	aCmd.SetOut(aOut)
	aCmd.SetErr(io.Discard)
	aCmd.SetArgs([]string{
		"--data-dir", dataA,
		"run",
		"--listen", addrA,
	})
	go func() { aDone <- aCmd.ExecuteContext(aCtx) }()

	time.Sleep(500 * time.Millisecond)

	cancelA()
	if err := awaitDone(aDone, 10*time.Second); err != nil {
		t.Fatalf("node A second run: %v", err)
	}
}

// TestRunCmd_AutoJoinBadToken_FailsBeforeDaemon asserts that a malformed
// BACKUPSWARM_INVITE_TOKEN env var on a fresh data dir surfaces a token
// decode error from `run` instead of silently starting the daemon.
func TestRunCmd_AutoJoinBadToken_FailsBeforeDaemon(t *testing.T) {
	dataDir := t.TempDir()
	addr := reserveLocalUDPAddr(t)

	t.Setenv("BACKUPSWARM_INVITE_TOKEN", "not-a-real-token")

	cmd := NewRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--listen", addr,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		t.Fatal("run with bad token env returned nil error")
	}
	if !strings.Contains(err.Error(), "token") {
		t.Errorf("error did not mention 'token': %v", err)
	}
}

// waitForPeerStorePopulated polls peers.db (read-only) until at least one
// peer entry exists or the deadline expires.
func waitForPeerStorePopulated(t *testing.T, path string, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if hasPeer(path) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("peers.db at %q did not gain a peer entry within %s", path, deadline)
}

func hasPeer(path string) bool {
	store, err := peers.OpenReadOnly(path)
	if err != nil {
		return false
	}
	defer store.Close()
	list, err := store.List()
	if err != nil {
		return false
	}
	return len(list) > 0
}
