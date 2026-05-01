package cli

import (
	"context"
	"io"
	"log/slog"
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

	logBuf := &syncBuffer{}
	captureSlog(t, logBuf)

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

	waitForLog(t, logBuf, "auto-joined peer", 15*time.Second)

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

// TestRunCmd_AutoJoin_AdvertiseAddrSentToFounder asserts the joiner sends
// its --advertise-addr (not the 0.0.0.0:<port> bind address) when --listen
// is omitted, so the founder's peers.db records a routable peer address.
func TestRunCmd_AutoJoin_AdvertiseAddrSentToFounder(t *testing.T) {
	dataB := filepath.Join(t.TempDir(), "node-b")
	dataA := filepath.Join(t.TempDir(), "node-a")
	addrB := reserveLocalUDPAddr(t)
	joinerAdvertise := reserveLocalUDPAddr(t)

	logBuf := &syncBuffer{}
	captureSlog(t, logBuf)

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

	aCtx, cancelA := context.WithCancel(overallCtx)
	aDone := make(chan error, 1)
	aCmd := NewRootCmd()
	aOut := &syncBuffer{}
	aCmd.SetOut(aOut)
	aCmd.SetErr(io.Discard)
	aCmd.SetArgs([]string{
		"--data-dir", dataA,
		"run",
		"--advertise-addr", joinerAdvertise,
	})
	go func() { aDone <- aCmd.ExecuteContext(aCtx) }()

	waitForLog(t, logBuf, "auto-joined peer", 15*time.Second)
	waitForLog(t, logBuf, "peer joined", 5*time.Second)

	cancelA()
	if err := awaitDone(aDone, 10*time.Second); err != nil {
		t.Fatalf("node A run: %v", err)
	}
	cancelB()
	if err := awaitDone(bDone, 10*time.Second); err != nil {
		t.Fatalf("node B run: %v", err)
	}

	bStore, err := peers.OpenReadOnly(filepath.Join(dataB, peers.DefaultFilename))
	if err != nil {
		t.Fatalf("open founder peers.db: %v", err)
	}
	defer func() { _ = bStore.Close() }()
	list, err := bStore.List()
	if err != nil {
		t.Fatalf("list founder peers: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("founder peers.db: want exactly 1 peer (the joiner), got %d: %v", len(list), list)
	}
	got := list[0].Addr
	if strings.HasPrefix(got, "0.0.0.0:") {
		t.Errorf("founder peers.db recorded bind addr %q; want advertise addr %q", got, joinerAdvertise)
	}
	if got != joinerAdvertise {
		t.Errorf("founder peers.db Addr = %q, want %q", got, joinerAdvertise)
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

// captureSlog redirects the default slog logger to w for the lifetime
// of the test, restoring the previous default via t.Cleanup.
func captureSlog(t *testing.T, w io.Writer) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// waitForLog polls buf until it contains needle or deadline expires.
func waitForLog(t *testing.T, buf *syncBuffer, needle string, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if strings.Contains(buf.String(), needle) {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("log did not contain %q within %s\nbuffer:\n%s", needle, deadline, buf.String())
}
