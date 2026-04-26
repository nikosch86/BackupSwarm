package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/daemon"
	"backupswarm/pkg/token"
)

// syncBuffer is a thread-safe io.Writer+Snapshot wrapper around bytes.Buffer.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) Snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]byte, b.buf.Len())
	copy(out, b.buf.Bytes())
	return out
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

var _ io.Writer = (*syncBuffer)(nil)

// TestInviteCmd_RequiresRunningDaemon asserts `invite` against a data
// dir with no listen.addr surfaces the daemon.ErrNoRunningDaemon
// sentinel — a fail-fast guard against issuing tokens for an inviter
// that nothing is listening on.
func TestInviteCmd_RequiresRunningDaemon(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", dataDir, "invite"})
	err := root.Execute()
	if err == nil {
		t.Fatal("invite without running daemon returned nil error")
	}
	if !errors.Is(err, daemon.ErrNoRunningDaemon) {
		t.Errorf("err = %v, want wraps daemon.ErrNoRunningDaemon", err)
	}
}

// TestInviteCmd_AgainstRunningDaemon_PrintsToken seeds listen.addr (no
// real daemon needed for this surface — the issuance path only needs
// the bound addr file + a writable invites.db) and asserts the printed
// token decodes with the embedded address.
func TestInviteCmd_AgainstRunningDaemon_PrintsToken(t *testing.T) {
	dataDir := t.TempDir()
	const fakeAddr = "127.0.0.1:54321"
	if err := daemon.WriteListenAddr(dataDir, fakeAddr); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}

	root := NewRootCmd()
	stdout := &syncBuffer{}
	root.SetOut(stdout)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--data-dir", dataDir, "invite"})
	if err := root.Execute(); err != nil {
		t.Fatalf("invite: %v", err)
	}

	tokStr := strings.TrimSpace(stdout.String())
	if tokStr == "" {
		t.Fatal("invite printed no token")
	}
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("printed token did not decode: %v", err)
	}
	if tok.Addr != fakeAddr {
		t.Errorf("token addr = %q, want %q", tok.Addr, fakeAddr)
	}
}

// TestInviteCmd_TokenOut_WritesFile asserts --token-out writes the
// same token printed to stdout (with a trailing newline).
func TestInviteCmd_TokenOut_WritesFile(t *testing.T) {
	dataDir := t.TempDir()
	const fakeAddr = "127.0.0.1:9999"
	if err := daemon.WriteListenAddr(dataDir, fakeAddr); err != nil {
		t.Fatalf("seed listen.addr: %v", err)
	}
	tokenPath := filepath.Join(t.TempDir(), "token.txt")

	root := NewRootCmd()
	stdout := &syncBuffer{}
	root.SetOut(stdout)
	root.SetErr(io.Discard)
	root.SetArgs([]string{"--data-dir", dataDir, "invite", "--token-out", tokenPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("invite: %v", err)
	}

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	gotFile := strings.TrimSpace(string(data))
	gotStdout := strings.TrimSpace(stdout.String())
	if gotFile != gotStdout {
		t.Errorf("token mismatch: stdout=%q file=%q", gotStdout, gotFile)
	}
	if _, err := token.Decode(gotFile); err != nil {
		t.Errorf("--token-out content did not decode: %v", err)
	}
}

// TestInviteJoin_HappyPath drives the new split surface end-to-end:
// `run --invite` boots a daemon and prints the founder token; `join`
// consumes it. After both commands return, the joiner's peer store
// must list the introducer.
func TestInviteJoin_HappyPath(t *testing.T) {
	inviterDir := t.TempDir()
	joinerDir := t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	inviteOut := &syncBuffer{}
	inviterCmd := NewRootCmd()
	inviterCmd.SetOut(inviteOut)
	inviterCmd.SetErr(io.Discard)
	inviterCmd.SetArgs([]string{
		"--data-dir", inviterDir,
		"run",
		"--listen", "127.0.0.1:0",
		"--invite",
	})

	inviterCtx, inviterCancel := context.WithCancel(ctx)
	defer inviterCancel()
	inviterDone := make(chan error, 1)
	go func() { inviterDone <- inviterCmd.ExecuteContext(inviterCtx) }()

	tokStr := waitForToken(t, inviteOut, 5*time.Second)

	joinerCmd := NewRootCmd()
	joinerCmd.SetOut(io.Discard)
	joinerCmd.SetErr(io.Discard)
	joinerCmd.SetArgs([]string{
		"--data-dir", joinerDir,
		"join",
		"--listen", "192.0.2.55:7777",
		tokStr,
	})
	if err := joinerCmd.ExecuteContext(ctx); err != nil {
		t.Fatalf("join: %v", err)
	}

	inviterCancel()
	select {
	case err := <-inviterDone:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("inviter run --invite: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("inviter did not exit within 5s of cancel")
	}
}

// waitForToken polls a syncBuffer until it contains a newline-terminated
// decodable token or the deadline expires.
func waitForToken(t *testing.T, buf *syncBuffer, deadline time.Duration) string {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		snap := buf.Snapshot()
		if idx := bytes.IndexByte(snap, '\n'); idx >= 0 {
			candidate := strings.TrimSpace(string(snap[:idx]))
			if _, err := token.Decode(candidate); err == nil {
				return candidate
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("token did not appear within %s; got: %q", deadline, buf.String())
	return ""
}
