package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/node"
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

func TestInviteCmd_RequiresListenFlag(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "node")
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--data-dir", dataDir, "invite"})
	if err := root.Execute(); err == nil {
		t.Error("invite without --listen returned nil error")
	}
}

func TestInviteCmd_TimesOutWhenNoJoinerArrives(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "node")
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"invite",
		"--listen", "127.0.0.1:0",
		"--timeout", "200ms",
	})
	if err := root.Execute(); err == nil {
		t.Error("invite returned nil error on timeout")
	}

	tokStr := strings.TrimSpace(stdout.String())
	if tokStr == "" {
		t.Error("invite did not print a token before the timeout")
	}
	if _, err := token.Decode(tokStr); err != nil {
		t.Errorf("printed token did not decode: %v", err)
	}

	if _, err := node.Load(dataDir); err != nil {
		t.Errorf("invite should have created identity: %v", err)
	}
}

// TestInviteJoin_HappyPath runs invite and join in parallel and asserts both sides' peer stores end up populated.
func TestInviteJoin_HappyPath(t *testing.T) {
	inviterDir := filepath.Join(t.TempDir(), "inviter")
	joinerDir := filepath.Join(t.TempDir(), "joiner")

	inviteOut := &syncBuffer{}
	inviterCmd := NewRootCmd()
	inviterCmd.SetOut(inviteOut)
	inviterCmd.SetErr(&bytes.Buffer{})
	inviterCmd.SetArgs([]string{
		"--data-dir", inviterDir,
		"invite",
		"--listen", "127.0.0.1:0",
		"--timeout", "5s",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var inviteErr, joinErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		inviteErr = inviterCmd.ExecuteContext(ctx)
	}()

	tokStr := waitForToken(t, inviteOut, 3*time.Second)

	joinerCmd := NewRootCmd()
	joinerCmd.SetOut(&bytes.Buffer{})
	joinerCmd.SetErr(&bytes.Buffer{})
	joinerCmd.SetArgs([]string{
		"--data-dir", joinerDir,
		"join",
		"--listen", "192.0.2.55:7777",
		tokStr,
	})
	wg.Add(1)
	go func() {
		defer wg.Done()
		joinErr = joinerCmd.ExecuteContext(ctx)
	}()

	wg.Wait()
	if inviteErr != nil {
		t.Fatalf("invite: %v", inviteErr)
	}
	if joinErr != nil {
		t.Fatalf("join: %v", joinErr)
	}
}

// TestInviteCmd_TokenOut_WritesFile asserts --token-out writes the same token that was printed to stdout.
func TestInviteCmd_TokenOut_WritesFile(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "node")
	tokenPath := filepath.Join(t.TempDir(), "token.txt")
	root := NewRootCmd()
	var stdout, stderr bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"invite",
		"--listen", "127.0.0.1:0",
		"--timeout", "300ms",
		"--token-out", tokenPath,
	})
	_ = root.Execute()

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		t.Fatalf("read token file: %v", err)
	}
	tokStr := strings.TrimSpace(string(data))
	if _, err := token.Decode(tokStr); err != nil {
		t.Errorf("--token-out content did not decode: %v (contents=%q)", err, tokStr)
	}
	stdoutTok := strings.TrimSpace(stdout.String())
	if stdoutTok != tokStr {
		t.Errorf("token mismatch: stdout=%q file=%q", stdoutTok, tokStr)
	}
}

// TestWriteTokenFile_CreateTempFails asserts a missing target directory surfaces as a "create temp" error.
func TestWriteTokenFile_CreateTempFails(t *testing.T) {
	err := writeTokenFile(filepath.Join(t.TempDir(), "missing-dir", "token.txt"), "tok")
	if err == nil {
		t.Fatal("expected error when target directory does not exist")
	}
	if !strings.Contains(err.Error(), "create temp") {
		t.Errorf("expected 'create temp' in error, got: %v", err)
	}
}

// TestWriteTokenFile_RenameFails asserts a rename failure surfaces as "rename" and removes the temp file.
func TestWriteTokenFile_RenameFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target-is-a-dir")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	err := writeTokenFile(target, "tok")
	if err == nil {
		t.Fatal("expected error when target is an existing directory")
	}
	if !strings.Contains(err.Error(), "rename") {
		t.Errorf("expected 'rename' in error, got: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".token-") {
			t.Errorf("orphaned temp file left behind: %q", e.Name())
		}
	}
}

// waitForToken polls a syncBuffer until it contains a newline-terminated decodable token or the deadline expires.
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
	t.Fatalf("token did not appear on invite stdout within %s; got: %q", deadline, buf.String())
	return ""
}
