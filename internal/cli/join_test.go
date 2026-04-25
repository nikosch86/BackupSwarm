package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/peers"
	"backupswarm/pkg/token"
)

func TestJoinCmd_RequiresTokenArg(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", t.TempDir(), "join"})
	if err := root.Execute(); err == nil {
		t.Error("join without a token arg returned nil error")
	}
}

func TestJoinCmd_RejectsMalformedToken(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", t.TempDir(), "join", "not-a-valid-token"})
	if err := root.Execute(); err == nil {
		t.Error("join accepted a malformed token")
	}
}

// TestJoinCmd_WrongPubkeyDoesNotPersist asserts a token with a wrong pubkey makes join fail and leaves the peer store empty.
func TestJoinCmd_WrongPubkeyDoesNotPersist(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "joiner")

	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tokStr, err := token.Encode(token.Token{Addr: "127.0.0.1:1", Pub: wrongPub})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"join",
		"--timeout", "500ms",
		tokStr,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := root.ExecuteContext(ctx); err == nil {
		t.Error("join succeeded against a dead address")
	}

	storePath := filepath.Join(dataDir, "peers.db")
	if store, err := peers.Open(storePath); err == nil {
		list, _ := store.List()
		_ = store.Close()
		if len(list) != 0 {
			t.Errorf("failed join left %d peers in store, want 0", len(list))
		}
	}
}

// TestJoinCmd_TokenFileAndArgConflict asserts join rejects combining --token-file with a positional token.
func TestJoinCmd_TokenFileAndArgConflict(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"join",
		"--token-file", filepath.Join(t.TempDir(), "tok"),
		"some-token-positional",
	})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected error when --token-file and positional <token> are both set")
	}
	if !strings.Contains(err.Error(), "--token-file cannot be combined") {
		t.Errorf("unexpected error text: %v", err)
	}
}

// TestJoinCmd_TokenFileMissingTimesOut asserts a never-appearing token file surfaces as a DeadlineExceeded error.
func TestJoinCmd_TokenFileMissingTimesOut(t *testing.T) {
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"join",
		"--token-file", filepath.Join(t.TempDir(), "never-appears"),
		"--timeout", "300ms",
	})
	err := root.Execute()
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("expected DeadlineExceeded in error chain, got: %v", err)
	}
}

// TestJoinCmd_TokenFileLateArrival asserts join waits for a late-arriving token file before erroring on dial.
func TestJoinCmd_TokenFileLateArrival(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "joiner")
	tokenPath := filepath.Join(t.TempDir(), "token.txt")

	_, pub, err := ed25519Gen()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	goodTok, err := token.Encode(token.Token{Addr: "127.0.0.1:1", Pub: pub})
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}
	go func() {
		time.Sleep(150 * time.Millisecond)
		_ = os.WriteFile(tokenPath, []byte(goodTok+"\n"), 0o600)
	}()

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{
		"--data-dir", dataDir,
		"join",
		"--token-file", tokenPath,
		"--timeout", "2s",
	})
	err = root.Execute()
	if err == nil {
		t.Fatal("expected join to fail on dial after successfully reading the late-arriving token file")
	}
	if !strings.Contains(err.Error(), "join:") {
		t.Errorf("expected dial-phase error, got: %v", err)
	}
}

func ed25519Gen() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}
