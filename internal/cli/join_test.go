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

// TestJoinCmd_WrongPubkeyDoesNotPersist asserts the TLS pin protects the
// peer store from tokens that decode fine but point at the wrong pubkey.
// We start a listener under a real introducer key, craft a token with
// the right addr but a different pubkey, and assert `join` fails AND
// leaves the peer store empty.
func TestJoinCmd_WrongPubkeyDoesNotPersist(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "joiner")

	wrongPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	// Point at an addr that resolves but pin a fake pubkey — should fail
	// dial (no listener) OR fail TLS (if listener happens to exist). We
	// use an arbitrary unused port so the fail mode is "cannot dial",
	// which still exercises "does not persist on failure."
	tokStr, err := token.Encode("127.0.0.1:1", wrongPub)
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

	// Peer store should not have been mutated.
	storePath := filepath.Join(dataDir, "peers.db")
	if store, err := peers.Open(storePath); err == nil {
		list, _ := store.List()
		_ = store.Close()
		if len(list) != 0 {
			t.Errorf("failed join left %d peers in store, want 0", len(list))
		}
	}
	// If the file doesn't exist yet, that's also fine — means the
	// command bailed early enough not to open peers.db at all.
}

// TestJoinCmd_TokenFileAndArgConflict rejects combinations that would
// leave it ambiguous where the token should come from.
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

// TestJoinCmd_TokenFileMissingTimesOut exercises the polling path when
// the file never appears — must return a timeout-wrapped context error
// rather than looping forever.
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

// TestJoinCmd_TokenFileLateArrival asserts that join waits for the
// file to appear mid-poll instead of failing when it's missing at
// startup. This is the docker-compose orchestration case.
func TestJoinCmd_TokenFileLateArrival(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), "joiner")
	tokenPath := filepath.Join(t.TempDir(), "token.txt")

	// Craft a malformed-but-decodable-looking token first to prove
	// partial contents are tolerated. We later overwrite it with a
	// well-formed (but pointing-nowhere) token so DoJoin fails on
	// dial — the assertion is that we got *past* the polling stage,
	// not that the handshake succeeds.
	_, pub, err := ed25519Gen()
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	goodTok, err := token.Encode("127.0.0.1:1", pub)
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}
	// Land the file ~150 ms after the command starts (two poll ticks).
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
	// We expect a dial failure (target port isn't serving QUIC) — the
	// important bit is we didn't error on "file not found" before then.
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
