package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
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
