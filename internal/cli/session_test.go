package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/peers"
)

// TestOpenPeerSession_HappyPath asserts the helper materialises a node
// identity, opens peers.db inside the resolved data dir, and returns a
// session whose Close releases the bbolt file lock so a second Open
// succeeds.
func TestOpenPeerSession_HappyPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")

	sess, err := openPeerSession(dir)
	if err != nil {
		t.Fatalf("openPeerSession: %v", err)
	}
	if sess.dir != dir {
		t.Errorf("sess.dir = %q, want %q", sess.dir, dir)
	}
	if sess.id == nil || sess.id.PrivateKey == nil {
		t.Error("session identity missing private key")
	}
	if sess.peerStore == nil {
		t.Fatal("session peer store is nil")
	}
	if err := sess.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	// Re-opening peers.db after Close must succeed — proves the bbolt
	// lock was actually released. Smoke-tests the defer discipline that
	// makes the helper safe to use behind cobra's RunE.
	store, err := peers.Open(filepath.Join(dir, peers.DefaultFilename))
	if err != nil {
		t.Fatalf("peers.Open after session.Close: %v", err)
	}
	_ = store.Close()
}

// TestOpenPeerSession_PeersDirNotADir exercises the peers.Open error
// wrap. We seed `peers.db` as a directory (not a regular file) so bbolt
// fails with a non-nil error; the helper must wrap it as
// "open peer store: ...".
func TestOpenPeerSession_PeersDirNotADir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
	// Make the data dir and pre-create peers.db as a directory, so bbolt
	// cannot open it as a database file.
	if err := os.MkdirAll(filepath.Join(dir, peers.DefaultFilename), 0o700); err != nil {
		t.Fatalf("seed peers.db as dir: %v", err)
	}

	_, err := openPeerSession(dir)
	if err == nil {
		t.Fatal("openPeerSession accepted peers.db as a directory")
	}
	if !strings.Contains(err.Error(), "open peer store") {
		t.Errorf("err = %q, want 'open peer store' wrap", err)
	}
}

// TestWithTimeout_Disabled covers the d <= 0 branch: the helper must
// return the original ctx and a no-op cancel. invite/join expose
// `--timeout 0` as "no timeout", so this path is reachable from the CLI.
func TestWithTimeout_Disabled(t *testing.T) {
	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()

	ctx, cancel := withTimeout(parent, 0)
	if ctx != parent {
		t.Error("withTimeout(0) returned a wrapped context; expected parent unchanged")
	}
	// cancel must be safe to call and a no-op (does not cancel parent).
	cancel()
	if err := parent.Err(); err != nil {
		t.Errorf("parent ctx err = %v, want nil after no-op cancel", err)
	}
}

// TestWithTimeout_Negative pins the boundary at d == 0 by also covering
// negative durations, which a malformed flag could produce. Should
// behave identically to d == 0 (no wrapping, no cancel).
func TestWithTimeout_Negative(t *testing.T) {
	parent := context.Background()
	ctx, cancel := withTimeout(parent, -1*time.Second)
	defer cancel()
	if ctx != parent {
		t.Error("withTimeout(-1s) returned a wrapped context; expected parent unchanged")
	}
}

// TestWithTimeout_Active covers the d > 0 branch: the returned context
// must inherit a deadline that fires before the test deadline.
func TestWithTimeout_Active(t *testing.T) {
	ctx, cancel := withTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()

	select {
	case <-ctx.Done():
		if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			t.Errorf("ctx.Err() = %v, want DeadlineExceeded", ctx.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("withTimeout(25ms) ctx did not fire within 2s")
	}
}
