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

// TestOpenPeerSession_HappyPath asserts openPeerSession materialises identity, opens peers.db, and Close releases the lock.
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

	store, err := peers.Open(filepath.Join(dir, peers.DefaultFilename))
	if err != nil {
		t.Fatalf("peers.Open after session.Close: %v", err)
	}
	_ = store.Close()
}

// TestOpenPeerSession_PeersDirNotADir asserts a peers.Open failure surfaces as "open peer store".
func TestOpenPeerSession_PeersDirNotADir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
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

// TestWithTimeout_Disabled asserts withTimeout(0) returns the parent ctx and a no-op cancel.
func TestWithTimeout_Disabled(t *testing.T) {
	parent, parentCancel := context.WithCancel(context.Background())
	defer parentCancel()

	ctx, cancel := withTimeout(parent, 0)
	if ctx != parent {
		t.Error("withTimeout(0) returned a wrapped context; expected parent unchanged")
	}
	cancel()
	if err := parent.Err(); err != nil {
		t.Errorf("parent ctx err = %v, want nil after no-op cancel", err)
	}
}

// TestWithTimeout_Negative asserts withTimeout returns the parent ctx unchanged for negative durations.
func TestWithTimeout_Negative(t *testing.T) {
	parent := context.Background()
	ctx, cancel := withTimeout(parent, -1*time.Second)
	defer cancel()
	if ctx != parent {
		t.Error("withTimeout(-1s) returned a wrapped context; expected parent unchanged")
	}
}

// TestWithTimeout_Active asserts withTimeout returns a context whose deadline fires.
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
