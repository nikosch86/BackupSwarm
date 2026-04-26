package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"backupswarm/internal/invites"
	"backupswarm/internal/peers"
)

// captureSlog redirects the default logger to buf for the duration of
// the test. Returns the original logger via t.Cleanup.
func captureSlog(t *testing.T, w *syncWriter) {
	t.Helper()
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
}

// syncWriter is a thread-safe io.Writer for slog test capture.
type syncWriter struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *syncWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

// TestRefreshPendingInvites_OpenFails leaves the cache untouched and
// logs a warning when invites.Open errors.
func TestRefreshPendingInvites_OpenFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	w := &syncWriter{}
	captureSlog(t, w)

	pc := &pendingCache{}
	pc.n.Store(7)
	refreshPendingInvites(context.Background(), dir, pc)
	if got := pc.n.Load(); got != 7 {
		t.Errorf("cache mutated to %d on open failure; want previous value 7", got)
	}
	if !strings.Contains(w.String(), "open invites.db") {
		t.Errorf("log = %q, want 'open invites.db' substring", w.String())
	}
}

// TestRefreshPendingInvites_CountFails seeds a corrupt record so
// PendingCount errors; the cache must keep its previous value.
func TestRefreshPendingInvites_CountFails(t *testing.T) {
	dir := t.TempDir()
	store, err := invites.Open(filepath.Join(dir, invites.DefaultFilename))
	if err != nil {
		t.Fatalf("invites.Open seed: %v", err)
	}
	if err := store.PutRawForTest([32]byte{1, 2, 3}, []byte{0xFF, 0x00}); err != nil {
		t.Fatalf("PutRawForTest: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	w := &syncWriter{}
	captureSlog(t, w)
	pc := &pendingCache{}
	pc.n.Store(5)
	refreshPendingInvites(context.Background(), dir, pc)
	if got := pc.n.Load(); got != 5 {
		t.Errorf("cache mutated to %d on count failure; want previous value 5", got)
	}
	if !strings.Contains(w.String(), "count pending invites") {
		t.Errorf("log = %q, want 'count pending invites' substring", w.String())
	}
}

// TestMakeVerifyPeer_PeerStoreErrorWraps closes the peer store so Get
// errors with a reason other than ErrPeerNotFound; the predicate must
// surface it as a wrapped lookup error.
func TestMakeVerifyPeer_PeerStoreErrorWraps(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "broken-peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	pc := &pendingCache{}
	verify := makeVerifyPeer(ps, pc)
	err = verify(pub)
	if err == nil {
		t.Fatal("verify against closed peer store returned nil error")
	}
	if errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("err = %v, must not be ErrPeerNotFound for non-NotFound failures", err)
	}
	if !strings.Contains(err.Error(), "lookup peer") {
		t.Errorf("err = %q, want 'lookup peer' wrap", err)
	}
}
