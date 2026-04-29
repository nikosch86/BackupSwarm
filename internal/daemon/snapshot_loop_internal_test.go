package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
)

// TestRunIndexBackupLoop_FirstTickFiresSync asserts the first tick of
// runIndexBackupLoop fires immediately, producing one upload per live conn.
func TestRunIndexBackupLoop_FirstTickFiresSync(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idx, recipient := newIndexLoopRig(t)
	connA := newDialConn(t)
	connB := newDialConn(t)
	conns := []*bsquic.Conn{connA, connB}

	var (
		mu      sync.Mutex
		uploads = make(map[string][]byte)
	)
	uploadFunc := func(_ context.Context, c *bsquic.Conn, blob []byte) error {
		mu.Lock()
		defer mu.Unlock()
		uploads[string(c.RemotePub())] = append([]byte(nil), blob...)
		return nil
	}

	prev := indexSnapshotUploadFunc
	indexSnapshotUploadFunc = uploadFunc
	t.Cleanup(func() { indexSnapshotUploadFunc = prev })

	done := make(chan struct{})
	go func() {
		defer close(done)
		runIndexBackupLoop(ctx, indexBackupLoopOptions{
			interval:     2 * time.Second,
			connsFn:      func() []*bsquic.Conn { return conns },
			indexFn:      func() *index.Index { return idx },
			recipientPub: recipient,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := len(uploads)
		mu.Unlock()
		if got == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	mu.Lock()
	defer mu.Unlock()
	if len(uploads) != 2 {
		t.Fatalf("uploads to %d peers, want 2", len(uploads))
	}
	for k, blob := range uploads {
		if len(blob) == 0 {
			t.Errorf("upload to %x produced empty blob", k)
		}
	}
}

// TestRunIndexBackupLoop_FailedUploadDoesNotAbortLoop asserts a single
// peer's upload error does not stop other peers' uploads.
func TestRunIndexBackupLoop_FailedUploadDoesNotAbortLoop(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idx, recipient := newIndexLoopRig(t)
	connA := newDialConn(t)
	connB := newDialConn(t)
	conns := []*bsquic.Conn{connA, connB}
	pubA := append([]byte(nil), connA.RemotePub()...)

	var pubBCount atomic.Int32
	uploadFunc := func(_ context.Context, c *bsquic.Conn, blob []byte) error {
		if string(c.RemotePub()) == string(pubA) {
			return errors.New("simulated upload error")
		}
		pubBCount.Add(1)
		return nil
	}

	prev := indexSnapshotUploadFunc
	indexSnapshotUploadFunc = uploadFunc
	t.Cleanup(func() { indexSnapshotUploadFunc = prev })

	done := make(chan struct{})
	go func() {
		defer close(done)
		runIndexBackupLoop(ctx, indexBackupLoopOptions{
			interval:     2 * time.Second,
			connsFn:      func() []*bsquic.Conn { return conns },
			indexFn:      func() *index.Index { return idx },
			recipientPub: recipient,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if pubBCount.Load() >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if pubBCount.Load() < 1 {
		t.Errorf("pubB never received upload despite pubA failing")
	}
}

// TestRunIndexBackupLoop_NoConnsNoUpload asserts the loop is a no-op
// when there are no live conns.
func TestRunIndexBackupLoop_NoConnsNoUpload(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idx, recipient := newIndexLoopRig(t)

	var calls atomic.Int32
	prev := indexSnapshotUploadFunc
	indexSnapshotUploadFunc = func(context.Context, *bsquic.Conn, []byte) error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() { indexSnapshotUploadFunc = prev })

	done := make(chan struct{})
	go func() {
		defer close(done)
		runIndexBackupLoop(ctx, indexBackupLoopOptions{
			interval:     200 * time.Millisecond,
			connsFn:      func() []*bsquic.Conn { return nil },
			indexFn:      func() *index.Index { return idx },
			recipientPub: recipient,
		})
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done

	if got := calls.Load(); got != 0 {
		t.Errorf("upload called %d times with no conns; want 0", got)
	}
}

// TestRunIndexBackupLoop_NilIndexExits asserts the loop returns
// immediately when no index is available (storage-only daemon).
func TestRunIndexBackupLoop_NilIndexExits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var calls atomic.Int32
	prev := indexSnapshotUploadFunc
	indexSnapshotUploadFunc = func(context.Context, *bsquic.Conn, []byte) error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() { indexSnapshotUploadFunc = prev })

	done := make(chan struct{})
	go func() {
		defer close(done)
		runIndexBackupLoop(ctx, indexBackupLoopOptions{
			interval:     200 * time.Millisecond,
			connsFn:      func() []*bsquic.Conn { return nil },
			indexFn:      func() *index.Index { return nil },
			recipientPub: nil,
		})
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("runIndexBackupLoop did not exit on nil index")
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("upload called %d times; want 0", got)
	}
}

// TestRunIndexBackupLoop_NilRecipientExits asserts the loop returns
// immediately when recipientPub is nil even with a non-nil index.
func TestRunIndexBackupLoop_NilRecipientExits(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idx, _ := newIndexLoopRig(t)
	var calls atomic.Int32
	prev := indexSnapshotUploadFunc
	indexSnapshotUploadFunc = func(context.Context, *bsquic.Conn, []byte) error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() { indexSnapshotUploadFunc = prev })

	done := make(chan struct{})
	go func() {
		defer close(done)
		runIndexBackupLoop(ctx, indexBackupLoopOptions{
			interval:     200 * time.Millisecond,
			connsFn:      func() []*bsquic.Conn { return nil },
			indexFn:      func() *index.Index { return idx },
			recipientPub: nil,
		})
	}()
	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("runIndexBackupLoop did not exit on nil recipient")
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("upload called %d times; want 0", got)
	}
}

// TestRunIndexBackupLoop_TickFiresAfterInterval asserts the ticker case
// fires at least once after the first sync tick.
func TestRunIndexBackupLoop_TickFiresAfterInterval(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	idx, recipient := newIndexLoopRig(t)
	conn := newDialConn(t)

	var calls atomic.Int32
	prev := indexSnapshotUploadFunc
	indexSnapshotUploadFunc = func(context.Context, *bsquic.Conn, []byte) error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() { indexSnapshotUploadFunc = prev })

	done := make(chan struct{})
	go func() {
		defer close(done)
		runIndexBackupLoop(ctx, indexBackupLoopOptions{
			interval:     50 * time.Millisecond,
			connsFn:      func() []*bsquic.Conn { return []*bsquic.Conn{conn} },
			indexFn:      func() *index.Index { return idx },
			recipientPub: recipient,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if got := calls.Load(); got < 2 {
		t.Errorf("calls = %d, want >= 2 (sync tick + at least one ticker tick)", got)
	}
}

// TestBroadcastIndexSnapshot_EncodingErrorAbortsTick asserts a list/encode
// failure aborts the tick before any upload runs.
func TestBroadcastIndexSnapshot_EncodingErrorAbortsTick(t *testing.T) {
	idx, recipient := newIndexLoopRig(t)
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	conn := newDialConn(t)
	var calls atomic.Int32
	prev := indexSnapshotUploadFunc
	indexSnapshotUploadFunc = func(context.Context, *bsquic.Conn, []byte) error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() { indexSnapshotUploadFunc = prev })

	broadcastIndexSnapshot(context.Background(), []*bsquic.Conn{conn}, idx, recipient)
	if got := calls.Load(); got != 0 {
		t.Errorf("upload called %d times despite encode failure; want 0", got)
	}
}

// TestBroadcastIndexSnapshot_NilConnSkipped asserts a nil conn entry is
// skipped without panicking and other entries still upload.
func TestBroadcastIndexSnapshot_NilConnSkipped(t *testing.T) {
	idx, recipient := newIndexLoopRig(t)
	conn := newDialConn(t)

	var calls atomic.Int32
	prev := indexSnapshotUploadFunc
	indexSnapshotUploadFunc = func(context.Context, *bsquic.Conn, []byte) error {
		calls.Add(1)
		return nil
	}
	t.Cleanup(func() { indexSnapshotUploadFunc = prev })

	broadcastIndexSnapshot(context.Background(), []*bsquic.Conn{nil, conn}, idx, recipient)
	if got := calls.Load(); got != 1 {
		t.Errorf("upload called %d times; want 1 (nil entry skipped)", got)
	}
}

// TestBuildIndexSnapshotBlob_ListErrorWrapped asserts an idx.List failure
// surfaces from buildIndexSnapshotBlob with a "list index" wrap.
func TestBuildIndexSnapshotBlob_ListErrorWrapped(t *testing.T) {
	idx, recipient := newIndexLoopRig(t)
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err := buildIndexSnapshotBlob(idx, recipient)
	if err == nil {
		t.Fatal("buildIndexSnapshotBlob succeeded on closed index")
	}
	if !contains(err.Error(), "list index") {
		t.Errorf("err = %v, want 'list index' wrap", err)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// newIndexLoopRig builds a populated index and a recipient pubkey used
// across the runIndexBackupLoop tests.
func newIndexLoopRig(t *testing.T) (*index.Index, *[crypto.RecipientKeySize]byte) {
	t.Helper()
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, "index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	if err := idx.Put(index.FileEntry{
		Path:    "demo.bin",
		Size:    1,
		ModTime: time.Now(),
	}); err != nil {
		t.Fatalf("index.Put: %v", err)
	}

	pub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	return idx, pub
}

// newDialConn brings up a fresh listener and dials it once, returning
// the dial-side conn. The conn's RemotePub is the listener's pubkey.
// Both sides are torn down on test cleanup.
func newDialConn(t *testing.T) *bsquic.Conn {
	t.Helper()
	_, listenPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("listen key: %v", err)
	}
	_, dialPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("dial key: %v", err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", listenPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), dialPriv, listenPriv.Public().(ed25519.PublicKey), nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
