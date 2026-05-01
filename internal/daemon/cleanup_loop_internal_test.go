package daemon

import (
	"bytes"
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/index"
	"backupswarm/internal/swarm"
)

func TestRunCleanupLoop_ConsumesEvents(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ch := make(chan []byte, 4)

	var got [][]byte
	var mu sync.Mutex
	cleanFn := func(_ context.Context, pub []byte) {
		mu.Lock()
		defer mu.Unlock()
		got = append(got, append([]byte(nil), pub...))
	}

	done := make(chan struct{})
	go func() {
		runCleanupLoop(ctx, cleanupLoopOptions{ch: ch, cleanFn: cleanFn})
		close(done)
	}()

	ch <- []byte("peer-A")
	ch <- []byte("peer-B")

	deadline := time.After(2 * time.Second)
	for {
		mu.Lock()
		n := len(got)
		mu.Unlock()
		if n == 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for events; got %d", n)
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	<-done

	if !bytes.Equal(got[0], []byte("peer-A")) || !bytes.Equal(got[1], []byte("peer-B")) {
		t.Errorf("got = %v, want [peer-A, peer-B]", got)
	}
}

func TestRunCleanupLoop_ExitsOnContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan []byte)

	done := make(chan struct{})
	go func() {
		runCleanupLoop(ctx, cleanupLoopOptions{
			ch:      ch,
			cleanFn: func(context.Context, []byte) { t.Error("cleanFn called on empty input") },
		})
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCleanupLoop did not exit within 2s of cancel")
	}
}

func TestRunCleanupLoop_ExitsOnChannelClose(t *testing.T) {
	ch := make(chan []byte)
	done := make(chan struct{})
	go func() {
		runCleanupLoop(context.Background(), cleanupLoopOptions{
			ch:      ch,
			cleanFn: func(context.Context, []byte) {},
		})
		close(done)
	}()
	close(ch)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runCleanupLoop did not exit on channel close")
	}
}

func TestMakeRecoverDispatcher_PushesToChannel(t *testing.T) {
	ch := make(chan []byte, 1)
	dispatch := makeRecoverDispatcher(ch)
	dispatch([]byte("peer-X"))
	select {
	case got := <-ch:
		if !bytes.Equal(got, []byte("peer-X")) {
			t.Errorf("ch <- %x, want peer-X", got)
		}
	case <-time.After(time.Second):
		t.Fatal("dispatcher did not deliver to channel")
	}
}

func TestMakeRecoverDispatcher_DropsWhenFull(t *testing.T) {
	ch := make(chan []byte, 1)
	dispatch := makeRecoverDispatcher(ch)
	dispatch([]byte("peer-1")) // fills the buffer
	dispatch([]byte("peer-2")) // would block; expected to drop
	if len(ch) != 1 {
		t.Errorf("buffer len = %d, want 1 (second send should drop)", len(ch))
	}
}

func TestMakeRecoverDispatcher_NonBlockingUnderLoad(t *testing.T) {
	ch := make(chan []byte, 1)
	dispatch := makeRecoverDispatcher(ch)
	var fired atomic.Int32
	done := make(chan struct{})
	go func() {
		for i := 0; i < 100; i++ {
			dispatch([]byte{byte(i)})
			fired.Add(1)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("dispatcher blocked; fired = %d", fired.Load())
	}
}

func TestFindConnByPub_ReturnsMatchingConn(t *testing.T) {
	conn := newDialConn(t)
	cs := swarm.NewConnSet()
	cs.Add(conn)
	got := findConnByPub(cs, conn.RemotePub())
	if got != conn {
		t.Errorf("findConnByPub matching pub = %v, want %v", got, conn)
	}
}

func TestFindConnByPub_NoMatch_ReturnsNil(t *testing.T) {
	conn := newDialConn(t)
	cs := swarm.NewConnSet()
	cs.Add(conn)
	other := make([]byte, 32)
	other[0] = 0xFF
	if got := findConnByPub(cs, other); got != nil {
		t.Errorf("findConnByPub non-matching pub = %v, want nil", got)
	}
}

func TestFindConnByPub_EmptyConnSet_ReturnsNil(t *testing.T) {
	cs := swarm.NewConnSet()
	if got := findConnByPub(cs, []byte("anything")); got != nil {
		t.Errorf("findConnByPub on empty set = %v, want nil", got)
	}
}

func TestMakeCleanupFn_NoConnForPub_Skips(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	cs := swarm.NewConnSet()
	fn := makeCleanupFn(idx, cs, 1, nil)
	fn(context.Background(), []byte("absent-pub"))
}

func TestMakeCleanupFn_DispatchesToReplication(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	conn := newDialConn(t)
	cs := swarm.NewConnSet()
	cs.Add(conn)
	var buf bytes.Buffer
	fn := makeCleanupFn(idx, cs, 1, &buf)
	fn(context.Background(), conn.RemotePub())
	if buf.Len() != 0 {
		t.Errorf("progress output on empty index = %q, want empty", buf.String())
	}
}

func TestMakeCleanupFn_ReplicationFails_LoggedAndReturns(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "idx.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	conn := newDialConn(t)
	cs := swarm.NewConnSet()
	cs.Add(conn)
	// Close the index so replication.RunCleanup's List call fails.
	if err := idx.Close(); err != nil {
		t.Fatalf("idx.Close: %v", err)
	}
	fn := makeCleanupFn(idx, cs, 1, nil)
	fn(context.Background(), conn.RemotePub())
}
