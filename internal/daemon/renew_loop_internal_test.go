package daemon

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"

	"go.etcd.io/bbolt"
)

func TestRunRenewLoop_TicksAndStopsOnCancel(t *testing.T) {
	var calls atomic.Int32
	renewFn := func(_ context.Context) (RenewResult, error) {
		calls.Add(1)
		return RenewResult{Sent: 7}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runRenewLoop(ctx, renewLoopOptions{
			interval: 50 * time.Millisecond,
			renewFn:  renewFn,
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 2 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := calls.Load(); got < 2 {
		t.Fatalf("only %d renew calls fired in 2s with 50ms interval", got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runRenewLoop did not exit on ctx cancel")
	}
}

func TestRunRenewLoop_ContinuesAfterError(t *testing.T) {
	var calls atomic.Int32
	renewFn := func(_ context.Context) (RenewResult, error) {
		calls.Add(1)
		return RenewResult{}, errors.New("renew boom")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		runRenewLoop(ctx, renewLoopOptions{
			interval: 30 * time.Millisecond,
			renewFn:  renewFn,
		})
		close(done)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 3 {
		time.Sleep(20 * time.Millisecond)
	}
	if got := calls.Load(); got < 3 {
		t.Fatalf("only %d renew calls fired despite errors; got %d", got, got)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runRenewLoop did not exit on ctx cancel")
	}
}

func TestRunRenewLoop_FirstTickIsSynchronous(t *testing.T) {
	gate := make(chan struct{})
	renewFn := func(_ context.Context) (RenewResult, error) {
		select {
		case <-gate:
		case <-time.After(2 * time.Second):
		}
		return RenewResult{}, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan struct{})
	go func() {
		runRenewLoop(ctx, renewLoopOptions{
			interval: 1 * time.Hour,
			renewFn:  renewFn,
		})
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("runRenewLoop returned before renewFn finished")
	case <-time.After(100 * time.Millisecond):
	}
	close(gate)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("runRenewLoop did not exit after gate + cancel")
	}
}

func TestRenewAllChunks_SendsForEachLivePeer(t *testing.T) {
	connA, pubA := newProbeConn(t)
	connB, pubB := newProbeConn(t)

	hashA := sha256.Sum256([]byte("a"))
	hashB := sha256.Sum256([]byte("b"))
	entries := []index.FileEntry{
		{
			Path: "file-1",
			Chunks: []index.ChunkRef{
				{CiphertextHash: hashA, Peers: [][]byte{pubA, pubB}},
			},
		},
		{
			Path: "file-2",
			Chunks: []index.ChunkRef{
				{CiphertextHash: hashB, Peers: [][]byte{pubA}},
			},
		},
	}

	type call struct {
		pub  string
		hash [32]byte
	}
	var (
		mu    sync.Mutex
		calls []call
	)
	orig := sendRenewFunc
	t.Cleanup(func() { sendRenewFunc = orig })
	sendRenewFunc = func(_ context.Context, c *bsquic.Conn, h [32]byte) error {
		mu.Lock()
		defer mu.Unlock()
		calls = append(calls, call{pub: hex.EncodeToString(c.RemotePub()), hash: h})
		return nil
	}

	res, err := renewAllChunks(context.Background(), entries, []*bsquic.Conn{connA, connB})
	if err != nil {
		t.Fatalf("renewAllChunks: %v", err)
	}
	if res.Sent != 3 {
		t.Errorf("res.Sent = %d, want 3", res.Sent)
	}
	if got := len(calls); got != 3 {
		t.Errorf("calls = %d, want 3", got)
	}
	want := map[string]int{
		hex.EncodeToString(pubA): 2,
		hex.EncodeToString(pubB): 1,
	}
	got := map[string]int{}
	for _, c := range calls {
		got[c.pub]++
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("calls for %s = %d, want %d", k[:8], got[k], v)
		}
	}
}

func TestRenewAllChunks_SkipsChunksWithoutLiveConn(t *testing.T) {
	connA, pubA := newProbeConn(t)
	missingPub := make([]byte, 32)
	for i := range missingPub {
		missingPub[i] = 0x77
	}

	hashOnlyMissing := sha256.Sum256([]byte("missing"))
	hashLive := sha256.Sum256([]byte("live"))
	entries := []index.FileEntry{
		{
			Path: "f",
			Chunks: []index.ChunkRef{
				{CiphertextHash: hashOnlyMissing, Peers: [][]byte{missingPub}},
				{CiphertextHash: hashLive, Peers: [][]byte{pubA}},
			},
		},
	}

	var calls atomic.Int32
	orig := sendRenewFunc
	t.Cleanup(func() { sendRenewFunc = orig })
	sendRenewFunc = func(_ context.Context, _ *bsquic.Conn, _ [32]byte) error {
		calls.Add(1)
		return nil
	}

	res, err := renewAllChunks(context.Background(), entries, []*bsquic.Conn{connA})
	if err != nil {
		t.Fatalf("renewAllChunks: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("calls = %d, want 1 (skip chunk with no live conn)", got)
	}
	if res.Sent != 1 {
		t.Errorf("res.Sent = %d, want 1", res.Sent)
	}
	if res.Skipped == 0 {
		t.Errorf("res.Skipped = %d, want >= 1", res.Skipped)
	}
}

func TestRenewAllChunks_ContinuesAfterPerPeerFailure(t *testing.T) {
	connA, pubA := newProbeConn(t)
	connB, pubB := newProbeConn(t)

	hash := sha256.Sum256([]byte("x"))
	entries := []index.FileEntry{
		{
			Path: "f",
			Chunks: []index.ChunkRef{
				{CiphertextHash: hash, Peers: [][]byte{pubA, pubB}},
			},
		},
	}

	orig := sendRenewFunc
	t.Cleanup(func() { sendRenewFunc = orig })
	sendRenewFunc = func(_ context.Context, c *bsquic.Conn, _ [32]byte) error {
		if hex.EncodeToString(c.RemotePub()) == hex.EncodeToString(pubA) {
			return errors.New("simulated send failure")
		}
		return nil
	}

	res, err := renewAllChunks(context.Background(), entries, []*bsquic.Conn{connA, connB})
	if err != nil {
		t.Fatalf("renewAllChunks: %v", err)
	}
	if res.Sent != 1 {
		t.Errorf("res.Sent = %d, want 1 (one peer failed)", res.Sent)
	}
	if res.Failed != 1 {
		t.Errorf("res.Failed = %d, want 1", res.Failed)
	}
}

func TestRenewAllChunks_EmptyEntriesNoop(t *testing.T) {
	connA, _ := newProbeConn(t)

	var calls atomic.Int32
	orig := sendRenewFunc
	t.Cleanup(func() { sendRenewFunc = orig })
	sendRenewFunc = func(_ context.Context, _ *bsquic.Conn, _ [32]byte) error {
		calls.Add(1)
		return nil
	}

	res, err := renewAllChunks(context.Background(), nil, []*bsquic.Conn{connA})
	if err != nil {
		t.Fatalf("renewAllChunks: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("calls = %d, want 0", got)
	}
	if res != (RenewResult{}) {
		t.Errorf("res = %+v, want zero value", res)
	}
}

func TestRenewAllChunks_RespectsContextCancel(t *testing.T) {
	connA, pubA := newProbeConn(t)
	hash := sha256.Sum256([]byte("a"))
	entries := []index.FileEntry{
		{Path: "f", Chunks: []index.ChunkRef{{CiphertextHash: hash, Peers: [][]byte{pubA}}}},
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := renewAllChunks(ctx, entries, []*bsquic.Conn{connA}); err == nil {
		t.Error("renewAllChunks returned nil despite cancelled ctx")
	}
}

func TestRenewClosure_HappyPath(t *testing.T) {
	connA, pubA := newProbeConn(t)
	idxPath := filepath.Join(t.TempDir(), "index.db")
	idx, err := index.Open(idxPath)
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	hash := sha256.Sum256([]byte("renewable"))
	if err := idx.Put(index.FileEntry{
		Path:   "f",
		Chunks: []index.ChunkRef{{CiphertextHash: hash, Peers: [][]byte{pubA}}},
	}); err != nil {
		t.Fatalf("idx.Put: %v", err)
	}

	var calls atomic.Int32
	orig := sendRenewFunc
	t.Cleanup(func() { sendRenewFunc = orig })
	sendRenewFunc = func(_ context.Context, _ *bsquic.Conn, _ [32]byte) error {
		calls.Add(1)
		return nil
	}

	fn := renewClosure(idx, func() []*bsquic.Conn { return []*bsquic.Conn{connA} })
	res, err := fn(context.Background())
	if err != nil {
		t.Fatalf("renewClosure: %v", err)
	}
	if res.Sent != 1 {
		t.Errorf("res.Sent = %d, want 1", res.Sent)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("calls = %d, want 1", got)
	}
}

func TestRenewClosure_PropagatesListError(t *testing.T) {
	idxPath := filepath.Join(t.TempDir(), "index.db")
	idx, err := index.Open(idxPath)
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	db, err := bbolt.Open(idxPath, 0o600, &bbolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("bbolt.Open: %v", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		return tx.Bucket([]byte("files")).Put([]byte("not-gob"), []byte{0xff, 0xff, 0xff, 0xff})
	}); err != nil {
		t.Fatalf("inject corrupt entry: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("bbolt close: %v", err)
	}

	idx2, err := index.Open(idxPath)
	if err != nil {
		t.Fatalf("reopen index: %v", err)
	}
	t.Cleanup(func() { _ = idx2.Close() })

	fn := renewClosure(idx2, func() []*bsquic.Conn { return nil })
	_, err = fn(context.Background())
	if err == nil {
		t.Fatal("renewClosure returned nil despite corrupt index entry")
	}
	if !strings.Contains(err.Error(), "list index") {
		t.Errorf("err = %q, want 'list index' prefix", err.Error())
	}
}
