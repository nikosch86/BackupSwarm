package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/iotest"
)

// TestHashStream_PropagatesReadError asserts an io.Copy failure surfaces
// from hashStream with the bytes-read tally cleared.
func TestHashStream_PropagatesReadError(t *testing.T) {
	sentinel := errors.New("forced read failure")
	r := iotest.ErrReader(sentinel)
	sum, n, err := hashStream(r)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if n != 0 {
		t.Errorf("n = %d, want 0 on Read failure", n)
	}
	var zero [sha256.Size]byte
	if sum != zero {
		t.Errorf("sum = %x, want zero on Read failure", sum)
	}
}

// TestHashStream_ReturnsLengthAndSum asserts hashStream sums the same as
// sha256.Sum256 over the input and reports the byte count.
func TestHashStream_ReturnsLengthAndSum(t *testing.T) {
	data := []byte("hash me")
	sum, n, err := hashStream(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("hashStream: %v", err)
	}
	if n != int64(len(data)) {
		t.Errorf("n = %d, want %d", n, len(data))
	}
	if sum != sha256.Sum256(data) {
		t.Errorf("sum = %x, want %x", sum, sha256.Sum256(data))
	}
}

// TestScrubOne_DropOwnerRowFailureWraps forces dropOwnerRow to fail via
// a chmod-seam injection on a re-opened owners.db; scrubOne wraps the
// error so scrubShard logs and continues without counting Corrupt.
func TestScrubOne_DropOwnerRowFailureWraps(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	data := []byte("rot bait")
	h, err := s.Put(data)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	hexHash := hex.EncodeToString(h[:])
	corrupt := append([]byte(nil), data...)
	corrupt[0] ^= 0xff
	if err := os.WriteFile(filepath.Join(root, hexHash[:2], hexHash), corrupt, 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	sentinel := errors.New("forced chmod failure")
	withChmodFunc(t, func(_ string, _ os.FileMode) error {
		return sentinel
	})

	res, err := s.Scrub(context.Background())
	if err != nil {
		t.Fatalf("Scrub: %v", err)
	}
	if res.Scanned != 1 || res.Corrupt != 0 {
		t.Errorf("ScrubResult = {Scanned:%d Corrupt:%d}, want {1, 0} (owner-row drop failed)", res.Scanned, res.Corrupt)
	}
}

// flakyCtx returns nil from Err for the first threshold calls and
// context.Canceled afterward.
type flakyCtx struct {
	context.Context
	canceled  chan struct{}
	calls     int
	threshold int
}

func (c *flakyCtx) Err() error {
	c.calls++
	if c.calls > c.threshold {
		select {
		case <-c.canceled:
		default:
			close(c.canceled)
		}
		return context.Canceled
	}
	return nil
}

func (c *flakyCtx) Done() <-chan struct{} { return c.canceled }

func TestScrubShard_ContextCancelledMidBlobLoop(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	first, second := sameShardPair(t)
	if _, err := s.Put(first); err != nil {
		t.Fatalf("Put first: %v", err)
	}
	if _, err := s.Put(second); err != nil {
		t.Fatalf("Put second: %v", err)
	}

	ctx := &flakyCtx{
		Context:   context.Background(),
		canceled:  make(chan struct{}),
		threshold: 1,
	}
	res, err := s.Scrub(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Scrub err = %v, want context.Canceled", err)
	}
	if res.Scanned != 0 {
		t.Errorf("Scanned = %d, want 0 (cancel fired before any scrubOne)", res.Scanned)
	}
}

// sameShardPair returns two payloads whose sha256 hashes share a first
// byte so they land in the same shard dir. Searches a deterministic
// space; fails the test if no pair is found within the budget.
func sameShardPair(t *testing.T) ([]byte, []byte) {
	t.Helper()
	hashes := make(map[byte]int)
	for i := 0; i < 4096; i++ {
		payload := []byte{byte(i >> 8), byte(i)}
		h := sha256.Sum256(payload)
		if prev, ok := hashes[h[0]]; ok {
			a := []byte{byte(prev >> 8), byte(prev)}
			b := payload
			return a, b
		}
		hashes[h[0]] = i
	}
	t.Fatalf("could not find two payloads sharing a sha256 prefix byte")
	return nil, nil
}

// TestDropOwnerRow_EnsureOwnersDBError asserts dropOwnerRow surfaces an
// ensureOwnersDB failure unwrapped to the caller without touching the
// running used tally.
func TestDropOwnerRow_EnsureOwnersDBError(t *testing.T) {
	root := t.TempDir()
	s, err := New(root)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	sentinel := errors.New("forced chmod failure")
	withChmodFunc(t, func(_ string, _ os.FileMode) error {
		return sentinel
	})

	var hash [sha256.Size]byte
	hash[0] = 0xAA
	if err := s.dropOwnerRow(hash); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}
