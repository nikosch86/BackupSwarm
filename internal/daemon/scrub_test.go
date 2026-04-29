package daemon_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"backupswarm/internal/daemon"
	"backupswarm/internal/store"
)

// TestRun_ScrubLoopRemovesCorruptBlob seeds a corrupt blob in the
// daemon's chunk store and asserts the scrub loop removes it.
func TestRun_ScrubLoopRemovesCorruptBlob(t *testing.T) {
	dataDir := t.TempDir()
	chunksDir := filepath.Join(dataDir, "chunks")

	seed, err := store.New(chunksDir)
	if err != nil {
		t.Fatalf("seed store: %v", err)
	}
	owner := bytes.Repeat([]byte{0xab}, 32)
	data := []byte("rot bait")
	h, err := seed.PutOwned(data, owner)
	if err != nil {
		t.Fatalf("seed PutOwned: %v", err)
	}
	if err := seed.Close(); err != nil {
		t.Fatalf("close seed: %v", err)
	}
	hexHash := hex.EncodeToString(h[:])
	blobPath := filepath.Join(chunksDir, hexHash[:2], hexHash)
	corrupt := append([]byte(nil), data...)
	corrupt[0] ^= 0xff
	if err := os.WriteFile(blobPath, corrupt, 0o600); err != nil {
		t.Fatalf("corrupt: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			DataDir:       dataDir,
			ListenAddr:    "127.0.0.1:0",
			ChunkSize:     1 << 20,
			ScrubInterval: 50 * time.Millisecond,
			Progress:      io.Discard,
		})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(blobPath); errors.Is(err, os.ErrNotExist) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := os.Stat(blobPath); !errors.Is(err, os.ErrNotExist) {
		cancel()
		<-done
		t.Fatalf("corrupt blob still present after scrub; stat err = %v", err)
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run err = %v, want nil on cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit within 5s of cancel")
	}
}
