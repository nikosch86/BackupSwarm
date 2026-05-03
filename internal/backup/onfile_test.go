package backup_test

import (
	"context"
	"path/filepath"
	"sync/atomic"
	"testing"

	"backupswarm/internal/backup"
	bsquic "backupswarm/internal/quic"
)

// TestRun_OnFileBackedUp_FiresOncePerNewFile asserts the OnFileBackedUp
// callback fires exactly once per file whose chunks are placed and index
// entry persisted.
func TestRun_OnFileBackedUp_FiresOncePerNewFile(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	relPaths := []string{"a.txt", filepath.Join("sub", "b.txt"), "c.txt"}
	for _, rel := range relPaths {
		writeFile(t, filepath.Join(root, rel), 1<<20)
	}

	var calls atomic.Int64
	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		OnFileBackedUp: func() {
			calls.Add(1)
		},
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if got := calls.Load(); got != int64(len(relPaths)) {
		t.Errorf("OnFileBackedUp calls = %d, want %d", got, len(relPaths))
	}
}

// TestRun_OnFileBackedUp_NotCalledForUnchanged asserts a re-run that
// detects an unchanged file does not fire the callback (the file was
// already backed up; nothing was shipped or persisted this pass).
func TestRun_OnFileBackedUp_NotCalledForUnchanged(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.bin"), 1<<20)

	opts := backup.RunOptions{
		Path:         root,
		Conns:        []*bsquic.Conn{rig.ownerConn},
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run #1: %v", err)
	}

	var calls atomic.Int64
	opts.OnFileBackedUp = func() { calls.Add(1) }
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run #2: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("OnFileBackedUp calls = %d, want 0 for unchanged file", got)
	}
}

// TestRun_OnFileBackedUp_NilCallbackNoPanic asserts a nil callback is
// safe (callback is optional).
func TestRun_OnFileBackedUp_NilCallbackNoPanic(t *testing.T) {
	rig := newTestRig(t)
	root := t.TempDir()
	writeFile(t, filepath.Join(root, "f.bin"), 1<<10)

	opts := backup.RunOptions{
		Path:           root,
		Conns:          []*bsquic.Conn{rig.ownerConn},
		RecipientPub:   rig.recipientPub,
		Index:          rig.ownerIndex,
		ChunkSize:      1 << 20,
		OnFileBackedUp: nil,
	}
	if err := backup.Run(context.Background(), opts); err != nil {
		t.Fatalf("Run: %v", err)
	}
}
