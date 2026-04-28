package daemon

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/index"
)

// TestOwnBackupFromIndex_ListFailureLogsAndReturnsZero asserts the
// closure logs and returns the zero snapshot when idx.List fails.
func TestOwnBackupFromIndex_ListFailureLogsAndReturnsZero(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "ownbackup-list-fail.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("index.Close: %v", err)
	}

	w := &syncWriter{}
	captureSlog(t, w)

	got := ownBackupFromIndex(context.Background(), idx)()
	if got != (RuntimeOwnBackupSnapshot{}) {
		t.Errorf("snapshot on list failure = %+v, want zero value", got)
	}
	logged := w.String()
	if !strings.Contains(logged, "list index for snapshot own-backup") {
		t.Errorf("slog output missing warn message: %q", logged)
	}
}

// TestOwnBackupFromIndex_HappyPath asserts the closure returns totals
// equal to ComputeOwnBackup over the index entries.
func TestOwnBackupFromIndex_HappyPath(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "ownbackup-ok.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	entry := index.FileEntry{
		Path: "f", Size: 42, ModTime: time.Now(),
		Chunks: []index.ChunkRef{{Size: 42, Peers: [][]byte{{0x01}, {0x02}}}},
	}
	if err := idx.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	got := ownBackupFromIndex(context.Background(), idx)()
	want := ComputeOwnBackup([]index.FileEntry{entry})
	if got != want {
		t.Errorf("snapshot = %+v, want %+v", got, want)
	}
}
