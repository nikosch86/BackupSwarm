package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestE2E_RestoreIndex_DisasterRecovery drives a 2-node swarm, lets
// node A back up files and publish an encrypted index snapshot to
// node B, wipes node A's local index, then runs `restore-index` to
// pull the snapshot back from B and confirms a subsequent `restore`
// re-creates the source tree byte-for-byte.
func TestE2E_RestoreIndex_DisasterRecovery(t *testing.T) {
	dataA := filepath.Join(t.TempDir(), "node-a")
	dataB := filepath.Join(t.TempDir(), "node-b")
	srcDir := filepath.Join(t.TempDir(), "src")
	restoreRoot := filepath.Join(t.TempDir(), "restored")

	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	fixtures := []struct {
		rel  string
		body []byte
	}{
		{"alpha.txt", []byte("alpha contents\n")},
		{"nested/beta.txt", []byte("beta contents\n")},
		{"nested/sub/gamma.bin", bytes.Repeat([]byte{0x5a}, 2<<20)},
	}
	for _, f := range fixtures {
		full := filepath.Join(srcDir, f.rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", f.rel, err)
		}
		if err := os.WriteFile(full, f.body, 0o600); err != nil {
			t.Fatalf("write %s: %v", f.rel, err)
		}
	}
	expectedBlobs := 1 + 1 + 2

	addrB := reserveLocalUDPAddr(t)

	overallCtx, cancelOverall := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancelOverall()

	// Phase 1: B starts the daemon with --invite.
	bCtx, cancelB := context.WithCancel(overallCtx)
	bDone := make(chan error, 1)
	bRunCmd := NewRootCmd()
	bOut := &syncBuffer{}
	bRunCmd.SetOut(bOut)
	bRunCmd.SetErr(io.Discard)
	bRunCmd.SetArgs([]string{
		"--data-dir", dataB,
		"run",
		"--listen", addrB,
		"--invite",
	})
	go func() { bDone <- bRunCmd.ExecuteContext(bCtx) }()
	tokStr := waitForToken(t, bOut, 10*time.Second)

	joinCmd := NewRootCmd()
	joinCmd.SetOut(io.Discard)
	joinCmd.SetErr(io.Discard)
	joinCmd.SetArgs([]string{"--data-dir", dataA, "join", tokStr})
	if err := joinCmd.ExecuteContext(overallCtx); err != nil {
		t.Fatalf("join: %v", err)
	}

	// Phase 2: A runs with --backup-dir AND a fast index-backup interval.
	addrA := reserveLocalUDPAddr(t)
	aCtx, cancelA := context.WithCancel(overallCtx)
	aDone := make(chan error, 1)
	aRunCmd := NewRootCmd()
	aStdout := &syncBuffer{}
	aRunCmd.SetOut(aStdout)
	aRunCmd.SetErr(io.Discard)
	aRunCmd.SetArgs([]string{
		"--data-dir", dataA,
		"run",
		"--backup-dir", srcDir,
		"--listen", addrA,
		"--scan-interval", "100ms",
		"--index-backup-interval", "200ms",
	})
	go func() { aDone <- aRunCmd.ExecuteContext(aCtx) }()

	// Wait for chunk uploads to land at B.
	waitForBlobs(t, filepath.Join(dataB, "chunks"), expectedBlobs, 20*time.Second)
	for _, f := range fixtures {
		waitForSubstring(t, aStdout, "backed up "+f.rel, 20*time.Second)
	}
	// Wait for the index snapshot file to appear, then for its mtime
	// to advance past the post-backup wall clock so we know the
	// snapshot reflects the fully-populated index, not an empty
	// pre-backup snapshot from the loop's first sync tick.
	snapshotsDir := filepath.Join(dataB, "chunks", "snapshots")
	waitForBlobs(t, snapshotsDir, 1, 10*time.Second)
	waitForSnapshotAfter(t, snapshotsDir, time.Now(), 5*time.Second)

	// Phase 3: stop A, wipe its index.db.
	cancelA()
	if err := awaitDone(aDone, 10*time.Second); err != nil {
		t.Fatalf("node A run: %v", err)
	}
	if err := os.Remove(filepath.Join(dataA, "index.db")); err != nil {
		t.Fatalf("rm index.db: %v", err)
	}

	// Phase 4: restore-index pulls the snapshot from B.
	restoreIdxCmd := NewRootCmd()
	idxOut := &syncBuffer{}
	restoreIdxCmd.SetOut(idxOut)
	restoreIdxCmd.SetErr(io.Discard)
	restoreIdxCmd.SetArgs([]string{"--data-dir", dataA, "restore-index"})
	if err := restoreIdxCmd.ExecuteContext(overallCtx); err != nil {
		t.Fatalf("restore-index: %v", err)
	}
	if !bytes.Contains(idxOut.Snapshot(), []byte("restored index")) {
		t.Errorf("expected 'restored index' in stdout, got: %s", idxOut.String())
	}
	if _, err := os.Stat(filepath.Join(dataA, "index.db")); err != nil {
		t.Fatalf("index.db missing after restore-index: %v", err)
	}

	// Phase 5: full restore from the recovered index.
	restoreCmd := NewRootCmd()
	restoreCmd.SetOut(io.Discard)
	restoreCmd.SetErr(io.Discard)
	restoreCmd.SetArgs([]string{"--data-dir", dataA, "restore", restoreRoot})
	if err := restoreCmd.ExecuteContext(overallCtx); err != nil {
		t.Fatalf("restore: %v", err)
	}

	cancelB()
	if err := awaitDone(bDone, 10*time.Second); err != nil {
		t.Fatalf("node B run: %v", err)
	}

	// Phase 6: byte-for-byte equality.
	assertTreesEqual(t, srcDir, restoreRoot)
}

// waitForSnapshotAfter polls dir for a regular file whose mtime is at
// or after threshold, failing the test if the deadline elapses first.
// Used to wait past the index-backup loop's first (empty) sync tick.
func waitForSnapshotAfter(t *testing.T, dir string, threshold time.Time, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		entries, err := os.ReadDir(dir)
		if err == nil {
			for _, e := range entries {
				info, err := e.Info()
				if err != nil {
					continue
				}
				if !info.Mode().IsRegular() {
					continue
				}
				if !info.ModTime().Before(threshold) {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("no snapshot in %q with mtime ≥ %s within %s", dir, threshold, deadline)
}
