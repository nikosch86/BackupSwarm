package cli

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// TestE2E_BackupAndRestoreRoundTrip is the M1.11 end-to-end check: two
// in-process nodes wired through the real cobra CLI form a swarm, ship
// a directory of files through the chunk → encrypt → transport → store
// pipeline, and restore it to a fresh location. Final tree is compared
// byte-for-byte against the source.
func TestE2E_BackupAndRestoreRoundTrip(t *testing.T) {
	dataA := filepath.Join(t.TempDir(), "node-a")
	dataB := filepath.Join(t.TempDir(), "node-b")
	srcDir := filepath.Join(t.TempDir(), "src")
	restoreRoot := filepath.Join(t.TempDir(), "restored")

	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	// Fixture spans the interesting chunking cases at the 1 MiB minimum
	// chunk size: tiny single-chunk files plus one file that splits into
	// multiple chunks.
	fixtures := []struct {
		rel  string
		body []byte
	}{
		{"hello.txt", []byte("hello world\n")},
		{"nested/greet.txt", []byte("hi there\n")},
		{"nested/sub/big.bin", bytes.Repeat([]byte{0xab}, 3<<20)}, // 3 MiB -> 3 chunks
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
	expectedBlobs := 1 + 1 + 3

	// Stable UDP port for B — invite and run both bind here so the peer
	// record A persists during `join` stays valid into phase 2.
	addrB := reserveLocalUDPAddr(t)

	overallCtx, cancelOverall := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelOverall()

	// Phase 1: B's `invite` prints a token; A's `join` consumes it.
	inviteOut := &syncBuffer{}
	inviteCmd := NewRootCmd()
	inviteCmd.SetOut(inviteOut)
	inviteCmd.SetErr(io.Discard)
	inviteCmd.SetArgs([]string{
		"--data-dir", dataB,
		"invite",
		"--listen", addrB,
		"--timeout", "20s",
	})
	var inviteErr error
	var inviteWG sync.WaitGroup
	inviteWG.Add(1)
	go func() {
		defer inviteWG.Done()
		inviteErr = inviteCmd.ExecuteContext(overallCtx)
	}()
	tokStr := waitForToken(t, inviteOut, 5*time.Second)

	// --listen omitted so A advertises no return address; B's peers.db
	// ends up with {addr:"", pub:A_pub}, which pickStoragePeer filters
	// out. That keeps B in storage-only mode after `invite` exits.
	joinCmd := NewRootCmd()
	joinCmd.SetOut(io.Discard)
	joinCmd.SetErr(io.Discard)
	joinCmd.SetArgs([]string{"--data-dir", dataA, "join", tokStr})
	if err := joinCmd.ExecuteContext(overallCtx); err != nil {
		t.Fatalf("join: %v", err)
	}
	inviteWG.Wait()
	if inviteErr != nil {
		t.Fatalf("invite returned error: %v", inviteErr)
	}

	// Phase 2: B runs as a pure storage peer on the same address.
	bCtx, cancelB := context.WithCancel(overallCtx)
	bDone := make(chan error, 1)
	bRunCmd := NewRootCmd()
	bRunCmd.SetOut(io.Discard)
	bRunCmd.SetErr(io.Discard)
	bRunCmd.SetArgs([]string{"--data-dir", dataB, "run", "--listen", addrB})
	go func() { bDone <- bRunCmd.ExecuteContext(bCtx) }()

	// Phase 3: A runs with --backup-dir, dials B, ships the chunks.
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
	})
	go func() { aDone <- aRunCmd.ExecuteContext(aCtx) }()

	// Wait for the index to record every file. `backupFile` writes
	// "backed up <path> (N chunks)\n" only *after* Index.Put commits, so
	// observing that line per fixture proves the index is consistent
	// with what's on the peer. Watching B's blob count alone races the
	// index write for multi-chunk files.
	waitForBlobs(t, filepath.Join(dataB, "chunks"), expectedBlobs, 20*time.Second)
	for _, f := range fixtures {
		line := "backed up " + filepath.Join(srcDir, f.rel)
		waitForSubstring(t, aStdout, line, 20*time.Second)
	}

	// Stop A, keep B up so restore can fetch.
	cancelA()
	if err := awaitDone(aDone, 10*time.Second); err != nil {
		t.Fatalf("node A run: %v", err)
	}

	// Phase 4: restore to a fresh tree. Files land at
	// <restoreRoot><original-abs-path> (M1.10 restore layout).
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

	// Phase 5: byte-for-byte equality between source and restored tree.
	assertTreesEqual(t, srcDir, filepath.Join(restoreRoot, srcDir))
}

// TestE2E_ThenRunFlags_BackupAndRestoreRoundTrip covers the docker-compose-
// style flow: both invite and join transition into the sync daemon
// after the handshake, and the token is exchanged via a shared file
// rather than a copy-pasted stdout line. Same verification as the base
// e2e test (byte-for-byte tree equality post-restore).
func TestE2E_ThenRunFlags_BackupAndRestoreRoundTrip(t *testing.T) {
	dataA := filepath.Join(t.TempDir(), "node-a")
	dataB := filepath.Join(t.TempDir(), "node-b")
	srcDir := filepath.Join(t.TempDir(), "src")
	restoreRoot := filepath.Join(t.TempDir(), "restored")
	sharedDir := t.TempDir()
	tokenPath := filepath.Join(sharedDir, "token.txt")

	if err := os.MkdirAll(srcDir, 0o700); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	fixtures := []struct {
		rel  string
		body []byte
	}{
		{"hello.txt", []byte("hello world\n")},
		{"nested/greet.txt", []byte("hi there\n")},
		{"nested/sub/big.bin", bytes.Repeat([]byte{0xcd}, 3<<20)},
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
	expectedBlobs := 1 + 1 + 3

	addrB := reserveLocalUDPAddr(t)
	addrA := reserveLocalUDPAddr(t)

	overallCtx, cancelOverall := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancelOverall()

	// B: `invite --then-run` stays alive as a storage peer after the
	// join handshake. --token-out drops the token into the shared dir
	// for A to pick up.
	bCtx, cancelB := context.WithCancel(overallCtx)
	bDone := make(chan error, 1)
	bCmd := NewRootCmd()
	bCmd.SetOut(io.Discard)
	bCmd.SetErr(io.Discard)
	bCmd.SetArgs([]string{
		"--data-dir", dataB,
		"invite",
		"--listen", addrB,
		"--timeout", "20s",
		"--token-out", tokenPath,
		"--then-run",
	})
	go func() { bDone <- bCmd.ExecuteContext(bCtx) }()

	// A: `join --token-file --then-run` polls for the token, dials,
	// handshakes, and continues as a backup daemon.
	aCtx, cancelA := context.WithCancel(overallCtx)
	aDone := make(chan error, 1)
	aCmd := NewRootCmd()
	aStdout := &syncBuffer{}
	aCmd.SetOut(aStdout)
	aCmd.SetErr(io.Discard)
	aCmd.SetArgs([]string{
		"--data-dir", dataA,
		"join",
		"--token-file", tokenPath,
		"--timeout", "10s",
		"--then-run",
		"--backup-dir", srcDir,
		"--listen", addrA,
		"--scan-interval", "100ms",
	})
	go func() { aDone <- aCmd.ExecuteContext(aCtx) }()

	waitForBlobs(t, filepath.Join(dataB, "chunks"), expectedBlobs, 20*time.Second)
	for _, f := range fixtures {
		waitForSubstring(t, aStdout, "backed up "+filepath.Join(srcDir, f.rel), 20*time.Second)
	}

	cancelA()
	if err := awaitDone(aDone, 10*time.Second); err != nil {
		t.Fatalf("node A (join --then-run): %v", err)
	}

	restoreCmd := NewRootCmd()
	restoreCmd.SetOut(io.Discard)
	restoreCmd.SetErr(io.Discard)
	restoreCmd.SetArgs([]string{"--data-dir", dataA, "restore", restoreRoot})
	if err := restoreCmd.ExecuteContext(overallCtx); err != nil {
		t.Fatalf("restore: %v", err)
	}

	cancelB()
	if err := awaitDone(bDone, 10*time.Second); err != nil {
		t.Fatalf("node B (invite --then-run): %v", err)
	}

	assertTreesEqual(t, srcDir, filepath.Join(restoreRoot, srcDir))
}

// reserveLocalUDPAddr binds a 127.0.0.1 UDP socket on a kernel-assigned
// port, closes it, and returns the "host:port" string. The caller
// re-binds the same port immediately; the window is small enough that
// another process stealing it is not a concern in a local test run.
func reserveLocalUDPAddr(t *testing.T) string {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("reserve UDP port: %v", err)
	}
	addr := conn.LocalAddr().String()
	_ = conn.Close()
	return addr
}

// waitForSubstring polls buf until it contains needle, or fails the
// test when the deadline elapses.
func waitForSubstring(t *testing.T, buf *syncBuffer, needle string, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if bytes.Contains(buf.Snapshot(), []byte(needle)) {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("substring %q not seen within %s; got:\n%s", needle, deadline, buf.String())
}

// waitForBlobs polls dir for regular files until count reaches min or
// the deadline elapses.
func waitForBlobs(t *testing.T, dir string, min int, deadline time.Duration) {
	t.Helper()
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		if countRegularFiles(dir) >= min {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("expected >=%d blobs under %q within %s, got %d",
		min, dir, deadline, countRegularFiles(dir))
}

// countRegularFiles walks dir and returns the number of regular files at
// any depth. A missing dir is treated as empty.
func countRegularFiles(dir string) int {
	count := 0
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			count++
		}
		return nil
	})
	return count
}

// awaitDone waits for one message on done, returning its value, or an
// error if nothing arrives within timeout.
func awaitDone(done <-chan error, timeout time.Duration) error {
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		return fmt.Errorf("command did not exit within %s", timeout)
	}
}

// assertTreesEqual walks want and got in parallel, failing on missing
// entries, type mismatches, content mismatches, or unexpected extras.
func assertTreesEqual(t *testing.T, want, got string) {
	t.Helper()
	seen := make(map[string]struct{})
	err := filepath.WalkDir(want, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(want, path)
		if err != nil {
			return err
		}
		seen[rel] = struct{}{}
		if rel == "." {
			return nil
		}
		gotPath := filepath.Join(got, rel)
		gotInfo, err := os.Lstat(gotPath)
		if err != nil {
			t.Errorf("missing in restored tree: %q: %v", rel, err)
			return nil
		}
		if d.IsDir() {
			if !gotInfo.IsDir() {
				t.Errorf("%q: want dir, got %s", rel, gotInfo.Mode().Type())
			}
			return nil
		}
		wantBytes, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		gotBytes, err := os.ReadFile(gotPath)
		if err != nil {
			t.Errorf("read restored %q: %v", rel, err)
			return nil
		}
		if !bytes.Equal(wantBytes, gotBytes) {
			t.Errorf("%q: content differs (want %d bytes, got %d bytes)",
				rel, len(wantBytes), len(gotBytes))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk want tree: %v", err)
	}
	_ = filepath.WalkDir(got, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(got, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if _, ok := seen[rel]; !ok {
			t.Errorf("unexpected entry in restored tree: %q", rel)
		}
		return nil
	})
}
