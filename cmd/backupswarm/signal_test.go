package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"syscall"
	"testing"
	"time"
)

var (
	binBuildOnce sync.Once
	binPath      string
	binBuildErr  error
)

// buildBinary builds the CLI into a tempdir once per test process and
// returns the cached path.
func buildBinary(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skipf("subprocess signal test runs on unix only; got %s", runtime.GOOS)
	}
	binBuildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "bsw-signal-bin-")
		if err != nil {
			binBuildErr = fmt.Errorf("mkdir: %w", err)
			return
		}
		binPath = filepath.Join(dir, "backupswarm")
		cmd := exec.Command("go", "build", "-o", binPath, ".")
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			binBuildErr = fmt.Errorf("go build: %w", err)
		}
	})
	if binBuildErr != nil {
		t.Fatalf("build binary: %v", binBuildErr)
	}
	return binPath
}

// waitForFile polls until path exists or the deadline expires.
func waitForFile(t *testing.T, path string, d time.Duration) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout waiting for %s", path)
}

// runDaemonAndSignal spawns the built binary in storage-only mode,
// waits for listen.addr, sends sig, and returns the exit code plus the
// data dir.
func runDaemonAndSignal(t *testing.T, sig os.Signal) (exitCode int, dataDir string) {
	t.Helper()
	bin := buildBinary(t)
	dataDir = t.TempDir()

	cmd := exec.Command(bin,
		"--data-dir", dataDir,
		"run",
		"--listen", "127.0.0.1:0",
		"--port-mapping=off",
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start daemon: %v", err)
	}

	// Kill the subprocess on test failure so it never leaks past the
	// test run.
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_, _ = cmd.Process.Wait()
		}
	})

	waitForFile(t, filepath.Join(dataDir, "listen.addr"), 10*time.Second)

	if err := cmd.Process.Signal(sig); err != nil {
		t.Fatalf("send %v: %v", sig, err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err == nil {
			return 0, dataDir
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), dataDir
		}
		t.Fatalf("wait daemon: %v", err)
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		t.Fatalf("daemon did not exit within 15s of %v", sig)
	}
	return -1, dataDir
}

func TestRun_SIGTERMShutsDownCleanly(t *testing.T) {
	code, dataDir := runDaemonAndSignal(t, syscall.SIGTERM)
	if code != 0 {
		t.Fatalf("daemon exit code = %d after SIGTERM, want 0", code)
	}
	for _, name := range []string{"listen.addr", "runtime.json"} {
		path := filepath.Join(dataDir, name)
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("expected %s removed after shutdown, stat err = %v", name, err)
		}
	}
}

func TestRun_SIGINTShutsDownCleanly(t *testing.T) {
	code, dataDir := runDaemonAndSignal(t, syscall.SIGINT)
	if code != 0 {
		t.Fatalf("daemon exit code = %d after SIGINT, want 0", code)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "listen.addr")); !os.IsNotExist(err) {
		t.Errorf("expected listen.addr removed after shutdown, stat err = %v", err)
	}
}
