package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/pkg/token"
)

// TestRunCmd_AdvertiseAddrAuto_ResolvesViaSTUN sets --advertise-addr=auto and
// asserts the issued token's Addr starts with the STUN-discovered host plus
// the daemon's listen port.
func TestRunCmd_AdvertiseAddrAuto_ResolvesViaSTUN(t *testing.T) {
	orig := cliDiscoverFunc
	t.Cleanup(func() { cliDiscoverFunc = orig })
	var calls atomic.Int32
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		calls.Add(1)
		return "203.0.113.7", nil
	}

	tokStr := runRunInviteForToken(t, t.TempDir(),
		"--advertise-addr", "auto",
	)
	if calls.Load() < 1 {
		t.Errorf("cliDiscoverFunc not called")
	}
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(tok.Addr, "203.0.113.7:") {
		t.Errorf("token.Addr = %q, want host=203.0.113.7", tok.Addr)
	}
}

// TestRunCmd_AdvertiseAddrAuto_FromEnv asserts BACKUPSWARM_ADVERTISE_ADDR=auto
// triggers the same resolution path.
func TestRunCmd_AdvertiseAddrAuto_FromEnv(t *testing.T) {
	orig := cliDiscoverFunc
	t.Cleanup(func() { cliDiscoverFunc = orig })
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return "198.51.100.42", nil
	}
	t.Setenv("BACKUPSWARM_ADVERTISE_ADDR", "auto")

	tokStr := runRunInviteForToken(t, t.TempDir())
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(tok.Addr, "198.51.100.42:") {
		t.Errorf("token.Addr = %q, want host=198.51.100.42", tok.Addr)
	}
}

// TestRunCmd_AdvertiseAddrAuto_STUNFailureSurfaces asserts a STUN error
// aborts startup with a clear message.
func TestRunCmd_AdvertiseAddrAuto_STUNFailureSurfaces(t *testing.T) {
	orig := cliDiscoverFunc
	t.Cleanup(func() { cliDiscoverFunc = orig })
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return "", errors.New("network unreachable")
	}

	cmd := NewRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--invite",
		"--advertise-addr", "auto",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := cmd.ExecuteContext(ctx)
	if err == nil {
		t.Fatal("expected STUN failure to surface")
	}
	if !strings.Contains(err.Error(), "network unreachable") {
		t.Errorf("err = %v, want STUN failure mentioned", err)
	}
}

// TestRunCmd_StunServerFlag asserts --stun-server is propagated to the
// resolver call (for documentation as a regression seam).
func TestRunCmd_StunServerFlag(t *testing.T) {
	orig := cliDiscoverFunc
	t.Cleanup(func() { cliDiscoverFunc = orig })
	var seenServer atomic.Value
	cliDiscoverFunc = func(_ context.Context, server string) (string, error) {
		seenServer.Store(server)
		return "203.0.113.7", nil
	}

	_ = runRunInviteForToken(t, t.TempDir(),
		"--advertise-addr", "auto",
		"--stun-server", "stun.example.org:3478",
	)
	if got, _ := seenServer.Load().(string); got != "stun.example.org:3478" {
		t.Errorf("--stun-server flag not propagated: got %q", got)
	}
}
