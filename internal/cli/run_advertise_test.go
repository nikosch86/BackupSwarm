package cli

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"backupswarm/pkg/token"
)

// TestRunCmd_AdvertiseAddrEmbedsInToken runs `run --invite --advertise-addr X
// --listen 127.0.0.1:0` and asserts the issued token's Addr equals X
// regardless of the actual bound listener.
func TestRunCmd_AdvertiseAddrEmbedsInToken(t *testing.T) {
	dataDir := t.TempDir()
	const advertise = "203.0.113.7:7777"

	tokStr := runRunInviteForToken(t, dataDir,
		"--advertise-addr", advertise,
	)
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tok.Addr != advertise {
		t.Errorf("token.Addr = %q, want %q", tok.Addr, advertise)
	}
}

// TestRunCmd_AdvertiseAddrDefaultsListen runs `run --invite --advertise-addr
// 203.0.113.7:9999` (no --listen) and asserts the daemon binds and the token
// carries the advertise value with port 9999.
func TestRunCmd_AdvertiseAddrDefaultsListen(t *testing.T) {
	dataDir := t.TempDir()
	const advertise = "203.0.113.7:9999"

	cmd := NewRootCmd()
	stdout := &syncBuffer{}
	cmd.SetOut(stdout)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--data-dir", dataDir,
		"run",
		"--invite",
		"--advertise-addr", advertise,
	})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- cmd.ExecuteContext(ctx) }()
	tokStr := waitForToken(t, stdout, 5*time.Second)
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Errorf("run --invite --advertise-addr: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not exit within 5s of cancel")
	}

	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tok.Addr != advertise {
		t.Errorf("token.Addr = %q, want %q", tok.Addr, advertise)
	}
}

// TestRunCmd_AdvertiseAddrFromEnv asserts the env var fallback works when
// --advertise-addr is omitted.
func TestRunCmd_AdvertiseAddrFromEnv(t *testing.T) {
	dataDir := t.TempDir()
	const advertise = "203.0.113.42:8888"
	t.Setenv("BACKUPSWARM_ADVERTISE_ADDR", advertise)

	tokStr := runRunInviteForToken(t, dataDir)
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tok.Addr != advertise {
		t.Errorf("token.Addr = %q, want %q", tok.Addr, advertise)
	}
}

// TestRunCmd_AdvertiseAddrFlagOverridesEnv asserts the flag wins over the env.
func TestRunCmd_AdvertiseAddrFlagOverridesEnv(t *testing.T) {
	dataDir := t.TempDir()
	t.Setenv("BACKUPSWARM_ADVERTISE_ADDR", "10.0.0.1:1111")
	const flagVal = "203.0.113.99:2222"

	tokStr := runRunInviteForToken(t, dataDir,
		"--advertise-addr", flagVal,
	)
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tok.Addr != flagVal {
		t.Errorf("token.Addr = %q, want %q (flag should override env)", tok.Addr, flagVal)
	}
}

// TestRunCmd_RequiresListenOrAdvertise asserts that without either flag the
// command rejects at parse time.
func TestRunCmd_RequiresListenOrAdvertise(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("run with no --listen and no --advertise-addr returned nil error")
	}
	if !strings.Contains(err.Error(), "listen") && !strings.Contains(err.Error(), "advertise") {
		t.Errorf("error did not mention listen or advertise: %v", err)
	}
}

// TestRunCmd_BadAdvertiseAddrRejected asserts a malformed advertise value is
// rejected before the daemon starts.
func TestRunCmd_BadAdvertiseAddrRejected(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--invite",
		"--advertise-addr", "no-port-here",
	})
	err := cmd.Execute()
	if err == nil {
		t.Fatal("run with bad --advertise-addr returned nil error")
	}
}

// TestRunCmd_AdvertiseAddrAcceptsFQDN exercises FQDN and IPv6-literal forms.
func TestRunCmd_AdvertiseAddrAcceptsFQDN(t *testing.T) {
	cases := []string{
		"backup.example.com:7777",
		"sub.host.example.org:443",
		"[2001:db8::1]:9000",
	}
	for _, advertise := range cases {
		t.Run(advertise, func(t *testing.T) {
			tokStr := runRunInviteForToken(t, t.TempDir(),
				"--advertise-addr", advertise,
			)
			tok, err := token.Decode(tokStr)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if tok.Addr != advertise {
				t.Errorf("token.Addr = %q, want %q", tok.Addr, advertise)
			}
		})
	}
}
