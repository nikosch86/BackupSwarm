package cli

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/nat"
	"backupswarm/pkg/token"
)

// fakeCLIPortMapper is a minimal nat.PortMapper for CLI tests.
type fakeCLIPortMapper struct {
	mapping  nat.Mapping
	mapErr   error
	mapped   atomic.Int32
	unmapped atomic.Int32
}

func (f *fakeCLIPortMapper) Map(_ context.Context, _ int) (nat.Mapping, error) {
	f.mapped.Add(1)
	if f.mapErr != nil {
		return nat.Mapping{}, f.mapErr
	}
	return f.mapping, nil
}

func (f *fakeCLIPortMapper) Unmap(_ context.Context, _ nat.Mapping) error {
	f.unmapped.Add(1)
	return nil
}

func TestRunCmd_PortMappingAuto_AdvertisesMappedAddress(t *testing.T) {
	prevDiscover := cliPortMapDiscoverFunc
	prevSTUN := cliDiscoverFunc
	t.Cleanup(func() {
		cliPortMapDiscoverFunc = prevDiscover
		cliDiscoverFunc = prevSTUN
	})

	mapper := &fakeCLIPortMapper{
		mapping: nat.Mapping{
			ExternalIP:   net.IPv4(203, 0, 113, 50),
			ExternalPort: 17777,
			InternalPort: 7777,
			Protocol:     "upnp",
			LeaseSeconds: 7200,
		},
	}
	cliPortMapDiscoverFunc = func(_ context.Context) (nat.PortMapper, error) {
		return mapper, nil
	}
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		t.Fatal("STUN should not be called when port mapping succeeds")
		return "", nil
	}

	tokStr := runRunInviteForToken(t, t.TempDir(),
		"--advertise-addr", "auto",
	)
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if tok.Addr != "203.0.113.50:17777" {
		t.Errorf("token.Addr = %q, want %q", tok.Addr, "203.0.113.50:17777")
	}
	if mapper.mapped.Load() == 0 {
		t.Error("Map was not called")
	}
	if mapper.unmapped.Load() == 0 {
		t.Error("Unmap was not called on shutdown")
	}
}

func TestRunCmd_PortMappingAuto_FailureFallsBackToSTUN(t *testing.T) {
	prevDiscover := cliPortMapDiscoverFunc
	prevSTUN := cliDiscoverFunc
	t.Cleanup(func() {
		cliPortMapDiscoverFunc = prevDiscover
		cliDiscoverFunc = prevSTUN
	})

	cliPortMapDiscoverFunc = func(_ context.Context) (nat.PortMapper, error) {
		return nil, errors.New("forced discovery failure")
	}
	var stunCalls atomic.Int32
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		stunCalls.Add(1)
		return "198.51.100.42", nil
	}

	tokStr := runRunInviteForToken(t, t.TempDir(),
		"--advertise-addr", "auto",
	)
	if stunCalls.Load() == 0 {
		t.Error("STUN was not called as fallback")
	}
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(tok.Addr, "198.51.100.42:") {
		t.Errorf("token.Addr = %q, want host=198.51.100.42", tok.Addr)
	}
}

func TestRunCmd_PortMappingOff_SkipsDiscovery(t *testing.T) {
	prevDiscover := cliPortMapDiscoverFunc
	prevSTUN := cliDiscoverFunc
	t.Cleanup(func() {
		cliPortMapDiscoverFunc = prevDiscover
		cliDiscoverFunc = prevSTUN
	})

	cliPortMapDiscoverFunc = func(_ context.Context) (nat.PortMapper, error) {
		t.Fatal("port-mapping=off should not invoke discovery")
		return nil, nil
	}
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return "203.0.113.99", nil
	}

	tokStr := runRunInviteForToken(t, t.TempDir(),
		"--advertise-addr", "auto",
		"--port-mapping", "off",
	)
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(tok.Addr, "203.0.113.99:") {
		t.Errorf("token.Addr = %q, want host=203.0.113.99", tok.Addr)
	}
}

func TestRunCmd_PortMapping_InvalidValueRejected(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{
		"--data-dir", t.TempDir(),
		"run",
		"--listen", "127.0.0.1:0",
		"--invite",
		"--port-mapping", "bogus",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := cmd.ExecuteContext(ctx); err == nil {
		t.Fatal("expected error on bogus --port-mapping value")
	}
}

func TestRunCmd_PortMappingFromEnv(t *testing.T) {
	prevDiscover := cliPortMapDiscoverFunc
	prevSTUN := cliDiscoverFunc
	t.Cleanup(func() {
		cliPortMapDiscoverFunc = prevDiscover
		cliDiscoverFunc = prevSTUN
	})

	cliPortMapDiscoverFunc = func(_ context.Context) (nat.PortMapper, error) {
		t.Fatal("port-mapping env=off should not invoke discovery")
		return nil, nil
	}
	cliDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return "192.0.2.10", nil
	}
	t.Setenv("BACKUPSWARM_PORT_MAPPING", "off")

	tokStr := runRunInviteForToken(t, t.TempDir(),
		"--advertise-addr", "auto",
	)
	tok, err := token.Decode(tokStr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.HasPrefix(tok.Addr, "192.0.2.10:") {
		t.Errorf("token.Addr = %q, want host=192.0.2.10", tok.Addr)
	}
}
