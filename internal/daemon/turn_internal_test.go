package daemon

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/nat"

	"github.com/pion/logging"
	pturn "github.com/pion/turn/v4"
)

var errSentinelTURN = errors.New("turn-allocate-sentinel")

// TestRun_TURNAllocateFuncReceivesConfig asserts the daemon calls into
// turnAllocateFunc with the operator-supplied TURN credentials and surfaces
// the allocation failure.
func TestRun_TURNAllocateFuncReceivesConfig(t *testing.T) {
	prev := turnAllocateFunc
	t.Cleanup(func() { turnAllocateFunc = prev })
	var seen atomic.Value
	called := make(chan struct{}, 1)
	turnAllocateFunc = func(_ context.Context, cfg nat.TURNConfig) (*nat.Allocation, error) {
		seen.Store(cfg)
		select {
		case called <- struct{}{}:
		default:
		}
		return nil, errSentinelTURN
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:    t.TempDir(),
			ListenAddr: "127.0.0.1:0",
			TURN: TURNOptions{
				Server:   "turn.example:3478",
				Username: "u",
				Password: "p",
				Realm:    "r",
			},
		})
	}()

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("turnAllocateFunc not called within 2s")
	}

	select {
	case err := <-done:
		if !errors.Is(err, errSentinelTURN) {
			t.Fatalf("Run err = %v, want errSentinelTURN", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit after allocation failure")
	}

	cfg := seen.Load().(nat.TURNConfig)
	if cfg.Server != "turn.example:3478" || cfg.Username != "u" || cfg.Password != "p" || cfg.Realm != "r" {
		t.Errorf("propagated cfg = %+v", cfg)
	}
}

// startTURNServerForDaemonTest spins up a localhost TURN server long enough
// for the daemon to allocate against it.
func startTURNServerForDaemonTest(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen turn: %v", err)
	}
	const realm = "backupswarm.test"
	credKey := pturn.GenerateAuthKey("u", realm, "p")
	server, err := pturn.NewServer(pturn.ServerConfig{
		Realm:       realm,
		AuthHandler: func(_, _ string, _ net.Addr) ([]byte, bool) { return credKey, true },
		PacketConnConfigs: []pturn.PacketConnConfig{{
			PacketConn: listener,
			RelayAddressGenerator: &pturn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("turn server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return listener.LocalAddr().String()
}

// TestRun_TURNAllocation_PublishesAndRemovesRelayAddr drives daemon.Run
// with TURN configured and asserts <data-dir>/relay.addr appears with the
// allocated relay address while the daemon is alive and is removed on
// shutdown — the file is what the `invite` oneshot reads to embed in
// outbound tokens.
func TestRun_TURNAllocation_PublishesAndRemovesRelayAddr(t *testing.T) {
	turnAddr := startTURNServerForDaemonTest(t)
	dataDir := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:    dataDir,
			ListenAddr: "127.0.0.1:0",
			TURN: TURNOptions{
				Server:   turnAddr,
				Username: "u",
				Password: "p",
				Realm:    "backupswarm.test",
			},
		})
	}()

	deadline := time.Now().Add(5 * time.Second)
	var relayAddr string
	for {
		var readErr error
		relayAddr, readErr = ReadRelayAddr(dataDir)
		if readErr == nil && relayAddr != "" {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("relay.addr never appeared (last err: %v)", readErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.HasPrefix(relayAddr, "127.0.0.1:") {
		t.Errorf("relay.addr = %q, want 127.0.0.1:<port> prefix", relayAddr)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}

	if _, err := ReadRelayAddr(dataDir); err != nil {
		t.Fatalf("post-shutdown ReadRelayAddr: %v", err)
	}
	got, _ := ReadRelayAddr(dataDir)
	if got != "" {
		t.Errorf("relay.addr still present after shutdown: %q", got)
	}
}

// TestRun_TURNAllocation_PrePermitsServerIP asserts the daemon resolves
// opts.TURN.Server to an IP and calls AddPermission on the allocation
// immediately after Allocate.
func TestRun_TURNAllocation_PrePermitsServerIP(t *testing.T) {
	turnAddr := startTURNServerForDaemonTest(t)
	turnHost, _, err := net.SplitHostPort(turnAddr)
	if err != nil {
		t.Fatalf("split turn addr: %v", err)
	}

	prev := turnAddPermissionFunc
	t.Cleanup(func() { turnAddPermissionFunc = prev })
	var seenIP atomic.Value
	called := make(chan struct{}, 1)
	turnAddPermissionFunc = func(alloc *nat.Allocation, ip net.IP) error {
		seenIP.Store(ip.String())
		select {
		case called <- struct{}{}:
		default:
		}
		return prev(alloc, ip)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:    t.TempDir(),
			ListenAddr: "127.0.0.1:0",
			TURN: TURNOptions{
				Server:   turnAddr,
				Username: "u",
				Password: "p",
				Realm:    "backupswarm.test",
			},
		})
	}()

	select {
	case <-called:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("turnAddPermissionFunc not called within 5s")
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s of cancel")
	}

	got, _ := seenIP.Load().(string)
	if got != turnHost {
		t.Errorf("AddPermission ip = %q, want %q", got, turnHost)
	}
}

// TestRun_TURNAllocationLogsRelayAddr asserts the relay address is emitted
// at Info level when the daemon allocates against a real TURN server.
func TestRun_TURNAllocationLogsRelayAddr(t *testing.T) {
	turnAddr := startTURNServerForDaemonTest(t)

	w := &syncWriter{}
	captureSlog(t, w)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:    t.TempDir(),
			ListenAddr: "127.0.0.1:0",
			TURN: TURNOptions{
				Server:   turnAddr,
				Username: "u",
				Password: "p",
				Realm:    "backupswarm.test",
			},
		})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(w.String(), "nat: turn relay allocated") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s of cancel")
	}

	got := w.String()
	if !strings.Contains(got, "nat: turn relay allocated") {
		t.Errorf("missing relay-allocated log line; buffer:\n%s", got)
	}
	if !strings.Contains(got, "relay_addr=127.0.0.1:") {
		t.Errorf("relay-allocated log missing relay_addr=127.0.0.1:<port>; buffer:\n%s", got)
	}
}
