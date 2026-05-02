package daemon

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
			Progress:   io.Discard,
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
			Progress:   io.Discard,
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
