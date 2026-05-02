package daemon

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"net"
	"time"

	"backupswarm/internal/nat"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// natDiscoverFunc is the test seam for STUN binding requests.
var natDiscoverFunc = nat.Discover

// turnAllocateFunc is the test seam for TURN relay allocation; production
// wraps nat.Allocate.
var turnAllocateFunc = nat.Allocate

// broadcastAddressChangedFunc is the test seam for AddressChanged emission.
var broadcastAddressChangedFunc = swarm.BroadcastAddressChanged

// natLoopOptions configures runNATLoop.
type natLoopOptions struct {
	server      string
	interval    time.Duration
	perProbe    time.Duration
	port        string
	pub         ed25519.PublicKey
	initialHost string
	connsFn     func() []*bsquic.Conn
}

// runNATLoop polls the STUN server every opts.interval and broadcasts
// AddressChanged to all live conns when the discovered host changes.
// The first tick fires synchronously before the ticker starts.
func runNATLoop(ctx context.Context, opts natLoopOptions) {
	lastHost := opts.initialHost
	tick := func() {
		pctx, cancel := context.WithTimeout(ctx, opts.perProbe)
		defer cancel()
		host, err := natDiscoverFunc(pctx, opts.server)
		if err != nil {
			slog.WarnContext(ctx, "nat: stun discover failed",
				"server", opts.server,
				"err", err)
			return
		}
		if host == lastHost {
			return
		}
		lastHost = host
		addr := net.JoinHostPort(host, opts.port)
		if err := broadcastAddressChangedFunc(ctx, opts.connsFn(), opts.pub, addr); err != nil {
			slog.WarnContext(ctx, "nat: broadcast AddressChanged failed",
				"addr", addr,
				"err", err)
			return
		}
		slog.InfoContext(ctx, "nat: external address changed",
			"addr", addr)
	}
	tick()
	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}
