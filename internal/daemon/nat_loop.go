package daemon

import (
	"context"
	"crypto/ed25519"
	"fmt"
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

// turnAddPermissionFunc is the test seam for installing a TURN allocation
// permission; production wraps (*nat.Allocation).AddPermission.
var turnAddPermissionFunc = func(alloc *nat.Allocation, ip net.IP) error {
	return alloc.AddPermission(ip)
}

// resolveTURNServerIP parses host:port and returns the host's IPv4 address,
// using net.ParseIP for literal IPs and falling back to DNS for hostnames.
func resolveTURNServerIP(server string) (net.IP, error) {
	host, _, err := net.SplitHostPort(server)
	if err != nil {
		return nil, fmt.Errorf("split host:port %q: %w", server, err)
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	addr, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", host, err)
	}
	return addr.IP, nil
}

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
	relayAddr   string
	connsFn     func() []*bsquic.Conn
}

// runNATLoop polls the STUN server every opts.interval and broadcasts
// AddressChanged (Addr + RelayAddr) to all live conns when the host
// changes. The first tick fires synchronously before the ticker.
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
		if err := broadcastAddressChangedFunc(ctx, opts.connsFn(), opts.pub, addr, opts.relayAddr); err != nil {
			slog.WarnContext(ctx, "nat: broadcast AddressChanged failed",
				"addr", addr,
				"err", err)
			return
		}
		slog.InfoContext(ctx, "nat: external address changed",
			"addr", addr,
			"relay_addr", opts.relayAddr)
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
