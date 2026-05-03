package daemon

import (
	"context"
	"crypto/ed25519"
	"log/slog"
	"math/rand"
	"net"
	"strconv"
	"time"

	"backupswarm/internal/nat"
	bsquic "backupswarm/internal/quic"
)

// portmapLoopOptions configures runPortMapLoop.
type portmapLoopOptions struct {
	mapper       nat.PortMapper
	initial      nat.Mapping
	internalPort int
	pub          ed25519.PublicKey
	connsFn      func() []*bsquic.Conn
}

// Refresh bounds; vars (not consts) so tests can shorten them.
var (
	defaultPortMapRefresh = 30 * time.Minute
	maxPortMapRefresh     = 24 * time.Hour
	minPortMapRefresh     = 30 * time.Second
	portMapAttemptTimeout = 10 * time.Second
)

// portmapMapFunc is the test seam for refresh-time Map calls; production
// invokes mapper.Map directly.
var portmapMapFunc = func(ctx context.Context, mapper nat.PortMapper, internalPort int) (nat.Mapping, error) {
	return mapper.Map(ctx, internalPort)
}

// portmapJitterFn returns a multiplier in [0.85, 1.15] for the next refresh
// interval. Swappable in tests.
var portmapJitterFn = func() float64 {
	return 0.85 + rand.Float64()*0.30
}

// runPortMapLoop refreshes the port mapping at lease/2 cadence and emits
// AddressChanged when the mapped external address changes. Best-effort:
// per-tick failures log and continue.
func runPortMapLoop(ctx context.Context, opts portmapLoopOptions) {
	current := opts.initial
	for {
		wait := nextPortMapRefresh(current.LeaseSeconds)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		mctx, cancel := context.WithTimeout(ctx, portMapAttemptTimeout)
		next, err := portmapMapFunc(mctx, opts.mapper, opts.internalPort)
		cancel()
		if err != nil {
			slog.WarnContext(ctx, "nat: port mapping refresh failed",
				"protocol", current.Protocol,
				"err", err,
			)
			continue
		}
		if portMapAddrEqual(next, current) {
			current = next
			continue
		}
		previous := current
		current = next
		addr := net.JoinHostPort(next.ExternalIP.String(), strconv.Itoa(next.ExternalPort))
		if err := broadcastAddressChangedFunc(ctx, opts.connsFn(), opts.pub, addr); err != nil {
			slog.WarnContext(ctx, "nat: port mapping broadcast AddressChanged failed",
				"addr", addr,
				"err", err,
			)
			continue
		}
		slog.InfoContext(ctx, "nat: port mapping changed",
			"protocol", next.Protocol,
			"prev_addr", net.JoinHostPort(previous.ExternalIP.String(), strconv.Itoa(previous.ExternalPort)),
			"addr", addr,
		)
	}
}

// nextPortMapRefresh derives a jittered refresh interval from the lease.
func nextPortMapRefresh(leaseSeconds int) time.Duration {
	base := defaultPortMapRefresh
	if leaseSeconds > 0 {
		base = time.Duration(leaseSeconds/2) * time.Second
	}
	if base < minPortMapRefresh {
		base = minPortMapRefresh
	}
	if base > maxPortMapRefresh {
		base = maxPortMapRefresh
	}
	scaled := time.Duration(float64(base) * portmapJitterFn())
	return scaled
}

func portMapAddrEqual(a, b nat.Mapping) bool {
	if a.ExternalPort != b.ExternalPort {
		return false
	}
	if !a.ExternalIP.Equal(b.ExternalIP) {
		return false
	}
	return true
}

// portFromListenerAddr extracts the integer port from a host:port string.
// Used by daemon.Run to derive the internal port for the port-mapping
// loop.
func portFromListenerAddr(addr string) (int, error) {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(p)
}
