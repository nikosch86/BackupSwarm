package daemon

import (
	"context"
	"sync"
	"time"

	"backupswarm/internal/backup"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// pingProbeFunc is the test seam for liveness probes.
var pingProbeFunc = backup.SendPing

// heartbeatLoopOptions configures runHeartbeatLoop.
type heartbeatLoopOptions struct {
	interval time.Duration
	connsFn  func() []*bsquic.Conn
	reach    *swarm.ReachabilityMap
}

// probeAllPings sends Ping to every conn concurrently and records the
// outcome via reach.RecordHeartbeat.
func probeAllPings(ctx context.Context, conns []*bsquic.Conn, reach *swarm.ReachabilityMap, perProbe time.Duration) {
	var wg sync.WaitGroup
	for _, c := range conns {
		if c == nil {
			continue
		}
		pub := c.RemotePub()
		if len(pub) == 0 {
			continue
		}
		pubCopy := append([]byte(nil), pub...)
		wg.Add(1)
		go func(c *bsquic.Conn, pub []byte) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, perProbe)
			defer cancel()
			err := pingProbeFunc(pctx, c)
			reach.RecordHeartbeat(pub, err == nil)
		}(c, pubCopy)
	}
	wg.Wait()
}

// runHeartbeatLoop ticks every opts.interval, fanning out probeAllPings
// across opts.connsFn().
func runHeartbeatLoop(ctx context.Context, opts heartbeatLoopOptions) {
	perProbe := perProbeTimeout(opts.interval)
	tick := func() {
		probeAllPings(ctx, opts.connsFn(), opts.reach, perProbe)
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
