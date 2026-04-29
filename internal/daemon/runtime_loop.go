package daemon

import (
	"context"
	"encoding/hex"
	"log/slog"
	"sort"
	"sync"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// capacityResult is one MsgGetCapacity probe outcome.
type capacityResult struct {
	Used int64
	Max  int64
	OK   bool
	At   time.Time
}

// maxPerProbeTimeout is the upper bound on a single probe's deadline.
const maxPerProbeTimeout = 5 * time.Second

// capacityProbeFunc is the test seam for capacity probes.
var capacityProbeFunc = backup.SendGetCapacity

// perProbeTimeout returns min(interval/4, maxPerProbeTimeout).
func perProbeTimeout(interval time.Duration) time.Duration {
	t := interval / 4
	if t > maxPerProbeTimeout {
		t = maxPerProbeTimeout
	}
	return t
}

// probeAllCapacities probes every conn concurrently with a perProbe deadline.
func probeAllCapacities(ctx context.Context, conns []*bsquic.Conn, perProbe time.Duration, now func() time.Time) map[string]capacityResult {
	out := make(map[string]capacityResult, len(conns))
	var (
		mu sync.Mutex
		wg sync.WaitGroup
	)
	for _, c := range conns {
		pub := c.RemotePub()
		if len(pub) == 0 {
			continue
		}
		key := hex.EncodeToString(pub)
		wg.Add(1)
		go func(c *bsquic.Conn, key string) {
			defer wg.Done()
			pctx, cancel := context.WithTimeout(ctx, perProbe)
			defer cancel()
			used, max, err := capacityProbeFunc(pctx, c)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				out[key] = capacityResult{OK: false}
				return
			}
			out[key] = capacityResult{Used: used, Max: max, OK: true, At: now()}
		}(c, key)
	}
	wg.Wait()
	return out
}

// buildSnapshot composes a RuntimeSnapshot from gathered inputs and
// sorts Peers by hex(pubkey).
func buildSnapshot(base RuntimeSnapshot, knownPeers []peers.Peer, reach *swarm.ReachabilityMap, probedCaps map[string]capacityResult) RuntimeSnapshot {
	snap := base
	snap.Peers = nil
	seen := make(map[string]struct{})
	for _, p := range knownPeers {
		key := hex.EncodeToString(p.PubKey)
		cap := probedCaps[key]
		reachState := swarm.StateUnknown.String()
		if reach != nil {
			reachState = reach.State(p.PubKey).String()
		}
		snap.Peers = append(snap.Peers, RuntimePeerSnapshot{
			PubKeyHex:    key,
			Role:         p.Role.String(),
			Addr:         p.Addr,
			Reach:        reachState,
			RemoteUsed:   cap.Used,
			RemoteMax:    cap.Max,
			HasCapacity:  cap.OK,
			LastProbedAt: cap.At,
		})
		seen[key] = struct{}{}
	}
	if reach != nil {
		for k, s := range reach.Snapshot() {
			if _, ok := seen[k]; ok {
				continue
			}
			cap := probedCaps[k]
			snap.Peers = append(snap.Peers, RuntimePeerSnapshot{
				PubKeyHex:    k,
				Reach:        s.String(),
				RemoteUsed:   cap.Used,
				RemoteMax:    cap.Max,
				HasCapacity:  cap.OK,
				LastProbedAt: cap.At,
			})
			seen[k] = struct{}{}
		}
	}
	for k, cap := range probedCaps {
		if _, ok := seen[k]; ok {
			continue
		}
		snap.Peers = append(snap.Peers, RuntimePeerSnapshot{
			PubKeyHex:    k,
			Reach:        swarm.StateUnknown.String(),
			RemoteUsed:   cap.Used,
			RemoteMax:    cap.Max,
			HasCapacity:  cap.OK,
			LastProbedAt: cap.At,
		})
	}
	sort.Slice(snap.Peers, func(i, j int) bool {
		return snap.Peers[i].PubKeyHex < snap.Peers[j].PubKeyHex
	})
	return snap
}

// snapshotLoopOptions configures runSnapshotLoop.
type snapshotLoopOptions struct {
	dataDir      string
	interval     time.Duration
	listenAddr   string
	modeFn       func() string
	connsFn      func() []*bsquic.Conn
	lastScanFn   func() time.Time
	storeStatsFn func() (used, capacity int64)
	ownBackupFn  func() RuntimeOwnBackupSnapshot
	reach        *swarm.ReachabilityMap
	peerStore    *peers.Store
	nowFn        func() time.Time
}

// runSnapshotLoop publishes runtime.json on entry and once per opts.interval.
func runSnapshotLoop(ctx context.Context, opts snapshotLoopOptions) {
	if opts.nowFn == nil {
		opts.nowFn = time.Now
	}
	publish := func() {
		var known []peers.Peer
		if opts.peerStore != nil {
			list, err := opts.peerStore.List()
			if err != nil {
				slog.WarnContext(ctx, "list peers for snapshot", "err", err)
			} else {
				known = list
			}
		}
		base := RuntimeSnapshot{
			Mode:       opts.modeFn(),
			ListenAddr: opts.listenAddr,
			LastScanAt: opts.lastScanFn(),
		}
		if opts.storeStatsFn != nil {
			used, capacity := opts.storeStatsFn()
			base.LocalStore = RuntimeStoreSnapshot{Used: used, Capacity: capacity}
		}
		if opts.ownBackupFn != nil {
			base.OwnBackup = opts.ownBackupFn()
		}
		caps := probeAllCapacities(ctx, opts.connsFn(), perProbeTimeout(opts.interval), opts.nowFn)
		snap := buildSnapshot(base, known, opts.reach, caps)
		if err := WriteRuntimeSnapshot(opts.dataDir, snap); err != nil {
			slog.WarnContext(ctx, "write runtime snapshot", "err", err)
		}
	}
	publish()
	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			publish()
		}
	}
}
