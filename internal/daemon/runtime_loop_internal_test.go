package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

func mkPeer(role peers.Role, addr string, pub ...byte) peers.Peer {
	p := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(p, pub)
	return peers.Peer{Addr: addr, PubKey: p, Role: role}
}

func TestBuildSnapshot_EmptyInputs(t *testing.T) {
	snap := buildSnapshot(RuntimeSnapshot{Mode: "idle", ListenAddr: "127.0.0.1:7777"}, nil, nil, nil)
	if snap.Mode != "idle" {
		t.Errorf("Mode = %q, want idle", snap.Mode)
	}
	if snap.ListenAddr != "127.0.0.1:7777" {
		t.Errorf("ListenAddr = %q, want 127.0.0.1:7777", snap.ListenAddr)
	}
	if len(snap.Peers) != 0 {
		t.Errorf("Peers = %+v, want empty", snap.Peers)
	}
}

func TestBuildSnapshot_KnownPeer_NoReach_NoCapacity(t *testing.T) {
	known := []peers.Peer{mkPeer(peers.RoleStorage, "10.0.0.1:7777", 0x01, 0x02, 0x03)}
	snap := buildSnapshot(RuntimeSnapshot{Mode: "reconcile", ListenAddr: "addr"}, known, nil, nil)
	if len(snap.Peers) != 1 {
		t.Fatalf("Peers len = %d, want 1", len(snap.Peers))
	}
	p := snap.Peers[0]
	if p.PubKeyHex[:6] != "010203" {
		t.Errorf("PubKeyHex prefix = %q, want 010203", p.PubKeyHex[:6])
	}
	if p.Role != "storage" {
		t.Errorf("Role = %q, want storage", p.Role)
	}
	if p.Addr != "10.0.0.1:7777" {
		t.Errorf("Addr = %q, want 10.0.0.1:7777", p.Addr)
	}
	if p.Reach != "unknown" {
		t.Errorf("Reach = %q, want unknown", p.Reach)
	}
	if p.HasCapacity {
		t.Error("HasCapacity = true with no probes")
	}
}

func TestBuildSnapshot_KnownPeer_ReachAndCapacityMerged(t *testing.T) {
	pub := make([]byte, ed25519.PublicKeySize)
	pub[0], pub[1], pub[2] = 0x01, 0x02, 0x03
	known := []peers.Peer{{Addr: "10.0.0.1:7777", PubKey: pub, Role: peers.RoleIntroducer}}

	reach := swarm.NewReachabilityMap()
	reach.Mark(pub, swarm.StateReachable)

	when := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	caps := map[string]capacityResult{
		hex.EncodeToString(pub): {Used: 100, Max: 1000, OK: true, At: when},
	}

	snap := buildSnapshot(RuntimeSnapshot{Mode: "reconcile", ListenAddr: "addr"}, known, reach, caps)
	if len(snap.Peers) != 1 {
		t.Fatalf("Peers len = %d, want 1", len(snap.Peers))
	}
	p := snap.Peers[0]
	if p.Role != "introducer" || p.Addr != "10.0.0.1:7777" || p.Reach != "reachable" || !p.HasCapacity || p.RemoteUsed != 100 || p.RemoteMax != 1000 {
		t.Errorf("merged peer = %+v", p)
	}
	if !p.LastProbedAt.Equal(when) {
		t.Errorf("LastProbedAt = %v, want %v", p.LastProbedAt, when)
	}
}

func TestBuildSnapshot_ReachOnly_NotInPeersDB(t *testing.T) {
	// A peer reach knows about but peers.db doesn't (rare edge case —
	// e.g. a join handshake conn before the persisted-peer announcement
	// lands). Should still appear; role/addr empty.
	reach := swarm.NewReachabilityMap()
	reach.Mark([]byte{0x04, 0x05, 0x06}, swarm.StateReachable)
	snap := buildSnapshot(RuntimeSnapshot{Mode: "reconcile", ListenAddr: "addr"}, nil, reach, nil)
	if len(snap.Peers) != 1 {
		t.Fatalf("Peers len = %d, want 1", len(snap.Peers))
	}
	p := snap.Peers[0]
	if p.Role != "" || p.Addr != "" {
		t.Errorf("expected empty role/addr for non-peers.db entry, got role=%q addr=%q", p.Role, p.Addr)
	}
	if p.Reach != "reachable" {
		t.Errorf("Reach = %q, want reachable", p.Reach)
	}
}

func TestBuildSnapshot_FailedProbeKeepsKnownPeerEntry(t *testing.T) {
	pub := make([]byte, ed25519.PublicKeySize)
	pub[0] = 0x01
	known := []peers.Peer{{Addr: "10.0.0.1:7777", PubKey: pub, Role: peers.RolePeer}}
	caps := map[string]capacityResult{hex.EncodeToString(pub): {OK: false}}
	snap := buildSnapshot(RuntimeSnapshot{Mode: "reconcile", ListenAddr: "addr"}, known, nil, caps)
	if len(snap.Peers) != 1 {
		t.Fatalf("Peers len = %d, want 1", len(snap.Peers))
	}
	p := snap.Peers[0]
	if p.HasCapacity {
		t.Error("HasCapacity = true after failed probe, want false")
	}
	if p.RemoteUsed != 0 || p.RemoteMax != 0 {
		t.Errorf("Used=%d Max=%d after failed probe, want 0/0", p.RemoteUsed, p.RemoteMax)
	}
}

func TestBuildSnapshot_PeersSortedByHex(t *testing.T) {
	known := []peers.Peer{
		mkPeer(peers.RolePeer, "a", 0xff),
		mkPeer(peers.RolePeer, "b", 0x00),
		mkPeer(peers.RolePeer, "c", 0x80),
	}
	snap := buildSnapshot(RuntimeSnapshot{Mode: "reconcile", ListenAddr: "addr"}, known, nil, nil)
	if len(snap.Peers) != 3 {
		t.Fatalf("Peers len = %d, want 3", len(snap.Peers))
	}
	keys := []string{snap.Peers[0].PubKeyHex, snap.Peers[1].PubKeyHex, snap.Peers[2].PubKeyHex}
	if !sort.StringsAreSorted(keys) {
		t.Errorf("peers not sorted: %v", keys)
	}
}

func TestBuildSnapshot_LastScanAtPreserved(t *testing.T) {
	when := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	snap := buildSnapshot(RuntimeSnapshot{Mode: "reconcile", ListenAddr: "addr", LastScanAt: when}, nil, nil, nil)
	if !snap.LastScanAt.Equal(when) {
		t.Errorf("LastScanAt = %v, want %v", snap.LastScanAt, when)
	}
}

func TestBuildSnapshot_OwnBackupPreserved(t *testing.T) {
	own := RuntimeOwnBackupSnapshot{Files: 5, Bytes: 1024, Chunks: 7, ReplMin: 1, ReplMax: 3, ReplAvg: 2.0}
	snap := buildSnapshot(RuntimeSnapshot{Mode: "reconcile", ListenAddr: "addr", OwnBackup: own}, nil, nil, nil)
	if snap.OwnBackup != own {
		t.Errorf("OwnBackup = %+v, want %+v", snap.OwnBackup, own)
	}
}

// TestSnapshotLoop_OwnBackupFnLandsInPublishedSnapshot drives the loop
// with a stubbed ownBackupFn and asserts the value reaches runtime.json.
func TestSnapshotLoop_OwnBackupFnLandsInPublishedSnapshot(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())

	fixed := RuntimeOwnBackupSnapshot{Files: 7, Bytes: 1234, Chunks: 11, ReplMin: 1, ReplMax: 3, ReplAvg: 2.0}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runSnapshotLoop(ctx, snapshotLoopOptions{
			dataDir:     dir,
			interval:    time.Hour, // first publish runs synchronously before the ticker
			listenAddr:  "addr",
			modeFn:      func() string { return "reconcile" },
			connsFn:     func() []*bsquic.Conn { return nil },
			lastScanFn:  func() time.Time { return time.Time{} },
			ownBackupFn: func() RuntimeOwnBackupSnapshot { return fixed },
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	var snap RuntimeSnapshot
	for {
		var err error
		snap, err = ReadRuntimeSnapshot(dir)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("snapshot never appeared: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	if snap.OwnBackup != fixed {
		t.Errorf("snap.OwnBackup = %+v, want %+v", snap.OwnBackup, fixed)
	}
}

// TestSnapshotLoop_ModeFnReadEachTick asserts runSnapshotLoop calls
// modeFn fresh on every publish, so a value swap between ticks lands
// in the next runtime.json.
func TestSnapshotLoop_ModeFnReadEachTick(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())

	var mode atomic.Pointer[string]
	initial := "restore"
	mode.Store(&initial)

	done := make(chan struct{})
	go func() {
		defer close(done)
		runSnapshotLoop(ctx, snapshotLoopOptions{
			dataDir:    dir,
			interval:   30 * time.Millisecond,
			listenAddr: "addr",
			modeFn:     func() string { return *mode.Load() },
			connsFn:    func() []*bsquic.Conn { return nil },
			lastScanFn: func() time.Time { return time.Time{} },
		})
	}()
	defer func() {
		cancel()
		<-done
	}()

	awaitSnapshotMode(t, dir, "restore")

	next := "reconcile"
	mode.Store(&next)
	awaitSnapshotMode(t, dir, "reconcile")
}

// awaitSnapshotMode polls runtime.json in dir until snap.Mode == want
// or 2s elapses.
func awaitSnapshotMode(t *testing.T, dir, want string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		snap, err := ReadRuntimeSnapshot(dir)
		if err == nil && snap.Mode == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	snap, _ := ReadRuntimeSnapshot(dir)
	t.Fatalf("snapshot.Mode = %q, want %q", snap.Mode, want)
}

// TestSnapshotLoop_NilOwnBackupFnLeavesZero asserts a nil ownBackupFn
// doesn't crash and leaves OwnBackup at its zero value.
func TestSnapshotLoop_NilOwnBackupFnLeavesZero(t *testing.T) {
	dir := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		defer close(done)
		runSnapshotLoop(ctx, snapshotLoopOptions{
			dataDir:    dir,
			interval:   time.Hour,
			listenAddr: "addr",
			modeFn:     func() string { return "storage-only" },
			connsFn:    func() []*bsquic.Conn { return nil },
			lastScanFn: func() time.Time { return time.Time{} },
			// ownBackupFn intentionally nil
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	var snap RuntimeSnapshot
	for {
		var err error
		snap, err = ReadRuntimeSnapshot(dir)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("snapshot never appeared: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done

	if snap.OwnBackup != (RuntimeOwnBackupSnapshot{}) {
		t.Errorf("OwnBackup = %+v, want zero value with nil ownBackupFn", snap.OwnBackup)
	}
}

// newProbeConn dials a fresh listener and returns the dialer-side conn
// plus the listener's pubkey (== conn.RemotePub()). The listener accepts
// once and holds the conn until cleanup.
func newProbeConn(t *testing.T) (*bsquic.Conn, ed25519.PublicKey) {
	t.Helper()
	listenerPub, listenerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("listener key: %v", err)
	}
	_, dialerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("dialer key: %v", err)
	}

	listener, err := bsquic.Listen("127.0.0.1:0", listenerPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := listener.Accept(ctx)
		if err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
	}()

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), dialerPriv, listenerPub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return conn, listenerPub
}

// TestProbeAllCapacities_SlowProbeBoundedByTimeout asserts a slow probe
// is cancelled by the per-probe timeout, recorded as OK:false, and does
// not block fast probes from completing.
func TestProbeAllCapacities_SlowProbeBoundedByTimeout(t *testing.T) {
	slowConn, slowPub := newProbeConn(t)
	fastConn, fastPub := newProbeConn(t)

	timeout := 100 * time.Millisecond

	orig := capacityProbeFunc
	t.Cleanup(func() { capacityProbeFunc = orig })
	capacityProbeFunc = func(ctx context.Context, c *bsquic.Conn) (int64, int64, error) {
		if bytes.Equal(c.RemotePub(), slowPub) {
			select {
			case <-time.After(10 * time.Second):
				return 0, 0, nil
			case <-ctx.Done():
				return 0, 0, ctx.Err()
			}
		}
		return 100, 1000, nil
	}

	start := time.Now()
	out := probeAllCapacities(context.Background(), []*bsquic.Conn{slowConn, fastConn}, timeout, time.Now)
	elapsed := time.Since(start)

	maxAcceptable := timeout + 500*time.Millisecond
	if elapsed > maxAcceptable {
		t.Fatalf("probeAllCapacities took %v, want < %v (timeout + slop)", elapsed, maxAcceptable)
	}
	if got, ok := out[hex.EncodeToString(slowPub)]; !ok || got.OK {
		t.Errorf("slow peer = %+v, want present with OK=false", got)
	}
	got := out[hex.EncodeToString(fastPub)]
	if !got.OK || got.Used != 100 || got.Max != 1000 {
		t.Errorf("fast peer = %+v, want OK=true Used=100 Max=1000", got)
	}
}

// TestProbeAllCapacities_FanOutIsConcurrent asserts probes run in parallel:
// two probes that each take ~probeDelay finish in roughly probeDelay
// wall-time, not 2*probeDelay.
func TestProbeAllCapacities_FanOutIsConcurrent(t *testing.T) {
	connA, _ := newProbeConn(t)
	connB, _ := newProbeConn(t)

	probeDelay := 80 * time.Millisecond
	timeout := 500 * time.Millisecond

	orig := capacityProbeFunc
	t.Cleanup(func() { capacityProbeFunc = orig })
	capacityProbeFunc = func(ctx context.Context, c *bsquic.Conn) (int64, int64, error) {
		select {
		case <-time.After(probeDelay):
			return 1, 2, nil
		case <-ctx.Done():
			return 0, 0, ctx.Err()
		}
	}

	start := time.Now()
	out := probeAllCapacities(context.Background(), []*bsquic.Conn{connA, connB}, timeout, time.Now)
	elapsed := time.Since(start)

	if elapsed >= 2*probeDelay {
		t.Fatalf("probeAllCapacities took %v with 2 conns × %v probe; serial behavior detected", elapsed, probeDelay)
	}
	if len(out) != 2 {
		t.Fatalf("len(out) = %d, want 2 (got %+v)", len(out), out)
	}
	for k, v := range out {
		if !v.OK || v.Used != 1 || v.Max != 2 {
			t.Errorf("peer %s = %+v, want OK=true Used=1 Max=2", k, v)
		}
	}
}

// TestPerProbeTimeout asserts the helper's interval-driven timeout cap.
func TestPerProbeTimeout(t *testing.T) {
	tests := []struct {
		name     string
		interval time.Duration
		want     time.Duration
	}{
		{"short interval picks interval/4", 4 * time.Second, 1 * time.Second},
		{"long interval caps at 5s", 60 * time.Second, 5 * time.Second},
		{"exactly at 20s clamps at interval/4 = 5s", 20 * time.Second, 5 * time.Second},
		{"22s caps at 5s", 22 * time.Second, 5 * time.Second},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := perProbeTimeout(tc.interval); got != tc.want {
				t.Errorf("perProbeTimeout(%v) = %v, want %v", tc.interval, got, tc.want)
			}
		})
	}
}
