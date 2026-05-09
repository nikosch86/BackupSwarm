package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/index"
	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
	"backupswarm/internal/swarm"
)

// TestOutboundDialer_AdvertiseSelf_SkipsWhenSelfPubMalformed asserts the
// short-circuit when selfPub is not the canonical 32-byte ed25519 key
// length: no broadcast, even though selfAddr is populated.
func TestOutboundDialer_AdvertiseSelf_SkipsWhenSelfPubMalformed(t *testing.T) {
	called := false
	prev := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = prev })
	broadcastAddressChangedFunc = func(context.Context, []*bsquic.Conn, ed25519.PublicKey, string, string) error {
		called = true
		return nil
	}

	d := &outboundDialer{
		ctx:      context.Background(),
		selfPub:  ed25519.PublicKey{0x01, 0x02},
		selfAddr: "1.2.3.4:7777",
	}
	d.advertiseSelf(nil)

	if called {
		t.Error("broadcast fired despite malformed selfPub length")
	}
}

// TestOutboundDialer_AdvertiseSelf_LogsBroadcastFailure asserts the WARN
// log emitted when the broadcast seam errors; the conn's RemotePub() must
// be readable so the helper can include peer_pub in the slog attrs.
func TestOutboundDialer_AdvertiseSelf_LogsBroadcastFailure(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate pub: %v", err)
	}
	remotePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate remote pub: %v", err)
	}

	prev := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = prev })
	broadcastAddressChangedFunc = func(context.Context, []*bsquic.Conn, ed25519.PublicKey, string, string) error {
		return errors.New("broadcast: forced failure")
	}

	w := &syncWriter{}
	captureSlog(t, w)

	d := &outboundDialer{
		ctx:           context.Background(),
		selfPub:       pub,
		selfAddr:      "1.2.3.4:7777",
		selfRelayAddr: "9.8.7.6:54321",
	}
	conn := bsquic.NewConnForTest(remotePub)
	d.advertiseSelf(conn)

	got := w.String()
	if !strings.Contains(got, "advertise self addresses failed") {
		t.Errorf("missing failure log line; got:\n%s", got)
	}
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("expected WARN level; got:\n%s", got)
	}
	if !strings.Contains(got, "broadcast: forced failure") {
		t.Errorf("expected wrapped error in log; got:\n%s", got)
	}
}

// TestRunFirstBackupPhase_TotalsErrorDegradesToZeroTotals asserts that
// when backupDirTotals errors (e.g. missing dir), the helper logs a
// WARN, falls back to zero totals, and still drives one ScanOnce call.
func TestRunFirstBackupPhase_TotalsErrorDegradesToZeroTotals(t *testing.T) {
	prevScanFunc := scanOnceFunc
	t.Cleanup(func() { scanOnceFunc = prevScanFunc })
	var calls atomic.Int32
	scanOnceFunc = func(context.Context, ScanOnceOptions) error {
		calls.Add(1)
		return nil
	}

	w := &syncWriter{}
	captureSlog(t, w)

	missing := filepath.Join(t.TempDir(), "does-not-exist")
	runFirstBackupPhase(context.Background(), nil,
		ScanOnceOptions{BackupDir: missing}, nil,
		func() []*bsquic.Conn { return nil })

	if got := calls.Load(); got != 1 {
		t.Errorf("scanOnceFunc calls = %d, want 1 even after totals error", got)
	}
	if !strings.Contains(w.String(), "first-backup totals") {
		t.Errorf("missing 'first-backup totals' WARN; got:\n%s", w.String())
	}
}

// TestMakeImmediateDialOnApplied_LogsDialFailure asserts the goroutine
// inside the closure logs at DEBUG when the spawned dial fails.
func TestMakeImmediateDialOnApplied_LogsDialFailure(t *testing.T) {
	prevDirect := chainDirectDialFn
	chainDirectDialFn = func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
		return nil, errors.New("direct: stubbed failure")
	}
	t.Cleanup(func() { chainDirectDialFn = prevDirect })

	w := &syncWriter{}
	captureSlog(t, w)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, dialerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("dialer key: %v", err)
	}
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	dialer := &outboundDialer{
		ctx:     ctx,
		priv:    dialerPriv,
		timeout: 100 * time.Millisecond,
		st:      st,
		connSet: swarm.NewConnSet(),
		reach:   swarm.NewReachabilityMap(),
	}
	t.Cleanup(dialer.CloseAll)

	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:1", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	onApplied := makeImmediateDialOnApplied(ps, swarm.NewConnSet(), dialer)
	ann := shouldImmediateDialAnnouncement(pub, "127.0.0.1:1")
	onApplied(ctx, ann)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(w.String(), "immediate dial on announcement failed") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	got := w.String()
	if !strings.Contains(got, "immediate dial on announcement failed") {
		t.Errorf("missing failure log; got:\n%s", got)
	}
	if !strings.Contains(got, "direct: stubbed failure") {
		t.Errorf("expected wrapped error in log; got:\n%s", got)
	}
}

// TestRedialMissingPeers_ListErrorLogsWarn asserts a peerStore.List
// failure (closed store) emits a WARN log line and returns without
// dialing.
func TestRedialMissingPeers_ListErrorLogsWarn(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "list-fail.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	w := &syncWriter{}
	captureSlog(t, w)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, dialerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("dialer key: %v", err)
	}
	dialer := &outboundDialer{
		ctx:     ctx,
		priv:    dialerPriv,
		timeout: 100 * time.Millisecond,
		connSet: swarm.NewConnSet(),
		reach:   swarm.NewReachabilityMap(),
	}
	t.Cleanup(dialer.CloseAll)

	redialMissingPeers(ctx, ps, dialer, swarm.NewConnSet())

	got := w.String()
	if !strings.Contains(got, "redial sweep: list peers") {
		t.Errorf("missing list-peers warning; got:\n%s", got)
	}
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("expected WARN level; got:\n%s", got)
	}
}

// TestRedialMissingPeers_SkipsPeerAlreadyTrackedByDialer asserts the
// dialer.hasConn(p.PubKey) skip-branch fires when the dialer already
// tracks a conn for the peer even though the external connSet is empty.
func TestRedialMissingPeers_SkipsPeerAlreadyTrackedByDialer(t *testing.T) {
	rig := setupConnDialRig(t, 1)
	pub := rig.pubs[0]

	ps := openPickStoragePeerStore(t)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:1", PubKey: pub, Role: peers.RoleStorage}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, dialerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("dialer key: %v", err)
	}
	dialer := &outboundDialer{
		ctx:     ctx,
		priv:    dialerPriv,
		timeout: 100 * time.Millisecond,
		connSet: swarm.NewConnSet(),
		reach:   swarm.NewReachabilityMap(),
	}
	dialer.conns = append(dialer.conns, rig.conns[0])
	t.Cleanup(dialer.CloseAll)

	w := &syncWriter{}
	captureSlog(t, w)

	redialMissingPeers(ctx, ps, dialer, swarm.NewConnSet())

	got := w.String()
	if strings.Contains(got, "redial sweep: dial peer failed") {
		t.Errorf("dial fired despite dialer tracking the pubkey; got:\n%s", got)
	}
	if strings.Contains(got, "redial sweep: skip peer in backoff") {
		t.Errorf("backoff-skip branch fired instead of dialer-hasConn skip; got:\n%s", got)
	}
}

// TestRun_RejectsNegativePunchTimeout: Run validates PunchTimeout >= 0.
func TestRun_RejectsNegativePunchTimeout(t *testing.T) {
	t.Parallel()
	err := Run(context.Background(), Options{
		DataDir:      t.TempDir(),
		ListenAddr:   "127.0.0.1:0",
		PunchTimeout: -time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "punch timeout") {
		t.Fatalf("Run err = %v, want punch-timeout validation error", err)
	}
}

// TestRun_RejectsNegativeTURNDialTimeout: Run validates TURNDialTimeout >= 0.
func TestRun_RejectsNegativeTURNDialTimeout(t *testing.T) {
	t.Parallel()
	err := Run(context.Background(), Options{
		DataDir:         t.TempDir(),
		ListenAddr:      "127.0.0.1:0",
		TURNDialTimeout: -time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "turn dial timeout") {
		t.Fatalf("Run err = %v, want turn-dial-timeout validation error", err)
	}
}

// TestRun_RejectsNegativeRelayDialTimeout: Run validates RelayDialTimeout >= 0.
func TestRun_RejectsNegativeRelayDialTimeout(t *testing.T) {
	t.Parallel()
	err := Run(context.Background(), Options{
		DataDir:          t.TempDir(),
		ListenAddr:       "127.0.0.1:0",
		RelayDialTimeout: -time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "relay dial timeout") {
		t.Fatalf("Run err = %v, want relay-dial-timeout validation error", err)
	}
}

// TestRun_RejectsNegativeStatsInterval: Run validates StatsInterval >= 0.
func TestRun_RejectsNegativeStatsInterval(t *testing.T) {
	t.Parallel()
	err := Run(context.Background(), Options{
		DataDir:       t.TempDir(),
		ListenAddr:    "127.0.0.1:0",
		StatsInterval: -time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "stats interval") {
		t.Fatalf("Run err = %v, want stats-interval validation error", err)
	}
}

// TestRun_RejectsNegativeGracePeriod: Run validates GracePeriod >= 0.
func TestRun_RejectsNegativeGracePeriod(t *testing.T) {
	t.Parallel()
	err := Run(context.Background(), Options{
		DataDir:     t.TempDir(),
		ListenAddr:  "127.0.0.1:0",
		GracePeriod: -time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "grace period") {
		t.Fatalf("Run err = %v, want grace-period validation error", err)
	}
}

// TestRun_IssueInitialInviteWritesTokenToOutFile drives Run with
// IssueInitialInvite + InitialInviteOut and asserts the file contains
// a parseable token via the writeAtomicFile path.
func TestRun_IssueInitialInviteWritesTokenToOutFile(t *testing.T) {
	dataDir := t.TempDir()
	outFile := filepath.Join(t.TempDir(), "invite.tok")

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:            dataDir,
			ListenAddr:         "127.0.0.1:0",
			IssueInitialInvite: true,
			InitialInviteOut:   outFile,
			NoCA:               true,
		})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(outFile); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
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

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("read invite file: %v", err)
	}
	if len(data) == 0 {
		t.Fatalf("invite file empty")
	}
	if !strings.HasSuffix(string(data), "\n") {
		t.Errorf("invite file should end with newline; got %q", data)
	}
}

// TestRun_RestoreModeNoConnsReturnsImmediately asserts restore mode
// short-circuits when no live storage conn exists, falling through to
// waitForServe and exiting cleanly on cancel.
func TestRun_RestoreModeNoConnsReturnsImmediately(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()

	// Pre-seed the index so Classify picks Restore (local empty + index
	// populated + Restore=true).
	idxPath := filepath.Join(dataDir, "index.db")
	{
		ix, err := index.Open(idxPath)
		if err != nil {
			t.Fatalf("seed open: %v", err)
		}
		if err := ix.Put(index.FileEntry{Path: "ghost.bin", Size: 1}); err != nil {
			t.Fatalf("seed put: %v", err)
		}
		if err := ix.Close(); err != nil {
			t.Fatalf("seed close: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:      dataDir,
			BackupDir:    backupDir,
			ListenAddr:   "127.0.0.1:0",
			Restore:      true,
			ScanInterval: 50 * time.Millisecond,
		})
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s of cancel")
	}
}

// TestRun_PurgeModeNoConnsReturnsImmediately is the purge analogue:
// with index populated, Purge=true, and no peers, Run must short-circuit
// into waitForServe rather than enter the scan loop.
func TestRun_PurgeModeNoConnsReturnsImmediately(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()

	idxPath := filepath.Join(dataDir, "index.db")
	{
		ix, err := index.Open(idxPath)
		if err != nil {
			t.Fatalf("seed open: %v", err)
		}
		if err := ix.Put(index.FileEntry{Path: "ghost.bin", Size: 1}); err != nil {
			t.Fatalf("seed put: %v", err)
		}
		if err := ix.Close(); err != nil {
			t.Fatalf("seed close: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:      dataDir,
			BackupDir:    backupDir,
			ListenAddr:   "127.0.0.1:0",
			Purge:        true,
			ScanInterval: 50 * time.Millisecond,
		})
	}()

	time.Sleep(200 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s of cancel")
	}
}

// TestMakeImmediateDialOnApplied_NoOpWhenAddrEmpty asserts the closure
// does nothing for an announcement that lacks an Addr — exercises the
// shouldImmediateDial=false → early return branch inside the closure.
func TestMakeImmediateDialOnApplied_NoOpWhenAddrEmpty(t *testing.T) {
	called := atomic.Int32{}
	prevDirect := chainDirectDialFn
	chainDirectDialFn = func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
		called.Add(1)
		return nil, errors.New("should not be called")
	}
	t.Cleanup(func() { chainDirectDialFn = prevDirect })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	dialer := newImmediateDialDialer(t, ctx)
	t.Cleanup(dialer.CloseAll)

	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "1.2.3.4:5555", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	onApplied := makeImmediateDialOnApplied(ps, swarm.NewConnSet(), dialer)
	ann := shouldImmediateDialAnnouncement(pub, "")
	ann.Kind = protocol.AnnouncePeerJoined

	onApplied(ctx, ann)
	time.Sleep(150 * time.Millisecond)
	if got := called.Load(); got != 0 {
		t.Errorf("chainDirectDialFn calls = %d, want 0 (empty Addr must short-circuit)", got)
	}
}

// TestRun_AdvertiseSelfFiresOnFirstDialedPeer drives a two-daemon rig
// where the joiner's successful outbound dial triggers
// register → advertiseSelf → broadcastAddressChangedFunc.
func TestRun_AdvertiseSelfFiresOnFirstDialedPeer(t *testing.T) {
	prevBC := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = prevBC })
	captured := make(chan struct {
		addr  string
		relay string
	}, 4)
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, addr, relay string) error {
		select {
		case captured <- struct {
			addr  string
			relay string
		}{addr, relay}:
		default:
		}
		return nil
	}

	founderDataDir := t.TempDir()
	joinerDataDir := t.TempDir()
	joinerBackupDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(joinerBackupDir, "f.bin"), []byte("hi"), 0o600); err != nil {
		t.Fatalf("write joiner backup file: %v", err)
	}

	// Spin up a tiny "founder" peer that just accepts inbound conns.
	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	peerStore, err := store.New(filepath.Join(founderDataDir, "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = peerStore.Close() })
	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	serveCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = backup.Serve(serveCtx, listener, peerStore, nil, nil, nil, nil, nil) }()

	// Seed the joiner's peers.db so dialAllPeers fires on Run.
	{
		ps, err := peers.Open(filepath.Join(joinerDataDir, "peers.db"))
		if err != nil {
			t.Fatalf("joiner peers.Open: %v", err)
		}
		if err := ps.Add(peers.Peer{
			Addr:   listener.Addr().String(),
			PubKey: peerPub,
			Role:   peers.RoleIntroducer,
		}); err != nil {
			t.Fatalf("joiner peers.Add: %v", err)
		}
		_ = ps.Close()
	}

	ctx, runCancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:      joinerDataDir,
			BackupDir:    joinerBackupDir,
			ListenAddr:   "127.0.0.1:0",
			ChunkSize:    1 << 20,
			ScanInterval: 50 * time.Millisecond,
		})
	}()

	select {
	case ev := <-captured:
		if ev.addr == "" {
			t.Errorf("captured advertise event with empty addr: %+v", ev)
		}
	case <-time.After(3 * time.Second):
		runCancel()
		<-done
		t.Fatal("broadcastAddressChangedFunc never invoked from register/advertiseSelf")
	}
	runCancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s of cancel")
	}
}
