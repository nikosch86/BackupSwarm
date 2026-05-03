package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/index"
	"backupswarm/internal/invites"
	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
	"backupswarm/internal/swarm"
)

// openPickStoragePeerStore opens a fresh peers.db and registers a
// t.Cleanup for it.
func openPickStoragePeerStore(t *testing.T) *peers.Store {
	t.Helper()
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	return ps
}

func mustGenPub(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return pub
}

// TestWarnIfOverCap_OverCapEmitsSlogAndProgress: when used > capacity,
// the helper writes both an slog warning and a human-readable progress
// line so an operator notices the cap is below current on-disk usage.
func TestWarnIfOverCap_OverCapEmitsSlogAndProgress(t *testing.T) {
	w := &syncWriter{}
	captureSlog(t, w)

	var progress strings.Builder
	warnIfOverCap(context.Background(), 200, 100, &progress)

	logged := w.String()
	if !strings.Contains(logged, "stored bytes exceed configured max-storage") {
		t.Errorf("slog output missing warning: %q", logged)
	}
	if !strings.Contains(logged, "used_bytes=200") || !strings.Contains(logged, "max_bytes=100") || !strings.Contains(logged, "over_by_bytes=100") {
		t.Errorf("slog output missing structured fields: %q", logged)
	}
	if !strings.Contains(progress.String(), "exceeds --max-storage") {
		t.Errorf("progress output missing warning: %q", progress.String())
	}
}

// TestWarnIfOverCap_UnderCapSilent: usage at or below the cap (or
// unlimited cap) emits nothing — operators only hear from the helper
// when they need to act.
func TestWarnIfOverCap_UnderCapSilent(t *testing.T) {
	cases := []struct {
		name           string
		used, capacity int64
	}{
		{"unlimited", 1 << 30, 0},
		{"under cap", 50, 100},
		{"exactly at cap", 100, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &syncWriter{}
			captureSlog(t, w)
			var progress strings.Builder
			warnIfOverCap(context.Background(), tc.used, tc.capacity, &progress)
			if got := w.String(); got != "" {
				t.Errorf("slog wrote %q, want empty", got)
			}
			if got := progress.String(); got != "" {
				t.Errorf("progress wrote %q, want empty", got)
			}
		})
	}
}

// TestPollPendingInvites_TracksIssueAndConsume runs the poll loop with
// a tight interval, then issues + consumes an invite via a separate
// Open and asserts the cache reflects each transition within a few
// poll ticks.
func TestPollPendingInvites_TracksIssueAndConsume(t *testing.T) {
	dir := t.TempDir()
	pc := &pendingCache{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	const tick = 50 * time.Millisecond
	pollDone := make(chan struct{})
	go func() {
		defer close(pollDone)
		pollPendingInvites(ctx, dir, pc, tick)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-pollDone:
		case <-time.After(2 * time.Second):
			t.Error("poll loop did not exit within 2s of cancel")
		}
	})

	// Initial state: empty file → cache settles at 0.
	if got := pc.n.Load(); got != 0 {
		t.Errorf("initial cache = %d, want 0", got)
	}

	// Issue one invite via a separate Open (the poll loop briefly
	// releases the flock between ticks).
	openInvites := func() *invites.Store {
		s, err := invites.Open(filepath.Join(dir, invites.DefaultFilename))
		if err != nil {
			t.Fatalf("invites.Open: %v", err)
		}
		return s
	}
	store := openInvites()
	var secret, swarmID [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatalf("rand secret: %v", err)
	}
	if _, err := rand.Read(swarmID[:]); err != nil {
		t.Fatalf("rand swarmID: %v", err)
	}
	if err := store.Issue(secret, swarmID); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	_ = store.Close()

	waitFor := func(want int32, deadline time.Duration) {
		end := time.Now().Add(deadline)
		for time.Now().Before(end) {
			if pc.n.Load() == want {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("cache never reached %d (last %d)", want, pc.n.Load())
	}
	waitFor(1, 3*time.Second)

	store2 := openInvites()
	if _, err := store2.Consume(secret); err != nil {
		t.Fatalf("Consume: %v", err)
	}
	_ = store2.Close()
	waitFor(0, 3*time.Second)
}

// TestMakeVerifyPeer_KnownMemberAdmitted asserts a peer already in
// peers.db passes the predicate even with zero pending invites.
func TestMakeVerifyPeer_KnownMemberAdmitted(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:1", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	pc := &pendingCache{}
	verify := makeVerifyPeer(ps, pc)
	if err := verify(pub); err != nil {
		t.Errorf("known member rejected: %v", err)
	}
}

// TestMakeVerifyPeer_StrangerNoPending_Rejected asserts a peer absent
// from peers.db is rejected when the pending cache reads zero.
func TestMakeVerifyPeer_StrangerNoPending_Rejected(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	stranger := mustGenPub(t)
	pc := &pendingCache{}
	verify := makeVerifyPeer(ps, pc)
	if err := verify(stranger); err == nil {
		t.Fatal("stranger admitted with no pending invites")
	}
}

// TestMakeVerifyPeer_StrangerWithPending_Admitted asserts a stranger is
// admitted while at least one invite is pending — the join window lets
// an unknown pubkey complete the TLS handshake to consume its secret.
func TestMakeVerifyPeer_StrangerWithPending_Admitted(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	stranger := mustGenPub(t)
	pc := &pendingCache{}
	pc.n.Store(1)
	verify := makeVerifyPeer(ps, pc)
	if err := verify(stranger); err != nil {
		t.Errorf("stranger rejected during pending window: %v", err)
	}
}

// TestListDialablePeers_IncludesAllRoles asserts every peer with a
// non-empty Addr is returned regardless of role.
func TestListDialablePeers_IncludesAllRoles(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	rolePub := mustGenPub(t)
	introPub := mustGenPub(t)
	storagePub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:9", PubKey: rolePub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add RolePeer: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:10", PubKey: introPub, Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("Add RoleIntroducer: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:11", PubKey: storagePub, Role: peers.RoleStorage}); err != nil {
		t.Fatalf("Add RoleStorage: %v", err)
	}
	got, err := listDialablePeers(ps)
	if err != nil {
		t.Fatalf("listDialablePeers: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3 (every role with non-empty Addr)", len(got))
	}
	want := map[string]bool{
		string(rolePub):    false,
		string(introPub):   false,
		string(storagePub): false,
	}
	for _, p := range got {
		want[string(p.PubKey)] = true
	}
	for k, seen := range want {
		if !seen {
			t.Errorf("pubkey %x missing from list", []byte(k)[:8])
		}
	}
}

// TestListDialablePeers_SkipsEmptyAddr asserts a peer with empty Addr
// is filtered out.
func TestListDialablePeers_SkipsEmptyAddr(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	if err := ps.Add(peers.Peer{Addr: "", PubKey: mustGenPub(t), Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := listDialablePeers(ps)
	if err != nil {
		t.Fatalf("listDialablePeers: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0 (empty Addr must be filtered)", len(got))
	}
}

// TestListDialablePeers_EmptyStore asserts a fresh store returns an
// empty (non-nil) slice and no error.
func TestListDialablePeers_EmptyStore(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	got, err := listDialablePeers(ps)
	if err != nil {
		t.Fatalf("listDialablePeers: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("len = %d, want 0 on fresh store", len(got))
	}
}

// TestListDialablePeers_ListFailureSurfacesWrapped asserts a List error
// surfaces with a "list peers" wrap.
func TestListDialablePeers_ListFailureSurfacesWrapped(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "list-fail.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	_, err = listDialablePeers(ps)
	if err == nil {
		t.Fatal("listDialablePeers returned nil on closed store")
	}
	if !strings.Contains(err.Error(), "list peers") {
		t.Errorf("err = %q, want 'list peers' wrap", err)
	}
}

// connDialRig binds one listener and accepts N inbound conns, each
// with a distinct RemotePub from the corresponding dialer.
type connDialRig struct {
	listener *bsquic.Listener
	conns    []*bsquic.Conn
	pubs     []ed25519.PublicKey
}

func setupConnDialRig(t *testing.T, n int) *connDialRig {
	t.Helper()
	_, listenerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("listener key: %v", err)
	}
	listenerPub := listenerPriv.Public().(ed25519.PublicKey)
	l, err := bsquic.Listen("127.0.0.1:0", listenerPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	rig := &connDialRig{listener: l}
	for i := 0; i < n; i++ {
		dialPub, dialPriv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("dialer %d key: %v", i, err)
		}
		dialErr := make(chan error, 1)
		dialOut := make(chan *bsquic.Conn, 1)
		go func() {
			dctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			c, err := bsquic.Dial(dctx, l.Addr().String(), dialPriv, listenerPub, nil)
			if err != nil {
				dialErr <- err
				return
			}
			dialOut <- c
		}()
		actx, acancel := context.WithTimeout(context.Background(), 5*time.Second)
		accepted, err := l.Accept(actx)
		acancel()
		if err != nil {
			t.Fatalf("Accept %d: %v", i, err)
		}
		var dialedConn *bsquic.Conn
		select {
		case dialedConn = <-dialOut:
		case err := <-dialErr:
			t.Fatalf("Dial %d: %v", i, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("Dial %d timed out", i)
		}
		t.Cleanup(func() {
			_ = dialedConn.Close()
			_ = accepted.Close()
		})
		rig.conns = append(rig.conns, accepted)
		rig.pubs = append(rig.pubs, dialPub)
	}
	return rig
}

// TestLiveStorageConns_FiltersByRole asserts the live filter keeps
// conns whose remote pubkey maps to RoleStorage / RoleIntroducer in
// peers.db and drops RolePeer + unknown pubkeys.
func TestLiveStorageConns_FiltersByRole(t *testing.T) {
	rig := setupConnDialRig(t, 4)
	ps := openPickStoragePeerStore(t)
	if err := ps.Add(peers.Peer{Addr: "1", PubKey: rig.pubs[0], Role: peers.RoleStorage}); err != nil {
		t.Fatalf("Add storage: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "2", PubKey: rig.pubs[1], Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("Add introducer: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "3", PubKey: rig.pubs[2], Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add peer: %v", err)
	}
	// rig.pubs[3] intentionally absent from peers.db.
	cs := swarm.NewConnSet()
	for _, c := range rig.conns {
		cs.Add(c)
	}

	got := liveStorageConns(cs, ps)
	if len(got) != 2 {
		t.Fatalf("got %d conns, want 2 (storage + introducer)", len(got))
	}
	wantPubs := map[string]bool{
		string(rig.pubs[0]): false,
		string(rig.pubs[1]): false,
	}
	for _, c := range got {
		wantPubs[string(c.RemotePub())] = true
	}
	for k, seen := range wantPubs {
		if !seen {
			t.Errorf("pubkey %x missing from live storage conns", []byte(k)[:8])
		}
	}
}

// shouldImmediateDialAnnouncement builds a PeerJoined announcement
// for the predicate tests; tests override Kind per-case.
func shouldImmediateDialAnnouncement(pub ed25519.PublicKey, addr string) protocol.PeerAnnouncement {
	var ann protocol.PeerAnnouncement
	ann.Kind = protocol.AnnouncePeerJoined
	copy(ann.PubKey[:], pub)
	ann.Role = byte(peers.RolePeer)
	ann.Addr = addr
	return ann
}

// TestShouldImmediateDial_HappyPath asserts a Joined kind with an
// Addr and an in-store peer is selected for dial.
func TestShouldImmediateDial_HappyPath(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "1.2.3.4:5555", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	dialer := &outboundDialer{connSet: swarm.NewConnSet(), reach: swarm.NewReachabilityMap()}
	ann := shouldImmediateDialAnnouncement(pub, "1.2.3.4:5555")
	got, ok := shouldImmediateDial(ann, swarm.NewConnSet(), ps, dialer)
	if !ok {
		t.Fatal("shouldImmediateDial = false; want true")
	}
	if got.Addr != "1.2.3.4:5555" {
		t.Errorf("got peer addr %q, want %q", got.Addr, "1.2.3.4:5555")
	}
}

// TestShouldImmediateDial_SkipsNonJoinedKinds asserts Left and
// AddressChanged announcements are no-ops.
func TestShouldImmediateDial_SkipsNonJoinedKinds(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "1.2.3.4:5555", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	dialer := &outboundDialer{connSet: swarm.NewConnSet(), reach: swarm.NewReachabilityMap()}
	for _, kind := range []protocol.AnnouncementKind{protocol.AnnouncePeerLeft, protocol.AnnounceAddressChanged} {
		ann := shouldImmediateDialAnnouncement(pub, "1.2.3.4:5555")
		ann.Kind = kind
		if _, ok := shouldImmediateDial(ann, swarm.NewConnSet(), ps, dialer); ok {
			t.Errorf("kind %d: shouldImmediateDial = true; want false", kind)
		}
	}
}

// TestShouldImmediateDial_SkipsEmptyAddr asserts an announcement
// without an Addr (no dial target) is a no-op.
func TestShouldImmediateDial_SkipsEmptyAddr(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t)
	if err := ps.Add(peers.Peer{Addr: "", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	dialer := &outboundDialer{connSet: swarm.NewConnSet(), reach: swarm.NewReachabilityMap()}
	ann := shouldImmediateDialAnnouncement(pub, "")
	if _, ok := shouldImmediateDial(ann, swarm.NewConnSet(), ps, dialer); ok {
		t.Error("empty Addr accepted")
	}
}

// TestShouldImmediateDial_SkipsConnSetMatch asserts no dial when
// connSet already holds a conn for the announced pubkey.
func TestShouldImmediateDial_SkipsConnSetMatch(t *testing.T) {
	rig := setupConnDialRig(t, 1)
	pub := rig.pubs[0]
	ps := openPickStoragePeerStore(t)
	if err := ps.Add(peers.Peer{Addr: "1.2.3.4:5555", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	cs := swarm.NewConnSet()
	cs.Add(rig.conns[0])
	dialer := &outboundDialer{connSet: swarm.NewConnSet(), reach: swarm.NewReachabilityMap()}
	ann := shouldImmediateDialAnnouncement(pub, "1.2.3.4:5555")
	if _, ok := shouldImmediateDial(ann, cs, ps, dialer); ok {
		t.Error("dial proposed despite live conn for announced pubkey")
	}
}

// TestShouldImmediateDial_SkipsDialerHasConn asserts no dial when the
// dialer is already tracking a conn for the announced pubkey.
func TestShouldImmediateDial_SkipsDialerHasConn(t *testing.T) {
	rig := setupConnDialRig(t, 1)
	pub := rig.pubs[0]
	ps := openPickStoragePeerStore(t)
	if err := ps.Add(peers.Peer{Addr: "1.2.3.4:5555", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	dialer := &outboundDialer{connSet: swarm.NewConnSet(), reach: swarm.NewReachabilityMap()}
	dialer.conns = append(dialer.conns, rig.conns[0])
	ann := shouldImmediateDialAnnouncement(pub, "1.2.3.4:5555")
	if _, ok := shouldImmediateDial(ann, swarm.NewConnSet(), ps, dialer); ok {
		t.Error("dial proposed despite dialer already tracking the pubkey")
	}
}

// TestShouldImmediateDial_SkipsUnknownPeer asserts no dial when the
// announced pubkey is absent from peerStore.
func TestShouldImmediateDial_SkipsUnknownPeer(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	pub := mustGenPub(t) // not added
	dialer := &outboundDialer{connSet: swarm.NewConnSet(), reach: swarm.NewReachabilityMap()}
	ann := shouldImmediateDialAnnouncement(pub, "1.2.3.4:5555")
	if _, ok := shouldImmediateDial(ann, swarm.NewConnSet(), ps, dialer); ok {
		t.Error("dial proposed for pubkey not in peerStore")
	}
}

// TestLiveStorageConns_EmptyConnSet asserts an empty connSet returns
// an empty (non-nil) slice without consulting peers.db.
func TestLiveStorageConns_EmptyConnSet(t *testing.T) {
	ps := openPickStoragePeerStore(t)
	got := liveStorageConns(swarm.NewConnSet(), ps)
	if len(got) != 0 {
		t.Errorf("got %d conns, want 0 on empty connSet", len(got))
	}
}

// TestModeName_AllCases asserts modeName returns the expected string for every Mode value plus the unknown fallback.
func TestModeName_AllCases(t *testing.T) {
	tests := []struct {
		name string
		in   Mode
		want string
	}{
		{"idle", ModeIdle, "idle"},
		{"first-backup", ModeFirstBackup, "first-backup"},
		{"reconcile", ModeReconcile, "reconcile"},
		{"restore", ModeRestore, "restore"},
		{"purge", ModePurge, "purge"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := modeName(tc.in); got != tc.want {
				t.Errorf("modeName(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}

	t.Run("unknown fallback", func(t *testing.T) {
		got := modeName(ModePurge + 99)
		if !strings.HasPrefix(got, "unknown(") {
			t.Errorf("modeName(unknown) = %q, want 'unknown(...)' prefix", got)
		}
	})
}

// TestPurgeAll_ListFailure asserts an idx.List failure surfaces from purgeAll as "list index".
func TestPurgeAll_ListFailure(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "purge-list-fail.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("index.Close: %v", err)
	}

	err = purgeAll(context.Background(), idx, nil, io.Discard)
	if err == nil {
		t.Fatal("purgeAll returned nil on closed index")
	}
	if !strings.Contains(err.Error(), "list index") {
		t.Errorf("err = %q, want 'list index' prefix", err)
	}
}

// TestPurgeAll_ContextCancelled asserts an already-cancelled context makes purgeAll return without driving any Prune calls.
func TestPurgeAll_ContextCancelled(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "purge-ctx-cancel.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	if err := idx.Put(index.FileEntry{
		Path: filepath.Join(t.TempDir(), "ghost.bin"),
		Size: 1,
		Chunks: []index.ChunkRef{
			{CiphertextHash: [32]byte{0x01}, Size: 10},
		},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err = purgeAll(ctx, idx, nil, io.Discard)
	if err == nil {
		t.Fatal("purgeAll returned nil despite cancelled context")
	}
	if !strings.Contains(err.Error(), "context canceled") {
		t.Errorf("err = %q, want context.Canceled", err)
	}
}

// TestPurgeAll_PruneFailurePropagates asserts a backup.Prune failure surfaces from purgeAll.
func TestPurgeAll_PruneFailurePropagates(t *testing.T) {
	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	peerStore, err := store.New(filepath.Join(t.TempDir(), "peer-chunks"))
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

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), ownerPriv, peerPub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()

	idx, err := index.Open(filepath.Join(t.TempDir(), "purge-prune-fail.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	if err := idx.Put(index.FileEntry{
		Path: "ghost.bin",
		Size: 1,
		Chunks: []index.ChunkRef{
			{CiphertextHash: [32]byte{0xaa}, Size: 10},
		},
	}); err != nil {
		t.Fatalf("seed index: %v", err)
	}

	err = purgeAll(context.Background(), idx, []*bsquic.Conn{conn}, io.Discard)
	if err == nil {
		t.Fatal("purgeAll returned nil despite closed conn")
	}
	if strings.Contains(err.Error(), "list index") {
		t.Errorf("err = %q, want Prune-side error, got list-index wrap", err)
	}
}

// immediateDialRig wraps a real listener + Serve loop with an accepts
// counter for OnApplied closure tests.
type immediateDialRig struct {
	addr    string
	pub     ed25519.PublicKey
	accepts atomic.Int32
}

// newImmediateDialRig binds 127.0.0.1:0, opens a fresh chunk store, and
// runs backup.Serve with a ConnObserver that bumps accepts on inbound
// conns. Cleanup is registered via t.Cleanup.
func newImmediateDialRig(t *testing.T) *immediateDialRig {
	t.Helper()
	peerStore, err := store.New(filepath.Join(t.TempDir(), "peer-chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = peerStore.Close() })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", priv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	rig := &immediateDialRig{addr: listener.Addr().String(), pub: pub}
	obs := &backup.ConnObserver{
		OnAccept: func(*bsquic.Conn) { rig.accepts.Add(1) },
	}
	serveCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = backup.Serve(serveCtx, listener, peerStore, nil, nil, nil, nil, obs) }()
	return rig
}

// newImmediateDialDialer builds an outboundDialer with a fresh priv key,
// chunk store, and modest dial timeout.
func newImmediateDialDialer(t *testing.T, ctx context.Context) *outboundDialer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("dialer key: %v", err)
	}
	st, err := store.New(filepath.Join(t.TempDir(), "dialer-chunks"))
	if err != nil {
		t.Fatalf("dialer store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return &outboundDialer{
		ctx:     ctx,
		priv:    priv,
		timeout: 3 * time.Second,
		st:      st,
		connSet: swarm.NewConnSet(),
		reach:   swarm.NewReachabilityMap(),
	}
}

// TestMakeImmediateDialOnApplied_DialsOnPeerJoined asserts the closure
// spawns a dial that the target rig accepts when given a PeerJoined
// announcement matching a peer in peerStore.
func TestMakeImmediateDialOnApplied_DialsOnPeerJoined(t *testing.T) {
	rig := newImmediateDialRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dialer := newImmediateDialDialer(t, ctx)
	t.Cleanup(dialer.CloseAll)

	ps := openPickStoragePeerStore(t)
	if err := ps.Add(peers.Peer{Addr: rig.addr, PubKey: rig.pub, Role: peers.RoleStorage}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	onApplied := makeImmediateDialOnApplied(ps, swarm.NewConnSet(), dialer)
	ann := shouldImmediateDialAnnouncement(rig.pub, rig.addr)
	onApplied(ctx, ann)

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if rig.accepts.Load() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := rig.accepts.Load(); got < 1 {
		t.Errorf("rig accepts = %d, want >= 1 (closure must trigger a dial)", got)
	}
}

// TestMakeImmediateDialOnApplied_NoDialOnNonJoined asserts an
// AddressChanged announcement does not trigger a dial — the closure
// short-circuits via shouldImmediateDial.
func TestMakeImmediateDialOnApplied_NoDialOnNonJoined(t *testing.T) {
	rig := newImmediateDialRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	dialer := newImmediateDialDialer(t, ctx)
	t.Cleanup(dialer.CloseAll)

	ps := openPickStoragePeerStore(t)
	if err := ps.Add(peers.Peer{Addr: rig.addr, PubKey: rig.pub, Role: peers.RoleStorage}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	onApplied := makeImmediateDialOnApplied(ps, swarm.NewConnSet(), dialer)
	ann := shouldImmediateDialAnnouncement(rig.pub, rig.addr)
	ann.Kind = protocol.AnnounceAddressChanged
	onApplied(ctx, ann)

	time.Sleep(300 * time.Millisecond)
	if got := rig.accepts.Load(); got != 0 {
		t.Errorf("rig accepts = %d, want 0 (non-Joined announcement must not dial)", got)
	}
}

// TestRun_FounderWithBackupDir_EntersScanLoop asserts a daemon started
// with BackupDir set but an empty peers.db enters the scan loop and
// ticks at least once, witnessed by the "scan failed" log line.
func TestRun_FounderWithBackupDir_EntersScanLoop(t *testing.T) {
	dataDir := t.TempDir()
	backupDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(backupDir, "f.bin"), make([]byte, 1<<10), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	w := &syncWriter{}
	captureSlog(t, w)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:      dataDir,
			BackupDir:    backupDir,
			ListenAddr:   "127.0.0.1:0",
			ChunkSize:    1 << 20,
			ScanInterval: 50 * time.Millisecond,
			Progress:     io.Discard,
		})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(w.String(), "scan failed") {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run err = %v, want nil after cancel", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not exit within 5s of cancel")
	}

	if !strings.Contains(w.String(), "scan failed") {
		t.Errorf("scan loop never ticked — daemon did not enter scan loop with empty peers.db.\nLogs:\n%s", w.String())
	}
}

func TestRun_RejectsNegativeNATRefreshInterval(t *testing.T) {
	err := Run(context.Background(), Options{
		DataDir:            t.TempDir(),
		ListenAddr:         "127.0.0.1:0",
		NATRefreshInterval: -time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "nat refresh interval") {
		t.Fatalf("err = %v, want negative-NAT-refresh rejection", err)
	}
}

func TestRun_RejectsNegativeDurationOptions(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"chunk ttl", Options{ChunkTTL: -time.Second}, "chunk TTL"},
		{"renew interval", Options{ChunkTTL: time.Hour, RenewInterval: -time.Second}, "renew interval"},
		{"expire interval", Options{ExpireInterval: -time.Second}, "expire interval"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.DataDir = t.TempDir()
			tc.opts.ListenAddr = "127.0.0.1:0"
			err := Run(context.Background(), tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestRun_RejectsNegativeRateOptions(t *testing.T) {
	cases := []struct {
		name string
		opts Options
		want string
	}{
		{"upload rate", Options{UploadRateBytes: -1}, "upload rate"},
		{"download rate", Options{DownloadRateBytes: -1}, "download rate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.opts.DataDir = t.TempDir()
			tc.opts.ListenAddr = "127.0.0.1:0"
			err := Run(context.Background(), tc.opts)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}

func TestRun_STUNServerSpawnsLoopWithAdvertiseAddrPort(t *testing.T) {
	prevDiscover := natDiscoverFunc
	t.Cleanup(func() { natDiscoverFunc = prevDiscover })
	var calls atomic.Int32
	natDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		calls.Add(1)
		return "203.0.113.7", nil
	}
	prevBC := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = prevBC })
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, _ string) error {
		return nil
	}

	w := &syncWriter{}
	captureSlog(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:            t.TempDir(),
			ListenAddr:         "127.0.0.1:0",
			AdvertiseAddr:      "203.0.113.99:7777",
			STUNServer:         "stun.example:3478",
			NATRefreshInterval: 50 * time.Millisecond,
			Progress:           io.Discard,
		})
	}()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && calls.Load() < 1 {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s of cancel")
	}
	if got := calls.Load(); got < 1 {
		t.Errorf("natDiscoverFunc never invoked: calls=%d", got)
	}
}

func TestRun_STUNServerFallsBackToListenAddrWhenAdvertiseEmpty(t *testing.T) {
	prevDiscover := natDiscoverFunc
	t.Cleanup(func() { natDiscoverFunc = prevDiscover })
	natDiscoverFunc = func(_ context.Context, _ string) (string, error) {
		return "203.0.113.7", nil
	}
	prevBC := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = prevBC })
	broadcastAddressChangedFunc = func(_ context.Context, _ []*bsquic.Conn, _ ed25519.PublicKey, _ string) error {
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:            t.TempDir(),
			ListenAddr:         "127.0.0.1:0",
			STUNServer:         "stun.example:3478",
			NATRefreshInterval: 50 * time.Millisecond,
			Progress:           io.Discard,
		})
	}()
	time.Sleep(150 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not exit within 3s of cancel")
	}
}

// TestRedialMissingPeers_LogsFailureAtWarnLevel asserts a failed dial
// during the scan-loop sweep is logged at WARN level.
func TestRedialMissingPeers_LogsFailureAtWarnLevel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, dialerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("dialer key: %v", err)
	}

	ps := openPickStoragePeerStore(t)
	unreachablePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("unreachable key: %v", err)
	}
	if err := ps.Add(peers.Peer{
		Addr:   "127.0.0.1:1",
		PubKey: unreachablePub,
		Role:   peers.RoleStorage,
	}); err != nil {
		t.Fatalf("Add: %v", err)
	}

	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	dialer := &outboundDialer{
		ctx:     ctx,
		priv:    dialerPriv,
		timeout: 200 * time.Millisecond,
		st:      st,
		connSet: swarm.NewConnSet(),
		reach:   swarm.NewReachabilityMap(),
	}
	t.Cleanup(dialer.CloseAll)

	w := &syncWriter{}
	captureSlog(t, w)

	redialMissingPeers(ctx, ps, dialer, swarm.NewConnSet())

	got := w.String()
	if !strings.Contains(got, "redial sweep: dial peer failed") {
		t.Fatalf("expected dial-fail log line, got:\n%s", got)
	}
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("expected WARN level for dial failure, got:\n%s", got)
	}
}
