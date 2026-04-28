package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/index"
	"backupswarm/internal/invites"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
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

// TestPickStorageConns_OnlyStorageCandidates asserts pickStorageConns
// returns conns for every IsStorageCandidate and skips RolePeer entries.
func TestPickStorageConns_OnlyStorageCandidates(t *testing.T) {
	rolePub := mustGenPub(t)
	introPub := mustGenPub(t)
	storagePub := mustGenPub(t)
	dialed := []dialedPeer{
		{peer: peers.Peer{Addr: "a", PubKey: rolePub, Role: peers.RolePeer}},
		{peer: peers.Peer{Addr: "b", PubKey: introPub, Role: peers.RoleIntroducer}},
		{peer: peers.Peer{Addr: "c", PubKey: storagePub, Role: peers.RoleStorage}},
	}
	got := pickStorageConns(dialed)
	if len(got) != 2 {
		t.Fatalf("got %d conns, want 2 (introducer + storage)", len(got))
	}
}

// TestPickStorageConns_EmptyList asserts pickStorageConns returns an
// empty slice when the dialed list has only RolePeer entries.
func TestPickStorageConns_EmptyList(t *testing.T) {
	dialed := []dialedPeer{
		{peer: peers.Peer{Addr: "a", PubKey: mustGenPub(t), Role: peers.RolePeer}},
	}
	if got := pickStorageConns(dialed); len(got) != 0 {
		t.Errorf("pickStorageConns = %+v, want empty for non-storage list", got)
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
	go func() { _ = backup.Serve(serveCtx, listener, peerStore, nil, nil, nil) }()

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
