package daemon_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"testing"
	"time"

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/ca"
	"backupswarm/internal/daemon"
	"backupswarm/internal/invites"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
	"backupswarm/pkg/token"
)

// startStorageDaemon spins up a storage-only daemon on an ephemeral
// port; returns the bound address (read from listen.addr) and a stop
// func that cancels and waits for clean exit.
func startStorageDaemon(t *testing.T, dataDir string) (addr string, stop func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- daemon.Run(ctx, daemon.Options{
			DataDir:    dataDir,
			ListenAddr: "127.0.0.1:0",
			Progress:   io.Discard,
		})
	}()

	deadline := time.Now().Add(3 * time.Second)
	for {
		got, err := daemon.ReadListenAddr(dataDir)
		if err == nil && got != "" {
			addr = got
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("daemon listen.addr never appeared (last err: %v)", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop = func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Errorf("daemon.Run returned err: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("daemon.Run did not return within 3s of cancel")
		}
	}
	return addr, stop
}

// preIssueInvite opens invites.db at dataDir, issues a fresh secret,
// closes (releasing the flock for the daemon's poll loop), and returns
// the encoded token string.
func preIssueInvite(t *testing.T, dataDir, listenAddr string, introPub ed25519.PublicKey, caCertDER []byte) string {
	t.Helper()
	store, err := invites.Open(filepath.Join(dataDir, invites.DefaultFilename))
	if err != nil {
		t.Fatalf("invites.Open: %v", err)
	}
	defer func() { _ = store.Close() }()

	var swarmID, secret [32]byte
	if _, err := rand.Read(swarmID[:]); err != nil {
		t.Fatalf("rand swarm: %v", err)
	}
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatalf("rand secret: %v", err)
	}
	if err := store.Issue(secret, swarmID); err != nil {
		t.Fatalf("Issue: %v", err)
	}
	tokStr, err := token.Encode(token.Token{
		Addr:    listenAddr,
		Pub:     introPub,
		SwarmID: swarmID,
		Secret:  secret,
		CACert:  caCertDER,
	})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}
	return tokStr
}

// runConnectedPeer dials the daemon at addr (TLS pinned to introPub),
// then runs an AcceptStream loop that routes MsgPeerAnnouncement
// frames to swarm.ServeAnnouncementStream so localStore stays in sync
// with anything the daemon forwards. Returns once the dial completes
// and the loop is ready to receive.
func runConnectedPeer(ctx context.Context, t *testing.T, addr string, introPub ed25519.PublicKey, priv ed25519.PrivateKey, localStore *peers.Store) error {
	t.Helper()
	conn, err := bsquic.Dial(ctx, addr, priv, introPub, nil)
	if err != nil {
		return err
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Open one outbound stream so the daemon's serveConn loop sees this
	// conn participate (no-op write; never read on the daemon side
	// beyond the type byte). Without this, AcceptStream on the daemon
	// would simply park; with it, the daemon's OnAccept already fired
	// and the conn is in ConnSet — which is what we actually need.
	// The conn itself is enough; the OnAccept fires at server-side
	// l.Accept return.

	go func() {
		for {
			s, err := conn.AcceptStream(ctx)
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = s.Close() }()
				msgType, err := protocol.ReadMessageType(s)
				if err != nil {
					return
				}
				if msgType != protocol.MsgPeerAnnouncement {
					return
				}
				_ = swarm.ServeAnnouncementStream(ctx, s, localStore)
			}()
		}
	}()
	return nil
}

// pollPendingInviteVisible waits for the daemon's poll loop to observe
// the freshly-issued invite. Without this, DoJoin races the predicate
// and the TLS handshake fails with "unknown peer ... and no pending
// invites" before the cache refreshes.
const pollSettleWindow = 1500 * time.Millisecond

// TestDaemon_HandlesDispatchedJoin_PinMode pre-issues an invite,
// drives bootstrap.DoJoin against the daemon's listener, and asserts
// the joiner sees the introducer in its peer list — the only way that
// happens is if the dispatched MsgJoinRequest reached the daemon's
// inline join handler and the handler completed the JoinResponse +
// PeerListMessage round-trip.
func TestDaemon_HandlesDispatchedJoin_PinMode(t *testing.T) {
	dataDir := t.TempDir()
	id, _, err := node.Ensure(dataDir)
	if err != nil {
		t.Fatalf("node.Ensure: %v", err)
	}

	addr, stop := startStorageDaemon(t, dataDir)
	defer stop()

	tokStr := preIssueInvite(t, dataDir, addr, id.PublicKey, nil)
	time.Sleep(pollSettleWindow)

	_, joinerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("joiner key: %v", err)
	}
	joinerStore, err := peers.Open(filepath.Join(t.TempDir(), "joiner-peers.db"))
	if err != nil {
		t.Fatalf("joiner peers.Open: %v", err)
	}
	defer func() { _ = joinerStore.Close() }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	result, err := bootstrap.DoJoin(dialCtx, tokStr, joinerPriv, "192.0.2.7:9000", joinerStore)
	if err != nil {
		t.Fatalf("DoJoin: %v", err)
	}
	if !result.Introducer.PubKey.Equal(id.PublicKey) {
		t.Errorf("introducer pubkey mismatch")
	}
	if result.Introducer.Addr != addr {
		t.Errorf("introducer addr = %q, want %q", result.Introducer.Addr, addr)
	}
}

// TestDaemon_HandlesDispatchedJoin_CAMode generates a swarm CA in the
// daemon's data dir, runs the daemon, pre-issues an invite carrying
// the CA cert, and drives DoJoin. The joiner must receive a non-empty
// signed leaf — verifying the daemon's join handler invoked
// ca.SignNodeCert against the swarmCA loaded at startup.
func TestDaemon_HandlesDispatchedJoin_CAMode(t *testing.T) {
	dataDir := t.TempDir()
	id, _, err := node.Ensure(dataDir)
	if err != nil {
		t.Fatalf("node.Ensure: %v", err)
	}
	swarmCA, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	if err := ca.Save(dataDir, swarmCA); err != nil {
		t.Fatalf("ca.Save: %v", err)
	}

	addr, stop := startStorageDaemon(t, dataDir)
	defer stop()

	tokStr := preIssueInvite(t, dataDir, addr, id.PublicKey, swarmCA.CertDER)
	time.Sleep(pollSettleWindow)

	_, joinerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("joiner key: %v", err)
	}
	joinerStore, err := peers.Open(filepath.Join(t.TempDir(), "joiner-peers.db"))
	if err != nil {
		t.Fatalf("joiner peers.Open: %v", err)
	}
	defer func() { _ = joinerStore.Close() }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	result, err := bootstrap.DoJoin(dialCtx, tokStr, joinerPriv, "192.0.2.9:9000", joinerStore)
	if err != nil {
		t.Fatalf("DoJoin: %v", err)
	}
	if len(result.SignedCert) == 0 {
		t.Errorf("DoJoin returned empty SignedCert in CA-mode swarm")
	}
}

// TestDaemon_BroadcastsPeerJoinedToOtherConns sets up a daemon with one
// pre-existing connected peer (B), then has a stranger (C) join via the
// dispatch-routed handshake. B must receive a forwarded PeerJoined for
// C — that proves the daemon's join handler called BroadcastPeerJoined
// against ConnSet.SnapshotExcept(C) after persisting C.
func TestDaemon_BroadcastsPeerJoinedToOtherConns(t *testing.T) {
	dataDir := t.TempDir()
	id, _, err := node.Ensure(dataDir)
	if err != nil {
		t.Fatalf("node.Ensure: %v", err)
	}

	// Pre-seed B in the daemon's peers.db so the predicate admits B's
	// inbound handshake without an invite. The daemon's peer store
	// reads on every TLS handshake — first-write must land before the
	// daemon opens the file.
	bPub, bPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("B key: %v", err)
	}
	{
		ps, err := peers.Open(filepath.Join(dataDir, peers.DefaultFilename))
		if err != nil {
			t.Fatalf("peers.Open seed: %v", err)
		}
		if err := ps.Add(peers.Peer{Addr: "192.0.2.55:9000", PubKey: bPub, Role: peers.RolePeer}); err != nil {
			_ = ps.Close()
			t.Fatalf("seed B: %v", err)
		}
		_ = ps.Close()
	}

	addr, stop := startStorageDaemon(t, dataDir)
	defer stop()

	// B dials the daemon and runs an AcceptStream loop so the daemon
	// can open a forward stream to it.
	bCtx, bCancel := context.WithCancel(context.Background())
	defer bCancel()
	bStore, err := peers.Open(filepath.Join(t.TempDir(), "b-peers.db"))
	if err != nil {
		t.Fatalf("B peers.Open: %v", err)
	}
	defer func() { _ = bStore.Close() }()
	if err := runConnectedPeer(bCtx, t, addr, id.PublicKey, bPriv, bStore); err != nil {
		t.Fatalf("runConnectedPeer B: %v", err)
	}

	// Issue invite for C and let the poll cache observe it.
	tokStr := preIssueInvite(t, dataDir, addr, id.PublicKey, nil)
	time.Sleep(pollSettleWindow)

	cPub, cPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("C key: %v", err)
	}
	cStore, err := peers.Open(filepath.Join(t.TempDir(), "c-peers.db"))
	if err != nil {
		t.Fatalf("C peers.Open: %v", err)
	}
	defer func() { _ = cStore.Close() }()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	if _, err := bootstrap.DoJoin(dialCtx, tokStr, cPriv, "192.0.2.77:9000", cStore); err != nil {
		t.Fatalf("C DoJoin: %v", err)
	}

	// B must observe C in its local store within a few seconds — the
	// only path is through the daemon's forwarded PeerJoined.
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err := bStore.Get(cPub)
		if err == nil {
			if got.Addr != "192.0.2.77:9000" {
				t.Errorf("forwarded addr = %q, want %q", got.Addr, "192.0.2.77:9000")
			}
			if got.Role != peers.RoleStorage {
				t.Errorf("forwarded role = %v, want RoleStorage", got.Role)
			}
			return
		}
		if !errors.Is(err, peers.ErrPeerNotFound) {
			t.Fatalf("bStore.Get: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("B never received forwarded PeerJoined for C within 5s")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestDaemon_RejectsStrangerWithoutPendingInvite asserts a peer with no
// invite cannot complete the TLS handshake. The cache reads zero, the
// predicate denies, the dial errors out before any join body is read.
func TestDaemon_RejectsStrangerWithoutPendingInvite(t *testing.T) {
	dataDir := t.TempDir()
	id, _, err := node.Ensure(dataDir)
	if err != nil {
		t.Fatalf("node.Ensure: %v", err)
	}

	addr, stop := startStorageDaemon(t, dataDir)
	defer stop()
	time.Sleep(pollSettleWindow) // let the poll loop confirm 0 pending

	_, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("stranger key: %v", err)
	}
	// Forge a token (no Issue call — the introducer's invites.db is
	// empty so even reaching the secret-validation step is impossible).
	var swarmID, secret [32]byte
	tokStr, err := token.Encode(token.Token{
		Addr:    addr,
		Pub:     id.PublicKey,
		SwarmID: swarmID,
		Secret:  secret,
	})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}
	strangerStore, err := peers.Open(filepath.Join(t.TempDir(), "stranger-peers.db"))
	if err != nil {
		t.Fatalf("stranger peers.Open: %v", err)
	}
	defer func() { _ = strangerStore.Close() }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	if _, err := bootstrap.DoJoin(dialCtx, tokStr, strangerPriv, "192.0.2.66:9000", strangerStore); err == nil {
		t.Fatal("DoJoin succeeded against a daemon with no pending invites; predicate let the stranger through")
	}
}
