package daemon

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
)

// Two daemons with TURN; direct and TURN rungs forced to fail;
// asserts the relay rung produces method=relay on register.
func TestRun_TwoDaemons_PeerDialsViaRelayRung(t *testing.T) {
	turnAddr := startTURNServerForDaemonTest(t)
	const realm = "backupswarm.test"

	bID, err := node.Generate()
	if err != nil {
		t.Fatalf("generate B identity: %v", err)
	}
	aID, err := node.Generate()
	if err != nil {
		t.Fatalf("generate A identity: %v", err)
	}

	bDataDir := t.TempDir()
	if err := node.Save(bDataDir, bID); err != nil {
		t.Fatalf("save B identity: %v", err)
	}
	prePopulatePeer(t, bDataDir, peers.Peer{
		PubKey: aID.PublicKey,
		Role:   peers.RolePeer,
	})

	bCtx, bCancel := context.WithCancel(context.Background())
	bDone := make(chan error, 1)
	go func() {
		bDone <- Run(bCtx, Options{
			DataDir:    bDataDir,
			ListenAddr: "127.0.0.1:0",
			TURN: TURNOptions{
				Server: turnAddr, Username: "u", Password: "p", Realm: realm,
			},
		})
	}()
	t.Cleanup(func() {
		bCancel()
		select {
		case <-bDone:
		case <-time.After(3 * time.Second):
			t.Error("daemon B did not exit within 3s of cancel")
		}
	})

	bRelay := waitForRelayAddr(t, bDataDir, 5*time.Second)
	bListen := waitForListenAddr(t, bDataDir, 5*time.Second)

	aDataDir := t.TempDir()
	if err := node.Save(aDataDir, aID); err != nil {
		t.Fatalf("save A identity: %v", err)
	}
	prePopulatePeer(t, aDataDir, peers.Peer{
		PubKey:    bID.PublicKey,
		Addr:      bListen,
		RelayAddr: bRelay,
		Role:      peers.RoleStorage,
	})

	prevDirect := chainDirectDialFn
	chainDirectDialFn = func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
		return nil, errors.New("forced direct fail")
	}
	t.Cleanup(func() { chainDirectDialFn = prevDirect })

	prevTURN := chainTURNDialFn
	chainTURNDialFn = func(context.Context, turnRelayDialer, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
		return nil, errors.New("forced turn fail")
	}
	t.Cleanup(func() { chainTURNDialFn = prevTURN })

	w := &syncWriter{}
	captureSlog(t, w)

	aBackupDir := t.TempDir()
	aCtx, aCancel := context.WithCancel(context.Background())
	aDone := make(chan error, 1)
	go func() {
		aDone <- Run(aCtx, Options{
			DataDir:    aDataDir,
			BackupDir:  aBackupDir,
			ListenAddr: "127.0.0.1:0",
			TURN: TURNOptions{
				Server: turnAddr, Username: "u", Password: "p", Realm: realm,
			},
		})
	}()
	t.Cleanup(func() {
		aCancel()
		select {
		case <-aDone:
		case <-time.After(3 * time.Second):
			t.Error("daemon A did not exit within 3s of cancel")
		}
	})

	deadline := time.Now().Add(15 * time.Second)
	for {
		out := w.String()
		if strings.Contains(out, `msg="peer connected" method=relay `) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("never observed `peer connected method=relay` in slog\n--- captured ---\n%s\n--- end ---", out)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// waitForRelayAddr polls <dir>/relay.addr until populated or deadline.
func waitForRelayAddr(t *testing.T, dir string, within time.Duration) string {
	t.Helper()
	end := time.Now().Add(within)
	for {
		addr, _ := ReadRelayAddr(dir)
		if addr != "" {
			return addr
		}
		if time.Now().After(end) {
			t.Fatalf("relay.addr never appeared in %s within %v", dir, within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// waitForListenAddr polls <dir>/listen.addr until populated or deadline.
func waitForListenAddr(t *testing.T, dir string, within time.Duration) string {
	t.Helper()
	end := time.Now().Add(within)
	for {
		addr, _ := ReadListenAddr(dir)
		if addr != "" {
			return addr
		}
		if time.Now().After(end) {
			t.Fatalf("listen.addr never appeared in %s within %v", dir, within)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// prePopulatePeer opens <dir>/peers.db, adds p, and closes — leaves the
// file ready for daemon.Run to reopen on its own.
func prePopulatePeer(t *testing.T, dir string, p peers.Peer) {
	t.Helper()
	store, err := peers.Open(filepath.Join(dir, peers.DefaultFilename))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := store.Add(p); err != nil {
		_ = store.Close()
		t.Fatalf("peerStore.Add: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("peerStore.Close: %v", err)
	}
}

// advertiseSelf with both selfAddr + selfRelayAddr populated emits one
// AddressChanged frame on the supplied conn with those values.
func TestOutboundDialer_AdvertiseSelf_BroadcastsBothAddrs(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate pub: %v", err)
	}

	var (
		gotPub   ed25519.PublicKey
		gotAddr  string
		gotRelay string
		gotConns int
	)
	prev := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = prev })
	broadcastAddressChangedFunc = func(_ context.Context, conns []*bsquic.Conn, p ed25519.PublicKey, addr, relay string) error {
		gotConns = len(conns)
		gotPub = p
		gotAddr = addr
		gotRelay = relay
		return nil
	}

	d := &outboundDialer{
		ctx:           context.Background(),
		selfPub:       pub,
		selfAddr:      "1.2.3.4:7777",
		selfRelayAddr: "9.8.7.6:54321",
	}
	d.advertiseSelf(nil)

	if gotConns != 1 {
		t.Errorf("conn count = %d, want 1", gotConns)
	}
	if !strings.EqualFold(string(gotPub), string(pub)) {
		t.Errorf("pub captured = %x, want %x", gotPub, pub)
	}
	if gotAddr != "1.2.3.4:7777" {
		t.Errorf("addr = %q, want 1.2.3.4:7777", gotAddr)
	}
	if gotRelay != "9.8.7.6:54321" {
		t.Errorf("relay = %q, want 9.8.7.6:54321", gotRelay)
	}
}

// advertiseSelf with both selfAddr and selfRelayAddr empty does not
// invoke the broadcast seam.
func TestOutboundDialer_AdvertiseSelf_NoBroadcastWhenEmpty(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate pub: %v", err)
	}

	called := false
	prev := broadcastAddressChangedFunc
	t.Cleanup(func() { broadcastAddressChangedFunc = prev })
	broadcastAddressChangedFunc = func(context.Context, []*bsquic.Conn, ed25519.PublicKey, string, string) error {
		called = true
		return nil
	}

	d := &outboundDialer{
		ctx:     context.Background(),
		selfPub: pub,
	}
	d.advertiseSelf(nil)

	if called {
		t.Error("broadcast fired on empty self addrs")
	}
}
