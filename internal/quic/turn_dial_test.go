package quic_test

import (
	"context"
	"crypto/ed25519"
	"net"
	"testing"
	"time"

	"backupswarm/internal/nat"
	bsw "backupswarm/internal/quic"

	"github.com/pion/logging"
	pturn "github.com/pion/turn/v4"
)

// startTURNFixture brings up a long-term-credential pion/turn server on a
// random loopback UDP port for the duration of the test.
func startTURNFixture(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen turn: %v", err)
	}
	const realm = "backupswarm.test"
	credKey := pturn.GenerateAuthKey("user", realm, "pass")
	server, err := pturn.NewServer(pturn.ServerConfig{
		Realm: realm,
		AuthHandler: func(_, _ string, _ net.Addr) ([]byte, bool) {
			return credKey, true
		},
		PacketConnConfigs: []pturn.PacketConnConfig{{
			PacketConn: listener,
			RelayAddressGenerator: &pturn.RelayAddressGeneratorStatic{
				RelayAddress: net.ParseIP("127.0.0.1"),
				Address:      "127.0.0.1",
			},
		}},
		LoggerFactory: logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		_ = listener.Close()
		t.Fatalf("turn server: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return listener.LocalAddr().String()
}

// TestListenOver_RoundTripOverPacketConn asserts ListenOver wraps an
// arbitrary net.PacketConn into a working QUIC listener; pairs with
// DialOver to confirm the listener and dialer share a transport surface.
func TestListenOver_RoundTripOverPacketConn(t *testing.T) {
	t.Parallel()
	serverPub, serverPriv := newKeyPair(t)
	clientPub, clientPriv := newKeyPair(t)

	srvPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("server pc: %v", err)
	}
	l, err := bsw.ListenOver(srvPC, serverPriv, nil, nil)
	if err != nil {
		t.Fatalf("ListenOver: %v", err)
	}
	defer func() { _ = l.Close() }()

	cliPC, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("client pc: %v", err)
	}
	defer func() { _ = cliPC.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	type accept struct {
		pub ed25519.PublicKey
		err error
	}
	done := make(chan accept, 1)
	go func() {
		conn, aerr := l.Accept(ctx)
		if aerr != nil {
			done <- accept{err: aerr}
			return
		}
		defer func() { _ = conn.Close() }()
		done <- accept{pub: conn.RemotePub()}
	}()

	conn, err := bsw.DialOver(ctx, cliPC, l.Addr().String(), clientPriv, serverPub, nil)
	if err != nil {
		t.Fatalf("DialOver: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if !conn.RemotePub().Equal(serverPub) {
		t.Fatalf("dialer remote pub mismatch")
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	if !r.pub.Equal(clientPub) {
		t.Fatalf("server remote pub mismatch")
	}
}

// TestDialOver_TURNRelayHandshake asserts a client that allocates a TURN
// relay socket can complete a QUIC handshake with a directly-listening
// peer when its outbound traffic is routed through the relay.
func TestDialOver_TURNRelayHandshake(t *testing.T) {
	turnAddr := startTURNFixture(t)
	serverPub, serverPriv := newKeyPair(t)
	clientPub, clientPriv := newKeyPair(t)

	l, err := bsw.Listen("127.0.0.1:0", serverPriv, nil, nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = l.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	alloc, err := nat.Allocate(ctx, nat.TURNConfig{
		Server:   turnAddr,
		Username: "user",
		Password: "pass",
		Realm:    "backupswarm.test",
	})
	if err != nil {
		t.Fatalf("allocate: %v", err)
	}
	defer func() { _ = alloc.Close() }()

	type accept struct {
		pub ed25519.PublicKey
		err error
	}
	done := make(chan accept, 1)
	go func() {
		conn, aerr := l.Accept(ctx)
		if aerr != nil {
			done <- accept{err: aerr}
			return
		}
		defer func() { _ = conn.Close() }()
		done <- accept{pub: conn.RemotePub()}
	}()

	conn, err := bsw.DialOver(ctx, alloc.PacketConn(), l.Addr().String(), clientPriv, serverPub, nil)
	if err != nil {
		t.Fatalf("dial over relay: %v", err)
	}
	defer func() { _ = conn.Close() }()

	if !conn.RemotePub().Equal(serverPub) {
		t.Fatalf("dialer remote pub mismatch")
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	if !r.pub.Equal(clientPub) {
		t.Fatalf("server-side remote pub mismatch")
	}
}
