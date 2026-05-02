package nat_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/nat"

	"github.com/pion/logging"
	pturn "github.com/pion/turn/v4"
)

const (
	testRealm    = "backupswarm.test"
	testUser     = "alice"
	testPassword = "secret"
)

// startTestTURNServer brings up a long-term-credential pion/turn server on
// a random loopback UDP port and returns its host:port address. The caller
// receives a cleanup function that closes the server and listener.
func startTestTURNServer(t *testing.T) string {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen turn server: %v", err)
	}
	credKey := pturn.GenerateAuthKey(testUser, testRealm, testPassword)
	server, err := pturn.NewServer(pturn.ServerConfig{
		Realm: testRealm,
		AuthHandler: func(username, realm string, _ net.Addr) ([]byte, bool) {
			if username == testUser && realm == testRealm {
				return credKey, true
			}
			return nil, false
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
		t.Fatalf("new turn server: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	return listener.LocalAddr().String()
}

func TestAllocate_ReturnsRelayAddr(t *testing.T) {
	addr := startTestTURNServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	alloc, err := nat.Allocate(ctx, nat.TURNConfig{
		Server:   addr,
		Username: testUser,
		Password: testPassword,
		Realm:    testRealm,
	})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	defer alloc.Close()
	relay := alloc.RelayAddr()
	if relay == nil {
		t.Fatal("RelayAddr is nil")
	}
	udp, ok := relay.(*net.UDPAddr)
	if !ok {
		t.Fatalf("RelayAddr type %T, want *net.UDPAddr", relay)
	}
	if udp.Port == 0 {
		t.Errorf("RelayAddr port=0; want non-zero (%v)", relay)
	}
	if pc := alloc.PacketConn(); pc == nil {
		t.Errorf("PacketConn is nil")
	}
}

func TestAllocate_CloseReleases(t *testing.T) {
	addr := startTestTURNServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	alloc, err := nat.Allocate(ctx, nat.TURNConfig{
		Server:   addr,
		Username: testUser,
		Password: testPassword,
		Realm:    testRealm,
	})
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if err := alloc.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Second Close is a no-op.
	if err := alloc.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	// Re-allocate from same server proves the prior release didn't leave the
	// server in a broken state.
	alloc2, err := nat.Allocate(ctx, nat.TURNConfig{
		Server:   addr,
		Username: testUser,
		Password: testPassword,
		Realm:    testRealm,
	})
	if err != nil {
		t.Fatalf("re-Allocate: %v", err)
	}
	_ = alloc2.Close()
}

func TestAllocate_EmptyServer(t *testing.T) {
	_, err := nat.Allocate(context.Background(), nat.TURNConfig{
		Username: testUser,
		Password: testPassword,
		Realm:    testRealm,
	})
	if err == nil {
		t.Fatal("Allocate without server: want error, got nil")
	}
}

func TestAllocate_EmptyCredentials(t *testing.T) {
	cases := []struct {
		name string
		cfg  nat.TURNConfig
	}{
		{"missing user", nat.TURNConfig{Server: "127.0.0.1:1", Password: "p", Realm: "r"}},
		{"missing pass", nat.TURNConfig{Server: "127.0.0.1:1", Username: "u", Realm: "r"}},
		{"missing realm", nat.TURNConfig{Server: "127.0.0.1:1", Username: "u", Password: "p"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := nat.Allocate(context.Background(), tc.cfg)
			if err == nil {
				t.Fatal("want error, got nil")
			}
		})
	}
}

func TestAllocate_BadServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	// Use a port unlikely to host a TURN server; the allocate call should
	// time out or fail rather than hang.
	_, err := nat.Allocate(ctx, nat.TURNConfig{
		Server:   "127.0.0.1:1",
		Username: testUser,
		Password: testPassword,
		Realm:    testRealm,
	})
	if err == nil {
		t.Fatal("Allocate against dead server: want error")
	}
	if strings.Contains(err.Error(), "panic") {
		t.Fatalf("unexpected panic-like error: %v", err)
	}
}
