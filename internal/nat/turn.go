package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/pion/logging"
	pturn "github.com/pion/turn/v4"
)

// listenPacketFunc is the package-level UDP listener seam; tests swap it.
var listenPacketFunc = net.ListenPacket

// newTURNClient is the package-level pion turn client constructor seam.
var newTURNClient = pturn.NewClient

// TURNConfig identifies a TURN server and the long-term credentials used to
// authenticate against it.
type TURNConfig struct {
	Server   string
	Username string
	Password string
	Realm    string
}

// Allocation owns the local UDP socket, the pion/turn client, and the
// server-side relay reservation. PacketConn returns the relayed
// net.PacketConn callers send/receive on; Close releases everything.
type Allocation struct {
	local  net.PacketConn
	client *pturn.Client
	relay  net.PacketConn

	closeOnce sync.Once
	closeErr  error
}

// Allocate dials the configured TURN server, authenticates, and reserves a
// relay address. The returned Allocation owns its underlying socket and
// must be closed by the caller.
func Allocate(ctx context.Context, cfg TURNConfig) (*Allocation, error) {
	if cfg.Server == "" {
		return nil, errors.New("nat: TURNConfig.Server is required")
	}
	if cfg.Username == "" || cfg.Password == "" || cfg.Realm == "" {
		return nil, errors.New("nat: TURNConfig requires Username, Password, and Realm")
	}
	local, err := listenPacketFunc("udp4", "0.0.0.0:0")
	if err != nil {
		return nil, fmt.Errorf("nat: turn local listen: %w", err)
	}
	client, err := newTURNClient(&pturn.ClientConfig{
		STUNServerAddr: cfg.Server,
		TURNServerAddr: cfg.Server,
		Conn:           local,
		Username:       cfg.Username,
		Password:       cfg.Password,
		Realm:          cfg.Realm,
		LoggerFactory:  logging.NewDefaultLoggerFactory(),
	})
	if err != nil {
		_ = local.Close()
		return nil, fmt.Errorf("nat: turn client: %w", err)
	}
	if err := client.Listen(); err != nil {
		client.Close()
		_ = local.Close()
		return nil, fmt.Errorf("nat: turn listen: %w", err)
	}
	relay, err := allocateWithCtx(ctx, client)
	if err != nil {
		client.Close()
		_ = local.Close()
		return nil, fmt.Errorf("nat: turn allocate: %w", err)
	}
	return &Allocation{local: local, client: client, relay: relay}, nil
}

// allocateWithCtx runs client.Allocate in a goroutine so the caller's ctx
// cancellation aborts the wait. The pion API is synchronous; on ctx
// cancellation we close the client to unblock it, then return ctx.Err.
func allocateWithCtx(ctx context.Context, client *pturn.Client) (net.PacketConn, error) {
	type result struct {
		pc  net.PacketConn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		pc, err := client.Allocate()
		ch <- result{pc: pc, err: err}
	}()
	select {
	case <-ctx.Done():
		client.Close()
		<-ch
		return nil, ctx.Err()
	case r := <-ch:
		return r.pc, r.err
	}
}

// RelayAddr is the externally-visible TURN-allocated address peers send to.
func (a *Allocation) RelayAddr() net.Addr { return a.relay.LocalAddr() }

// PacketConn is the relayed socket; reads receive datagrams from peers,
// writes route via the TURN server.
func (a *Allocation) PacketConn() net.PacketConn { return a.relay }

// Close releases the relay reservation and the underlying socket. Idempotent.
func (a *Allocation) Close() error {
	a.closeOnce.Do(func() {
		if err := a.relay.Close(); err != nil {
			a.closeErr = err
		}
		if a.client != nil {
			a.client.Close()
		}
		if err := a.local.Close(); err != nil && a.closeErr == nil {
			a.closeErr = err
		}
	})
	return a.closeErr
}
