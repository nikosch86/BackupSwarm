// Package nat resolves a node's externally-visible UDP address via STUN.
package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/pion/stun/v3"
)

var (
	// ErrEmptyServer is returned when Discover is called with no server.
	ErrEmptyServer = errors.New("nat: server is required")
	// ErrEmptyAddress is returned when the response had no XOR-MAPPED-ADDRESS.
	ErrEmptyAddress = errors.New("nat: response missing xor-mapped-address")
)

// MaxResponseSize is the largest STUN response we will read.
const MaxResponseSize = 2048

// Transactor is the per-call STUN transport seam. Production wraps a UDP
// conn that sends one BindingRequest and reads one response.
type Transactor interface {
	Send(req []byte) error
	Recv(buf []byte, deadline time.Time) (int, error)
	Close() error
}

// DialFunc opens a Transactor for the named server. Replace in tests.
var DialFunc = func(ctx context.Context, network, address string) (Transactor, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	return &udpTransactor{conn: conn}, nil
}

type udpTransactor struct {
	conn net.Conn
}

func (u *udpTransactor) Send(req []byte) error {
	_, err := u.conn.Write(req)
	return err
}

func (u *udpTransactor) Recv(buf []byte, deadline time.Time) (int, error) {
	if !deadline.IsZero() {
		_ = u.conn.SetReadDeadline(deadline)
	}
	return u.conn.Read(buf)
}

func (u *udpTransactor) Close() error { return u.conn.Close() }

// Discover sends one STUN BindingRequest to server and returns the host
// portion of the XOR-MAPPED-ADDRESS in the response. The caller must set a
// ctx deadline to bound the read.
func Discover(ctx context.Context, server string) (string, error) {
	if server == "" {
		return "", ErrEmptyServer
	}
	t, err := DialFunc(ctx, "udp", server)
	if err != nil {
		return "", fmt.Errorf("nat: dial %q: %w", server, err)
	}
	defer func() { _ = t.Close() }()

	// Watch ctx in a side goroutine; on cancel, close the transactor so a
	// blocked Recv returns immediately with a use-of-closed-network-conn err.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = t.Close()
		case <-done:
		}
	}()

	req := stun.MustBuild(stun.TransactionID, stun.BindingRequest)
	if err := t.Send(req.Raw); err != nil {
		return "", fmt.Errorf("nat: send: %w", err)
	}

	buf := make([]byte, MaxResponseSize)
	deadline, _ := ctx.Deadline()
	n, err := t.Recv(buf, deadline)
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return "", cerr
		}
		return "", fmt.Errorf("nat: recv: %w", err)
	}

	msg := &stun.Message{Raw: append([]byte(nil), buf[:n]...)}
	if err := msg.Decode(); err != nil {
		return "", fmt.Errorf("nat: decode: %w", err)
	}
	var xor stun.XORMappedAddress
	if err := xor.GetFrom(msg); err != nil {
		return "", fmt.Errorf("nat: parse xor-mapped-address: %w", err)
	}
	if len(xor.IP) == 0 {
		return "", ErrEmptyAddress
	}
	return xor.IP.String(), nil
}
