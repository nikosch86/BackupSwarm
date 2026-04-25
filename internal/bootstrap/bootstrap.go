// Package bootstrap implements the invite/join handshake: one QUIC stream
// carrying a single JoinHello{listen_addr} from joiner and a JoinAck from
// introducer. Each side records the other in its peer store.
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"

	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/pkg/token"
)

// Test-only seams for fault-injection on transport-died error wraps.
var (
	writeJoinAckFunc   = protocol.WriteJoinAck
	writeJoinHelloFunc = protocol.WriteJoinHello
	streamCloseFunc    = func(s io.Closer) error { return s.Close() }
)

// maxAdvertisedAddrLen caps an incoming JoinHello address at 1 KiB —
// well above any legitimate host:port, safely below allocation-abuse territory.
const maxAdvertisedAddrLen = 1 << 10

// AcceptJoin blocks for one inbound join, persists the joiner, and returns
// it. Teardown: the joiner owns the connection close — we half-close and
// wait, so the ack's FIN reaches them before the connection tears down.
func AcceptJoin(ctx context.Context, l *bsquic.Listener, store *peers.Store) (peers.Peer, error) {
	conn, err := l.Accept(ctx)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("accept: %w", err)
	}

	// Defensive wrap: transport dying between Accept and first stream.
	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("accept stream: %w", err)
	}

	addr, err := protocol.ReadJoinHello(stream, maxAdvertisedAddrLen)
	if err != nil {
		_ = protocol.WriteJoinAck(stream, "malformed hello")
		_ = stream.Close()
		return peers.Peer{}, fmt.Errorf("read hello: %w", err)
	}

	peer := peers.Peer{
		Addr:   addr,
		PubKey: ed25519PubCopy(conn.RemotePub()),
		Role:   peers.RolePeer,
	}
	if err := store.Add(peer); err != nil {
		_ = protocol.WriteJoinAck(stream, "store error")
		_ = stream.Close()
		return peers.Peer{}, fmt.Errorf("persist peer: %w", err)
	}
	if err := writeJoinAckFunc(stream, ""); err != nil {
		return peers.Peer{}, fmt.Errorf("write ack: %w", err)
	}
	// Half-close so the ack FIN reaches the joiner, then wait for close.
	_ = stream.Close()
	_, _ = conn.AcceptStream(ctx)
	return peer, nil
}

// DoJoin dials the introducer named by tokenStr (TLS pinned to the token's
// pubkey), advertises myListenAddr, reads the ack, and persists the
// introducer. Peer store is untouched on any failure.
func DoJoin(ctx context.Context, tokenStr string, myPriv ed25519.PrivateKey, myListenAddr string, store *peers.Store) (peers.Peer, error) {
	tok, err := token.Decode(tokenStr)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("decode token: %w", err)
	}
	conn, err := bsquic.Dial(ctx, tok.Addr, myPriv, tok.Pub)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("dial introducer: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Defensive wrap: transport dying between Dial and first stream.
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("open stream: %w", err)
	}
	if err := writeJoinHelloFunc(stream, myListenAddr); err != nil {
		_ = stream.Close()
		return peers.Peer{}, fmt.Errorf("write hello: %w", err)
	}
	if err := streamCloseFunc(stream); err != nil {
		return peers.Peer{}, fmt.Errorf("close hello send: %w", err)
	}
	appErr, err := protocol.ReadJoinAck(stream)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("read ack: %w", err)
	}
	if appErr != "" {
		return peers.Peer{}, fmt.Errorf("introducer rejected join: %s", appErr)
	}

	peer := peers.Peer{Addr: tok.Addr, PubKey: ed25519PubCopy(tok.Pub), Role: peers.RoleIntroducer}
	if err := store.Add(peer); err != nil {
		return peers.Peer{}, fmt.Errorf("persist peer: %w", err)
	}
	return peer, nil
}

// ed25519PubCopy returns a copy of pub. Callers hold the result past the
// TLS connection's lifetime, so aliasing the cert buffer would be unsafe.
func ed25519PubCopy(pub ed25519.PublicKey) ed25519.PublicKey {
	if pub == nil {
		return nil
	}
	out := make(ed25519.PublicKey, len(pub))
	copy(out, pub)
	return out
}
