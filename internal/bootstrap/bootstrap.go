// Package bootstrap implements the M1.8 one-shot invite/join handshake:
// an introducer accepts a single incoming QUIC connection and records
// the joiner's (verified) pubkey plus advertised listen address; the
// joiner dials the introducer, pins the introducer's pubkey from the
// token, and records the introducer reciprocally.
//
// The handshake is deliberately minimal — one bidirectional QUIC stream,
// a single `JoinHello{listen_addr}` from joiner, a single `JoinAck{}`
// from introducer — and is reused from both the standalone `invite` /
// `join` CLI commands and (in M1.9) the long-running sync daemon's
// `--invite` / `--join` startup modes. No swarm ID, no CA, no single-use
// secret enforcement yet; those arrive in M2.
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

// Package-level seams so internal tests can exercise otherwise-defensive
// branches. Production code never reassigns these — same pattern as the
// gobEncodeFunc / chmodFunc seams in internal/index and internal/peers.
var (
	// writeJoinAckFunc seams the success-path protocol.WriteJoinAck call
	// in AcceptJoin. The ack is written to a stream we just successfully
	// received a hello on; the error path is a defensive wrap for a
	// transport-dies-mid-ack edge case that fault injection is the only
	// reliable way to exercise.
	writeJoinAckFunc = protocol.WriteJoinAck
	// writeJoinHelloFunc seams protocol.WriteJoinHello in DoJoin. The
	// stream was opened successfully one line earlier, so a write failure
	// is a stdlib-invariant transport-died branch.
	writeJoinHelloFunc = protocol.WriteJoinHello
	// streamCloseFunc seams the post-hello half-close call in DoJoin.
	streamCloseFunc = func(s io.Closer) error { return s.Close() }
)

// maxAdvertisedAddrLen caps the bytes an incoming JoinHello may advertise.
// Addresses are host:port strings; 1 KiB is a generous ceiling that rules
// out allocation abuse without rejecting legitimate DNS names or IPv6
// zone identifiers.
const maxAdvertisedAddrLen = 1 << 10

// AcceptJoin blocks until a single incoming join handshake completes, or
// ctx is cancelled. On success the joining peer is persisted in the
// supplied peer store (keyed by pubkey, addr from the peer's JoinHello)
// and returned. On any failure before persistence, the peer store is
// not mutated.
//
// Teardown discipline: the joiner owns the connection close, not us.
// After writing the ack we half-close our send side and wait for the
// joiner's subsequent close (observed as an AcceptStream error). Calling
// conn.Close() ourselves mid-ack-flush would trigger an application
// error on the joiner's read side before the ack bytes arrived — the
// same QUIC footgun we hit in M1.5's echo test.
func AcceptJoin(ctx context.Context, l *bsquic.Listener, store *peers.Store) (peers.Peer, error) {
	conn, err := l.Accept(ctx)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("accept: %w", err)
	}

	// Defensive wrap for a QUIC transport death between Accept() and the
	// joiner opening their first stream. Deliberately uncovered: the QUIC
	// stack doesn't give us a clean seam to force AcceptStream to fail
	// after a successful Accept without reimplementing the connection.
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
	}
	if err := store.Add(peer); err != nil {
		_ = protocol.WriteJoinAck(stream, "store error")
		_ = stream.Close()
		return peers.Peer{}, fmt.Errorf("persist peer: %w", err)
	}
	if err := writeJoinAckFunc(stream, ""); err != nil {
		return peers.Peer{}, fmt.Errorf("write ack: %w", err)
	}
	// Half-close send so the ack's FIN reaches the joiner, then block
	// until the joiner closes the connection. AcceptStream returning
	// any error here means "peer went away" — that's our signal to exit.
	_ = stream.Close()
	_, _ = conn.AcceptStream(ctx)
	return peer, nil
}

// DoJoin decodes tokenStr, dials the introducer with a TLS pubkey pin
// derived from the token, sends the joiner's advertised listen address
// (may be empty), reads the ack, and persists the introducer. Returns
// the persisted introducer peer on success; peer store is untouched on
// any failure.
func DoJoin(ctx context.Context, tokenStr string, myPriv ed25519.PrivateKey, myListenAddr string, store *peers.Store) (peers.Peer, error) {
	addr, pub, err := token.Decode(tokenStr)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("decode token: %w", err)
	}
	conn, err := bsquic.Dial(ctx, addr, myPriv, pub)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("dial introducer: %w", err)
	}
	defer func() { _ = conn.Close() }()

	// Defensive wrap for a QUIC transport death between Dial success and
	// the first stream open. Deliberately uncovered: OpenStreamSync on a
	// freshly-dialed conn doesn't have a clean fault-injection seam.
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

	peer := peers.Peer{Addr: addr, PubKey: ed25519PubCopy(pub)}
	if err := store.Add(peer); err != nil {
		return peers.Peer{}, fmt.Errorf("persist peer: %w", err)
	}
	return peer, nil
}

// ed25519PubCopy returns a defensively-owned copy of pub. Callers in
// this package hold the returned slice past the TLS connection's
// lifetime, so aliasing the cert's buffer would be a use-after-free
// waiting to happen.
func ed25519PubCopy(pub ed25519.PublicKey) ed25519.PublicKey {
	if pub == nil {
		return nil
	}
	out := make(ed25519.PublicKey, len(pub))
	copy(out, pub)
	return out
}
