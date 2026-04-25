// Package bootstrap implements the invite/join handshake: a single QUIC
// stream carrying a JoinRequest from the joiner, a JoinResponse from the
// introducer, and a PeerListMessage with the introducer's known peers.
package bootstrap

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"

	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/pkg/token"
)

// Test-only seams for fault-injection on transport-died error wraps.
var (
	writeJoinResponseFunc = protocol.WriteJoinResponse
	writeJoinRequestFunc  = protocol.WriteJoinRequest
	writePeerListFunc     = protocol.WritePeerListMessage
	streamCloseFunc       = func(s io.Closer) error { return s.Close() }
)

// maxAdvertisedAddrLen caps incoming addresses at 1 KiB.
const maxAdvertisedAddrLen = 1 << 10

// maxPeerListEntries caps the inbound peer-list count.
const maxPeerListEntries = 1 << 10

// Wire vocabulary for JoinResponse application errors.
const (
	wireErrSwarmMismatch = "swarm_mismatch"
	wireErrBadSecret     = "bad_secret"
	wireErrInternal      = "internal"
)

// ErrSwarmMismatch is returned by DoJoin when the introducer rejected
// the request because the swarm IDs disagreed.
var ErrSwarmMismatch = errors.New("introducer reports swarm ID mismatch")

// ErrBadSecret is returned by DoJoin when the introducer rejected the
// single-use secret in the token.
var ErrBadSecret = errors.New("introducer rejected join secret")

// ErrIntroducerInternal is returned by DoJoin for an opaque introducer-
// side failure.
var ErrIntroducerInternal = errors.New("introducer reported internal error")

// Expected is the introducer-side per-invite session state: the values
// AcceptJoin compares the joiner's request against.
type Expected struct {
	SwarmID [token.SwarmIDSize]byte
	Secret  [token.SecretSize]byte
}

// JoinResult is what DoJoin gives back: the introducer record persisted
// locally and the peer list the introducer reported. Persistence of the
// peer list is the caller's responsibility.
type JoinResult struct {
	Introducer peers.Peer
	Peers      []peers.Peer
}

// AcceptJoin blocks for one inbound join, validates it against expected,
// sends the introducer's peer list, and persists the joiner. The stream
// is closed on every return path so the joiner surfaces EOF.
func AcceptJoin(ctx context.Context, l *bsquic.Listener, store *peers.Store, expected Expected) (peers.Peer, error) {
	conn, err := l.Accept(ctx)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("accept: %w", err)
	}

	stream, err := conn.AcceptStream(ctx)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("accept stream: %w", err)
	}
	streamClosed := false
	defer func() {
		if !streamClosed {
			_ = stream.Close()
		}
	}()

	gotSwarm, gotSecret, addr, err := protocol.ReadJoinRequest(stream, maxAdvertisedAddrLen)
	if err != nil {
		_ = writeJoinResponseFunc(stream, "malformed request")
		return peers.Peer{}, fmt.Errorf("read join request: %w", err)
	}
	if subtle.ConstantTimeCompare(gotSwarm[:], expected.SwarmID[:]) != 1 {
		_ = writeJoinResponseFunc(stream, wireErrSwarmMismatch)
		return peers.Peer{}, fmt.Errorf("swarm id mismatch")
	}
	if subtle.ConstantTimeCompare(gotSecret[:], expected.Secret[:]) != 1 {
		_ = writeJoinResponseFunc(stream, wireErrBadSecret)
		return peers.Peer{}, fmt.Errorf("join secret mismatch")
	}

	snapshot, err := store.List()
	if err != nil {
		_ = writeJoinResponseFunc(stream, wireErrInternal)
		return peers.Peer{}, fmt.Errorf("snapshot peers: %w", err)
	}
	if err := writeJoinResponseFunc(stream, ""); err != nil {
		return peers.Peer{}, fmt.Errorf("write response: %w", err)
	}
	entries, err := peersToEntries(snapshot)
	if err != nil {
		return peers.Peer{}, fmt.Errorf("encode peer list: %w", err)
	}
	if err := writePeerListFunc(stream, entries); err != nil {
		return peers.Peer{}, fmt.Errorf("write peer list: %w", err)
	}

	peer := peers.Peer{
		Addr:   addr,
		PubKey: ed25519PubCopy(conn.RemotePub()),
		Role:   peers.RolePeer,
	}
	if err := store.Add(peer); err != nil {
		return peers.Peer{}, fmt.Errorf("persist peer: %w", err)
	}
	_ = stream.Close()
	streamClosed = true
	_, _ = conn.AcceptStream(ctx)
	return peer, nil
}

// DoJoin dials the introducer named by tokenStr (TLS pinned to the
// token's pubkey), exchanges the join handshake, persists the introducer,
// and returns the received peer list. Store untouched on any failure.
func DoJoin(ctx context.Context, tokenStr string, myPriv ed25519.PrivateKey, myListenAddr string, store *peers.Store) (JoinResult, error) {
	tok, err := token.Decode(tokenStr)
	if err != nil {
		return JoinResult{}, fmt.Errorf("decode token: %w", err)
	}
	conn, err := bsquic.Dial(ctx, tok.Addr, myPriv, tok.Pub)
	if err != nil {
		return JoinResult{}, fmt.Errorf("dial introducer: %w", err)
	}
	defer func() { _ = conn.Close() }()

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return JoinResult{}, fmt.Errorf("open stream: %w", err)
	}
	if err := writeJoinRequestFunc(stream, tok.SwarmID, tok.Secret, myListenAddr); err != nil {
		_ = stream.Close()
		return JoinResult{}, fmt.Errorf("write request: %w", err)
	}
	if err := streamCloseFunc(stream); err != nil {
		return JoinResult{}, fmt.Errorf("close request send: %w", err)
	}
	appErr, err := protocol.ReadJoinResponse(stream)
	if err != nil {
		return JoinResult{}, fmt.Errorf("read response: %w", err)
	}
	if appErr != "" {
		return JoinResult{}, joinResponseError(appErr)
	}
	entries, err := protocol.ReadPeerListMessage(stream, maxPeerListEntries, maxAdvertisedAddrLen)
	if err != nil {
		return JoinResult{}, fmt.Errorf("read peer list: %w", err)
	}
	receivedPeers, err := entriesToPeers(entries)
	if err != nil {
		return JoinResult{}, fmt.Errorf("decode peer list: %w", err)
	}

	introducer := peers.Peer{Addr: tok.Addr, PubKey: ed25519PubCopy(tok.Pub), Role: peers.RoleIntroducer}
	if err := store.Add(introducer); err != nil {
		return JoinResult{}, fmt.Errorf("persist introducer: %w", err)
	}
	return JoinResult{Introducer: introducer, Peers: receivedPeers}, nil
}

// peersToEntries maps the peer-store snapshot to wire entries, rejecting
// records with an invalid pubkey size or zero role.
func peersToEntries(in []peers.Peer) ([]protocol.PeerEntry, error) {
	out := make([]protocol.PeerEntry, 0, len(in))
	for i, p := range in {
		if len(p.PubKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("peer %d: pubkey size %d", i, len(p.PubKey))
		}
		if p.Role == peers.RoleUnspecified {
			return nil, fmt.Errorf("peer %d: role unspecified", i)
		}
		var entry protocol.PeerEntry
		copy(entry.PubKey[:], p.PubKey)
		entry.Role = byte(p.Role)
		entry.Addr = p.Addr
		out = append(out, entry)
	}
	return out, nil
}

// entriesToPeers maps wire entries back to peer records, validating the
// role byte against the known peers.Role enum.
func entriesToPeers(in []protocol.PeerEntry) ([]peers.Peer, error) {
	out := make([]peers.Peer, 0, len(in))
	for i, e := range in {
		role := peers.Role(e.Role)
		switch role {
		case peers.RolePeer, peers.RoleIntroducer, peers.RoleStorage:
		default:
			return nil, fmt.Errorf("peer entry %d: unknown role %d", i, e.Role)
		}
		pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
		copy(pub, e.PubKey[:])
		out = append(out, peers.Peer{Addr: e.Addr, PubKey: pub, Role: role})
	}
	return out, nil
}

// joinResponseError maps a wire error code to its typed sentinel.
func joinResponseError(code string) error {
	switch code {
	case wireErrSwarmMismatch:
		return ErrSwarmMismatch
	case wireErrBadSecret:
		return ErrBadSecret
	case wireErrInternal:
		return ErrIntroducerInternal
	default:
		return fmt.Errorf("introducer rejected join: %s", code)
	}
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
