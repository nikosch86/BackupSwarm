// Package bootstrap implements the invite/join handshake: a single QUIC
// stream carrying a JoinRequest from the joiner, a JoinResponse from the
// introducer, and a PeerListMessage with the introducer's known peers.
package bootstrap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"backupswarm/internal/ca"
	"backupswarm/internal/invites"
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

// maxJoinCSRLen / maxJoinCertLen cap the CSR sent by the joiner and the
// signed leaf cert returned by the introducer. An Ed25519 CSR/leaf is ~250 bytes.
const (
	maxJoinCSRLen  = 1 << 12
	maxJoinCertLen = 1 << 12
)

// Wire vocabulary for JoinResponse application errors.
const (
	wireErrSwarmMismatch = "swarm_mismatch"
	wireErrBadSecret     = "bad_secret"
	wireErrTokenUsed     = "already_used"
	wireErrInternal      = "internal"
)

// ErrSwarmMismatch is returned by DoJoin when the introducer rejected
// the request because the swarm IDs disagreed.
var ErrSwarmMismatch = errors.New("introducer reports swarm ID mismatch")

// ErrBadSecret is returned by DoJoin when the introducer did not
// recognize the single-use secret in the token.
var ErrBadSecret = errors.New("introducer rejected join secret")

// ErrTokenUsed is returned by DoJoin when the secret was previously
// consumed by an earlier successful join.
var ErrTokenUsed = errors.New("introducer reports token already used")

// ErrIntroducerInternal is returned by DoJoin for an opaque introducer-
// side failure.
var ErrIntroducerInternal = errors.New("introducer reported internal error")

// SecretValidator atomically verifies a join secret and returns the
// swarm ID it was issued for. Implementations may consult an on-disk
// log; the validation must be a same-transaction read+mark-consumed.
type SecretValidator func(secret [token.SecretSize]byte) ([token.SwarmIDSize]byte, error)

// ErrMissingSignedCert is returned by DoJoin when the token carried a
// CACert but the introducer's response had no signed leaf.
var ErrMissingSignedCert = errors.New("introducer returned empty signed cert in CA-mode swarm")

// JoinResult bundles the introducer record, the introducer's peer list,
// and the joiner's CA-signed leaf cert (empty in pubkey-pin swarms).
// Persistence of the cert and peer list is the caller's responsibility.
type JoinResult struct {
	Introducer peers.Peer
	Peers      []peers.Peer
	SignedCert []byte
}

// AcceptJoin blocks for one inbound join, validates the request via
// validate, signs the joiner's CSR with swarmCA when non-nil, sends the
// peer list, and persists the joiner. swarmCA nil = pubkey-pin mode.
func AcceptJoin(ctx context.Context, l *bsquic.Listener, store *peers.Store, validate SecretValidator, swarmCA *ca.CA) (peers.Peer, error) {
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

	gotSwarm, gotSecret, addr, csrDER, err := protocol.ReadJoinRequest(stream, maxAdvertisedAddrLen, maxJoinCSRLen)
	if err != nil {
		_ = writeJoinResponseFunc(stream, nil, "malformed request")
		return peers.Peer{}, fmt.Errorf("read join request: %w", err)
	}
	expectedSwarm, err := validate(gotSecret)
	if err != nil {
		_ = writeJoinResponseFunc(stream, nil, validatorWireCode(err))
		return peers.Peer{}, fmt.Errorf("validate secret: %w", err)
	}
	if subtle.ConstantTimeCompare(gotSwarm[:], expectedSwarm[:]) != 1 {
		_ = writeJoinResponseFunc(stream, nil, wireErrSwarmMismatch)
		return peers.Peer{}, fmt.Errorf("swarm id mismatch")
	}

	signedCertDER, err := signJoinerCSRIfCA(ctx, swarmCA, csrDER, conn.RemotePub())
	if err != nil {
		_ = writeJoinResponseFunc(stream, nil, wireErrInternal)
		return peers.Peer{}, err
	}

	snapshot, err := store.List()
	if err != nil {
		_ = writeJoinResponseFunc(stream, nil, wireErrInternal)
		return peers.Peer{}, fmt.Errorf("snapshot peers: %w", err)
	}
	if err := writeJoinResponseFunc(stream, signedCertDER, ""); err != nil {
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
// token's pubkey), exchanges the handshake (sending a CSR when the token
// carries a CA cert), and persists the introducer. Store untouched on failure.
func DoJoin(ctx context.Context, tokenStr string, myPriv ed25519.PrivateKey, myListenAddr string, store *peers.Store) (JoinResult, error) {
	tok, err := token.Decode(tokenStr)
	if err != nil {
		return JoinResult{}, fmt.Errorf("decode token: %w", err)
	}
	var csrDER []byte
	if len(tok.CACert) > 0 {
		csrDER, err = ca.CreateCSR(myPriv)
		if err != nil {
			return JoinResult{}, fmt.Errorf("create csr: %w", err)
		}
	}
	conn, err := bsquic.Dial(ctx, tok.Addr, myPriv, tok.Pub, nil)
	if err != nil {
		return JoinResult{}, fmt.Errorf("dial introducer: %w", err)
	}
	defer func() { _ = conn.Close() }()

	stream, err := conn.OpenStream(ctx)
	if err != nil {
		return JoinResult{}, fmt.Errorf("open stream: %w", err)
	}
	if err := writeJoinRequestFunc(stream, tok.SwarmID, tok.Secret, myListenAddr, csrDER); err != nil {
		_ = stream.Close()
		return JoinResult{}, fmt.Errorf("write request: %w", err)
	}
	if err := streamCloseFunc(stream); err != nil {
		return JoinResult{}, fmt.Errorf("close request send: %w", err)
	}
	signedCertDER, appErr, err := protocol.ReadJoinResponse(stream, maxJoinCertLen)
	if err != nil {
		return JoinResult{}, fmt.Errorf("read response: %w", err)
	}
	if appErr != "" {
		return JoinResult{}, joinResponseError(appErr)
	}
	if len(tok.CACert) > 0 {
		if len(signedCertDER) == 0 {
			return JoinResult{}, ErrMissingSignedCert
		}
		if err := verifySignedCert(signedCertDER, tok.CACert, myPriv); err != nil {
			return JoinResult{}, fmt.Errorf("verify signed cert: %w", err)
		}
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
	// Entries colliding with the introducer pubkey are skipped so a
	// downgraded peer-list role cannot overwrite the RoleIntroducer
	// record, which IsStorageCandidate relies on.
	for i, p := range receivedPeers {
		if bytes.Equal(p.PubKey, introducer.PubKey) {
			continue
		}
		if err := store.Add(p); err != nil {
			return JoinResult{}, fmt.Errorf("persist peer %d: %w", i, err)
		}
	}
	return JoinResult{Introducer: introducer, Peers: receivedPeers, SignedCert: signedCertDER}, nil
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
	case wireErrTokenUsed:
		return ErrTokenUsed
	case wireErrInternal:
		return ErrIntroducerInternal
	default:
		return fmt.Errorf("introducer rejected join: %s", code)
	}
}

// validatorWireCode picks the wire error code for a validator error.
func validatorWireCode(err error) string {
	switch {
	case errors.Is(err, invites.ErrUnknown):
		return wireErrBadSecret
	case errors.Is(err, invites.ErrAlreadyUsed):
		return wireErrTokenUsed
	default:
		return wireErrInternal
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

// signJoinerCSRIfCA signs csrDER with swarmCA, pinning the CSR pubkey
// to joinerPub. Returns (nil, nil) when swarmCA is nil; errors when
// swarmCA is non-nil and csrDER is empty or invalid.
func signJoinerCSRIfCA(ctx context.Context, swarmCA *ca.CA, csrDER []byte, joinerPub ed25519.PublicKey) ([]byte, error) {
	if swarmCA == nil {
		return nil, nil
	}
	if len(csrDER) == 0 {
		slog.WarnContext(ctx, "join request missing csr in ca-mode swarm",
			"joiner_pub", hex.EncodeToString(joinerPub))
		return nil, fmt.Errorf("missing CSR in CA-mode swarm")
	}
	signedCertDER, err := ca.SignNodeCert(swarmCA, csrDER, joinerPub, ca.DefaultLeafValidity)
	if err != nil {
		slog.WarnContext(ctx, "sign joiner csr failed",
			"joiner_pub", hex.EncodeToString(joinerPub),
			"error", err)
		return nil, fmt.Errorf("sign joiner csr: %w", err)
	}
	slog.InfoContext(ctx, "signed joiner leaf cert",
		"joiner_pub", hex.EncodeToString(joinerPub),
		"validity", ca.DefaultLeafValidity)
	return signedCertDER, nil
}

// verifySignedCert checks that certDER chains to caCertDER and that the
// leaf's Ed25519 pubkey equals myPriv.Public().
func verifySignedCert(certDER, caCertDER []byte, myPriv ed25519.PrivateKey) error {
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse leaf: %w", err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		return fmt.Errorf("parse swarm ca cert: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("chain verify: %w", err)
	}
	leafPub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("leaf public key is %T, want ed25519.PublicKey", leaf.PublicKey)
	}
	myPub, ok := myPriv.Public().(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("my private key is not ed25519")
	}
	if !leafPub.Equal(myPub) {
		return errors.New("leaf public key does not match our identity")
	}
	return nil
}
