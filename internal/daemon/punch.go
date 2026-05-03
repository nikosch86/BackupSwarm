package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/nat"
	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// maxPunchAddrLen caps the addr field on punch wire frames; larger frames
// are rejected at read time before allocation.
const maxPunchAddrLen = 256

// errPunchTargetOffline is returned by a forwardSignal seam when the target
// has no live conn to relay through.
var errPunchTargetOffline = errors.New("punch: target offline")

// Test seams; production never reassigns these.
var (
	punchSendRequestFn = backup.SendPunchRequest
	punchSendSignalFn  = backup.SendPunchSignal
	punchFireFn        = nat.Punch
	punchDialFn        = bsquic.Dial
)

// punchOrchestrator runs the rendezvous, target, and initiator sides of
// UDP hole-punching. It owns the listener's PacketConn for the punch and
// the connSet/peerStore views needed to resolve targets.
type punchOrchestrator struct {
	ctx           context.Context
	listener      *bsquic.Listener
	connSet       *swarm.ConnSet
	peerStore     *peers.Store
	priv          ed25519.PrivateKey
	advertiseAddr string

	attempts int
	interval time.Duration

	// forwardSignal is the rendezvous's "relay this PunchSignal to target"
	// seam. Production wires it to connSet.Get + backup.SendPunchSignal;
	// returns errPunchTargetOffline when the target has no live conn.
	forwardSignal func(ctx context.Context, targetPub []byte, payload protocol.PunchPayload) error

	// pendingPunches tracks in-flight target-side punch goroutines so
	// daemon shutdown can wait for them.
	pendingPunches sync.WaitGroup
}

// defaultPunchAttempts and defaultPunchInterval set how many datagrams
// each side fires and how long the firing window lasts. 5 × 100ms gives
// ~500ms of overlap with the peer's punch window — comfortable for the
// 30s+ mapping lifetimes typical NATs allow.
const (
	defaultPunchAttempts = 5
	defaultPunchInterval = 100 * time.Millisecond
)

// newPunchOrchestrator wires the runtime dependencies into a fresh
// orchestrator with default tunables. forwardSignal is computed from
// connSet + the SendPunchSignal seam.
func newPunchOrchestrator(ctx context.Context, listener *bsquic.Listener, connSet *swarm.ConnSet, peerStore *peers.Store, priv ed25519.PrivateKey, advertiseAddr string) *punchOrchestrator {
	po := &punchOrchestrator{
		ctx:           ctx,
		listener:      listener,
		connSet:       connSet,
		peerStore:     peerStore,
		priv:          priv,
		advertiseAddr: advertiseAddr,
		attempts:      defaultPunchAttempts,
		interval:      defaultPunchInterval,
	}
	po.forwardSignal = po.defaultForwardSignal
	return po
}

// defaultForwardSignal looks up the target's live conn and forwards the
// signal frame; returns errPunchTargetOffline when no conn exists.
func (po *punchOrchestrator) defaultForwardSignal(ctx context.Context, targetPub []byte, payload protocol.PunchPayload) error {
	conn, ok := po.connSet.Get(targetPub)
	if !ok {
		return errPunchTargetOffline
	}
	return punchSendSignalFn(ctx, conn, payload)
}

// handleRequest is the rendezvous-side handler for MsgPunchRequest streams.
func (po *punchOrchestrator) handleRequest(ctx context.Context, rw io.ReadWriter, initiatorPub []byte) error {
	payload, err := protocol.ReadPunchPayload(rw, maxPunchAddrLen)
	if err != nil {
		return fmt.Errorf("read punch request: %w", err)
	}
	targetPub := payload.PeerPub[:]
	if _, err := po.peerStore.Get(targetPub); err != nil {
		slog.WarnContext(ctx, "punch request rejected",
			"reason", "unknown_target",
			"initiator_pub", hex.EncodeToString(initiatorPub),
			"target_pub", hex.EncodeToString(targetPub))
		return protocol.WritePunchResponse(rw, "unknown_target")
	}
	var initiatorPubArr [32]byte
	copy(initiatorPubArr[:], initiatorPub)
	signal := protocol.PunchPayload{
		PeerPub: initiatorPubArr,
		Addr:    payload.Addr,
	}
	if err := po.forwardSignal(ctx, targetPub, signal); err != nil {
		if errors.Is(err, errPunchTargetOffline) {
			slog.WarnContext(ctx, "punch request rejected",
				"reason", "target_offline",
				"target_pub", hex.EncodeToString(targetPub))
			return protocol.WritePunchResponse(rw, "target_offline")
		}
		slog.WarnContext(ctx, "punch request forward failed",
			"target_pub", hex.EncodeToString(targetPub),
			"err", err)
		return protocol.WritePunchResponse(rw, "internal")
	}
	slog.InfoContext(ctx, "relayed punch signal",
		"initiator_pub", hex.EncodeToString(initiatorPub),
		"target_pub", hex.EncodeToString(targetPub),
		"initiator_addr", payload.Addr)
	return protocol.WritePunchResponse(rw, "")
}

// handleSignal is the target-side handler for MsgPunchSignal streams. It
// ACKs the relay immediately, then fires punch packets at the initiator
// in the background so both sides punch concurrently.
func (po *punchOrchestrator) handleSignal(ctx context.Context, rw io.ReadWriter, _ []byte) error {
	payload, err := protocol.ReadPunchPayload(rw, maxPunchAddrLen)
	if err != nil {
		return fmt.Errorf("read punch signal: %w", err)
	}
	initiatorAddr, err := net.ResolveUDPAddr("udp", payload.Addr)
	if err != nil {
		slog.WarnContext(ctx, "punch signal rejected",
			"reason", "invalid_addr",
			"addr", payload.Addr,
			"err", err)
		return protocol.WritePunchResponse(rw, "invalid_addr")
	}
	if err := protocol.WritePunchResponse(rw, ""); err != nil {
		return err
	}
	slog.InfoContext(ctx, "nat_punch firing",
		"method", "hole_punch",
		"role", "target",
		"initiator_pub", hex.EncodeToString(payload.PeerPub[:]),
		"initiator_addr", initiatorAddr.String(),
		"attempts", po.attempts)
	po.pendingPunches.Add(1)
	go func() {
		defer po.pendingPunches.Done()
		budget := time.Duration(po.attempts)*po.interval + 2*time.Second
		punchCtx, cancel := context.WithTimeout(po.ctx, budget)
		defer cancel()
		if err := punchFireFn(punchCtx, po.listener.PacketConn(), initiatorAddr, po.attempts, po.interval); err != nil {
			slog.WarnContext(punchCtx, "nat_punch failed",
				"role", "target",
				"initiator_addr", initiatorAddr.String(),
				"err", err)
		}
	}()
	return nil
}

// RequestPunch is the initiator-side API: ask `rendezvous` to relay a
// signal to `targetPub`, then fire local punch packets and dial through
// the punched mapping. Returns the established conn or an error.
func (po *punchOrchestrator) RequestPunch(ctx context.Context, targetPub ed25519.PublicKey, rendezvous *bsquic.Conn) (*bsquic.Conn, error) {
	targetPubHex := hex.EncodeToString(targetPub)
	target, err := po.peerStore.Get(targetPub)
	if err != nil {
		return nil, fmt.Errorf("punch: unknown target: %w", err)
	}
	if target.Addr == "" {
		return nil, errors.New("punch: target has no advertise addr")
	}
	if po.advertiseAddr == "" {
		return nil, errors.New("punch: own advertise addr is empty")
	}
	var targetPubArr [32]byte
	copy(targetPubArr[:], targetPub)
	req := protocol.PunchPayload{
		PeerPub: targetPubArr,
		Addr:    po.advertiseAddr,
	}
	slog.DebugContext(ctx, "nat_punch: sending request",
		"role", "initiator",
		"target_pub", targetPubHex,
		"own_advertise_addr", po.advertiseAddr)
	if err := punchSendRequestFn(ctx, rendezvous, req); err != nil {
		slog.DebugContext(ctx, "nat_punch: send request failed",
			"role", "initiator",
			"target_pub", targetPubHex,
			"err", err)
		return nil, fmt.Errorf("punch: send request: %w", err)
	}
	slog.DebugContext(ctx, "nat_punch: rendezvous accepted request",
		"role", "initiator",
		"target_pub", targetPubHex)
	targetUDP, err := net.ResolveUDPAddr("udp", target.Addr)
	if err != nil {
		return nil, fmt.Errorf("punch: resolve target: %w", err)
	}
	slog.InfoContext(ctx, "nat_punch firing",
		"method", "hole_punch",
		"role", "initiator",
		"target_pub", targetPubHex,
		"target_addr", targetUDP.String(),
		"attempts", po.attempts)
	if err := punchFireFn(ctx, po.listener.PacketConn(), targetUDP, po.attempts, po.interval); err != nil {
		slog.WarnContext(ctx, "nat_punch failed",
			"role", "initiator",
			"target_addr", targetUDP.String(),
			"err", err)
		return nil, fmt.Errorf("punch: %w", err)
	}
	slog.DebugContext(ctx, "nat_punch: dialing punched target",
		"role", "initiator",
		"target_pub", targetPubHex,
		"target_addr", target.Addr)
	conn, err := punchDialFn(ctx, target.Addr, po.priv, targetPub, nil)
	if err != nil {
		slog.WarnContext(ctx, "peer dial after punch failed",
			"peer_pub", targetPubHex,
			"addr", target.Addr,
			"err", err)
		return nil, fmt.Errorf("punch: dial after punch: %w", err)
	}
	slog.DebugContext(ctx, "nat_punch: dial after punch succeeded",
		"role", "initiator",
		"target_pub", targetPubHex,
		"target_addr", target.Addr)
	return conn, nil
}
