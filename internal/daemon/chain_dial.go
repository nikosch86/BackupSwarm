package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"time"

	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// chainDial step seams: one var per fallback rung (direct, hole-punch,
// TURN). Tests swap them.
var (
	chainDirectDialFn = bsquic.Dial
	chainTURNDialFn   = bsquic.DialOver
	chainPunchFn      = func(ctx context.Context, po *punchOrchestrator, target ed25519.PublicKey, rdv *bsquic.Conn) (*bsquic.Conn, error) {
		return po.RequestPunch(ctx, target, rdv)
	}
)

// chainMethod identifies which fallback step produced the conn.
type chainMethod string

const (
	chainMethodDirect    chainMethod = "direct"
	chainMethodHolePunch chainMethod = "hole_punch"
	chainMethodTURN      chainMethod = "turn"
)

// chainDialOptions configures one fallback-chain dial. Nil punchOrch
// disables the hole-punch step; nil turnPC disables the TURN step.
// Each timeout bounds only its own step.
type chainDialOptions struct {
	target        peers.Peer
	priv          ed25519.PrivateKey
	directTimeout time.Duration
	punchTimeout  time.Duration
	turnTimeout   time.Duration
	punchOrch     *punchOrchestrator
	turnPC        net.PacketConn
	connSet       *swarm.ConnSet
}

// chainDial tries direct → hole-punch → TURN with per-step sub-contexts,
// returns the first success. Skipped steps (absent prerequisites) do not
// contribute to the joined error returned on full failure.
func chainDial(ctx context.Context, opts chainDialOptions) (*bsquic.Conn, chainMethod, error) {
	targetPubHex := hex.EncodeToString(opts.target.PubKey)
	slog.DebugContext(ctx, "chain_dial: start",
		"target_pub", targetPubHex,
		"target_addr", opts.target.Addr,
		"punch_enabled", opts.punchOrch != nil,
		"turn_enabled", opts.turnPC != nil,
		"direct_timeout", opts.directTimeout,
		"punch_timeout", opts.punchTimeout,
		"turn_timeout", opts.turnTimeout,
	)
	var errs []error

	slog.DebugContext(ctx, "chain_dial: direct attempt",
		"target_pub", targetPubHex,
		"target_addr", opts.target.Addr,
		"timeout", opts.directTimeout)
	dctx, dcancel := context.WithTimeout(ctx, opts.directTimeout)
	conn, err := chainDirectDialFn(dctx, opts.target.Addr, opts.priv, opts.target.PubKey, nil)
	dcancel()
	if err == nil {
		slog.DebugContext(ctx, "chain_dial: direct succeeded", "target_pub", targetPubHex)
		return conn, chainMethodDirect, nil
	}
	slog.DebugContext(ctx, "chain_dial: direct failed",
		"target_pub", targetPubHex,
		"err", err)
	errs = append(errs, fmt.Errorf("direct: %w", err))

	if opts.punchOrch == nil {
		slog.DebugContext(ctx, "chain_dial: hole_punch skipped",
			"target_pub", targetPubHex,
			"reason", "no_orchestrator")
	} else {
		rdv, ok := pickRendezvous(opts.connSet, opts.target.PubKey)
		if !ok {
			slog.DebugContext(ctx, "chain_dial: hole_punch skipped",
				"target_pub", targetPubHex,
				"reason", "no_rendezvous")
		} else {
			rdvPubHex := hex.EncodeToString(rdv.RemotePub())
			slog.DebugContext(ctx, "chain_dial: hole_punch attempt",
				"target_pub", targetPubHex,
				"rendezvous_pub", rdvPubHex,
				"timeout", opts.punchTimeout)
			pctx, pcancel := context.WithTimeout(ctx, opts.punchTimeout)
			conn, err := chainPunchFn(pctx, opts.punchOrch, opts.target.PubKey, rdv)
			pcancel()
			if err == nil {
				slog.DebugContext(ctx, "chain_dial: hole_punch succeeded",
					"target_pub", targetPubHex,
					"rendezvous_pub", rdvPubHex)
				return conn, chainMethodHolePunch, nil
			}
			slog.DebugContext(ctx, "chain_dial: hole_punch failed",
				"target_pub", targetPubHex,
				"rendezvous_pub", rdvPubHex,
				"err", err)
			errs = append(errs, fmt.Errorf("hole_punch: %w", err))
		}
	}

	if opts.turnPC == nil {
		slog.DebugContext(ctx, "chain_dial: turn skipped",
			"target_pub", targetPubHex,
			"reason", "no_allocation")
	} else {
		slog.DebugContext(ctx, "chain_dial: turn attempt",
			"target_pub", targetPubHex,
			"target_addr", opts.target.Addr,
			"timeout", opts.turnTimeout)
		tctx, tcancel := context.WithTimeout(ctx, opts.turnTimeout)
		conn, err := chainTURNDialFn(tctx, opts.turnPC, opts.target.Addr, opts.priv, opts.target.PubKey, nil)
		tcancel()
		if err == nil {
			slog.DebugContext(ctx, "chain_dial: turn succeeded", "target_pub", targetPubHex)
			return conn, chainMethodTURN, nil
		}
		slog.DebugContext(ctx, "chain_dial: turn failed",
			"target_pub", targetPubHex,
			"err", err)
		errs = append(errs, fmt.Errorf("turn: %w", err))
	}

	slog.DebugContext(ctx, "chain_dial: all steps failed",
		"target_pub", targetPubHex,
		"steps_attempted", len(errs))
	return nil, "", errors.Join(errs...)
}

// pickRendezvous returns any conn in cs whose RemotePub differs from
// target. Iteration order is map-undefined.
func pickRendezvous(cs *swarm.ConnSet, target ed25519.PublicKey) (*bsquic.Conn, bool) {
	if cs == nil {
		return nil, false
	}
	for _, c := range cs.Snapshot() {
		if !bytes.Equal(c.RemotePub(), target) {
			return c, true
		}
	}
	return nil, false
}
