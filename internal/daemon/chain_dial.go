package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// turnRelayDialer is the surface chainDial drives for the TURN step.
// *bsquic.Listener satisfies it via DialPeer; sharing the listener's
// transport keeps inbound and outbound on the same allocation.
type turnRelayDialer interface {
	DialPeer(ctx context.Context, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error)
}

// chainDial step seams: one var per fallback rung (direct, hole-punch,
// TURN, relay). Tests swap them.
var (
	chainDirectDialFn = bsquic.Dial
	chainTURNDialFn   = func(ctx context.Context, l turnRelayDialer, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error) {
		return l.DialPeer(ctx, addr, priv, expected, trust)
	}
	chainPunchFn = func(ctx context.Context, po *punchOrchestrator, target ed25519.PublicKey, rdv *bsquic.Conn) (*bsquic.Conn, error) {
		return po.RequestPunch(ctx, target, rdv)
	}
	chainRelayDialFn = func(ctx context.Context, l turnRelayDialer, addr string, priv ed25519.PrivateKey, expected ed25519.PublicKey, trust *bsquic.TrustConfig) (*bsquic.Conn, error) {
		if l != nil {
			return l.DialPeer(ctx, addr, priv, expected, trust)
		}
		return bsquic.Dial(ctx, addr, priv, expected, trust)
	}
)

// chainMethod identifies which fallback step produced the conn.
type chainMethod string

const (
	chainMethodDirect    chainMethod = "direct"
	chainMethodHolePunch chainMethod = "hole_punch"
	chainMethodTURN      chainMethod = "turn"
	chainMethodRelay     chainMethod = "relay"
)

// chainDialOptions configures one fallback-chain dial. Nil punchOrch
// disables hole-punch; nil turnListener disables TURN; empty
// target.RelayAddr disables relay. Each timeout bounds its own step.
type chainDialOptions struct {
	target        peers.Peer
	priv          ed25519.PrivateKey
	directTimeout time.Duration
	punchTimeout  time.Duration
	turnTimeout   time.Duration
	relayTimeout  time.Duration
	punchOrch     *punchOrchestrator
	turnListener  turnRelayDialer
	connSet       *swarm.ConnSet

	// allowDirectRelayDial opts the relay rung in when turnListener is
	// nil; default false skips the rung in that case.
	allowDirectRelayDial bool
}

// chainDial tries direct → hole-punch → TURN → relay with per-step
// sub-contexts, returns the first success. Skipped steps do not
// contribute to the joined error returned on full failure.
func chainDial(ctx context.Context, opts chainDialOptions) (*bsquic.Conn, chainMethod, error) {
	targetPubHex := hex.EncodeToString(opts.target.PubKey)
	slog.DebugContext(ctx, "chain_dial: start",
		"target_pub", targetPubHex,
		"target_addr", opts.target.Addr,
		"target_relay_addr", opts.target.RelayAddr,
		"punch_enabled", opts.punchOrch != nil,
		"turn_enabled", opts.turnListener != nil,
		"relay_enabled", opts.target.RelayAddr != "",
		"direct_timeout", opts.directTimeout,
		"punch_timeout", opts.punchTimeout,
		"turn_timeout", opts.turnTimeout,
		"relay_timeout", opts.relayTimeout,
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

	relayRungEligible := opts.target.RelayAddr != "" && (opts.turnListener != nil || opts.allowDirectRelayDial)

	switch {
	case opts.target.RelayAddr == "":
		slog.DebugContext(ctx, "chain_dial: relay skipped",
			"target_pub", targetPubHex,
			"reason", "no_relay_addr")
	case opts.turnListener == nil && !opts.allowDirectRelayDial:
		slog.DebugContext(ctx, "chain_dial: relay skipped",
			"target_pub", targetPubHex,
			"reason", "no_turn_listener_for_relay_addr")
	default:
		slog.DebugContext(ctx, "chain_dial: relay attempt",
			"target_pub", targetPubHex,
			"target_relay_addr", opts.target.RelayAddr,
			"via_turn_listener", opts.turnListener != nil,
			"timeout", opts.relayTimeout)
		rctx, rcancel := context.WithTimeout(ctx, opts.relayTimeout)
		conn, err := chainRelayDialFn(rctx, opts.turnListener, opts.target.RelayAddr, opts.priv, opts.target.PubKey, nil)
		rcancel()
		if err == nil {
			slog.DebugContext(ctx, "chain_dial: relay succeeded", "target_pub", targetPubHex)
			return conn, chainMethodRelay, nil
		}
		slog.DebugContext(ctx, "chain_dial: relay failed",
			"target_pub", targetPubHex,
			"err", err)
		errs = append(errs, fmt.Errorf("relay: %w", err))
	}

	switch {
	case opts.turnListener == nil:
		slog.DebugContext(ctx, "chain_dial: turn skipped",
			"target_pub", targetPubHex,
			"reason", "no_allocation")
	case relayRungEligible:
		slog.DebugContext(ctx, "chain_dial: turn skipped",
			"target_pub", targetPubHex,
			"reason", "relay_rung_already_attempted")
	default:
		slog.DebugContext(ctx, "chain_dial: turn attempt",
			"target_pub", targetPubHex,
			"target_addr", opts.target.Addr,
			"timeout", opts.turnTimeout)
		tctx, tcancel := context.WithTimeout(ctx, opts.turnTimeout)
		conn, err := chainTURNDialFn(tctx, opts.turnListener, opts.target.Addr, opts.priv, opts.target.PubKey, nil)
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
