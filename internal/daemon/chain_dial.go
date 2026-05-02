package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
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
	var errs []error

	dctx, dcancel := context.WithTimeout(ctx, opts.directTimeout)
	conn, err := chainDirectDialFn(dctx, opts.target.Addr, opts.priv, opts.target.PubKey, nil)
	dcancel()
	if err == nil {
		return conn, chainMethodDirect, nil
	}
	errs = append(errs, fmt.Errorf("direct: %w", err))

	if opts.punchOrch != nil {
		if rdv, ok := pickRendezvous(opts.connSet, opts.target.PubKey); ok {
			pctx, pcancel := context.WithTimeout(ctx, opts.punchTimeout)
			conn, err := chainPunchFn(pctx, opts.punchOrch, opts.target.PubKey, rdv)
			pcancel()
			if err == nil {
				return conn, chainMethodHolePunch, nil
			}
			errs = append(errs, fmt.Errorf("hole_punch: %w", err))
		}
	}

	if opts.turnPC != nil {
		tctx, tcancel := context.WithTimeout(ctx, opts.turnTimeout)
		conn, err := chainTURNDialFn(tctx, opts.turnPC, opts.target.Addr, opts.priv, opts.target.PubKey, nil)
		tcancel()
		if err == nil {
			return conn, chainMethodTURN, nil
		}
		errs = append(errs, fmt.Errorf("turn: %w", err))
	}

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
