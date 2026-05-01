package daemon

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"log/slog"

	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/replication"
	"backupswarm/internal/swarm"
)

// defaultCleanupChannelDepth bounds the in-flight recovery events the
// dispatcher will buffer before dropping new arrivals.
const defaultCleanupChannelDepth = 16

// cleanupLoopOptions configures runCleanupLoop.
type cleanupLoopOptions struct {
	ch      <-chan []byte
	cleanFn func(ctx context.Context, pub []byte)
}

// runCleanupLoop processes recovery events serially until ctx is cancelled.
func runCleanupLoop(ctx context.Context, opts cleanupLoopOptions) {
	for {
		select {
		case <-ctx.Done():
			return
		case pub, ok := <-opts.ch:
			if !ok {
				return
			}
			opts.cleanFn(ctx, pub)
		}
	}
}

// makeRecoverDispatcher returns the OnRecover callback that enqueues
// recovery events to the cleanup loop. Drops on a full channel.
func makeRecoverDispatcher(ch chan<- []byte) swarm.OnRecoverFunc {
	return func(pub []byte) {
		select {
		case ch <- pub:
		default:
			slog.Warn("cleanup channel full; recover event dropped",
				"peer_pub", hex.EncodeToString(pub))
		}
	}
}

// makeCleanupFn returns the per-event cleanup closure used by runCleanupLoop.
func makeCleanupFn(idx *index.Index, connSet *swarm.ConnSet, redundancy int, progress io.Writer) func(context.Context, []byte) {
	return func(ctx context.Context, pub []byte) {
		c := findConnByPub(connSet, pub)
		if c == nil {
			slog.DebugContext(ctx, "cleanup skipped: no live conn for recovered peer",
				"peer_pub", hex.EncodeToString(pub))
			return
		}
		if err := replication.RunCleanup(ctx, replication.CleanupOptions{
			Index:      idx,
			Conn:       c,
			Redundancy: redundancy,
			Progress:   progress,
		}); err != nil {
			slog.WarnContext(ctx, "cleanup sweep failed",
				"peer_pub", hex.EncodeToString(pub),
				"err", err)
		}
	}
}

// findConnByPub returns the conn in connSet whose RemotePub equals pub.
func findConnByPub(connSet *swarm.ConnSet, pub []byte) *bsquic.Conn {
	for _, c := range connSet.Snapshot() {
		if bytes.Equal(c.RemotePub(), pub) {
			return c
		}
	}
	return nil
}
