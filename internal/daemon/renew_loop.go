package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
)

// sendRenewFunc is the test seam for owner-side TTL renewal.
var sendRenewFunc = backup.SendRenewTTL

// RenewResult is the per-pass count of (chunk, peer) renewals attempted.
type RenewResult struct {
	// Sent is the number of accepted RenewTTL requests.
	Sent int
	// Failed is the number of rejected or dropped RenewTTL requests.
	Failed int
	// Skipped is the number of pairs whose peer had no live conn.
	Skipped int
}

// renewLoopOptions configures runRenewLoop.
type renewLoopOptions struct {
	interval time.Duration
	renewFn  func(ctx context.Context) (RenewResult, error)
}

// runRenewLoop runs renewFn on entry and once per opts.interval.
func runRenewLoop(ctx context.Context, opts renewLoopOptions) {
	tick := func() {
		res, err := opts.renewFn(ctx)
		if err != nil {
			slog.WarnContext(ctx, "renew sweep failed", "err", err)
			return
		}
		slog.DebugContext(ctx, "renew sweep tick",
			"sent", res.Sent,
			"failed", res.Failed,
			"skipped", res.Skipped,
		)
	}
	tick()
	ticker := time.NewTicker(opts.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			tick()
		}
	}
}

// renewAllChunks sends RenewTTL to every (chunk, peer) pair with a live conn.
func renewAllChunks(ctx context.Context, entries []index.FileEntry, conns []*bsquic.Conn) (RenewResult, error) {
	var res RenewResult
	if err := ctx.Err(); err != nil {
		return res, err
	}
	if len(entries) == 0 {
		return res, nil
	}
	connByPub := make(map[string]*bsquic.Conn, len(conns))
	for _, c := range conns {
		if c == nil {
			continue
		}
		connByPub[hex.EncodeToString(c.RemotePub())] = c
	}
	for _, entry := range entries {
		for chunkIdx, ref := range entry.Chunks {
			for _, peerPub := range ref.Peers {
				if err := ctx.Err(); err != nil {
					return res, err
				}
				key := hex.EncodeToString(peerPub)
				conn, ok := connByPub[key]
				if !ok {
					res.Skipped++
					continue
				}
				if err := sendRenewFunc(ctx, conn, ref.CiphertextHash); err != nil {
					res.Failed++
					slog.WarnContext(ctx, "renew chunk failed",
						"path", entry.Path,
						"chunk", chunkIdx,
						"peer_pub", key,
						"err", err)
					continue
				}
				res.Sent++
			}
		}
	}
	return res, nil
}

// renewClosure returns a renewFn that re-reads the index and conns each tick.
func renewClosure(idx *index.Index, connsFn func() []*bsquic.Conn) func(context.Context) (RenewResult, error) {
	return func(ctx context.Context) (RenewResult, error) {
		entries, err := idx.List()
		if err != nil {
			return RenewResult{}, fmt.Errorf("list index: %w", err)
		}
		return renewAllChunks(ctx, entries, connsFn())
	}
}
