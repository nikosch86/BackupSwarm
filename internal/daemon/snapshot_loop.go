package daemon

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
)

// Test-only seam; production never reassigns.
var indexSnapshotUploadFunc = backup.SendPutIndexSnapshot

// indexBackupLoopOptions configures runIndexBackupLoop.
type indexBackupLoopOptions struct {
	interval     time.Duration
	connsFn      func() []*bsquic.Conn
	indexFn      func() *index.Index
	recipientPub *[crypto.RecipientKeySize]byte
}

// runIndexBackupLoop encrypts the local index and broadcasts it to every
// live storage conn on entry and once per opts.interval.
func runIndexBackupLoop(ctx context.Context, opts indexBackupLoopOptions) {
	if opts.indexFn == nil || opts.indexFn() == nil {
		return
	}
	if opts.recipientPub == nil {
		return
	}
	tick := func() {
		broadcastIndexSnapshot(ctx, opts.connsFn(), opts.indexFn(), opts.recipientPub)
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

// broadcastIndexSnapshot encrypts the index and ships it to every conn.
func broadcastIndexSnapshot(ctx context.Context, conns []*bsquic.Conn, idx *index.Index, recipientPub *[crypto.RecipientKeySize]byte) {
	if len(conns) == 0 {
		return
	}
	blob, err := buildIndexSnapshotBlob(idx, recipientPub)
	if err != nil {
		slog.WarnContext(ctx, "build index snapshot blob", "err", err)
		return
	}
	var wg sync.WaitGroup
	for _, c := range conns {
		if c == nil {
			continue
		}
		wg.Add(1)
		go func(c *bsquic.Conn) {
			defer wg.Done()
			if err := indexSnapshotUploadFunc(ctx, c, blob); err != nil {
				slog.WarnContext(ctx, "index snapshot upload failed",
					"peer_pub", hex.EncodeToString(c.RemotePub()),
					"err", err)
			}
		}(c)
	}
	wg.Wait()
}

// buildIndexSnapshotBlob lists the index, marshals it, and encrypts the result.
func buildIndexSnapshotBlob(idx *index.Index, recipientPub *[crypto.RecipientKeySize]byte) ([]byte, error) {
	entries, err := idx.List()
	if err != nil {
		return nil, fmt.Errorf("list index: %w", err)
	}
	plain, err := index.MarshalSnapshot(entries)
	if err != nil {
		return nil, fmt.Errorf("marshal snapshot: %w", err)
	}
	ec, err := crypto.Encrypt(plain, recipientPub)
	if err != nil {
		return nil, fmt.Errorf("encrypt snapshot: %w", err)
	}
	blob, err := ec.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal encrypted snapshot: %w", err)
	}
	return blob, nil
}
