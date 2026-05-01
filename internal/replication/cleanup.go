package replication

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"backupswarm/internal/backup"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
)

// CleanupTask is one stale-replica delete to issue against the recovered peer.
type CleanupTask struct {
	EntryPath      string
	ChunkIndex     int
	CiphertextHash [32]byte
	StalePub       []byte
}

// CleanupOptions configures one stale-cleanup sweep against a recovered peer.
type CleanupOptions struct {
	Index      *index.Index
	Conn       Conn
	Redundancy int
	Progress   io.Writer
}

// Test seams (cleanup-side).
var (
	sendDeleteChunkFunc = func(ctx context.Context, c Conn, hash [32]byte) error {
		return backup.SendDeleteChunk(ctx, c.(*bsquic.Conn), hash)
	}
	isPeerNotFoundFunc = backup.IsPeerNotFound
)

// PlanCleanup emits one task per chunk where recoveredPub is in
// ref.Peers AND len(ref.Peers) > redundancy.
func PlanCleanup(entries []index.FileEntry, recoveredPub []byte, redundancy int) []CleanupTask {
	if redundancy <= 0 || len(recoveredPub) == 0 {
		return nil
	}
	var tasks []CleanupTask
	for _, entry := range entries {
		for i, ref := range entry.Chunks {
			if len(ref.Peers) <= redundancy {
				continue
			}
			if !containsPub(ref.Peers, recoveredPub) {
				continue
			}
			tasks = append(tasks, CleanupTask{
				EntryPath:      entry.Path,
				ChunkIndex:     i,
				CiphertextHash: ref.CiphertextHash,
				StalePub:       append([]byte(nil), recoveredPub...),
			})
		}
	}
	return tasks
}

// RunCleanup plans then executes one stale-cleanup sweep.
func RunCleanup(ctx context.Context, opts CleanupOptions) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	if opts.Redundancy <= 0 || opts.Conn == nil {
		return nil
	}
	recoveredPub := []byte(opts.Conn.RemotePub())
	if len(recoveredPub) == 0 {
		return nil
	}
	entries, err := indexListFunc(opts.Index)
	if err != nil {
		return fmt.Errorf("list index: %w", err)
	}
	tasks := PlanCleanup(entries, recoveredPub, opts.Redundancy)
	for _, task := range tasks {
		executeCleanup(ctx, task, opts)
	}
	return nil
}

// executeCleanup sends DeleteChunk to the recovered peer and drops the
// stale pub from the chunk's Peers list on success or "not_found".
func executeCleanup(ctx context.Context, task CleanupTask, opts CleanupOptions) {
	if err := sendDeleteChunkFunc(ctx, opts.Conn, task.CiphertextHash); err != nil {
		if !isPeerNotFoundFunc(err) {
			slog.WarnContext(ctx, "cleanup delete failed",
				"path", task.EntryPath,
				"chunk", task.ChunkIndex,
				"peer_pub", hex.EncodeToString(task.StalePub),
				"err", err)
			return
		}
	}
	if err := dropPeerFromIndex(opts.Index, task); err != nil {
		slog.WarnContext(ctx, "cleanup index update failed",
			"path", task.EntryPath,
			"chunk", task.ChunkIndex,
			"err", err)
		return
	}
	fmt.Fprintf(opts.Progress, "cleaned up %s chunk %d on peer %s\n",
		task.EntryPath, task.ChunkIndex, hex.EncodeToString(task.StalePub[:8]))
}

// dropPeerFromIndex removes task.StalePub from the chunk's Peers list
// when the entry's hash and chunk index are still consistent.
func dropPeerFromIndex(idx *index.Index, task CleanupTask) error {
	entry, err := indexGetFunc(idx, task.EntryPath)
	if err != nil {
		if errors.Is(err, index.ErrFileNotFound) {
			return nil
		}
		return err
	}
	if task.ChunkIndex >= len(entry.Chunks) {
		return nil
	}
	if entry.Chunks[task.ChunkIndex].CiphertextHash != task.CiphertextHash {
		return nil
	}
	old := entry.Chunks[task.ChunkIndex].Peers
	kept := make([][]byte, 0, len(old))
	for _, p := range old {
		if !bytes.Equal(p, task.StalePub) {
			kept = append(kept, p)
		}
	}
	if len(kept) == len(old) {
		return nil
	}
	entry.Chunks[task.ChunkIndex].Peers = kept
	return indexPutFunc(idx, entry)
}

// containsPub reports whether peers contains pub.
func containsPub(peers [][]byte, pub []byte) bool {
	for _, p := range peers {
		if bytes.Equal(p, pub) {
			return true
		}
	}
	return false
}
