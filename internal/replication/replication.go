// Package replication detects under-replicated chunks in the local index
// and copies them onto new peers. A chunk is under-replicated when the
// count of its existing peers that are not flagged lost (per the grace
// machinery in internal/swarm) drops below the configured redundancy.
package replication

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/index"
	"backupswarm/internal/placement"
	bsquic "backupswarm/internal/quic"
)

// Task is one chunk that needs additional replicas.
type Task struct {
	EntryPath      string
	ChunkIndex     int
	CiphertextHash [32]byte
	Size           int64
	// AliveSources are existing peers that are not-lost and currently
	// dialable; the executor fetches the encrypted blob from one of them.
	AliveSources [][]byte
	// ExistingPeers is the full ChunkRef.Peers list, used to exclude
	// already-known peers when picking new targets.
	ExistingPeers [][]byte
	NeedCount     int
}

// Plan walks entries and returns one Task per under-replicated chunk.
// livePubs is peers with a current QUIC conn; lostFn reports peers
// past their grace period (nil treats every peer as never-lost).
func Plan(entries []index.FileEntry, livePubs [][]byte, lostFn func(pub []byte) bool, redundancy int) []Task {
	if redundancy <= 0 {
		return nil
	}
	if lostFn == nil {
		lostFn = func([]byte) bool { return false }
	}
	live := make(map[string]struct{}, len(livePubs))
	for _, p := range livePubs {
		live[hex.EncodeToString(p)] = struct{}{}
	}
	var tasks []Task
	for _, entry := range entries {
		for i, ref := range entry.Chunks {
			alive := 0
			var sources [][]byte
			for _, p := range ref.Peers {
				if lostFn(p) {
					continue
				}
				alive++
				if _, ok := live[hex.EncodeToString(p)]; ok {
					sources = append(sources, p)
				}
			}
			if alive >= redundancy {
				continue
			}
			tasks = append(tasks, Task{
				EntryPath:      entry.Path,
				ChunkIndex:     i,
				CiphertextHash: ref.CiphertextHash,
				Size:           ref.Size,
				AliveSources:   sources,
				ExistingPeers:  ref.Peers,
				NeedCount:      redundancy - alive,
			})
		}
	}
	return tasks
}

// Conn is the subset of *bsquic.Conn used to identify a peer; the
// production wiring also requires that the underlying type be
// *bsquic.Conn so the package-level seams can call backup.Send*.
type Conn interface {
	RemotePub() ed25519.PublicKey
}

// RunOptions configures one re-replication sweep.
type RunOptions struct {
	// Index is the local owner index. Required.
	Index *index.Index
	// Conns are the live QUIC conns to all known peers (including
	// non-storage peers). The executor filters by ChunkRef.Peers and
	// excludes existing holders when picking new targets.
	Conns []Conn
	// LostFn reports peers past their grace period; nil treats every
	// peer as never-lost (no-op sweep).
	LostFn func(pub []byte) bool
	// Redundancy is the target replica count per chunk. Zero or negative
	// makes Run a no-op.
	Redundancy int
	// Rng is the random source for new-target selection; nil seeds a
	// fresh PCG from the wall clock.
	Rng placement.Rng
	// Progress receives a per-task line on successful repair. nil is
	// treated as io.Discard.
	Progress io.Writer
}

// Test-only seams; production never reassigns.
var (
	sendGetChunkFunc = func(ctx context.Context, c Conn, hash [32]byte) ([]byte, error) {
		return backup.SendGetChunk(ctx, c.(*bsquic.Conn), hash)
	}
	sendPutChunkFunc = func(ctx context.Context, c Conn, blob []byte) ([32]byte, error) {
		return backup.SendChunk(ctx, c.(*bsquic.Conn), blob)
	}
	sendGetCapacityFunc = func(ctx context.Context, c Conn) (int64, int64, error) {
		return backup.SendGetCapacity(ctx, c.(*bsquic.Conn))
	}
	indexListFunc = func(idx *index.Index) ([]index.FileEntry, error) { return idx.List() }
	indexGetFunc  = func(idx *index.Index, path string) (index.FileEntry, error) { return idx.Get(path) }
	indexPutFunc  = func(idx *index.Index, entry index.FileEntry) error { return idx.Put(entry) }
)

// unlimitedReplicationWeight bounds the placement weight for peers
// reporting max=0 (unlimited) so a swarm of many such peers still sums
// within int64.
const unlimitedReplicationWeight = int64(1) << 50

// repCandidate is a target peer paired with its probed available bytes.
type repCandidate struct {
	conn      Conn
	available int64
}

// Run executes one re-replication sweep. Per-task failures log and
// continue; only an index-list failure surfaces upward.
func Run(ctx context.Context, opts RunOptions) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	if opts.Redundancy <= 0 {
		return nil
	}
	livePubs := make([][]byte, 0, len(opts.Conns))
	for _, c := range opts.Conns {
		livePubs = append(livePubs, c.RemotePub())
	}
	entries, err := indexListFunc(opts.Index)
	if err != nil {
		return fmt.Errorf("list index: %w", err)
	}
	tasks := Plan(entries, livePubs, opts.LostFn, opts.Redundancy)
	if len(tasks) == 0 {
		return nil
	}
	connByPub := make(map[string]Conn, len(opts.Conns))
	for _, c := range opts.Conns {
		connByPub[hex.EncodeToString(c.RemotePub())] = c
	}
	rng := opts.Rng
	if rng == nil {
		rng = mrand.New(mrand.NewPCG(uint64(time.Now().UnixNano()), 0xc0ffee))
	}
	for _, task := range tasks {
		executeTask(ctx, task, opts, connByPub, rng)
	}
	return nil
}

// executeTask repairs one chunk: fetches it from a live source, places
// it on NeedCount new targets, and merges accepted target pubkeys into
// the index entry. Per-task failures log and return; the sweep continues.
func executeTask(ctx context.Context, task Task, opts RunOptions, connByPub map[string]Conn, rng placement.Rng) {
	srcConn := pickSource(task.AliveSources, connByPub)
	if srcConn == nil {
		slog.WarnContext(ctx, "replication skipped: no live source",
			"path", task.EntryPath,
			"chunk", task.ChunkIndex,
			"existing_peers", len(task.ExistingPeers))
		return
	}
	blob, err := sendGetChunkFunc(ctx, srcConn, task.CiphertextHash)
	if err != nil {
		slog.WarnContext(ctx, "replication source fetch failed",
			"path", task.EntryPath,
			"chunk", task.ChunkIndex,
			"err", err)
		return
	}
	pool := probedTargetPool(ctx, opts.Conns, task.ExistingPeers)
	if len(pool) < task.NeedCount {
		slog.WarnContext(ctx, "replication skipped: target pool too small",
			"path", task.EntryPath,
			"chunk", task.ChunkIndex,
			"pool", len(pool),
			"need", task.NeedCount)
		return
	}
	selected, err := placement.WeightedRandom(pool, repCandidateWeight, task.NeedCount, rng)
	if err != nil {
		slog.WarnContext(ctx, "replication placement failed",
			"path", task.EntryPath,
			"chunk", task.ChunkIndex,
			"err", err)
		return
	}
	newPeers := putToTargets(ctx, selected, blob, task.CiphertextHash)
	if len(newPeers) == 0 {
		return
	}
	if err := mergePeersIntoIndex(opts.Index, task, newPeers); err != nil {
		slog.WarnContext(ctx, "replication index update failed",
			"path", task.EntryPath,
			"chunk", task.ChunkIndex,
			"err", err)
		return
	}
	fmt.Fprintf(opts.Progress, "replicated %s chunk %d to %d new peer(s)\n", task.EntryPath, task.ChunkIndex, len(newPeers))
}

// pickSource returns the first conn matching one of sources, or nil if
// none of the source pubkeys has a current connection.
func pickSource(sources [][]byte, connByPub map[string]Conn) Conn {
	for _, p := range sources {
		if c, ok := connByPub[hex.EncodeToString(p)]; ok {
			return c
		}
	}
	return nil
}

// probedTargetPool builds the candidate slice for new-target selection:
// every conn whose pubkey is not in exclude, with positive probed
// available capacity. A failed probe drops the peer from the pool.
func probedTargetPool(ctx context.Context, conns []Conn, exclude [][]byte) []repCandidate {
	excludeSet := make(map[string]struct{}, len(exclude))
	for _, p := range exclude {
		excludeSet[hex.EncodeToString(p)] = struct{}{}
	}
	pool := make([]repCandidate, 0, len(conns))
	for _, c := range conns {
		if _, ex := excludeSet[hex.EncodeToString(c.RemotePub())]; ex {
			continue
		}
		used, max, err := sendGetCapacityFunc(ctx, c)
		if err != nil {
			slog.WarnContext(ctx, "replication capacity probe failed",
				"peer_pub", hex.EncodeToString(c.RemotePub()),
				"err", err)
			continue
		}
		avail := availableFromProbe(used, max)
		if avail == 0 {
			continue
		}
		pool = append(pool, repCandidate{conn: c, available: avail})
	}
	return pool
}

// availableFromProbe collapses (used, max) into the placement weight.
// max=0 is the wire convention for "unlimited"; negative results clamp
// to zero to keep weights non-negative.
func availableFromProbe(used, max int64) int64 {
	if max == 0 {
		return unlimitedReplicationWeight
	}
	avail := max - used
	if avail < 0 {
		return 0
	}
	return avail
}

func repCandidateWeight(c repCandidate) int64 { return c.available }

// putToTargets ships blob to each candidate and returns the pubkeys of
// peers that accepted with the matching content hash. Peer-side errors
// and hash mismatches are logged and skipped.
func putToTargets(ctx context.Context, targets []repCandidate, blob []byte, want [32]byte) [][]byte {
	out := make([][]byte, 0, len(targets))
	for _, c := range targets {
		hash, err := sendPutChunkFunc(ctx, c.conn, blob)
		if err != nil {
			slog.WarnContext(ctx, "replication put failed",
				"peer_pub", hex.EncodeToString(c.conn.RemotePub()),
				"err", err)
			continue
		}
		if hash != want {
			slog.WarnContext(ctx, "replication peer returned mismatched hash",
				"peer_pub", hex.EncodeToString(c.conn.RemotePub()),
				"want_hash", hex.EncodeToString(want[:]),
				"got_hash", hex.EncodeToString(hash[:]))
			continue
		}
		out = append(out, append([]byte(nil), c.conn.RemotePub()...))
	}
	return out
}

// mergePeersIntoIndex re-reads the entry, verifies the chunk's hash
// and index are unchanged, and appends newPeers to its Peers list. A
// concurrent rewrite drops the merge silently.
func mergePeersIntoIndex(idx *index.Index, task Task, newPeers [][]byte) error {
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
	merged := make([][]byte, 0, len(entry.Chunks[task.ChunkIndex].Peers)+len(newPeers))
	merged = append(merged, entry.Chunks[task.ChunkIndex].Peers...)
	merged = append(merged, newPeers...)
	entry.Chunks[task.ChunkIndex].Peers = merged
	return indexPutFunc(idx, entry)
}
