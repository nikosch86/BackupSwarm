// Package backup implements the end-to-end backup pipeline: owner walks a
// path, splits files into fixed-size chunks, encrypts for a recipient
// X25519 key, ships each chunk on one or more QUIC streams to the
// weighted-random selection of storage peers, and records placements in
// the local index; each peer stores received ciphertext by content hash.
package backup

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"backupswarm/internal/chunk"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/placement"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// maxBlobLen caps one PutChunkRequest body: MaxChunkSize + headroom for
// the crypto.MarshalBinary overhead.
const maxBlobLen = chunk.MaxChunkSize + 1024

// Test-only seams; production never reassigns these.
var (
	indexDeleteFunc = func(idx *index.Index, path string) error {
		return idx.Delete(path)
	}
	indexPutFunc = func(idx *index.Index, entry index.FileEntry) error {
		return idx.Put(entry)
	}
	dispatchStreamFunc func(ctx context.Context, rw io.ReadWriter, st *store.Store, ownerKey []byte, ann AnnouncementHandler, join JoinHandler) error = dispatchStream
	serveConnStreamCap                                                                                                                                = int(bsquic.MaxIncomingStreamsPerConn)
)

// RunOptions is the owner-side configuration for a backup invocation.
type RunOptions struct {
	// Path is the directory to back up. Must exist and be a directory.
	// Each indexed file's entry.Path is recorded relative to Path so a
	// subsequent restore stays bounded to the same configured root.
	Path string
	// Conns are the live QUIC connections to candidate storage peers.
	// Each invocation probes capacity per conn and picks Redundancy
	// peers per chunk weighted by available bytes.
	Conns []*bsquic.Conn
	// Redundancy is the number of unique peers each chunk is placed on.
	// Zero or negative is treated as 1.
	Redundancy int
	// RecipientPub is the X25519 public key for which every chunk key is
	// wrapped. Typically the owner's own recipient public key, so that
	// restore decrypts on the same node that backed up.
	RecipientPub *[crypto.RecipientKeySize]byte
	// Index is the local bbolt index, updated per file with the per-chunk
	// peer placement recorded in ChunkRef.Peers.
	Index *index.Index
	// ChunkSize is the target chunk size in bytes; must fall within the
	// [chunk.MinChunkSize, chunk.MaxChunkSize] bounds.
	ChunkSize int
	// Progress receives human-readable per-file progress lines. Pass
	// io.Discard in non-interactive contexts.
	Progress io.Writer
	// Rng is the random source for weighted-random placement; nil seeds
	// a fresh PCG from the wall clock.
	Rng placement.Rng
}

// Run backs up every regular file under opts.Path across opts.Conns.
// opts.Path must be an existing directory; each file's entry.Path is
// recorded relative to it. Symlinks and special files are skipped (with
// a progress note).
func Run(ctx context.Context, opts RunOptions) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	if opts.Redundancy <= 0 {
		opts.Redundancy = 1
	}
	if len(opts.Conns) == 0 {
		return errors.New("backup: no peer conns provided")
	}
	if opts.Path == "" {
		return errors.New("backup: opts.Path is empty")
	}
	info, err := os.Stat(opts.Path)
	if err != nil {
		return fmt.Errorf("stat %q: %w", opts.Path, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("backup: opts.Path %q is not a directory", opts.Path)
	}

	candidates := probeCandidates(ctx, opts.Conns)
	if len(candidates) < opts.Redundancy {
		return fmt.Errorf("%w: pool=%d, redundancy=%d", placement.ErrInsufficientPeers, len(candidates), opts.Redundancy)
	}

	rng := opts.Rng
	if rng == nil {
		rng = mrand.New(mrand.NewPCG(uint64(time.Now().UnixNano()), 0xc0ffee))
	}

	return filepath.WalkDir(opts.Path, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			fmt.Fprintf(opts.Progress, "skip non-regular file %s\n", path)
			return nil
		}
		rel, err := filepath.Rel(opts.Path, path)
		if err != nil {
			return fmt.Errorf("rel %q under %q: %w", path, opts.Path, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("backup: walk produced path %q outside root %q", path, opts.Path)
		}
		return backupFile(ctx, opts, path, rel, candidates, rng)
	})
}

func backupFile(ctx context.Context, opts RunOptions, path, rel string, candidates []candidate, rng placement.Rng) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat %q: %w", path, err)
	}

	// Incremental skip: stat-matching index entry means unchanged file.
	if existing, err := opts.Index.Get(rel); err == nil {
		if existing.Size == info.Size() && existing.ModTime.Equal(info.ModTime()) {
			fmt.Fprintf(opts.Progress, "unchanged %s\n", rel)
			return nil
		}
	} else if !errors.Is(err, index.ErrFileNotFound) {
		return fmt.Errorf("index get %q: %w", rel, err)
	}

	chunks, err := chunk.Split(f, opts.ChunkSize)
	if err != nil {
		return fmt.Errorf("split %q: %w", path, err)
	}

	entry := index.FileEntry{
		Path:    rel,
		Size:    info.Size(),
		ModTime: info.ModTime(),
		Chunks:  make([]index.ChunkRef, 0, len(chunks)),
	}
	for i, c := range chunks {
		if err := ctx.Err(); err != nil {
			return err
		}
		encrypted, err := crypto.Encrypt(c.Data, opts.RecipientPub)
		if err != nil {
			return fmt.Errorf("encrypt chunk %d of %q: %w", i, rel, err)
		}
		blob, err := encrypted.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal chunk %d of %q: %w", i, rel, err)
		}
		peers, hash, err := placeChunk(ctx, candidates, opts.Redundancy, blob, rng)
		if err != nil {
			return fmt.Errorf("place chunk %d of %q: %w", i, rel, err)
		}
		entry.Chunks = append(entry.Chunks, index.ChunkRef{
			PlaintextHash:  c.Hash,
			CiphertextHash: hash,
			Size:           int64(len(blob)),
			Peers:          peers,
		})
	}
	if err := indexPutFunc(opts.Index, entry); err != nil {
		return fmt.Errorf("index put %q: %w", rel, err)
	}
	fmt.Fprintf(opts.Progress, "backed up %s (%d chunks)\n", rel, len(chunks))
	return nil
}

// candidate pairs a conn with its probed available capacity in bytes.
type candidate struct {
	conn      *bsquic.Conn
	available int64
}

// unlimitedPlacementWeight is the per-peer weight applied when a peer
// reports max==0 on the wire. Bounded so the sum across many peers
// fits in int64.
const unlimitedPlacementWeight = int64(1) << 50

// probeCandidates queries each conn for its capacity and returns peers
// with positive available capacity. A failed probe drops the peer from
// the pool for this scan.
func probeCandidates(ctx context.Context, conns []*bsquic.Conn) []candidate {
	out := make([]candidate, 0, len(conns))
	for _, c := range conns {
		used, max, err := SendGetCapacity(ctx, c)
		if err != nil {
			slog.WarnContext(ctx, "capacity probe failed; peer excluded for this scan",
				"peer_pub", hex.EncodeToString(c.RemotePub()),
				"err", err)
			continue
		}
		var avail int64
		if max == 0 {
			avail = unlimitedPlacementWeight
		} else {
			avail = max - used
			if avail < 0 {
				avail = 0
			}
		}
		if avail == 0 {
			slog.InfoContext(ctx, "peer at capacity; excluded for this scan",
				"peer_pub", hex.EncodeToString(c.RemotePub()),
				"used", used, "max", max)
			continue
		}
		out = append(out, candidate{conn: c, available: avail})
	}
	return out
}

// placeChunk picks r peers via weighted-random and ships blob to each.
// Returns the pubkeys of peers that accepted the put plus the canonical
// content hash. Per-peer failures are logged and skipped; an empty
// success set fails the call.
func placeChunk(ctx context.Context, pool []candidate, r int, blob []byte, rng placement.Rng) ([][]byte, [32]byte, error) {
	selected, err := placement.WeightedRandom(pool, func(c candidate) int64 { return c.available }, r, rng)
	if err != nil {
		return nil, [32]byte{}, err
	}
	var canonical [32]byte
	var canonicalSet bool
	out := make([][]byte, 0, len(selected))
	for _, c := range selected {
		hash, sendErr := sendChunk(ctx, bsquicConnAdapter{c: c.conn}, blob)
		if sendErr != nil {
			slog.WarnContext(ctx, "put chunk to peer failed",
				"peer_pub", hex.EncodeToString(c.conn.RemotePub()),
				"err", sendErr)
			continue
		}
		if !canonicalSet {
			canonical = hash
			canonicalSet = true
		} else if hash != canonical {
			slog.WarnContext(ctx, "peer returned mismatched content hash; dropped from placement",
				"peer_pub", hex.EncodeToString(c.conn.RemotePub()),
				"want_hash", hex.EncodeToString(canonical[:]),
				"got_hash", hex.EncodeToString(hash[:]))
			continue
		}
		out = append(out, append([]byte(nil), c.conn.RemotePub()...))
	}
	if len(out) == 0 {
		return nil, [32]byte{}, errors.New("all selected peers rejected chunk")
	}
	return out, canonical, nil
}

// PruneOptions is the owner-side configuration for a Prune sweep.
type PruneOptions struct {
	// Root scopes the sweep; entries whose Path lies outside Root are
	// left alone (guards against a misconfigured daemon wiping unrelated
	// backups).
	Root string
	// Conns are the live QUIC connections to known peers. Per chunk,
	// Prune sends DeleteChunk to every peer in ChunkRef.Peers that
	// matches a conn here.
	Conns []*bsquic.Conn
	// Index is the local bbolt index.
	Index *index.Index
	// Progress receives a per-entry line when a delete is performed.
	// nil is treated as io.Discard.
	Progress io.Writer
}

// Prune sends DeleteChunk for every index entry under Root whose file is
// gone from disk, then removes the entry. For each chunk, it tries every
// peer in ChunkRef.Peers that has a matching conn. A "not_found" peer
// reply counts as success (idempotent delete). Entries are kept on the
// owner's side if no peer accepted the delete so the next sweep retries.
func Prune(ctx context.Context, opts PruneOptions) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	if len(opts.Conns) == 0 {
		return errors.New("prune: no peer conns provided")
	}
	if opts.Root == "" {
		return errors.New("prune: opts.Root is empty")
	}
	entries, err := opts.Index.List()
	if err != nil {
		return fmt.Errorf("index list: %w", err)
	}
	connByPub := make(map[string]*bsquic.Conn, len(opts.Conns))
	for _, c := range opts.Conns {
		connByPub[hex.EncodeToString(c.RemotePub())] = c
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Index entries are rel-to-Root by construction (backup.Run); a
		// tampered entry that escapes is skipped rather than deleted so
		// the operator can investigate.
		if filepath.IsAbs(entry.Path) || entry.Path == ".." || strings.HasPrefix(entry.Path, ".."+string(filepath.Separator)) {
			continue
		}
		fullPath := filepath.Join(opts.Root, entry.Path)
		if _, statErr := os.Stat(fullPath); statErr == nil {
			continue
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("stat %q: %w", fullPath, statErr)
		}
		for _, ref := range entry.Chunks {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := deleteChunkOnPeers(ctx, ref, connByPub); err != nil {
				return fmt.Errorf("delete chunk %x of %q: %w", ref.CiphertextHash, entry.Path, err)
			}
		}
		if err := indexDeleteFunc(opts.Index, entry.Path); err != nil {
			return fmt.Errorf("index delete %q: %w", entry.Path, err)
		}
		fmt.Fprintf(opts.Progress, "pruned %s (%d chunks)\n", entry.Path, len(entry.Chunks))
	}
	return nil
}

// deleteChunkOnPeers sends DeleteChunk to each peer in ref.Peers that has
// a matching conn. A peer reporting "not_found" counts as success: the
// chunk is in the desired (absent) state on that peer. Returns nil when
// at least one peer accepted; otherwise the last failure error.
func deleteChunkOnPeers(ctx context.Context, ref index.ChunkRef, connByPub map[string]*bsquic.Conn) error {
	var lastErr error
	any := false
	for _, peerPub := range ref.Peers {
		conn, ok := connByPub[hex.EncodeToString(peerPub)]
		if !ok {
			lastErr = fmt.Errorf("no live conn for peer %s", hex.EncodeToString(peerPub[:8]))
			continue
		}
		if err := sendDeleteChunk(ctx, bsquicConnAdapter{c: conn}, ref.CiphertextHash); err != nil {
			if isPeerNotFound(err) {
				any = true
				continue
			}
			slog.WarnContext(ctx, "delete chunk to peer failed",
				"peer_pub", hex.EncodeToString(peerPub),
				"err", err)
			lastErr = err
			continue
		}
		any = true
	}
	if !any {
		if lastErr == nil {
			lastErr = errors.New("no peers accepted delete")
		}
		return lastErr
	}
	return nil
}

// isPeerNotFound matches the wire vocabulary returned by the GetChunk /
// DeleteChunk handlers when the chunk is not in the peer's store.
func isPeerNotFound(err error) bool {
	if err == nil {
		return false
	}
	const code = "not_found"
	s := err.Error()
	for i := 0; i+len(code) <= len(s); i++ {
		if s[i:i+len(code)] == code {
			return true
		}
	}
	return false
}

// streamOpener is the subset of *bsquic.Conn that sendChunk needs; lets
// tests inject a failing stream opener to exercise post-OpenStream wraps.
type streamOpener interface {
	OpenStream(ctx context.Context) (io.ReadWriteCloser, error)
}

type bsquicConnAdapter struct{ c *bsquic.Conn }

func (a bsquicConnAdapter) OpenStream(ctx context.Context) (io.ReadWriteCloser, error) {
	return a.c.OpenStream(ctx)
}

// sendChunk writes a PutChunk request and reads the response, returning
// the peer-reported content hash.
func sendChunk(ctx context.Context, conn streamOpener, blob []byte) ([32]byte, error) {
	s, err := conn.OpenStream(ctx)
	if err != nil {
		return [32]byte{}, fmt.Errorf("open stream: %w", err)
	}

	if err := protocol.WriteMessageType(s, protocol.MsgPutChunk); err != nil {
		_ = s.Close()
		return [32]byte{}, err
	}
	if err := protocol.WritePutChunkRequest(s, blob); err != nil {
		_ = s.Close()
		return [32]byte{}, err
	}
	// Half-close the send side so the peer sees EOF on its request read.
	if err := s.Close(); err != nil {
		return [32]byte{}, fmt.Errorf("close send side: %w", err)
	}

	hash, appErr, err := protocol.ReadPutChunkResponse(s)
	if err != nil {
		return [32]byte{}, fmt.Errorf("read response: %w", err)
	}
	if appErr != "" {
		return [32]byte{}, fmt.Errorf("peer rejected chunk: %s", appErr)
	}
	return hash, nil
}

// SendGetChunk fetches the blob stored under hash from conn. Wraps any
// peer-reported application error (e.g. chunk-not-found).
func SendGetChunk(ctx context.Context, conn *bsquic.Conn, hash [32]byte) ([]byte, error) {
	return sendGetChunk(ctx, bsquicConnAdapter{c: conn}, hash)
}

// SendGetCapacity probes conn for the peer's used/max byte counts;
// max=0 reports the peer as unlimited. Wraps any peer-reported
// application error.
func SendGetCapacity(ctx context.Context, conn *bsquic.Conn) (used, max int64, err error) {
	return sendGetCapacity(ctx, bsquicConnAdapter{c: conn})
}

// SendPing probes conn for liveness. Returns nil on success or a wrapped
// transport / peer error.
func SendPing(ctx context.Context, conn *bsquic.Conn) error {
	return sendPing(ctx, bsquicConnAdapter{c: conn})
}

// sendPing opens a MsgPing stream (empty body — the type byte IS the
// request) and reads the OK/Err response.
func sendPing(ctx context.Context, conn streamOpener) error {
	s, err := conn.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	if err := protocol.WriteMessageType(s, protocol.MsgPing); err != nil {
		_ = s.Close()
		return err
	}
	if err := s.Close(); err != nil {
		return fmt.Errorf("close send side: %w", err)
	}
	appErr, err := protocol.ReadPingResponse(s)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if appErr != "" {
		return fmt.Errorf("peer rejected ping: %s", appErr)
	}
	return nil
}

// sendGetCapacity opens a MsgGetCapacity stream (empty body — the type
// byte is the entire request) and reads the response.
func sendGetCapacity(ctx context.Context, conn streamOpener) (used, max int64, err error) {
	s, err := conn.OpenStream(ctx)
	if err != nil {
		return 0, 0, fmt.Errorf("open stream: %w", err)
	}
	if err := protocol.WriteMessageType(s, protocol.MsgGetCapacity); err != nil {
		_ = s.Close()
		return 0, 0, err
	}
	if err := s.Close(); err != nil {
		return 0, 0, fmt.Errorf("close send side: %w", err)
	}
	used, max, appErr, err := protocol.ReadGetCapacityResponse(s)
	if err != nil {
		return 0, 0, fmt.Errorf("read response: %w", err)
	}
	if appErr != "" {
		return 0, 0, fmt.Errorf("peer rejected capacity probe: %s", appErr)
	}
	return used, max, nil
}

// sendGetChunk writes a GetChunk request and returns the blob or a
// wrapped peer application error.
func sendGetChunk(ctx context.Context, conn streamOpener, hash [32]byte) ([]byte, error) {
	s, err := conn.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}

	if err := protocol.WriteMessageType(s, protocol.MsgGetChunk); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := protocol.WriteGetChunkRequest(s, hash); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := s.Close(); err != nil {
		return nil, fmt.Errorf("close send side: %w", err)
	}

	blob, appErr, err := protocol.ReadGetChunkResponse(s, maxBlobLen)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if appErr != "" {
		return nil, fmt.Errorf("peer rejected get: %s", appErr)
	}
	return blob, nil
}

// sendDeleteChunk writes a DeleteChunk request and returns nil, or a
// wrapped peer application error (owner mismatch / chunk-not-found).
func sendDeleteChunk(ctx context.Context, conn streamOpener, hash [32]byte) error {
	s, err := conn.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}

	if err := protocol.WriteMessageType(s, protocol.MsgDeleteChunk); err != nil {
		_ = s.Close()
		return err
	}
	if err := protocol.WriteDeleteChunkRequest(s, hash); err != nil {
		_ = s.Close()
		return err
	}
	if err := s.Close(); err != nil {
		return fmt.Errorf("close send side: %w", err)
	}

	appErr, err := protocol.ReadDeleteChunkResponse(s)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if appErr != "" {
		return fmt.Errorf("peer rejected delete: %s", appErr)
	}
	return nil
}

// AnnouncementHandler reads one peer-announcement frame off r (the type
// byte already consumed by the dispatcher). senderPub is the conn's
// TLS-authenticated pubkey; a nil handler rejects MsgPeerAnnouncement.
type AnnouncementHandler func(ctx context.Context, r io.Reader, senderPub []byte) error

// JoinHandler reads one JoinRequest body off rw (type byte already
// consumed) and writes the response. joinerPub is the conn's
// TLS-authenticated pubkey; a nil handler rejects MsgJoinRequest.
type JoinHandler func(ctx context.Context, rw io.ReadWriter, joinerPub []byte) error

// ConnObserver receives a per-connection accept/close pair while Serve
// runs. Either field may be nil.
type ConnObserver struct {
	OnAccept func(*bsquic.Conn)
	OnClose  func(*bsquic.Conn)
}

// Serve accepts inbound QUIC connections on l and dispatches streams
// against st. ann handles MsgPeerAnnouncement, join handles
// MsgJoinRequest; obs is notified at conn accept/close. Exits on ctx
// cancellation.
func Serve(ctx context.Context, l *bsquic.Listener, st *store.Store, ann AnnouncementHandler, join JoinHandler, obs *ConnObserver) error {
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			serveConn(ctx, conn, st, ann, join, obs)
		}()
	}
}

func serveConn(ctx context.Context, conn *bsquic.Conn, st *store.Store, ann AnnouncementHandler, join JoinHandler, obs *ConnObserver) {
	if obs != nil && obs.OnAccept != nil {
		obs.OnAccept(conn)
	}
	defer func() {
		if obs != nil && obs.OnClose != nil {
			obs.OnClose(conn)
		}
		_ = conn.Close()
	}()
	AcceptStreams(ctx, conn, st, ann, join)
}

// AcceptStreams runs the dispatch loop on conn until conn closes or
// ctx cancels. Caller owns the conn lifecycle.
func AcceptStreams(ctx context.Context, conn *bsquic.Conn, st *store.Store, ann AnnouncementHandler, join JoinHandler) {
	ownerKey := append([]byte(nil), conn.RemotePub()...)
	sem := make(chan struct{}, serveConnStreamCap)
	var wg sync.WaitGroup
	defer wg.Wait()
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		select {
		case sem <- struct{}{}:
		case <-ctx.Done():
			_ = s.Close()
			return
		}
		wg.Add(1)
		go func(stream io.ReadWriteCloser) {
			defer wg.Done()
			defer func() {
				<-sem
				_ = stream.Close()
			}()
			if err := dispatchStreamFunc(ctx, stream, st, ownerKey, ann, join); err != nil {
				slog.WarnContext(ctx, "dispatch stream", "err", err)
			}
		}(s)
	}
}

// dispatchStream routes each inbound stream on its leading MessageType byte.
// ownerKey is the TLS-authenticated Ed25519 pubkey of the remote peer.
// A nil ann rejects MsgPeerAnnouncement; a nil join rejects MsgJoinRequest.
func dispatchStream(ctx context.Context, rw io.ReadWriter, st *store.Store, ownerKey []byte, ann AnnouncementHandler, join JoinHandler) error {
	msgType, err := protocol.ReadMessageType(rw)
	if err != nil {
		return fmt.Errorf("read message type: %w", err)
	}
	switch msgType {
	case protocol.MsgPutChunk:
		return handlePutChunkStream(ctx, rw, st, ownerKey)
	case protocol.MsgDeleteChunk:
		return handleDeleteChunkStream(ctx, rw, st, ownerKey)
	case protocol.MsgGetChunk:
		return handleGetChunkStream(ctx, rw, st, ownerKey)
	case protocol.MsgPeerAnnouncement:
		if ann == nil {
			return fmt.Errorf("peer announcement received but no handler configured")
		}
		return ann(ctx, rw, ownerKey)
	case protocol.MsgJoinRequest:
		if join == nil {
			return fmt.Errorf("join request received but no handler configured")
		}
		return join(ctx, rw, ownerKey)
	case protocol.MsgGetCapacity:
		return handleGetCapacityStream(ctx, rw, st)
	case protocol.MsgPing:
		return handlePingStream(ctx, rw)
	default:
		return fmt.Errorf("unknown message type %d", msgType)
	}
}

// errCode maps a store error to a stable on-wire short code. Sentinels
// surface as their named code; everything else falls through to "internal".
func errCode(err error) string {
	switch {
	case errors.Is(err, store.ErrChunkNotFound):
		return "not_found"
	case errors.Is(err, store.ErrOwnerMismatch):
		return "owner_mismatch"
	case errors.Is(err, store.ErrVolumeFull):
		return "no_space"
	default:
		return "internal"
	}
}

// handlePutChunkStream stores the request blob under owner and writes the
// response. Store errors map to a short code on the wire; the rich error
// is logged via slog.WarnContext.
func handlePutChunkStream(ctx context.Context, rw io.ReadWriter, st *store.Store, owner []byte) error {
	blob, err := protocol.ReadPutChunkRequest(rw, maxBlobLen)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	hash, putErr := st.PutOwned(blob, owner)
	if putErr != nil {
		code := errCode(putErr)
		slog.WarnContext(ctx, "put chunk failed", "code", code, "err", putErr)
		return protocol.WritePutChunkResponse(rw, [32]byte{}, code)
	}
	return protocol.WritePutChunkResponse(rw, hash, "")
}

// handleDeleteChunkStream authorizes the delete against owner (the TLS-
// authenticated pubkey) and writes the response. Store errors map to a
// short code on the wire; the rich error is logged via slog.WarnContext.
func handleDeleteChunkStream(ctx context.Context, rw io.ReadWriter, st *store.Store, owner []byte) error {
	hash, err := protocol.ReadDeleteChunkRequest(rw)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if delErr := st.DeleteForOwner(hash, owner); delErr != nil {
		code := errCode(delErr)
		slog.WarnContext(ctx, "delete chunk failed", "code", code, "err", delErr)
		return protocol.WriteDeleteChunkResponse(rw, code)
	}
	return protocol.WriteDeleteChunkResponse(rw, "")
}

// handleGetCapacityStream writes the store's used/max byte totals
// onto rw. Always reports success; the OK/Err frame shape leaves room
// for future error states.
func handleGetCapacityStream(_ context.Context, rw io.ReadWriter, st *store.Store) error {
	return protocol.WriteGetCapacityResponse(rw, st.Used(), st.Capacity(), "")
}

// handlePingStream writes a single OK status byte onto rw.
func handlePingStream(_ context.Context, rw io.ReadWriter) error {
	return protocol.WritePingResponse(rw, "")
}

// handleGetChunkStream authorizes the get against owner (the TLS-
// authenticated pubkey) and writes the response. Store errors map to a
// short code on the wire; the rich error is logged via slog.WarnContext.
func handleGetChunkStream(ctx context.Context, rw io.ReadWriter, st *store.Store, owner []byte) error {
	hash, err := protocol.ReadGetChunkRequest(rw)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	blob, getErr := st.GetForOwner(hash, owner)
	if getErr != nil {
		code := errCode(getErr)
		slog.WarnContext(ctx, "get chunk failed", "code", code, "err", getErr)
		return protocol.WriteGetChunkResponse(rw, nil, code)
	}
	return protocol.WriteGetChunkResponse(rw, blob, "")
}
