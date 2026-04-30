// Package backup implements the owner-side backup pipeline: walk, chunk,
// encrypt for a recipient X25519 key, ship to weighted-random peers, and
// record placements in the local index.
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

// maxBlobLen caps one PutChunkRequest body (MaxChunkSize + crypto overhead).
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
	// Path is the directory to back up; entry paths are recorded relative.
	Path string
	// Conns are the live QUIC connections to candidate storage peers.
	Conns []*bsquic.Conn
	// Redundancy is the per-chunk peer count; <=0 is treated as 1.
	Redundancy int
	// RecipientPub is the X25519 pubkey every chunk key is wrapped for.
	RecipientPub *[crypto.RecipientKeySize]byte
	// Index is the local bbolt index updated per file.
	Index *index.Index
	// ChunkSize is the target chunk size; must fall within
	// [chunk.MinChunkSize, chunk.MaxChunkSize].
	ChunkSize int
	// Progress receives per-file progress lines; nil = io.Discard.
	Progress io.Writer
	// Rng is the random source for placement; nil seeds a PCG from the clock.
	Rng placement.Rng
}

// Run backs up every regular file under opts.Path across opts.Conns.
// Symlinks and special files are skipped with a progress note.
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

// unlimitedPlacementWeight is the weight applied for a peer reporting max==0.
const unlimitedPlacementWeight = int64(1) << 50

// probeCandidates queries each conn for capacity and returns peers with
// positive available capacity.
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
// Returns accepting peer pubkeys and the canonical content hash.
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
	// Root scopes the sweep to entries under it.
	Root string
	// Conns are the live QUIC connections to known peers.
	Conns []*bsquic.Conn
	// Index is the local bbolt index.
	Index *index.Index
	// Progress receives per-entry lines; nil = io.Discard.
	Progress io.Writer
}

// Prune sends DeleteChunk for every index entry under Root whose file is
// gone from disk, then removes the entry. A "not_found" peer reply counts
// as success. Entries are kept when no peer accepted the delete.
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

// deleteChunkOnPeers sends DeleteChunk to each peer in ref.Peers with a
// matching conn. "not_found" counts as success.
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

// isPeerNotFound matches the "not_found" wire code from GetChunk/DeleteChunk.
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

// streamOpener is the subset of *bsquic.Conn that sendChunk needs.
type streamOpener interface {
	OpenStream(ctx context.Context) (io.ReadWriteCloser, error)
}

type bsquicConnAdapter struct{ c *bsquic.Conn }

func (a bsquicConnAdapter) OpenStream(ctx context.Context) (io.ReadWriteCloser, error) {
	return a.c.OpenStream(ctx)
}

// sendChunk writes a PutChunk request and reads the response hash.
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

// SendGetChunk fetches the blob stored under hash from conn.
func SendGetChunk(ctx context.Context, conn *bsquic.Conn, hash [32]byte) ([]byte, error) {
	return sendGetChunk(ctx, bsquicConnAdapter{c: conn}, hash)
}

// SendChunk uploads blob via PutChunk and returns the peer-reported hash.
func SendChunk(ctx context.Context, conn *bsquic.Conn, blob []byte) ([32]byte, error) {
	return sendChunk(ctx, bsquicConnAdapter{c: conn}, blob)
}

// SendGetCapacity probes conn for used/max byte counts; max=0 means unlimited.
func SendGetCapacity(ctx context.Context, conn *bsquic.Conn) (used, max int64, err error) {
	return sendGetCapacity(ctx, bsquicConnAdapter{c: conn})
}

// SendPing probes conn for liveness.
func SendPing(ctx context.Context, conn *bsquic.Conn) error {
	return sendPing(ctx, bsquicConnAdapter{c: conn})
}

// sendPing opens a MsgPing stream and reads the OK/Err response.
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

// sendGetCapacity opens a MsgGetCapacity stream and reads the response.
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

// sendGetChunk writes a GetChunk request and returns the blob.
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

// SendRenewTTL bumps the TTL for hash on conn.
func SendRenewTTL(ctx context.Context, conn *bsquic.Conn, hash [32]byte) error {
	return sendRenewTTL(ctx, bsquicConnAdapter{c: conn}, hash)
}

// sendRenewTTL writes a RenewTTL request and reads the response.
func sendRenewTTL(ctx context.Context, conn streamOpener, hash [32]byte) error {
	s, err := conn.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	if err := protocol.WriteMessageType(s, protocol.MsgRenewTTL); err != nil {
		_ = s.Close()
		return err
	}
	if err := protocol.WriteRenewTTLRequest(s, hash); err != nil {
		_ = s.Close()
		return err
	}
	if err := s.Close(); err != nil {
		return fmt.Errorf("close send side: %w", err)
	}
	appErr, err := protocol.ReadRenewTTLResponse(s)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if appErr != "" {
		return fmt.Errorf("peer rejected renew: %s", appErr)
	}
	return nil
}

// sendDeleteChunk writes a DeleteChunk request and reads the response.
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

// AnnouncementHandler reads one peer-announcement frame off r.
// senderPub is the conn's TLS-authenticated pubkey.
type AnnouncementHandler func(ctx context.Context, r io.Reader, senderPub []byte) error

// JoinHandler reads one JoinRequest off rw and writes the response.
// joinerPub is the conn's TLS-authenticated pubkey.
type JoinHandler func(ctx context.Context, rw io.ReadWriter, joinerPub []byte) error

// ConnObserver receives per-connection accept/close callbacks.
type ConnObserver struct {
	OnAccept func(*bsquic.Conn)
	OnClose  func(*bsquic.Conn)
}

// Serve accepts inbound QUIC connections on l and dispatches streams against st.
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

// AcceptStreams runs the dispatch loop on conn until conn closes or ctx cancels.
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
	case protocol.MsgPutIndexSnapshot:
		return handlePutIndexSnapshotStream(ctx, rw, st, ownerKey)
	case protocol.MsgGetIndexSnapshot:
		return handleGetIndexSnapshotStream(ctx, rw, st, ownerKey)
	case protocol.MsgRenewTTL:
		return handleRenewTTLStream(ctx, rw, st, ownerKey)
	default:
		return fmt.Errorf("unknown message type %d", msgType)
	}
}

// errCode maps a store error to a stable on-wire short code.
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

// handlePutChunkStream stores the request blob under owner and writes the response.
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

// handleDeleteChunkStream authorizes the delete against owner and writes the response.
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

// handleGetCapacityStream writes the store's used/max byte totals onto rw.
// NoStorage stores report a saturated 1/1.
func handleGetCapacityStream(_ context.Context, rw io.ReadWriter, st *store.Store) error {
	if st.IsNoStorage() {
		return protocol.WriteGetCapacityResponse(rw, 1, 1, "")
	}
	return protocol.WriteGetCapacityResponse(rw, st.Used(), st.Capacity(), "")
}

// handlePingStream writes a single OK status byte onto rw.
func handlePingStream(_ context.Context, rw io.ReadWriter) error {
	return protocol.WritePingResponse(rw, "")
}

// handleRenewTTLStream authorizes the renew against owner and writes the response.
func handleRenewTTLStream(ctx context.Context, rw io.ReadWriter, st *store.Store, owner []byte) error {
	hash, err := protocol.ReadRenewTTLRequest(rw)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if renewErr := st.RenewForOwner(hash, owner); renewErr != nil {
		code := errCode(renewErr)
		slog.WarnContext(ctx, "renew ttl failed", "code", code, "err", renewErr)
		return protocol.WriteRenewTTLResponse(rw, code)
	}
	return protocol.WriteRenewTTLResponse(rw, "")
}

// handleGetChunkStream authorizes the get against owner and writes the response.
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
