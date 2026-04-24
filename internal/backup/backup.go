// Package backup implements the M1.8 end-to-end backup pipeline:
// the owner side walks a local path, splits each file into fixed-size
// chunks, encrypts them for a recipient X25519 key, ships each chunk to a
// storage peer over a QUIC stream, and records the resulting placements
// in the local bbolt index; the peer side accepts those streams and
// content-addresses the ciphertext blobs in its local store.
//
// Owner and peer speak internal/protocol.PutChunk on a dedicated
// bidirectional QUIC stream per chunk. One chunk = one stream keeps the
// wire vocabulary minimal — there is no multiplexing, no pipelining, and
// no connection-level state beyond the mutual-TLS identity already
// established by internal/quic.
package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"backupswarm/internal/chunk"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// maxBlobLen bounds how many bytes the peer will accept for a single
// PutChunkRequest body. The largest legitimate chunk is chunk.MaxChunkSize
// plus the serialization overhead from crypto.MarshalBinary
// (version + nonce + two length prefixes + wrapped key). 4 MiB + a
// generous kilobyte is ample and keeps a malicious peer from forcing a
// multi-MB allocation.
const maxBlobLen = chunk.MaxChunkSize + 1024

// Package-level seams so internal tests can exercise otherwise-defensive
// branches. Production code never reassigns these — same pattern as the
// gobEncodeFunc / chmodFunc seams in internal/index.
var (
	// indexDeleteFunc seams the index.Delete call made by Prune after
	// it has already sent DeleteChunk for every chunk of a dangling
	// entry. A real Delete failure at that point requires either a
	// racy index close or a bbolt IO error — neither is reproducible
	// without the seam.
	indexDeleteFunc = func(idx *index.Index, path string) error {
		return idx.Delete(path)
	}
)

// RunOptions is the owner-side configuration for a backup invocation.
type RunOptions struct {
	// Path is the file or directory to backup.
	Path string
	// Conn is the QUIC connection to the storage peer.
	Conn *bsquic.Conn
	// RecipientPub is the X25519 public key for which every chunk key is
	// wrapped. Typically the owner's own recipient public key, so that
	// restore decrypts on the same node that backed up.
	RecipientPub *[crypto.RecipientKeySize]byte
	// Index is the local bbolt index, updated per file with the peer
	// placement recorded in ChunkRef.Peers.
	Index *index.Index
	// ChunkSize is the target chunk size in bytes; must fall within the
	// [chunk.MinChunkSize, chunk.MaxChunkSize] bounds.
	ChunkSize int
	// Progress receives human-readable per-file progress lines. Pass
	// io.Discard in non-interactive contexts.
	Progress io.Writer
}

// Run backs up everything under opts.Path to the storage peer reachable
// via opts.Conn. Directories are walked recursively; regular files are
// split, encrypted, shipped, and indexed. Symlinks and special files are
// skipped (with a progress note).
func Run(ctx context.Context, opts RunOptions) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	info, err := os.Stat(opts.Path)
	if err != nil {
		return fmt.Errorf("stat %q: %w", opts.Path, err)
	}

	peerKey := append([]byte(nil), opts.Conn.RemotePub()...)

	if !info.IsDir() {
		return backupFile(ctx, opts, opts.Path, peerKey)
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
		return backupFile(ctx, opts, path, peerKey)
	})
}

func backupFile(ctx context.Context, opts RunOptions, path string, peerKey []byte) error {
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

	// Incremental skip: if the index already has this path with the
	// same size and modtime, the file is unchanged and there's nothing
	// to chunk, encrypt, or ship. This is the core of the M1.9 scan —
	// the expected steady-state is that most files match their index
	// entry on every rescan, so the fast path must be cheap (one stat
	// syscall per file, already done above).
	if existing, err := opts.Index.Get(path); err == nil {
		if existing.Size == info.Size() && existing.ModTime.Equal(info.ModTime()) {
			fmt.Fprintf(opts.Progress, "unchanged %s\n", path)
			return nil
		}
	} else if !errors.Is(err, index.ErrFileNotFound) {
		return fmt.Errorf("index get %q: %w", path, err)
	}

	chunks, err := chunk.Split(f, opts.ChunkSize)
	if err != nil {
		return fmt.Errorf("split %q: %w", path, err)
	}

	entry := index.FileEntry{
		Path:    path,
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
			return fmt.Errorf("encrypt chunk %d of %q: %w", i, path, err)
		}
		blob, err := encrypted.MarshalBinary()
		if err != nil {
			return fmt.Errorf("marshal chunk %d of %q: %w", i, path, err)
		}
		hash, err := sendChunk(ctx, bsquicConnAdapter{c: opts.Conn}, blob)
		if err != nil {
			return fmt.Errorf("send chunk %d of %q: %w", i, path, err)
		}
		entry.Chunks = append(entry.Chunks, index.ChunkRef{
			PlaintextHash:  c.Hash,
			CiphertextHash: hash,
			Size:           int64(len(blob)),
			Peers:          [][]byte{peerKey},
		})
	}
	if err := opts.Index.Put(entry); err != nil {
		return fmt.Errorf("index put %q: %w", path, err)
	}
	fmt.Fprintf(opts.Progress, "backed up %s (%d chunks)\n", path, len(chunks))
	return nil
}

// PruneOptions is the owner-side configuration for a Prune sweep.
type PruneOptions struct {
	// Root constrains the sweep to index entries whose Path lies under
	// Root. Entries outside Root are left alone — a safeguard against a
	// misconfigured daemon wiping unrelated backups.
	Root string
	// Conn is the QUIC connection to the storage peer that currently
	// holds the chunks (M1.9 assumes one storage peer per swarm; M2.14
	// generalizes to the weighted-random set).
	Conn *bsquic.Conn
	// Index is the local bbolt index; Prune both reads it (to decide
	// what's gone) and writes it (to remove entries after successful
	// remote deletes).
	Index *index.Index
	// Progress receives a per-entry line when a delete is performed.
	// nil is treated as io.Discard.
	Progress io.Writer
}

// Prune sends DeleteChunk to the storage peer for every index entry
// whose file has disappeared from disk under opts.Root, then removes
// the entry from the local index. Entries whose files still exist on
// disk, or whose paths are outside opts.Root, are left alone.
//
// The index is the source of truth for "what's been backed up"; Prune
// makes it match the current on-disk reality for the subtree under
// Root. On any delete failure (transport error, owner-mismatch at the
// peer, etc.) the corresponding index entry is retained and an error
// is returned — the owner can retry on the next scan.
func Prune(ctx context.Context, opts PruneOptions) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	rootAbs, err := filepath.Abs(opts.Root)
	if err != nil {
		return fmt.Errorf("absolute root %q: %w", opts.Root, err)
	}
	entries, err := opts.Index.List()
	if err != nil {
		return fmt.Errorf("index list: %w", err)
	}
	opener := bsquicConnAdapter{c: opts.Conn}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		pathAbs, err := filepath.Abs(entry.Path)
		if err != nil {
			return fmt.Errorf("absolute path %q: %w", entry.Path, err)
		}
		rel, err := filepath.Rel(rootAbs, pathAbs)
		if err != nil || rel == ".." || len(rel) >= 3 && rel[:3] == ".."+string(os.PathSeparator) {
			continue
		}
		if _, statErr := os.Stat(entry.Path); statErr == nil {
			continue
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return fmt.Errorf("stat %q: %w", entry.Path, statErr)
		}
		for _, ref := range entry.Chunks {
			if err := ctx.Err(); err != nil {
				return err
			}
			if err := sendDeleteChunk(ctx, opener, ref.CiphertextHash); err != nil {
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

// streamOpener is the subset of *bsquic.Conn that sendChunk needs.
// Keeping sendChunk's first argument an interface (rather than the
// concrete type) lets white-box tests inject failing stream openers to
// exercise each post-OpenStream error wrap — otherwise unreachable
// without actually kicking the real QUIC transport mid-write. Same
// shape as the seam patterns in internal/index and internal/peers.
type streamOpener interface {
	OpenStream(ctx context.Context) (io.ReadWriteCloser, error)
}

// bsquicConnAdapter adapts *bsquic.Conn to the streamOpener interface
// (the real OpenStream returns a *qgo.Stream, which already satisfies
// io.ReadWriteCloser but not the exact signature).
type bsquicConnAdapter struct{ c *bsquic.Conn }

func (a bsquicConnAdapter) OpenStream(ctx context.Context) (io.ReadWriteCloser, error) {
	return a.c.OpenStream(ctx)
}

// sendChunk opens a new bidirectional stream on conn, writes the
// PutChunkRequest (prefixed by a MsgPutChunk byte so the server
// dispatcher can route it), half-closes the send side, and reads the
// PutChunkResponse. Returns the peer-reported content hash.
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

// sendDeleteChunk opens a new bidirectional stream on conn, writes a
// DeleteChunkRequest (prefixed by a MsgDeleteChunk byte), half-closes,
// and reads the DeleteChunkResponse. Returns nil on success, or an
// error that wraps the peer-reported application message on owner
// mismatch / chunk-not-found.
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

// Serve accepts inbound QUIC connections on l and handles PutChunk
// streams, storing every received blob in st. Exits when ctx is
// cancelled; a post-cancellation accept error (e.g., listener closed)
// is treated as a clean shutdown.
func Serve(ctx context.Context, l *bsquic.Listener, st *store.Store) error {
	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept: %w", err)
		}
		go serveConn(ctx, conn, st)
	}
}

func serveConn(ctx context.Context, conn *bsquic.Conn, st *store.Store) {
	defer func() { _ = conn.Close() }()
	ownerKey := append([]byte(nil), conn.RemotePub()...)
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(stream io.ReadWriteCloser) {
			defer func() { _ = stream.Close() }()
			if err := dispatchStream(ctx, stream, st, ownerKey); err != nil {
				slog.WarnContext(ctx, "dispatch stream", "err", err)
			}
		}(s)
	}
}

// dispatchStream reads the MessageType byte and routes the remainder of
// the stream to the right handler. ownerKey is the authenticated
// Ed25519 pubkey of the remote peer (captured once from the TLS
// session) and is used by handlePutChunkStream to record ownership and
// by handleDeleteChunkStream to authorize deletion.
func dispatchStream(ctx context.Context, rw io.ReadWriter, st *store.Store, ownerKey []byte) error {
	_ = ctx
	msgType, err := protocol.ReadMessageType(rw)
	if err != nil {
		return fmt.Errorf("read message type: %w", err)
	}
	switch msgType {
	case protocol.MsgPutChunk:
		return handlePutChunkStream(rw, st, ownerKey)
	case protocol.MsgDeleteChunk:
		return handleDeleteChunkStream(rw, st, ownerKey)
	default:
		return fmt.Errorf("unknown message type %d", msgType)
	}
}

// handlePutChunkStream reads a single PutChunkRequest from rw, stores
// the blob under owner, and writes the PutChunkResponse. A store.Put
// failure is surfaced as an application-level error in the response
// (not as a transport error), so the owner can distinguish "peer
// rejected" from "connection dropped".
func handlePutChunkStream(rw io.ReadWriter, st *store.Store, owner []byte) error {
	blob, err := protocol.ReadPutChunkRequest(rw, maxBlobLen)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	hash, putErr := st.PutOwned(blob, owner)
	if putErr != nil {
		return protocol.WritePutChunkResponse(rw, [32]byte{}, putErr.Error())
	}
	return protocol.WritePutChunkResponse(rw, hash, "")
}

// handleDeleteChunkStream reads a DeleteChunkRequest, authorizes the
// deletion against owner (the TLS-authenticated pubkey of the peer), and
// writes the DeleteChunkResponse. Owner-mismatch or chunk-not-found are
// surfaced as application errors in the response; transport failures
// are returned.
func handleDeleteChunkStream(rw io.ReadWriter, st *store.Store, owner []byte) error {
	hash, err := protocol.ReadDeleteChunkRequest(rw)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if delErr := st.DeleteForOwner(hash, owner); delErr != nil {
		return protocol.WriteDeleteChunkResponse(rw, delErr.Error())
	}
	return protocol.WriteDeleteChunkResponse(rw, "")
}
