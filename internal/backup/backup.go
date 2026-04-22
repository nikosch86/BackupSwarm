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

	chunks, err := chunk.Split(f, opts.ChunkSize)
	if err != nil {
		return fmt.Errorf("split %q: %w", path, err)
	}

	entry := index.FileEntry{
		Path:   path,
		Chunks: make([]index.ChunkRef, 0, len(chunks)),
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
// PutChunkRequest, half-closes the send side, and reads the
// PutChunkResponse. Returns the peer-reported content hash.
func sendChunk(ctx context.Context, conn streamOpener, blob []byte) ([32]byte, error) {
	s, err := conn.OpenStream(ctx)
	if err != nil {
		return [32]byte{}, fmt.Errorf("open stream: %w", err)
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
	for {
		s, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}
		go func(stream io.ReadWriteCloser) {
			defer func() { _ = stream.Close() }()
			if err := handlePutChunkStream(stream, st); err != nil {
				slog.WarnContext(ctx, "handle put-chunk stream", "err", err)
			}
		}(s)
	}
}

// handlePutChunkStream reads a single PutChunkRequest from rw, stores
// the blob, and writes the PutChunkResponse. A store.Put failure is
// surfaced as an application-level error in the response (not as a
// transport error), so the owner can distinguish "peer rejected" from
// "connection dropped".
func handlePutChunkStream(rw io.ReadWriter, st *store.Store) error {
	blob, err := protocol.ReadPutChunkRequest(rw, maxBlobLen)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	hash, putErr := st.Put(blob)
	if putErr != nil {
		return protocol.WritePutChunkResponse(rw, [32]byte{}, putErr.Error())
	}
	return protocol.WritePutChunkResponse(rw, hash, "")
}
