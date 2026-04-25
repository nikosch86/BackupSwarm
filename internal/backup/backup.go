// Package backup implements the end-to-end backup pipeline: owner walks a
// path, splits files into fixed-size chunks, encrypts for a recipient
// X25519 key, ships each chunk on one QUIC stream, and records placements
// in the local index; the peer stores received ciphertext by content hash.
package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	"backupswarm/internal/chunk"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// maxBlobLen caps one PutChunkRequest body: MaxChunkSize + headroom for
// the crypto.MarshalBinary overhead. Keeps a malicious peer from forcing
// a huge allocation.
const maxBlobLen = chunk.MaxChunkSize + 1024

// Test-only seams; production never reassigns these.
var (
	indexDeleteFunc = func(idx *index.Index, path string) error {
		return idx.Delete(path)
	}
	// dispatchStreamFunc routes each accepted stream to a handler.
	dispatchStreamFunc = dispatchStream
	// serveConnStreamCap is the per-connection handler-goroutine cap,
	// matched to bsquic.MaxIncomingStreamsPerConn.
	serveConnStreamCap = int(bsquic.MaxIncomingStreamsPerConn)
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

	// Incremental skip: stat-matching index entry means unchanged file.
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
	// Root scopes the sweep; entries whose Path lies outside Root are
	// left alone (guards against a misconfigured daemon wiping unrelated
	// backups).
	Root string
	// Conn is the QUIC connection to the storage peer holding the chunks.
	Conn *bsquic.Conn
	// Index is the local bbolt index.
	Index *index.Index
	// Progress receives a per-entry line when a delete is performed.
	// nil is treated as io.Discard.
	Progress io.Writer
}

// Prune sends DeleteChunk for every index entry under Root whose file is
// gone from disk, then removes the entry. On any delete failure the entry
// is retained so the owner can retry on the next scan.
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

// Serve accepts inbound QUIC connections on l and dispatches streams
// against st. Exits cleanly on ctx cancellation. Blocks until every
// per-connection serveConn it spawned has fully drained.
func Serve(ctx context.Context, l *bsquic.Listener, st *store.Store) error {
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
			serveConn(ctx, conn, st)
		}()
	}
}

func serveConn(ctx context.Context, conn *bsquic.Conn, st *store.Store) {
	defer func() { _ = conn.Close() }()
	ownerKey := append([]byte(nil), conn.RemotePub()...)
	// sem bounds concurrent dispatcher goroutines per connection.
	sem := make(chan struct{}, serveConnStreamCap)
	// wg ensures we don't return while dispatcher goroutines are still
	// reading dispatchStreamFunc or touching st.
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
			if err := dispatchStreamFunc(ctx, stream, st, ownerKey); err != nil {
				slog.WarnContext(ctx, "dispatch stream", "err", err)
			}
		}(s)
	}
}

// dispatchStream routes each inbound stream on its leading MessageType byte.
// ownerKey is the TLS-authenticated Ed25519 pubkey of the remote peer,
// used by put to record ownership and by delete to authorize removal.
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
	case protocol.MsgGetChunk:
		return handleGetChunkStream(rw, st)
	default:
		return fmt.Errorf("unknown message type %d", msgType)
	}
}

// handlePutChunkStream stores the request blob under owner and writes
// the response. Store errors are surfaced as application errors so the
// owner can distinguish them from transport failures.
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

// handleDeleteChunkStream authorizes the delete against owner (the
// TLS-authenticated pubkey) and writes the response. Owner-mismatch and
// chunk-not-found are surfaced as application errors.
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

// handleGetChunkStream looks up the blob by hash and writes the response.
// Unknown-hash is an application error; no owner check is performed —
// storage peers serve any stored chunk on an authenticated connection.
func handleGetChunkStream(rw io.ReadWriter, st *store.Store) error {
	hash, err := protocol.ReadGetChunkRequest(rw)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	blob, getErr := st.Get(hash)
	if getErr != nil {
		return protocol.WriteGetChunkResponse(rw, nil, getErr.Error())
	}
	return protocol.WriteGetChunkResponse(rw, blob, "")
}
