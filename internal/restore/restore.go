// Package restore fetches each indexed chunk from a storage peer, decrypts
// it, verifies its plaintext hash against the index, and reassembles the
// file at filepath.Join(Dest, entry.Path). Dirs are 0700, files 0600; a
// hash mismatch aborts before any further writes for that file. Index
// entries carry paths relative to the configured backup root (set by
// backup.Run); restore rejects absolute or `..`-bearing entries up front
// and routes every filesystem operation through an *os.Root rooted at
// Dest, so no tampered entry can escape the destination tree.
package restore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
)

const (
	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600
)

// ErrPlaintextHashMismatch is returned when a decrypted chunk's sha256
// does not match the PlaintextHash recorded at backup time. The restore
// aborts rather than write garbage to Dest.
var ErrPlaintextHashMismatch = errors.New("plaintext hash mismatch")

// writableFile lets tests substitute a fake that fails Write or Close.
type writableFile interface {
	Write(p []byte) (int, error)
	Close() error
}

// Test-only seams; production never reassigns these.
var (
	openRootFunc = func(name string) (*os.Root, error) {
		return os.OpenRoot(name)
	}
	openInRootFunc = func(root *os.Root, name string, flag int, perm os.FileMode) (writableFile, error) {
		return root.OpenFile(name, flag, perm)
	}
	chtimesInRootFunc = func(root *os.Root, name string, atime, mtime time.Time) error {
		return root.Chtimes(name, atime, mtime)
	}
)

// Options configures a restore invocation.
type Options struct {
	// Dest is the absolute directory under which every indexed path is
	// recreated (path "/home/alice/x" → Dest + "/home/alice/x").
	Dest string
	// Conns are the live QUIC connections to peers that may hold backed-up
	// chunks. For each chunk, restore tries every peer in ChunkRef.Peers
	// that has a matching conn until one succeeds.
	Conns []*bsquic.Conn
	// Index is the local bbolt index describing what to restore.
	Index *index.Index
	// RecipientPub and RecipientPriv are the X25519 keypair used at backup.
	RecipientPub, RecipientPriv *[crypto.RecipientKeySize]byte
	// Progress receives per-file progress lines. nil is treated as io.Discard.
	Progress io.Writer
}

// normalizeRel validates an index entry path. Index entries are written
// relative to the configured backup root; any absolute path or `..`
// segment indicates a tampered entry and is rejected before any I/O.
func normalizeRel(p string) (string, error) {
	if p == "" {
		return "", errors.New("empty entry path")
	}
	if filepath.IsAbs(p) {
		return "", fmt.Errorf("entry path is absolute")
	}
	for _, part := range strings.Split(filepath.ToSlash(p), "/") {
		if part == ".." {
			return "", fmt.Errorf("entry path contains '..' segment")
		}
	}
	return filepath.Clean(p), nil
}

// Run restores every indexed file under opts.Dest. Stops at the first
// error; any partial output is left for inspection.
func Run(ctx context.Context, opts Options) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	if !filepath.IsAbs(opts.Dest) {
		return fmt.Errorf("dest %q is not absolute", opts.Dest)
	}
	if len(opts.Conns) == 0 {
		return errors.New("restore: no peer conns provided")
	}
	connByPub := make(map[string]*bsquic.Conn, len(opts.Conns))
	for _, c := range opts.Conns {
		connByPub[hex.EncodeToString(c.RemotePub())] = c
	}
	entries, err := opts.Index.List()
	if err != nil {
		return fmt.Errorf("index list: %w", err)
	}
	if err := os.MkdirAll(opts.Dest, dirPerm); err != nil {
		return fmt.Errorf("create dest %q: %w", opts.Dest, err)
	}
	root, err := openRootFunc(opts.Dest)
	if err != nil {
		return fmt.Errorf("open dest %q: %w", opts.Dest, err)
	}
	defer root.Close()
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := normalizeRel(entry.Path)
		if err != nil {
			return fmt.Errorf("restore %q: %w", entry.Path, err)
		}
		if err := restoreFile(ctx, opts, root, rel, entry, connByPub); err != nil {
			return fmt.Errorf("restore %q: %w", entry.Path, err)
		}
	}
	return nil
}

func restoreFile(ctx context.Context, opts Options, root *os.Root, rel string, entry index.FileEntry, connByPub map[string]*bsquic.Conn) error {
	if dir := filepath.Dir(rel); dir != "." {
		if err := root.MkdirAll(dir, dirPerm); err != nil {
			return fmt.Errorf("mkdir parent: %w", err)
		}
	}
	f, err := openInRootFunc(root, rel, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, filePerm)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer f.Close()

	for i, ref := range entry.Chunks {
		if err := ctx.Err(); err != nil {
			return err
		}
		blob, err := fetchChunk(ctx, ref, connByPub)
		if err != nil {
			return fmt.Errorf("fetch chunk %d: %w", i, err)
		}
		ec, err := crypto.UnmarshalEncryptedChunk(blob)
		if err != nil {
			return fmt.Errorf("unmarshal chunk %d: %w", i, err)
		}
		plain, err := crypto.Decrypt(ec, opts.RecipientPub, opts.RecipientPriv)
		if err != nil {
			return fmt.Errorf("decrypt chunk %d: %w", i, err)
		}
		if sha256.Sum256(plain) != ref.PlaintextHash {
			return fmt.Errorf("%w on chunk %d", ErrPlaintextHashMismatch, i)
		}
		if _, err := f.Write(plain); err != nil {
			return fmt.Errorf("write chunk %d: %w", i, err)
		}
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	// Preserve mtime so the next scan's stat-match incremental-skips
	// this file rather than re-chunking and orphaning old ciphertext.
	if err := chtimesInRootFunc(root, rel, entry.ModTime, entry.ModTime); err != nil {
		return fmt.Errorf("chtimes: %w", err)
	}
	fmt.Fprintf(opts.Progress, "restored %s (%d chunks)\n", entry.Path, len(entry.Chunks))
	return nil
}

// fetchChunk tries each peer in ref.Peers that has a matching conn,
// returning the first successfully retrieved blob. Returns the last
// failure error if no peer yielded the blob.
func fetchChunk(ctx context.Context, ref index.ChunkRef, connByPub map[string]*bsquic.Conn) ([]byte, error) {
	if len(ref.Peers) == 0 {
		return nil, errors.New("chunk has no recorded peers")
	}
	var lastErr error
	for _, peerPub := range ref.Peers {
		conn, ok := connByPub[hex.EncodeToString(peerPub)]
		if !ok {
			lastErr = fmt.Errorf("no live conn for peer %s", hex.EncodeToString(peerPub[:8]))
			continue
		}
		blob, err := backup.SendGetChunk(ctx, conn, ref.CiphertextHash)
		if err != nil {
			lastErr = err
			continue
		}
		return blob, nil
	}
	if lastErr == nil {
		lastErr = errors.New("no peer reachable for chunk")
	}
	return nil, lastErr
}
