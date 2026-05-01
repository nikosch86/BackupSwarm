// Package restore fetches indexed chunks from peers, decrypts them, verifies
// each plaintext hash against the index, and writes files under Dest (dirs
// 0700, files 0600) via an *os.Root rooted at Dest.
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
	"sort"
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

	partialSuffix  = ".partial"
	defaultBackoff = 1 * time.Second
	maxBackoffCap  = 30 * time.Second
)

// ErrPlaintextHashMismatch is returned when a decrypted chunk's sha256 does
// not match the PlaintextHash recorded at backup time.
var ErrPlaintextHashMismatch = errors.New("plaintext hash mismatch")

// MissingPeersError maps each unrestored file's relative path to the
// peer pubkeys whose return would unblock it.
type MissingPeersError struct {
	Files map[string][][]byte
}

// Error returns a short summary suitable for log lines; the per-file
// detail is enumerable via the Files map.
func (e *MissingPeersError) Error() string {
	if e == nil || len(e.Files) == 0 {
		return "restore: missing peers"
	}
	rels := make([]string, 0, len(e.Files))
	for rel := range e.Files {
		rels = append(rels, rel)
	}
	sort.Strings(rels)
	var b strings.Builder
	fmt.Fprintf(&b, "restore: %d file(s) deferred awaiting missing peers", len(rels))
	const sample = 3
	if len(rels) > 0 {
		b.WriteString(": ")
		for i, rel := range rels {
			if i == sample {
				fmt.Fprintf(&b, ", ... (+%d more)", len(rels)-sample)
				break
			}
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(rel)
			peers := e.Files[rel]
			if len(peers) > 0 {
				fmt.Fprintf(&b, " (peer %s", shortPub(peers[0]))
				if len(peers) > 1 {
					fmt.Fprintf(&b, " +%d", len(peers)-1)
				}
				b.WriteString(")")
			}
		}
	}
	return b.String()
}

func shortPub(p []byte) string {
	const n = 8
	if len(p) <= n {
		return hex.EncodeToString(p)
	}
	return hex.EncodeToString(p[:n])
}

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
	renameInRootFunc = func(root *os.Root, oldName, newName string) error {
		return root.Rename(oldName, newName)
	}
	removeInRootFunc = func(root *os.Root, name string) error {
		return root.Remove(name)
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
	// RetryTimeout is the upper bound spent retrying files whose chunks
	// were unreachable on the first pass. Zero disables retries entirely
	// (any deferred file surfaces as *MissingPeersError immediately).
	RetryTimeout time.Duration
	// RetryBackoff is the initial sleep between retry attempts; doubles
	// (capped at 30s) until the retry deadline. Zero defaults to 1s.
	RetryBackoff time.Duration
	// Redial is invoked between retry attempts to refresh the conn slice.
	// Nil reuses the conns from the previous attempt. Errors from Redial
	// are non-fatal — restore continues with the prior conn set.
	Redial func(ctx context.Context) ([]*bsquic.Conn, error)
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

// pendingFile pairs a normalized relative path with its index entry.
type pendingFile struct {
	rel   string
	entry index.FileEntry
}

// Run restores every indexed file under opts.Dest. Files whose chunks
// cannot be fetched are deferred and retried up to opts.RetryTimeout;
// any remaining unrestored files surface as *MissingPeersError.
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
	connByPub := buildConnMap(opts.Conns)
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

	queue := make([]pendingFile, 0, len(entries))
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		rel, err := normalizeRel(e.Path)
		if err != nil {
			return fmt.Errorf("restore %q: %w", e.Path, err)
		}
		queue = append(queue, pendingFile{rel: rel, entry: e})
	}

	deferred := make(map[string]pendingFile)
	missing := make(map[string]map[string][]byte)

	if err := runPass(ctx, opts, root, queue, connByPub, deferred, missing); err != nil {
		return err
	}
	if len(deferred) == 0 {
		return nil
	}
	if opts.RetryTimeout <= 0 {
		return buildMissingErr(missing)
	}

	backoff := opts.RetryBackoff
	if backoff <= 0 {
		backoff = defaultBackoff
	}
	deadline := time.Now().Add(opts.RetryTimeout)

	for len(deferred) > 0 {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		sleep := backoff
		if sleep > remaining {
			sleep = remaining
		}
		select {
		case <-time.After(sleep):
		case <-ctx.Done():
			return ctx.Err()
		}
		if opts.Redial != nil {
			if newConns, dErr := opts.Redial(ctx); dErr == nil && len(newConns) > 0 {
				connByPub = buildConnMap(newConns)
			}
		}
		retryQueue := make([]pendingFile, 0, len(deferred))
		for _, p := range deferred {
			retryQueue = append(retryQueue, p)
			delete(missing, p.rel)
		}
		if err := runPass(ctx, opts, root, retryQueue, connByPub, deferred, missing); err != nil {
			return err
		}
		backoff *= 2
		if backoff > maxBackoffCap {
			backoff = maxBackoffCap
		}
	}
	if len(deferred) == 0 {
		return nil
	}
	return buildMissingErr(missing)
}

// runPass attempts each pendingFile once. Successes are removed from
// deferred/missing; deferrals are added; fatal errors abort.
func runPass(
	ctx context.Context,
	opts Options,
	root *os.Root,
	items []pendingFile,
	connByPub map[string]*bsquic.Conn,
	deferred map[string]pendingFile,
	missing map[string]map[string][]byte,
) error {
	for _, it := range items {
		if err := ctx.Err(); err != nil {
			return err
		}
		mp, err := restoreFile(ctx, opts, root, it.rel, it.entry, connByPub)
		if err == nil {
			delete(deferred, it.rel)
			delete(missing, it.rel)
			continue
		}
		if mp == nil {
			return fmt.Errorf("restore %q: %w", it.entry.Path, err)
		}
		deferred[it.rel] = it
		set := missing[it.rel]
		if set == nil {
			set = make(map[string][]byte, len(mp))
			missing[it.rel] = set
		}
		for _, pub := range mp {
			set[hex.EncodeToString(pub)] = pub
		}
	}
	return nil
}

func buildConnMap(conns []*bsquic.Conn) map[string]*bsquic.Conn {
	out := make(map[string]*bsquic.Conn, len(conns))
	for _, c := range conns {
		out[hex.EncodeToString(c.RemotePub())] = c
	}
	return out
}

func buildMissingErr(missing map[string]map[string][]byte) *MissingPeersError {
	out := &MissingPeersError{Files: make(map[string][][]byte, len(missing))}
	for rel, peers := range missing {
		pubs := make([][]byte, 0, len(peers))
		for _, p := range peers {
			pubs = append(pubs, p)
		}
		out.Files[rel] = pubs
	}
	return out
}

// restoreFile streams an entry's chunks into <rel>.partial then renames
// to <rel> on success. A chunk-fetch failure returns the candidate peer
// set for deferral; other failures abort with nil missingPeers.
func restoreFile(
	ctx context.Context,
	opts Options,
	root *os.Root,
	rel string,
	entry index.FileEntry,
	connByPub map[string]*bsquic.Conn,
) (missingPeers [][]byte, err error) {
	if dir := filepath.Dir(rel); dir != "." {
		if err := root.MkdirAll(dir, dirPerm); err != nil {
			return nil, fmt.Errorf("mkdir parent: %w", err)
		}
	}
	if info, lerr := root.Lstat(rel); lerr == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refuse to overwrite symlink at %q", rel)
	}
	partial := rel + partialSuffix
	f, err := openInRootFunc(root, partial, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|syscall.O_NOFOLLOW, filePerm)
	if err != nil {
		return nil, fmt.Errorf("create: %w", err)
	}
	defer f.Close()

	cleanupPartial := func() {
		_ = removeInRootFunc(root, partial)
	}
	seen := map[string]struct{}{}
	var missing [][]byte
	for i, ref := range entry.Chunks {
		if cerr := ctx.Err(); cerr != nil {
			cleanupPartial()
			return nil, cerr
		}
		blob, ferr := fetchChunk(ctx, ref, connByPub)
		if ferr != nil {
			for _, p := range ref.Peers {
				key := hex.EncodeToString(p)
				if _, dup := seen[key]; dup {
					continue
				}
				seen[key] = struct{}{}
				missing = append(missing, append([]byte(nil), p...))
			}
			cleanupPartial()
			return missing, fmt.Errorf("fetch chunk %d: %w", i, ferr)
		}
		ec, uerr := crypto.UnmarshalEncryptedChunk(blob)
		if uerr != nil {
			cleanupPartial()
			return nil, fmt.Errorf("unmarshal chunk %d: %w", i, uerr)
		}
		plain, derr := crypto.Decrypt(ec, opts.RecipientPub, opts.RecipientPriv)
		if derr != nil {
			cleanupPartial()
			return nil, fmt.Errorf("decrypt chunk %d: %w", i, derr)
		}
		if sha256.Sum256(plain) != ref.PlaintextHash {
			cleanupPartial()
			return nil, fmt.Errorf("%w on chunk %d", ErrPlaintextHashMismatch, i)
		}
		if _, werr := f.Write(plain); werr != nil {
			cleanupPartial()
			return nil, fmt.Errorf("write chunk %d: %w", i, werr)
		}
	}
	if cerr := f.Close(); cerr != nil {
		cleanupPartial()
		return nil, fmt.Errorf("close: %w", cerr)
	}
	if rerr := renameInRootFunc(root, partial, rel); rerr != nil {
		cleanupPartial()
		return nil, fmt.Errorf("rename: %w", rerr)
	}
	if cerr := chtimesInRootFunc(root, rel, entry.ModTime, entry.ModTime); cerr != nil {
		return nil, fmt.Errorf("chtimes: %w", cerr)
	}
	fmt.Fprintf(opts.Progress, "restored %s (%d chunks)\n", entry.Path, len(entry.Chunks))
	return nil, nil
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
