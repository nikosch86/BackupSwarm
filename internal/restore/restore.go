// Package restore is the M1.10 restore pipeline: given a local bbolt
// index describing what was backed up and a live QUIC connection to a
// storage peer, fetch each chunk, decrypt it, verify its plaintext
// hash, and reassemble the original files under a user-supplied Dest
// root.
//
// Layout: each file's original absolute path is rewritten under Dest
// via filepath.Join(Dest, entry.Path), so /home/alice/docs/foo.txt
// restored into /tmp/dest lands at /tmp/dest/home/alice/docs/foo.txt.
// Dest must be absolute so the rewrite is unambiguous. The original
// directory tree is created at 0700; restored files are 0600.
//
// Integrity: each chunk's post-decrypt plaintext hash is compared
// against ChunkRef.PlaintextHash from the index; a mismatch aborts the
// restore before writing any further bytes for that file.
package restore

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

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

// writableFile is the subset of *os.File that restoreFile uses after
// the initial OpenFile. Abstracting as an interface lets internal tests
// substitute a fake that fails Write or Close — the post-Open syscall
// error paths are otherwise unreachable without fault injection. Same
// pattern as the tempFile interface in internal/store.
type writableFile interface {
	Write(p []byte) (int, error)
	Close() error
}

// Package-level seams so internal tests can exercise post-OpenFile
// error branches (write, close) and the Chtimes error wrap. Production
// code never reassigns these — same pattern as the createTempFunc /
// renameFunc seams in internal/store.
var (
	openFileFunc = func(name string, flag int, perm os.FileMode) (writableFile, error) {
		return os.OpenFile(name, flag, perm)
	}
	chtimesFunc = os.Chtimes
)

// Options configures a restore invocation.
type Options struct {
	// Dest is the absolute directory under which every indexed path is
	// recreated. An entry with Path == "/home/alice/docs/a.txt" lands at
	// Dest + "/home/alice/docs/a.txt".
	Dest string
	// Conn is the live QUIC connection to the storage peer that holds
	// the chunks (M1 assumes a single peer per swarm; M2.14+ generalizes).
	Conn *bsquic.Conn
	// Index is the local bbolt index describing what to restore.
	Index *index.Index
	// RecipientPub and RecipientPriv are the X25519 keypair under which
	// the chunks were encrypted at backup time.
	RecipientPub, RecipientPriv *[crypto.RecipientKeySize]byte
	// Progress receives per-file progress lines. nil is treated as io.Discard.
	Progress io.Writer
}

// Run restores every file recorded in opts.Index under opts.Dest. On
// first error (transport, decrypt, or hash-mismatch) Run stops and
// returns the wrapped error; the partial-output file, if any, is left
// behind so the user can inspect it.
func Run(ctx context.Context, opts Options) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	if !filepath.IsAbs(opts.Dest) {
		return fmt.Errorf("dest %q is not absolute", opts.Dest)
	}
	entries, err := opts.Index.List()
	if err != nil {
		return fmt.Errorf("index list: %w", err)
	}
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := restoreFile(ctx, opts, entry); err != nil {
			return fmt.Errorf("restore %q: %w", entry.Path, err)
		}
	}
	return nil
}

func restoreFile(ctx context.Context, opts Options, entry index.FileEntry) error {
	outPath := filepath.Join(opts.Dest, entry.Path)
	if err := os.MkdirAll(filepath.Dir(outPath), dirPerm); err != nil {
		return fmt.Errorf("mkdir parent: %w", err)
	}
	f, err := openFileFunc(outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, filePerm)
	if err != nil {
		return fmt.Errorf("create: %w", err)
	}
	defer f.Close()

	for i, ref := range entry.Chunks {
		if err := ctx.Err(); err != nil {
			return err
		}
		blob, err := backup.SendGetChunk(ctx, opts.Conn, ref.CiphertextHash)
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
	// Preserve the original mtime so a subsequent daemon scan sees the
	// restored file as up-to-date (matching Size + ModTime in the index)
	// and incremental-skips it. Without this the scan would re-chunk and
	// re-ship every restored file, orphaning the old ciphertext blobs on
	// the peer.
	if err := chtimesFunc(outPath, entry.ModTime, entry.ModTime); err != nil {
		return fmt.Errorf("chtimes: %w", err)
	}
	fmt.Fprintf(opts.Progress, "restored %s (%d chunks)\n", entry.Path, len(entry.Chunks))
	return nil
}
