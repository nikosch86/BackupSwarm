// Package daemon is the M1.9 sync-daemon runner: a single long-running
// process that is both a backup source (keeping its own backup dir
// synced to a storage peer) and a storage peer (serving PutChunk +
// DeleteChunk streams for others).
//
// The core of the package is pure: Classify decides one of a fixed set
// of startup Modes from the (local-populated?, index-populated?)
// product, and helpers like BackupDirHasRegularFiles inspect the
// local filesystem. The Run function wires the mode selection to a
// real QUIC listener and a backup.Serve loop; integration coverage for
// Run lives in the CLI `run` command test suite (M1.11) rather than
// here.
package daemon

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// Mode is the startup classification produced by Classify. It drives
// what the daemon does immediately after opening its local state:
// either a first-ever backup, a steady-state reconcile, a restore, a
// purge, or plain idle.
type Mode int

const (
	// ModeIdle: nothing to back up, nothing to restore. The daemon
	// still accepts inbound chunks and deletes (it is a storage peer),
	// it just runs no scan loop of its own.
	ModeIdle Mode = iota
	// ModeFirstBackup: the backup dir contains data, but the local
	// index has no record of it. First-time setup — the scan will
	// chunk and ship everything.
	ModeFirstBackup
	// ModeReconcile: normal steady-state. Scan against the index,
	// upload changed files, emit DeleteChunk for files gone from disk.
	ModeReconcile
	// ModeRestore: the local backup dir is empty but the index knows
	// about files — the user asked for --restore. M1.10 implements the
	// actual restore logic; until then this Mode lets the daemon start
	// cleanly rather than refusing.
	ModeRestore
	// ModePurge: the local backup dir is empty but the index is
	// populated, and the user asked for --purge. The daemon will ask
	// storage peers to delete every blob recorded in the index, then
	// clear the index.
	ModePurge
)

// ErrRefuseStart is returned by Classify when the backup dir is empty
// but the index is populated, and the caller did not pass --restore or
// --purge. The daemon refuses to start rather than silently treat the
// situation as a fresh setup (which would orphan every swarm-stored
// blob) or a clean shutdown (which would race an in-flight backup).
var ErrRefuseStart = errors.New("local backup dir is empty but index is populated; pass --restore or --purge")

// ErrConflictingFlags is returned by Classify when both --restore and
// --purge are set. The daemon cannot simultaneously download files and
// delete them; this is a caller error.
var ErrConflictingFlags = errors.New("--restore and --purge are mutually exclusive")

// Classify returns the Mode a daemon should run in given whether the
// backup dir contains regular files (localPopulated) and whether the
// local index has any entries (indexPopulated).
//
// restore and purge are reserved for the (local-empty, index-populated)
// case. Passing either when localPopulated is true is ignored silently —
// there is no ambiguity: the daemon either reconciles or does a first
// backup and the flags are no-ops.
func Classify(localPopulated, indexPopulated, restore, purge bool) (Mode, error) {
	if restore && purge {
		return 0, ErrConflictingFlags
	}
	switch {
	case !localPopulated && !indexPopulated:
		return ModeIdle, nil
	case localPopulated && !indexPopulated:
		return ModeFirstBackup, nil
	case localPopulated && indexPopulated:
		return ModeReconcile, nil
	case !localPopulated && indexPopulated && restore:
		return ModeRestore, nil
	case !localPopulated && indexPopulated && purge:
		return ModePurge, nil
	default:
		return 0, ErrRefuseStart
	}
}

// ScanOnceOptions is the owner-side configuration for a single scan
// pass: back up changed files and prune deleted ones, using the same
// QUIC connection for both directions.
type ScanOnceOptions struct {
	// BackupDir is the directory being kept in sync. Incremental
	// backup-Run is invoked with Path == BackupDir and Prune with
	// Root == BackupDir.
	BackupDir string
	// Conn is the live QUIC connection to the storage peer.
	Conn *bsquic.Conn
	// Index is the local bbolt index.
	Index *index.Index
	// RecipientPub is the X25519 public key for chunk encryption.
	RecipientPub *[crypto.RecipientKeySize]byte
	// ChunkSize is the target fixed-chunk size in bytes.
	ChunkSize int
	// Progress receives per-file progress lines from both backup.Run
	// and backup.Prune. nil is treated as io.Discard.
	Progress io.Writer
}

// ScanOnce runs one incremental backup + one prune sweep against the
// storage peer on the other end of opts.Conn. Intended to be called
// repeatedly by the daemon's ticker loop; each call is independent and
// safe to re-run after a transient failure.
func ScanOnce(ctx context.Context, opts ScanOnceOptions) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	if err := backup.Run(ctx, backup.RunOptions{
		Path:         opts.BackupDir,
		Conn:         opts.Conn,
		RecipientPub: opts.RecipientPub,
		Index:        opts.Index,
		ChunkSize:    opts.ChunkSize,
		Progress:     opts.Progress,
	}); err != nil {
		return fmt.Errorf("backup run: %w", err)
	}
	if err := backup.Prune(ctx, backup.PruneOptions{
		Root:     opts.BackupDir,
		Conn:     opts.Conn,
		Index:    opts.Index,
		Progress: opts.Progress,
	}); err != nil {
		return fmt.Errorf("prune: %w", err)
	}
	return nil
}

// Options is the configuration for Run.
type Options struct {
	// DataDir is the node's data directory (identity, recipient keys,
	// index, store, owners db, peer store). The storage peer to dial
	// for outbound chunks is read from `<DataDir>/peers.db`, which is
	// populated by the `invite`/`join` handshake.
	DataDir string
	// BackupDir is the user's source-of-truth directory kept in sync
	// with the swarm.
	BackupDir string
	// ListenAddr is the UDP address for the inbound QUIC listener
	// (storage-peer role).
	ListenAddr string
	// ChunkSize is the target chunk size for backups (bytes).
	ChunkSize int
	// ScanInterval is the period between scan passes. Zero uses a
	// sensible default (60s).
	ScanInterval time.Duration
	// Restore selects ModeRestore when the backup dir is empty but the
	// index is populated. M1.9 does not yet implement restore; Run
	// logs a warning and continues in Idle mode. M1.10 wires the
	// actual restore logic to this flag.
	Restore bool
	// Purge selects ModePurge: delete every indexed blob from the
	// storage peer and clear the index, then continue in Idle mode.
	Purge bool
	// DialTimeout bounds the initial dial to the storage peer. Zero
	// uses 30s.
	DialTimeout time.Duration
	// Progress receives daemon-level progress lines (scan starts,
	// mode transitions). nil is treated as io.Discard.
	Progress io.Writer
}

// ErrMultiplePeers is returned by Run when more than one peer in
// peers.db has a non-empty address. M1 assumes a single storage peer
// per swarm; multi-peer placement lands in M2.14.
var ErrMultiplePeers = errors.New("multiple dialable peers in peers.db; M1.9 supports exactly one — remove extras with a future `peers` CLI or wait for M2.14")

const (
	defaultScanInterval = 60 * time.Second
	defaultDialTimeout  = 30 * time.Second

	indexFileName = "index.db"
	storeDirName  = "chunks"
	peersFileName = "peers.db"
)

// Run is the M1.9 sync-daemon entrypoint. It opens local state, applies
// the startup-mode classification from Classify, and then either runs a
// scan loop against a storage peer, performs a one-shot purge, or sits
// idle as a storage peer waiting for inbound requests. The function
// blocks until ctx is cancelled and returns the first unrecoverable
// error encountered.
func Run(ctx context.Context, opts Options) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	if opts.ScanInterval == 0 {
		opts.ScanInterval = defaultScanInterval
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = defaultDialTimeout
	}

	id, _, err := node.Ensure(opts.DataDir)
	if err != nil {
		return fmt.Errorf("ensure identity: %w", err)
	}
	rk, _, err := node.EnsureRecipient(opts.DataDir)
	if err != nil {
		return fmt.Errorf("ensure recipient keys: %w", err)
	}

	idx, err := index.Open(filepath.Join(opts.DataDir, indexFileName))
	if err != nil {
		return fmt.Errorf("open index: %w", err)
	}
	defer func() { _ = idx.Close() }()

	st, err := store.New(filepath.Join(opts.DataDir, storeDirName))
	if err != nil {
		return fmt.Errorf("open chunk store: %w", err)
	}
	defer func() { _ = st.Close() }()

	peerStore, err := peers.Open(filepath.Join(opts.DataDir, peersFileName))
	if err != nil {
		return fmt.Errorf("open peer store: %w", err)
	}
	defer func() { _ = peerStore.Close() }()

	storagePeer, err := pickStoragePeer(peerStore)
	if err != nil {
		return err
	}

	// Pure storage-peer role: no --backup-dir means this node only
	// serves chunks for others; no scan loop, no classification.
	if opts.BackupDir == "" {
		slog.InfoContext(ctx, "daemon starting (storage-only)",
			"node_id", id.ShortID(),
			"listen", opts.ListenAddr,
		)
		fmt.Fprintf(opts.Progress, "daemon starting: role=storage-peer listen=%s\n", opts.ListenAddr)
		return runStorageOnly(ctx, opts.ListenAddr, id.PrivateKey, st)
	}

	localPop, err := BackupDirHasRegularFiles(opts.BackupDir)
	if err != nil {
		return fmt.Errorf("inspect backup dir: %w", err)
	}
	indexEntries, err := idx.List()
	if err != nil {
		return fmt.Errorf("list index: %w", err)
	}
	mode, err := Classify(localPop, len(indexEntries) > 0, opts.Restore, opts.Purge)
	if err != nil {
		return fmt.Errorf("classify startup mode: %w", err)
	}
	peerAddr := ""
	if storagePeer != nil {
		peerAddr = storagePeer.Addr
	}
	slog.InfoContext(ctx, "daemon starting",
		"node_id", id.ShortID(),
		"mode", mode,
		"listen", opts.ListenAddr,
		"peer", peerAddr,
	)
	fmt.Fprintf(opts.Progress, "daemon starting: mode=%s listen=%s\n", modeName(mode), opts.ListenAddr)

	listener, err := bsquic.Listen(opts.ListenAddr, id.PrivateKey)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", opts.ListenAddr, err)
	}
	defer func() { _ = listener.Close() }()

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- backup.Serve(ctx, listener, st) }()

	// Backup dir present but no peer to dial — behave as storage-peer.
	// (Someone may be using the node as a shared data sink; their own
	// backups wait until peers.db is populated.)
	if storagePeer == nil {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serveErrCh:
			return err
		}
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, opts.DialTimeout)
	peerConn, err := bsquic.Dial(dialCtx, storagePeer.Addr, id.PrivateKey, storagePeer.PubKey)
	dialCancel()
	if err != nil {
		return fmt.Errorf("dial peer %q: %w", storagePeer.Addr, err)
	}
	defer func() { _ = peerConn.Close() }()
	slog.InfoContext(ctx, "dialed storage peer",
		"peer_addr", storagePeer.Addr,
		"peer_pub", hex.EncodeToString(storagePeer.PubKey),
	)

	switch mode {
	case ModePurge:
		// For purge we clear the whole tree under BackupDir. Since the
		// backup dir is empty (definition of the Purge mode), a Prune
		// with Root == BackupDir would leave nothing to do; we instead
		// iterate the index wholesale and delete every entry. Because
		// Prune already scopes by Root, we walk entries manually here.
		if err := purgeAll(ctx, idx, peerConn, opts.Progress); err != nil {
			return fmt.Errorf("purge: %w", err)
		}
		fmt.Fprintln(opts.Progress, "purge complete; daemon continuing in idle mode")
	case ModeRestore:
		// M1.10 replaces this with real restore; for M1.9 we accept
		// --restore as a no-op that lets the daemon start without the
		// refuse-to-start guard firing.
		fmt.Fprintln(opts.Progress, "restore flag set; restore will be implemented in M1.10")
	}

	scanOpts := ScanOnceOptions{
		BackupDir:    opts.BackupDir,
		Conn:         peerConn,
		Index:        idx,
		RecipientPub: rk.PublicKey,
		ChunkSize:    opts.ChunkSize,
		Progress:     opts.Progress,
	}
	return runScanLoop(ctx, scanOpts, opts.ScanInterval, serveErrCh)
}

// runStorageOnly binds a listener and serves inbound chunks until ctx
// is cancelled. Used when --backup-dir is unset (node participates in
// the swarm purely as a storage peer, no backup source of its own).
func runStorageOnly(ctx context.Context, listenAddr string, priv ed25519.PrivateKey, st *store.Store) error {
	listener, err := bsquic.Listen(listenAddr, priv)
	if err != nil {
		return fmt.Errorf("listen on %q: %w", listenAddr, err)
	}
	defer func() { _ = listener.Close() }()

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- backup.Serve(ctx, listener, st) }()

	select {
	case <-ctx.Done():
		return nil
	case err := <-serveErrCh:
		return err
	}
}

// pickStoragePeer selects the single storage peer the daemon should
// dial, using peers.db as the source of truth. Returns:
//   - (nil, nil) if no peer has a non-empty address (storage-peer-only
//     role; daemon serves inbound chunks but does not back up anywhere).
//   - (peer, nil) when exactly one peer has a non-empty address.
//   - (nil, ErrMultiplePeers) if more than one peer is dialable. M1.9
//     assumes a single storage peer per swarm; M2.14 introduces the
//     weighted-random placement that makes multi-peer meaningful.
//
// Peers with empty addresses (recorded by `join` when the joiner had
// no --listen of its own) are ignored — the daemon cannot dial them.
func pickStoragePeer(ps *peers.Store) (*peers.Peer, error) {
	all, err := ps.List()
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	var dialable []peers.Peer
	for _, p := range all {
		if p.Addr != "" {
			dialable = append(dialable, p)
		}
	}
	switch len(dialable) {
	case 0:
		return nil, nil
	case 1:
		p := dialable[0]
		return &p, nil
	default:
		return nil, ErrMultiplePeers
	}
}

// runScanLoop blocks until ctx is cancelled or the Serve goroutine
// surfaces an error, running ScanOnce every interval. The first scan
// runs immediately so the daemon doesn't sit idle for a full interval
// on startup.
func runScanLoop(ctx context.Context, opts ScanOnceOptions, interval time.Duration, serveErrCh <-chan error) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	doScan := func() {
		if err := ScanOnce(ctx, opts); err != nil {
			slog.WarnContext(ctx, "scan failed", "err", err)
			fmt.Fprintf(opts.Progress, "scan failed: %v\n", err)
		}
	}
	doScan()
	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-serveErrCh:
			return err
		case <-ticker.C:
			doScan()
		}
	}
}

// purgeAll sends DeleteChunk for every chunk of every index entry,
// then clears the index. Used by Run when Mode == ModePurge.
func purgeAll(ctx context.Context, idx *index.Index, conn *bsquic.Conn, progress io.Writer) error {
	entries, err := idx.List()
	if err != nil {
		return fmt.Errorf("list index: %w", err)
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		// Point Prune's root at the entry's directory so its rooted
		// check accepts the path. Stat will fail-with-ErrNotExist (we
		// are in Purge mode precisely because the dir is empty), so
		// Prune will delete + remove the entry.
		if err := backup.Prune(ctx, backup.PruneOptions{
			Root:     filepath.Dir(e.Path),
			Conn:     conn,
			Index:    idx,
			Progress: progress,
		}); err != nil {
			return err
		}
	}
	return nil
}

func modeName(m Mode) string {
	switch m {
	case ModeIdle:
		return "idle"
	case ModeFirstBackup:
		return "first-backup"
	case ModeReconcile:
		return "reconcile"
	case ModeRestore:
		return "restore"
	case ModePurge:
		return "purge"
	default:
		return fmt.Sprintf("unknown(%d)", m)
	}
}

// BackupDirHasRegularFiles walks dir and returns true as soon as one
// regular file is found. Symlinks, sockets, and device files don't
// count (matching backup.Run's selection rules). An error is returned
// if dir does not exist or cannot be walked.
func BackupDirHasRegularFiles(dir string) (bool, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return false, fmt.Errorf("stat backup dir %q: %w", dir, err)
	}
	if !info.IsDir() {
		return false, fmt.Errorf("backup dir %q is not a directory", dir)
	}
	found := false
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.Type().IsRegular() {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	if walkErr != nil && !errors.Is(walkErr, filepath.SkipAll) {
		return false, fmt.Errorf("walk backup dir %q: %w", dir, walkErr)
	}
	return found, nil
}
