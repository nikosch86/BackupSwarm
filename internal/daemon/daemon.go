// Package daemon is the sync-daemon runner: a single long-running
// process that is both a backup source (keeping its own backup dir
// synced to a storage peer) and a storage peer (serving PutChunk and
// DeleteChunk streams for others). Classify selects the startup Mode
// from (local-populated?, index-populated?); Run wires the selected
// Mode to a QUIC listener and a backup.Serve loop.
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
	"backupswarm/internal/restore"
	"backupswarm/internal/store"
)

// Mode is the startup classification produced by Classify.
type Mode int

const (
	// ModeIdle: nothing to back up, nothing to restore. The daemon still
	// serves inbound chunks but runs no scan loop of its own.
	ModeIdle Mode = iota
	// ModeFirstBackup: backup dir populated, index empty. Chunk and ship everything.
	ModeFirstBackup
	// ModeReconcile: steady state. Scan against the index, upload
	// changed files, emit DeleteChunk for files gone from disk.
	ModeReconcile
	// ModeRestore: backup dir empty, index populated, user asked for --restore.
	ModeRestore
	// ModePurge: backup dir empty, index populated, user asked for --purge.
	// Deletes every indexed blob from storage peers then clears the index.
	ModePurge
)

// ErrRefuseStart is returned by Classify when the backup dir is empty
// but the index is populated without --restore or --purge. Starting
// blindly would orphan every swarm-stored blob.
var ErrRefuseStart = errors.New("local backup dir is empty but index is populated; pass --restore or --purge")

// ErrConflictingFlags is returned by Classify when both --restore and --purge are set.
var ErrConflictingFlags = errors.New("--restore and --purge are mutually exclusive")

// Classify returns the Mode the daemon should run in. restore and purge
// are only consulted in the (local-empty, index-populated) case.
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

// ScanOnce runs one incremental backup pass followed by one prune sweep
// against opts.Conn. Each call is independent; safe to retry after failure.
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
	// DataDir holds identity, recipient keys, index, store, owners db,
	// and peers.db; the dial target is read from peers.db.
	DataDir string
	// BackupDir is the user's source-of-truth directory kept in sync
	// with the swarm.
	BackupDir string
	// ListenAddr is the UDP address for the inbound QUIC listener
	// (storage-peer role). Ignored when Listener is non-nil.
	ListenAddr string
	// Listener, when non-nil, is used as the inbound QUIC listener
	// instead of binding ListenAddr. Ownership is handed off — Run
	// closes it on exit. Callers pass a pre-bound listener to avoid
	// the close/rebind race that breaks ":0" ports (e.g. after an
	// `invite` handshake transitioning into the daemon).
	Listener *bsquic.Listener
	// PeerStore, when non-nil, is used instead of opening one at
	// <DataDir>/peers.db. Ownership is handed off — Run closes it on
	// exit. Lets `invite`/`join` hand their already-open peer store
	// into the daemon without a bbolt flock hiccup.
	PeerStore *peers.Store
	// ChunkSize is the target chunk size for backups (bytes).
	ChunkSize int
	// ScanInterval is the period between scan passes. Zero uses a
	// sensible default (60s).
	ScanInterval time.Duration
	// Restore selects ModeRestore when the backup dir is empty but the
	// index is populated.
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
// peers.db has a non-empty address. Only single-peer mode is supported.
var ErrMultiplePeers = errors.New("multiple dialable peers in peers.db; single-peer mode only")

const (
	defaultScanInterval = 60 * time.Second
	defaultDialTimeout  = 30 * time.Second

	indexFileName = "index.db"
	storeDirName  = "chunks"
)

// Run is the sync-daemon entrypoint. It opens local state, applies the
// Classify decision, and then either runs a scan loop, performs a one-shot
// purge, or sits idle serving inbound requests. Blocks until ctx is
// cancelled; returns the first unrecoverable error.
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

	peerStore := opts.PeerStore
	if peerStore == nil {
		peerStore, err = peers.Open(filepath.Join(opts.DataDir, peers.DefaultFilename))
		if err != nil {
			return fmt.Errorf("open peer store: %w", err)
		}
	}
	defer func() { _ = peerStore.Close() }()

	storagePeer, err := pickStoragePeer(peerStore)
	if err != nil {
		return err
	}

	// Classify before binding so flag-validation errors surface cleanly.
	// Storage-only mode (no BackupDir) has no scan to gate.
	var mode Mode
	if opts.BackupDir != "" {
		localPop, err := BackupDirHasRegularFiles(opts.BackupDir)
		if err != nil {
			return fmt.Errorf("inspect backup dir: %w", err)
		}
		indexEntries, err := idx.List()
		if err != nil {
			return fmt.Errorf("list index: %w", err)
		}
		mode, err = Classify(localPop, len(indexEntries) > 0, opts.Restore, opts.Purge)
		if err != nil {
			return fmt.Errorf("classify startup mode: %w", err)
		}
	}

	// Membership-check predicate: an inbound handshake is only admitted
	// if the peer's pubkey is already in peers.db.
	verifyMember := func(pub ed25519.PublicKey) error {
		if _, err := peerStore.Get(pub); err != nil {
			return fmt.Errorf("unknown peer %x: %w", pub[:8], err)
		}
		return nil
	}

	listener := opts.Listener
	if listener == nil {
		listener, err = bsquic.Listen(opts.ListenAddr, id.PrivateKey, verifyMember, nil)
		if err != nil {
			return fmt.Errorf("listen on %q: %w", opts.ListenAddr, err)
		}
	} else {
		// Handed-off listener (from `invite --then-run`): it was bound
		// in bootstrap mode (nil predicate) so AcceptJoin could admit
		// the joiner before they existed in peers.db. Flip to the
		// membership check now, before Serve starts, so steady-state
		// handshakes enforce swarm membership.
		listener.SetVerifyPeer(verifyMember)
	}
	defer func() { _ = listener.Close() }()

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- backup.Serve(ctx, listener, st) }()

	// Pure storage-peer role: serve inbound chunks only, no scan loop.
	if opts.BackupDir == "" {
		slog.InfoContext(ctx, "daemon starting (storage-only)",
			"node_id", id.ShortID(),
			"listen", opts.ListenAddr,
		)
		fmt.Fprintf(opts.Progress, "daemon starting: role=storage-peer listen=%s\n", opts.ListenAddr)
		return waitForServe(ctx, serveErrCh)
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

	// Backup dir present but no peer to dial — behave as storage-peer.
	// (Someone may be using the node as a shared data sink; their own
	// backups wait until peers.db is populated.)
	if storagePeer == nil {
		return waitForServe(ctx, serveErrCh)
	}

	dialCtx, dialCancel := context.WithTimeout(ctx, opts.DialTimeout)
	peerConn, err := bsquic.Dial(dialCtx, storagePeer.Addr, id.PrivateKey, storagePeer.PubKey, nil)
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
		// Purge: iterate the index and send DeleteChunk per entry.
		// (Prune scopes by Root and the empty backup dir has nothing
		// under Root to iterate.)
		if err := purgeAll(ctx, idx, peerConn, opts.Progress); err != nil {
			return fmt.Errorf("purge: %w", err)
		}
		fmt.Fprintln(opts.Progress, "purge complete; daemon continuing in idle mode")
	case ModeRestore:
		// Dest "/" puts each indexed file back at its absolute path. The
		// backup dir is empty by definition of ModeRestore, so no
		// collision with existing user data. Preserving ModTime lets the
		// next scan incremental-skip each restored file.
		if err := restore.Run(ctx, restore.Options{
			Dest:          "/",
			Conn:          peerConn,
			Index:         idx,
			RecipientPub:  rk.PublicKey,
			RecipientPriv: rk.PrivateKey,
			Progress:      opts.Progress,
		}); err != nil {
			return fmt.Errorf("restore: %w", err)
		}
		fmt.Fprintln(opts.Progress, "restore complete; daemon continuing in reconcile mode")
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

// waitForServe blocks until ctx is cancelled (clean shutdown) or the
// Serve goroutine surfaces an error. Used by the two idle paths in Run:
// pure storage-only mode and backup-dir-with-no-peer mode.
func waitForServe(ctx context.Context, serveErrCh <-chan error) error {
	select {
	case <-ctx.Done():
		return nil
	case err := <-serveErrCh:
		return err
	}
}

// pickStoragePeer picks the single dialable storage candidate from
// peers.db: non-empty Addr and a Role that IsStorageCandidate. Returns
// (nil, nil) on zero matches, (nil, ErrMultiplePeers) on more than one.
func pickStoragePeer(ps *peers.Store) (*peers.Peer, error) {
	all, err := ps.List()
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	var dialable []peers.Peer
	for _, p := range all {
		if p.Addr != "" && p.Role.IsStorageCandidate() {
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
		// Root at the entry's dir so Prune's rooted check accepts it;
		// Stat fails ErrNotExist (empty dir in Purge mode), so Prune
		// deletes and removes the entry.
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
// regular file is found (symlinks, sockets, and device files don't count).
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
