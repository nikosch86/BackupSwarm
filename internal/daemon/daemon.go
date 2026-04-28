// Package daemon is the sync-daemon runner: a single long-running
// process that is both a backup source (keeping its own backup dir
// synced to a storage peer) and a storage peer (serving PutChunk and
// DeleteChunk streams for others). Classify selects the startup Mode
// from (local-populated?, index-populated?); Run wires the selected
// Mode to a QUIC listener and a backup.Serve loop.
package daemon

import (
	"bytes"
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
	"sync"
	"sync/atomic"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/ca"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/restore"
	"backupswarm/internal/store"
	"backupswarm/internal/swarm"
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
// pass: back up changed files across all storage peers and prune deleted
// ones, using the same conn slice for both directions.
type ScanOnceOptions struct {
	// BackupDir is the directory being kept in sync. Incremental
	// backup-Run is invoked with Path == BackupDir and Prune with
	// Root == BackupDir.
	BackupDir string
	// Conns are the live QUIC connections to candidate storage peers.
	// backup.Run picks Redundancy peers per chunk weighted by capacity;
	// backup.Prune sends deletes to every conn that matches a peer in
	// each ChunkRef.Peers.
	Conns []*bsquic.Conn
	// Redundancy is the per-chunk peer count; zero or negative defaults
	// to 1 inside backup.Run.
	Redundancy int
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
// against opts.Conns. Each call is independent; safe to retry after failure.
func ScanOnce(ctx context.Context, opts ScanOnceOptions) error {
	if opts.Progress == nil {
		opts.Progress = io.Discard
	}
	if err := backup.Run(ctx, backup.RunOptions{
		Path:         opts.BackupDir,
		Conns:        opts.Conns,
		Redundancy:   opts.Redundancy,
		RecipientPub: opts.RecipientPub,
		Index:        opts.Index,
		ChunkSize:    opts.ChunkSize,
		Progress:     opts.Progress,
	}); err != nil {
		return fmt.Errorf("backup run: %w", err)
	}
	if err := backup.Prune(ctx, backup.PruneOptions{
		Root:     opts.BackupDir,
		Conns:    opts.Conns,
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
	// HeartbeatInterval is the period between liveness probes against
	// every live conn. Zero uses a sensible default (30s).
	HeartbeatInterval time.Duration
	// Restore selects ModeRestore when the backup dir is empty but the
	// index is populated.
	Restore bool
	// Purge selects ModePurge: delete every indexed blob from the
	// storage peer and clear the index, then continue in Idle mode.
	Purge bool
	// DialTimeout bounds the initial dial to the storage peer. Zero
	// uses 30s.
	DialTimeout time.Duration
	// IssueInitialInvite issues a token at startup, prints it to
	// Progress, and optionally writes it to InitialInviteOut.
	IssueInitialInvite bool
	// InitialInviteOut is the file path the initial invite token is
	// atomically written to. Only consulted when IssueInitialInvite.
	InitialInviteOut string
	// NoCA opts the founder into pin-mode trust. Only consulted when
	// IssueInitialInvite; rejected on a CA-mode swarm.
	NoCA bool
	// Progress receives daemon-level progress lines (scan starts,
	// mode transitions). nil is treated as io.Discard.
	Progress io.Writer
	// Reachability is the peer reachability map the daemon updates
	// from connection lifecycle events. nil makes Run allocate one
	// using MissThreshold.
	Reachability *swarm.ReachabilityMap
	// MissThreshold is the consecutive miss count required to flip a
	// peer from StateSuspect to StateUnreachable. Only consulted when
	// Reachability is nil. Zero or negative uses swarm.DefaultMissThreshold.
	MissThreshold int
	// GracePeriod is the duration a peer must stay StateUnreachable
	// before being flagged as lost. Only consulted when Reachability
	// is nil. Zero uses 24h; negative is rejected.
	GracePeriod time.Duration
	// MaxStorageBytes caps the local chunk store; 0 means unlimited.
	// PutChunk over the cap returns the "no_space" wire code.
	MaxStorageBytes int64
	// Redundancy is the per-chunk peer count used by ScanOnce. Zero or
	// negative defaults to 1 inside backup.Run.
	Redundancy int
}

const (
	defaultScanInterval      = 60 * time.Second
	defaultHeartbeatInterval = 30 * time.Second
	defaultDialTimeout       = 30 * time.Second
	defaultGracePeriod       = 24 * time.Hour

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
	if opts.HeartbeatInterval == 0 {
		opts.HeartbeatInterval = defaultHeartbeatInterval
	}
	if opts.GracePeriod == 0 {
		opts.GracePeriod = defaultGracePeriod
	}
	if opts.GracePeriod < 0 {
		return fmt.Errorf("grace period must be non-negative, got %v", opts.GracePeriod)
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

	st, err := store.NewWithMax(filepath.Join(opts.DataDir, storeDirName), opts.MaxStorageBytes)
	if err != nil {
		return fmt.Errorf("open chunk store: %w", err)
	}
	defer func() { _ = st.Close() }()

	warnIfOverCap(ctx, st.Used(), st.Capacity(), opts.Progress)

	peerStore := opts.PeerStore
	if peerStore == nil {
		peerStore, err = peers.Open(filepath.Join(opts.DataDir, peers.DefaultFilename))
		if err != nil {
			return fmt.Errorf("open peer store: %w", err)
		}
	}
	defer func() { _ = peerStore.Close() }()

	dialablePeers, err := listDialablePeers(peerStore)
	if err != nil {
		return err
	}

	reach := opts.Reachability
	if reach == nil {
		n := opts.MissThreshold
		if n <= 0 {
			n = swarm.DefaultMissThreshold
		}
		reach = swarm.NewReachabilityMapWithGrace(n, opts.GracePeriod, nil)
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

	// Admits a peer if its pubkey is in peers.db OR if at least one
	// invite is pending in the cache.
	pendingInvites := &pendingCache{}
	verifyMember := makeVerifyPeer(peerStore, pendingInvites)

	listener := opts.Listener
	if listener == nil {
		listener, err = bsquic.Listen(opts.ListenAddr, id.PrivateKey, verifyMember, nil)
		if err != nil {
			return fmt.Errorf("listen on %q: %w", opts.ListenAddr, err)
		}
	} else {
		// Handed-off listener flips its predicate to the membership
		// check before Serve starts.
		listener.SetVerifyPeer(verifyMember)
	}
	defer func() { _ = listener.Close() }()

	// Publishes the bound address for an `invite` CLI in another
	// process to read.
	if err := WriteListenAddr(opts.DataDir, listener.Addr().String()); err != nil {
		return fmt.Errorf("write listen.addr: %w", err)
	}
	defer func() { _ = RemoveListenAddr(opts.DataDir) }()

	// Shared *ca.CA (or nil for pin mode) for the initial-invite
	// issuer and the dispatchStream join handler.
	var swarmCA *ca.CA
	if opts.IssueInitialInvite {
		swarmCA, err = ResolveSwarmCA(ctx, opts.DataDir, opts.NoCA)
		if err != nil {
			return fmt.Errorf("resolve swarm ca: %w", err)
		}
	} else {
		swarmCA, err = loadSwarmCAIfPresent(opts.DataDir)
		if err != nil {
			return fmt.Errorf("load swarm ca: %w", err)
		}
	}

	if opts.IssueInitialInvite {
		var caCertDER []byte
		if swarmCA != nil {
			caCertDER = swarmCA.CertDER
		}
		tokStr, issueErr := IssueInvite(opts.DataDir, listener.Addr().String(), id.PublicKey, caCertDER)
		if issueErr != nil {
			return fmt.Errorf("issue initial invite: %w", issueErr)
		}
		fmt.Fprintln(opts.Progress, tokStr)
		if opts.InitialInviteOut != "" {
			if err := writeAtomicFile(opts.InitialInviteOut, tokStr+"\n"); err != nil {
				return fmt.Errorf("write initial invite token: %w", err)
			}
		}
	}

	// Synchronous first refresh warms the cache before Serve accepts;
	// the goroutine then refreshes on each tick.
	refreshPendingInvites(ctx, opts.DataDir, pendingInvites)
	go pollPendingInvites(ctx, opts.DataDir, pendingInvites, defaultInviteWatchInterval)

	connSet := swarm.NewConnSet()
	router := &swarm.Router{
		Store: peerStore,
		Dedup: swarm.NewDedupCache(swarm.DefaultDedupCapacity),
		Conns: connSet,
	}
	obs := &backup.ConnObserver{
		OnAccept: func(c *bsquic.Conn) {
			connSet.Add(c)
			reach.MarkConn(c, swarm.StateReachable)
		},
		OnClose: func(c *bsquic.Conn) {
			connSet.Remove(c)
			reach.MarkConn(c, swarm.StateUnreachable)
		},
	}
	joinHandler := makeJoinHandler(opts.DataDir, peerStore, swarmCA, connSet)

	dialer := &outboundDialer{
		ctx:         ctx,
		priv:        id.PrivateKey,
		timeout:     opts.DialTimeout,
		st:          st,
		annHandler:  router.HandleStream,
		joinHandler: joinHandler,
		connSet:     connSet,
		reach:       reach,
	}
	defer dialer.CloseAll()
	router.OnApplied = makeImmediateDialOnApplied(peerStore, connSet, dialer)

	serveErrCh := make(chan error, 1)
	go func() { serveErrCh <- backup.Serve(ctx, listener, st, router.HandleStream, joinHandler, obs) }()

	// modeStr is the snapshot's published Mode, swapped after a
	// one-shot restore/purge completes.
	var modeStr atomic.Pointer[string]
	initialMode := "storage-only"
	if opts.BackupDir != "" {
		initialMode = modeName(mode)
	}
	modeStr.Store(&initialMode)
	var lastScanAtNanos atomic.Int64
	lastScanAtFn := func() time.Time {
		v := lastScanAtNanos.Load()
		if v == 0 {
			return time.Time{}
		}
		return time.Unix(0, v)
	}
	// snapCtx bounds the snapshot loop to daemon.Run's lifetime.
	// Defer order: snapCancel → snapWG.Wait → RemoveRuntimeSnapshot.
	snapCtx, snapCancel := context.WithCancel(ctx)
	var snapWG sync.WaitGroup
	snapWG.Add(1)
	go func() {
		defer snapWG.Done()
		runSnapshotLoop(snapCtx, snapshotLoopOptions{
			dataDir:      opts.DataDir,
			interval:     opts.ScanInterval,
			listenAddr:   listener.Addr().String(),
			modeFn:       func() string { return *modeStr.Load() },
			connsFn:      connSet.Snapshot,
			lastScanFn:   lastScanAtFn,
			storeStatsFn: func() (int64, int64) { return st.Used(), st.Capacity() },
			ownBackupFn:  ownBackupFromIndex(snapCtx, idx),
			reach:        reach,
			peerStore:    peerStore,
		})
	}()
	defer func() { _ = RemoveRuntimeSnapshot(opts.DataDir) }()
	defer snapWG.Wait()
	defer snapCancel()

	// hbCtx bounds the heartbeat loop to daemon.Run's lifetime.
	// Defer order: hbCancel → hbWG.Wait.
	hbCtx, hbCancel := context.WithCancel(ctx)
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		runHeartbeatLoop(hbCtx, heartbeatLoopOptions{
			interval: opts.HeartbeatInterval,
			connsFn:  connSet.Snapshot,
			reach:    reach,
		})
	}()
	defer hbWG.Wait()
	defer hbCancel()

	// Pure storage-peer role: serve inbound chunks only, no scan loop.
	if opts.BackupDir == "" {
		slog.InfoContext(ctx, "daemon starting (storage-only)",
			"node_id", id.ShortID(),
			"listen", opts.ListenAddr,
		)
		fmt.Fprintf(opts.Progress, "daemon starting: role=storage-peer listen=%s\n", opts.ListenAddr)
		return waitForServe(ctx, serveErrCh)
	}

	slog.InfoContext(ctx, "daemon starting",
		"node_id", id.ShortID(),
		"mode", mode,
		"listen", opts.ListenAddr,
		"known_peers", len(dialablePeers),
	)
	fmt.Fprintf(opts.Progress, "daemon starting: mode=%s listen=%s known_peers=%d\n", modeName(mode), opts.ListenAddr, len(dialablePeers))

	// Backup dir present but no known peers — behave as storage-peer.
	if len(dialablePeers) == 0 {
		return waitForServe(ctx, serveErrCh)
	}

	if err := dialAllPeers(ctx, dialer, dialablePeers); err != nil {
		return err
	}

	connsFn := func() []*bsquic.Conn {
		return liveStorageConns(connSet, peerStore)
	}
	if len(connsFn()) == 0 {
		// No storage candidate dialable; fall through to storage-only.
		return waitForServe(ctx, serveErrCh)
	}

	switch mode {
	case ModePurge:
		// Purge: iterate the index and send DeleteChunk per entry.
		// (Prune scopes by Root and the empty backup dir has nothing
		// under Root to iterate.)
		if err := purgeAll(ctx, idx, connsFn(), opts.Progress); err != nil {
			return fmt.Errorf("purge: %w", err)
		}
		fmt.Fprintln(opts.Progress, "purge complete; daemon continuing in idle mode")
		idleMode := "idle"
		modeStr.Store(&idleMode)
	case ModeRestore:
		// Restore writes each file under opts.BackupDir, the same root
		// the daemon uses for backup. Index entries are stored relative
		// to that root, so a tampered entry can only redirect writes
		// inside the configured tree — never to system paths the user
		// did not opt to back up.
		if err := restore.Run(ctx, restore.Options{
			Dest:          opts.BackupDir,
			Conns:         connsFn(),
			Index:         idx,
			RecipientPub:  rk.PublicKey,
			RecipientPriv: rk.PrivateKey,
			Progress:      opts.Progress,
		}); err != nil {
			return fmt.Errorf("restore: %w", err)
		}
		fmt.Fprintln(opts.Progress, "restore complete; daemon continuing in reconcile mode")
		reconcileMode := "reconcile"
		modeStr.Store(&reconcileMode)
	}

	scanOpts := ScanOnceOptions{
		BackupDir:    opts.BackupDir,
		Redundancy:   opts.Redundancy,
		Index:        idx,
		RecipientPub: rk.PublicKey,
		ChunkSize:    opts.ChunkSize,
		Progress:     opts.Progress,
	}
	sweep := func() {
		redialMissingPeers(ctx, peerStore, dialer, connSet)
	}
	return runScanLoop(ctx, scanOpts, opts.ScanInterval, serveErrCh, connsFn, sweep, func() {
		lastScanAtNanos.Store(time.Now().UnixNano())
	})
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

// outboundDialer owns the lifecycle of outbound conns: each
// registered conn is added to connSet + reach, has an AcceptStreams
// loop spawned, and is closed on CloseAll.
type outboundDialer struct {
	ctx         context.Context
	priv        ed25519.PrivateKey
	timeout     time.Duration
	st          *store.Store
	annHandler  backup.AnnouncementHandler
	joinHandler backup.JoinHandler
	connSet     *swarm.ConnSet
	reach       *swarm.ReachabilityMap

	mu    sync.Mutex
	conns []*bsquic.Conn
}

// register wires conn into connSet + reach, spawns the AcceptStreams
// loop, and records conn for shutdown close.
func (d *outboundDialer) register(conn *bsquic.Conn, p peers.Peer) {
	d.connSet.Add(conn)
	d.reach.MarkConn(conn, swarm.StateReachable)
	go backup.AcceptStreams(d.ctx, conn, d.st, d.annHandler, d.joinHandler)
	d.mu.Lock()
	d.conns = append(d.conns, conn)
	d.mu.Unlock()
	slog.InfoContext(d.ctx, "dialed peer",
		"peer_addr", p.Addr,
		"peer_pub", hex.EncodeToString(p.PubKey),
		"role", p.Role,
	)
}

// dial bsquic-dials p with the dialer's bounded timeout, marks
// reachability on outcome, and registers a successful conn.
func (d *outboundDialer) dial(ctx context.Context, p peers.Peer) (*bsquic.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	conn, err := bsquic.Dial(dctx, p.Addr, d.priv, p.PubKey, nil)
	if err != nil {
		d.reach.Mark(p.PubKey, swarm.StateUnreachable)
		return nil, err
	}
	d.register(conn, p)
	return conn, nil
}

// CloseAll closes every registered conn and clears the daemon-side
// connSet/reach entries. Idempotent.
func (d *outboundDialer) CloseAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		d.connSet.Remove(c)
		d.reach.MarkConn(c, swarm.StateUnreachable)
		_ = c.Close()
	}
	d.conns = nil
}

// hasConn reports whether the dialer is already tracking a conn for
// the given remote pubkey.
func (d *outboundDialer) hasConn(pub []byte) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		if bytes.Equal(c.RemotePub(), pub) {
			return true
		}
	}
	return false
}

// listDialablePeers returns every peer record with a non-empty Addr.
// Role is not filtered; backup-target selection is separate.
func listDialablePeers(ps *peers.Store) ([]peers.Peer, error) {
	all, err := ps.List()
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	dialable := make([]peers.Peer, 0, len(all))
	for _, p := range all {
		if p.Addr != "" {
			dialable = append(dialable, p)
		}
	}
	return dialable, nil
}

// dialAllPeers dials each known peer best-effort via the dialer.
// Failed dials are logged and skipped. Returns the first dial error
// only when every dial failed.
func dialAllPeers(ctx context.Context, dialer *outboundDialer, known []peers.Peer) error {
	var firstErr error
	successes := 0
	for _, p := range known {
		if _, err := dialer.dial(ctx, p); err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("dial peer %q: %w", p.Addr, err)
			}
			slog.WarnContext(ctx, "dial peer failed",
				"peer_addr", p.Addr,
				"peer_pub", hex.EncodeToString(p.PubKey),
				"err", err)
			continue
		}
		successes++
	}
	if successes == 0 && firstErr != nil {
		return firstErr
	}
	return nil
}

// makeImmediateDialOnApplied returns a Router.OnApplied closure that
// spawns an async dial when shouldImmediateDial selects the announced
// peer.
func makeImmediateDialOnApplied(peerStore *peers.Store, connSet *swarm.ConnSet, dialer *outboundDialer) func(context.Context, protocol.PeerAnnouncement) {
	return func(ctx context.Context, ann protocol.PeerAnnouncement) {
		p, ok := shouldImmediateDial(ann, connSet, peerStore, dialer)
		if !ok {
			return
		}
		go func() {
			if _, err := dialer.dial(ctx, p); err != nil {
				slog.DebugContext(ctx, "immediate dial on announcement failed",
					"peer_addr", p.Addr,
					"peer_pub", hex.EncodeToString(p.PubKey),
					"err", err)
			}
		}()
	}
}

// shouldImmediateDial returns the peer record to dial, ok=true, when
// ann is a PeerJoined with non-empty Addr whose pubkey is in peerStore
// and not already in connSet or dialer.
func shouldImmediateDial(ann protocol.PeerAnnouncement, connSet *swarm.ConnSet, peerStore *peers.Store, dialer *outboundDialer) (peers.Peer, bool) {
	if ann.Kind != protocol.AnnouncePeerJoined {
		return peers.Peer{}, false
	}
	if ann.Addr == "" {
		return peers.Peer{}, false
	}
	pub := ed25519.PublicKey(ann.PubKey[:])
	for _, c := range connSet.Snapshot() {
		if bytes.Equal(c.RemotePub(), pub) {
			return peers.Peer{}, false
		}
	}
	if dialer.hasConn(pub) {
		return peers.Peer{}, false
	}
	p, err := peerStore.Get(pub)
	if err != nil {
		return peers.Peer{}, false
	}
	return p, true
}

// redialMissingPeers dials any peer in peerStore with a non-empty
// Addr not yet in connSet or dialer. Best-effort.
func redialMissingPeers(ctx context.Context, peerStore *peers.Store, dialer *outboundDialer, connSet *swarm.ConnSet) {
	known, err := peerStore.List()
	if err != nil {
		slog.WarnContext(ctx, "redial sweep: list peers", "err", err)
		return
	}
	live := make(map[string]struct{}, len(connSet.Snapshot()))
	for _, c := range connSet.Snapshot() {
		live[hex.EncodeToString(c.RemotePub())] = struct{}{}
	}
	for _, p := range known {
		if p.Addr == "" {
			continue
		}
		if _, ok := live[hex.EncodeToString(p.PubKey)]; ok {
			continue
		}
		if dialer.hasConn(p.PubKey) {
			continue
		}
		if _, err := dialer.dial(ctx, p); err != nil {
			slog.DebugContext(ctx, "redial sweep: dial peer failed",
				"peer_addr", p.Addr,
				"peer_pub", hex.EncodeToString(p.PubKey),
				"err", err)
		}
	}
}

// liveStorageConns returns the subset of connSet whose remote pubkey
// resolves to an IsStorageCandidate role in peerStore. Conns with an
// unknown pubkey or non-storage role are dropped.
func liveStorageConns(connSet *swarm.ConnSet, peerStore *peers.Store) []*bsquic.Conn {
	snapshot := connSet.Snapshot()
	out := make([]*bsquic.Conn, 0, len(snapshot))
	for _, c := range snapshot {
		pub := c.RemotePub()
		if len(pub) == 0 {
			continue
		}
		peer, err := peerStore.Get(ed25519.PublicKey(pub))
		if err != nil {
			continue
		}
		if peer.Role.IsStorageCandidate() {
			out = append(out, c)
		}
	}
	return out
}

// runScanLoop runs ScanOnce every interval until ctx is cancelled or
// serveErrCh fires. Each tick calls sweep, then connsFn for ScanOnce's
// Conns, then onScanSuccess on success.
func runScanLoop(ctx context.Context, opts ScanOnceOptions, interval time.Duration, serveErrCh <-chan error, connsFn func() []*bsquic.Conn, sweep func(), onScanSuccess func()) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	doScan := func() {
		if sweep != nil {
			sweep()
		}
		opts.Conns = connsFn()
		if err := ScanOnce(ctx, opts); err != nil {
			slog.WarnContext(ctx, "scan failed", "err", err)
			fmt.Fprintf(opts.Progress, "scan failed: %v\n", err)
			return
		}
		if onScanSuccess != nil {
			onScanSuccess()
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
func purgeAll(ctx context.Context, idx *index.Index, conns []*bsquic.Conn, progress io.Writer) error {
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
			Conns:    conns,
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

// warnIfOverCap logs a slog warning and writes a progress line when
// used exceeds capacity. capacity == 0 (unlimited) is a no-op.
func warnIfOverCap(ctx context.Context, used, capacity int64, progress io.Writer) {
	if capacity == 0 || used <= capacity {
		return
	}
	overBy := used - capacity
	slog.WarnContext(ctx, "stored bytes exceed configured max-storage; new chunks will be rejected until usage drops",
		"used_bytes", used,
		"max_bytes", capacity,
		"over_by_bytes", overBy,
	)
	fmt.Fprintf(progress, "warning: %d bytes on disk exceeds --max-storage %d (over by %d); new chunks will be rejected until usage drops\n", used, capacity, overBy)
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
