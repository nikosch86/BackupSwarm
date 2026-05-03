// Package daemon is the sync-daemon runner: a long-running process that is
// both a backup source and a storage peer. Classify picks a startup Mode;
// Run wires it to a QUIC listener and the backup.Serve loop.
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
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/ca"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/nat"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/replication"
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

// ErrRefuseStart is the sentinel returned when indexed files are missing
// from disk and no resolution flag has been supplied.
var ErrRefuseStart = errors.New("indexed files missing from disk; pass --restore, --purge, or --acknowledge-deletes")

// ErrConflictingFlags is returned by Classify when both --restore and --purge are set.
var ErrConflictingFlags = errors.New("--restore and --purge are mutually exclusive")

// Classify returns the Mode the daemon should run in. Refuse-to-start on
// missing-from-disk files is deferred to the per-file gate run after
// Classify.
func Classify(localPopulated, indexPopulated, restore, purge bool) (Mode, error) {
	if restore && purge {
		return 0, ErrConflictingFlags
	}
	if !indexPopulated {
		if localPopulated {
			return ModeFirstBackup, nil
		}
		return ModeIdle, nil
	}
	if restore {
		return ModeRestore, nil
	}
	if purge {
		return ModePurge, nil
	}
	return ModeReconcile, nil
}

// ScanOnceOptions configures a single owner-side scan: back up changed
// files across opts.Conns and prune deleted ones.
type ScanOnceOptions struct {
	// BackupDir is the directory being kept in sync.
	BackupDir string
	// Conns are the live QUIC connections to candidate storage peers.
	Conns []*bsquic.Conn
	// Redundancy is the per-chunk peer count; <=0 defaults to 1.
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
	// DataDir holds identity, recipient keys, index, store, owners db, peers.db.
	DataDir string
	// BackupDir is the user's source-of-truth directory kept in sync.
	BackupDir string
	// ListenAddr is the UDP address for the inbound QUIC listener.
	ListenAddr string
	// AdvertiseAddr is the host:port embedded in invite tokens; empty falls
	// back to the bound listener address.
	AdvertiseAddr string
	// Listener, when non-nil, replaces binding ListenAddr; Run closes it.
	Listener *bsquic.Listener
	// PeerStore, when non-nil, replaces opening <DataDir>/peers.db; Run closes it.
	PeerStore *peers.Store
	// ChunkSize is the target chunk size in bytes.
	ChunkSize int
	// ScanInterval is the period between scan passes. Zero defaults to 60s.
	ScanInterval time.Duration
	// HeartbeatInterval is the period between liveness probes. Zero defaults to 30s.
	HeartbeatInterval time.Duration
	// IndexBackupInterval is the period between index-snapshot uploads. Zero defaults to 5m.
	IndexBackupInterval time.Duration
	// ScrubInterval is the period between chunk-store scrubs. Zero defaults to 6h.
	ScrubInterval time.Duration
	// ChunkTTL is the storage-side lifetime per blob. Zero defaults to 30d.
	ChunkTTL time.Duration
	// RenewInterval is the owner-side cadence for sending RenewTTL. Zero uses ChunkTTL/5.
	RenewInterval time.Duration
	// ExpireInterval is the cadence for sweeping expired blobs. Zero defaults to 1h.
	ExpireInterval time.Duration
	// Restore selects ModeRestore.
	Restore bool
	// RestoreRetryTimeout caps the time spent retrying files whose chunks
	// could not be fetched on the first pass. Zero disables retries.
	RestoreRetryTimeout time.Duration
	// RestoreRetryBackoff is the initial inter-retry sleep; doubles up to
	// 30s. Zero defaults to 1s.
	RestoreRetryBackoff time.Duration
	// Purge selects ModePurge.
	Purge bool
	// AcknowledgeDeletes lets the daemon proceed when indexed files are
	// missing from disk; the next scan tick propagates DeleteChunk to peers.
	AcknowledgeDeletes bool
	// DialTimeout bounds the direct dial step. Zero defaults to 30s.
	DialTimeout time.Duration
	// PunchTimeout bounds the hole-punch fallback step. Zero defaults to 5s.
	PunchTimeout time.Duration
	// TURNDialTimeout bounds the TURN fallback step. Zero defaults to 15s.
	TURNDialTimeout time.Duration
	// IssueInitialInvite issues a token at startup.
	IssueInitialInvite bool
	// InitialInviteOut is the file path the initial invite token is written to.
	InitialInviteOut string
	// NoCA opts the founder into pin-mode trust.
	NoCA bool
	// Progress receives daemon-level progress lines.
	Progress io.Writer
	// Reachability is the peer reachability map; nil allocates one.
	Reachability *swarm.ReachabilityMap
	// MissThreshold is the miss count flipping Suspect to Unreachable.
	MissThreshold int
	// GracePeriod is the time Unreachable before flagged lost.
	GracePeriod time.Duration
	// MaxStorageBytes caps the local chunk store; 0 means unlimited.
	MaxStorageBytes int64
	// NoStorage refuses all incoming PutChunk and reports a saturated capacity probe.
	NoStorage bool
	// Redundancy is the per-chunk peer count used by ScanOnce.
	Redundancy int
	// STUNServer is the host:port of the STUN server queried by the NAT
	// refresh loop. Empty disables the loop entirely.
	STUNServer string
	// NATRefreshInterval is the period between STUN binding requests. Zero
	// defaults to 5 minutes when STUNServer is set.
	NATRefreshInterval time.Duration
	// TURN allocates a relay at startup and holds it for the daemon's
	// lifetime; empty Server disables.
	TURN TURNOptions
	// UploadRateBytes caps outbound bytes/sec across all conns. 0 = unlimited.
	UploadRateBytes int64
	// DownloadRateBytes caps inbound bytes/sec across all conns. 0 = unlimited.
	DownloadRateBytes int64
}

// TURNOptions configures the TURN client. All four fields are required
// when Server is non-empty.
type TURNOptions struct {
	Server   string
	Username string
	Password string
	Realm    string
}

const (
	defaultScanInterval        = 60 * time.Second
	defaultHeartbeatInterval   = 30 * time.Second
	defaultIndexBackupInterval = 5 * time.Minute
	defaultScrubInterval       = 6 * time.Hour
	defaultDialTimeout         = 30 * time.Second
	defaultPunchTimeout        = 5 * time.Second
	defaultTURNDialTimeout     = 15 * time.Second
	defaultGracePeriod         = 24 * time.Hour
	defaultChunkTTL            = 30 * 24 * time.Hour
	defaultExpireInterval      = 1 * time.Hour
	defaultNATRefreshInterval  = 5 * time.Minute

	indexFileName = "index.db"
	storeDirName  = "chunks"
)

// Run is the sync-daemon entrypoint. It opens local state, applies the
// Classify decision, and runs a scan loop, one-shot purge, or idle serve.
// Blocks until ctx is cancelled.
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
	if opts.IndexBackupInterval == 0 {
		opts.IndexBackupInterval = defaultIndexBackupInterval
	}
	if opts.ScrubInterval == 0 {
		opts.ScrubInterval = defaultScrubInterval
	}
	if opts.GracePeriod == 0 {
		opts.GracePeriod = defaultGracePeriod
	}
	if opts.GracePeriod < 0 {
		return fmt.Errorf("grace period must be non-negative, got %v", opts.GracePeriod)
	}
	if opts.ChunkTTL == 0 {
		opts.ChunkTTL = defaultChunkTTL
	}
	if opts.ChunkTTL < 0 {
		return fmt.Errorf("chunk TTL must be non-negative, got %v", opts.ChunkTTL)
	}
	if opts.RenewInterval == 0 {
		opts.RenewInterval = opts.ChunkTTL / 5
		if opts.RenewInterval == 0 {
			opts.RenewInterval = time.Minute
		}
	}
	if opts.RenewInterval < 0 {
		return fmt.Errorf("renew interval must be non-negative, got %v", opts.RenewInterval)
	}
	if opts.ExpireInterval == 0 {
		opts.ExpireInterval = defaultExpireInterval
	}
	if opts.ExpireInterval < 0 {
		return fmt.Errorf("expire interval must be non-negative, got %v", opts.ExpireInterval)
	}
	if opts.DialTimeout == 0 {
		opts.DialTimeout = defaultDialTimeout
	}
	if opts.PunchTimeout == 0 {
		opts.PunchTimeout = defaultPunchTimeout
	}
	if opts.PunchTimeout < 0 {
		return fmt.Errorf("punch timeout must be non-negative, got %v", opts.PunchTimeout)
	}
	if opts.TURNDialTimeout == 0 {
		opts.TURNDialTimeout = defaultTURNDialTimeout
	}
	if opts.TURNDialTimeout < 0 {
		return fmt.Errorf("turn dial timeout must be non-negative, got %v", opts.TURNDialTimeout)
	}
	if opts.NATRefreshInterval < 0 {
		return fmt.Errorf("nat refresh interval must be non-negative, got %v", opts.NATRefreshInterval)
	}
	if opts.STUNServer != "" && opts.NATRefreshInterval == 0 {
		opts.NATRefreshInterval = defaultNATRefreshInterval
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

	st, err := store.NewWithOptions(filepath.Join(opts.DataDir, storeDirName), store.Options{
		MaxBytes:  opts.MaxStorageBytes,
		NoStorage: opts.NoStorage,
		ChunkTTL:  opts.ChunkTTL,
	})
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
		if mode == ModeReconcile {
			missing, err := EnumerateMissingIndexEntries(opts.BackupDir, idx)
			if err != nil {
				return fmt.Errorf("enumerate missing index entries: %w", err)
			}
			mode, err = ResolveMissingFilesGate(GateOptions{
				Missing:            missing,
				Restore:            opts.Restore,
				Purge:              opts.Purge,
				AcknowledgeDeletes: opts.AcknowledgeDeletes,
			})
			if err != nil {
				return err
			}
		}
	}

	pendingInvites := &pendingCache{}
	verifyMember := makeVerifyPeer(peerStore, pendingInvites)

	if opts.UploadRateBytes < 0 {
		return fmt.Errorf("upload rate must be non-negative, got %d", opts.UploadRateBytes)
	}
	if opts.DownloadRateBytes < 0 {
		return fmt.Errorf("download rate must be non-negative, got %d", opts.DownloadRateBytes)
	}
	limiters := buildLimiters(opts.UploadRateBytes, opts.DownloadRateBytes)

	listener := opts.Listener
	if listener == nil {
		listener, err = bsquic.Listen(opts.ListenAddr, id.PrivateKey, verifyMember, nil)
		if err != nil {
			return fmt.Errorf("listen on %q: %w", opts.ListenAddr, err)
		}
	} else {
		listener.SetVerifyPeer(verifyMember)
	}
	listener.SetLimiters(limiters)
	defer func() { _ = listener.Close() }()

	if err := WriteListenAddr(opts.DataDir, listener.Addr().String()); err != nil {
		return fmt.Errorf("write listen.addr: %w", err)
	}
	defer func() { _ = RemoveListenAddr(opts.DataDir) }()

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
		inviteAddr := opts.AdvertiseAddr
		if inviteAddr == "" {
			inviteAddr = listener.Addr().String()
		}
		tokStr, issueErr := IssueInvite(opts.DataDir, inviteAddr, id.PublicKey, caCertDER)
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

	dialer := &outboundDialer{
		ctx:          ctx,
		priv:         id.PrivateKey,
		timeout:      opts.DialTimeout,
		punchTimeout: opts.PunchTimeout,
		turnTimeout:  opts.TURNDialTimeout,
		st:           st,
		annHandler:   router.HandleStream,
		connSet:      connSet,
		reach:        reach,
		limiters:     limiters,
	}
	defer dialer.CloseAll()
	joinHandler := makeJoinHandler(opts.DataDir, peerStore, swarmCA, connSet, dialer)
	dialer.joinHandler = joinHandler
	router.OnApplied = makeImmediateDialOnApplied(peerStore, connSet, dialer)

	punchAdvertise := opts.AdvertiseAddr
	if punchAdvertise == "" {
		punchAdvertise = listener.Addr().String()
	}
	punchOrch := newPunchOrchestrator(ctx, listener, connSet, peerStore, id.PrivateKey, punchAdvertise)
	defer punchOrch.pendingPunches.Wait()
	dialer.punchOrch = punchOrch

	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- backup.Serve(ctx, listener, st, router.HandleStream, joinHandler, punchOrch.handleRequest, punchOrch.handleSignal, obs)
	}()

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

	scrubCtx, scrubCancel := context.WithCancel(ctx)
	var scrubWG sync.WaitGroup
	scrubWG.Add(1)
	go func() {
		defer scrubWG.Done()
		runScrubLoop(scrubCtx, scrubLoopOptions{
			interval: opts.ScrubInterval,
			scrubFn:  st.Scrub,
		})
	}()
	defer scrubWG.Wait()
	defer scrubCancel()

	expireCtx, expireCancel := context.WithCancel(ctx)
	var expireWG sync.WaitGroup
	expireWG.Add(1)
	go func() {
		defer expireWG.Done()
		runExpireLoop(expireCtx, expireLoopOptions{
			interval: opts.ExpireInterval,
			expireFn: st.ExpireSweep,
		})
	}()
	defer expireWG.Wait()
	defer expireCancel()

	ibCtx, ibCancel := context.WithCancel(ctx)
	var ibWG sync.WaitGroup
	if opts.BackupDir != "" {
		ibWG.Add(1)
		go func() {
			defer ibWG.Done()
			runIndexBackupLoop(ibCtx, indexBackupLoopOptions{
				interval:     opts.IndexBackupInterval,
				connsFn:      func() []*bsquic.Conn { return liveStorageConns(connSet, peerStore) },
				indexFn:      func() *index.Index { return idx },
				recipientPub: rk.PublicKey,
			})
		}()
	}
	defer ibWG.Wait()
	defer ibCancel()

	renewCtx, renewCancel := context.WithCancel(ctx)
	var renewWG sync.WaitGroup
	if opts.BackupDir != "" {
		renewWG.Add(1)
		go func() {
			defer renewWG.Done()
			runRenewLoop(renewCtx, renewLoopOptions{
				interval: opts.RenewInterval,
				renewFn:  renewClosure(idx, func() []*bsquic.Conn { return liveStorageConns(connSet, peerStore) }),
			})
		}()
	}
	defer renewWG.Wait()
	defer renewCancel()

	cleanupCtx, cleanupCancel := context.WithCancel(ctx)
	var cleanupWG sync.WaitGroup
	if opts.BackupDir != "" {
		cleanupCh := make(chan []byte, defaultCleanupChannelDepth)
		cleanupWG.Add(1)
		go func() {
			defer cleanupWG.Done()
			runCleanupLoop(cleanupCtx, cleanupLoopOptions{
				ch:      cleanupCh,
				cleanFn: makeCleanupFn(idx, connSet, opts.Redundancy, opts.Progress),
			})
		}()
		reach.SetOnRecover(makeRecoverDispatcher(cleanupCh))
	}
	defer cleanupWG.Wait()
	defer cleanupCancel()

	natCtx, natCancel := context.WithCancel(ctx)
	defer natCancel()
	var natWG sync.WaitGroup
	defer natWG.Wait()
	if opts.TURN.Server != "" {
		alloc, err := turnAllocateFunc(ctx, nat.TURNConfig(opts.TURN))
		if err != nil {
			return fmt.Errorf("turn allocate: %w", err)
		}
		slog.InfoContext(ctx, "nat: turn relay allocated",
			"server", opts.TURN.Server,
			"relay_addr", alloc.RelayAddr().String(),
		)
		defer func() { _ = alloc.Close() }()
		dialer.turnPC = alloc.PacketConn()
	}

	if opts.STUNServer != "" {
		host, port, splitErr := net.SplitHostPort(opts.AdvertiseAddr)
		if splitErr != nil {
			_, port, splitErr = net.SplitHostPort(listener.Addr().String())
			if splitErr != nil {
				return fmt.Errorf("nat loop: split listen addr: %w", splitErr)
			}
			host = ""
		}
		natWG.Add(1)
		go func() {
			defer natWG.Done()
			runNATLoop(natCtx, natLoopOptions{
				server:      opts.STUNServer,
				interval:    opts.NATRefreshInterval,
				perProbe:    perProbeTimeout(opts.NATRefreshInterval),
				port:        port,
				pub:         id.PublicKey,
				initialHost: host,
				connsFn:     connSet.Snapshot,
			})
		}()
	}

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

	if len(dialablePeers) > 0 {
		if err := dialAllPeers(ctx, dialer, dialablePeers); err != nil {
			return err
		}
	}

	connsFn := func() []*bsquic.Conn {
		return liveStorageConns(connSet, peerStore)
	}
	// Restore and purge are one-shots that need a storage peer immediately;
	// first-backup and reconcile enter the scan loop and pick up joiners
	// from the inbound listener on the next tick.
	if (mode == ModeRestore || mode == ModePurge) && len(connsFn()) == 0 {
		return waitForServe(ctx, serveErrCh)
	}

	switch mode {
	case ModePurge:
		if err := purgeAll(ctx, idx, connsFn(), opts.Progress); err != nil {
			return fmt.Errorf("purge: %w", err)
		}
		fmt.Fprintln(opts.Progress, "purge complete; daemon continuing in idle mode")
		idleMode := "idle"
		modeStr.Store(&idleMode)
	case ModeRestore:
		var redial func(context.Context) ([]*bsquic.Conn, error)
		if opts.RestoreRetryTimeout > 0 {
			redial = func(rctx context.Context) ([]*bsquic.Conn, error) {
				redialMissingPeers(rctx, peerStore, dialer, connSet)
				return connsFn(), nil
			}
		}
		if err := restore.Run(ctx, restore.Options{
			Dest:          opts.BackupDir,
			Conns:         connsFn(),
			Index:         idx,
			RecipientPub:  rk.PublicKey,
			RecipientPriv: rk.PrivateKey,
			Progress:      opts.Progress,
			RetryTimeout:  opts.RestoreRetryTimeout,
			RetryBackoff:  opts.RestoreRetryBackoff,
			Redial:        redial,
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
		replicateOnce(ctx, idx, connsFn(), reach, opts.Redundancy, opts.Progress)
	})
}

// replicateOnce runs one re-replication sweep against the live storage
// conns. Best-effort; errors log and return.
func replicateOnce(ctx context.Context, idx *index.Index, conns []*bsquic.Conn, reach *swarm.ReachabilityMap, redundancy int, progress io.Writer) {
	if redundancy <= 0 || idx == nil || reach == nil {
		return
	}
	if err := replication.Run(ctx, replication.RunOptions{
		Index:      idx,
		Conns:      toReplicationConns(conns),
		LostFn:     reach.IsLost,
		Redundancy: redundancy,
		Progress:   progress,
	}); err != nil {
		slog.WarnContext(ctx, "replication sweep failed", "err", err)
	}
}

// toReplicationConns lifts each *bsquic.Conn into the replication.Conn
// interface slice the package consumes.
func toReplicationConns(conns []*bsquic.Conn) []replication.Conn {
	repConns := make([]replication.Conn, len(conns))
	for i, c := range conns {
		repConns[i] = c
	}
	return repConns
}

// waitForServe blocks until ctx is cancelled or Serve surfaces an error.
func waitForServe(ctx context.Context, serveErrCh <-chan error) error {
	select {
	case <-ctx.Done():
		return nil
	case err := <-serveErrCh:
		return err
	}
}

// outboundDialer owns the lifecycle of outbound conns.
type outboundDialer struct {
	ctx         context.Context
	priv        ed25519.PrivateKey
	timeout     time.Duration
	st          *store.Store
	annHandler  backup.AnnouncementHandler
	joinHandler backup.JoinHandler
	connSet     *swarm.ConnSet
	reach       *swarm.ReachabilityMap
	limiters    bsquic.Limiters

	// punchTimeout / turnTimeout bound the hole-punch and TURN steps of
	// the fallback chain; punchOrch / turnPC enable each step. Set
	// post-construction by the daemon once those subsystems are ready.
	punchTimeout time.Duration
	turnTimeout  time.Duration
	punchOrch    *punchOrchestrator
	turnPC       net.PacketConn

	mu    sync.Mutex
	conns []*bsquic.Conn
}

// register wires conn into connSet+reach and spawns AcceptStreams.
func (d *outboundDialer) register(conn *bsquic.Conn, p peers.Peer, method chainMethod) {
	conn.SetLimiters(d.limiters)
	d.connSet.Add(conn)
	d.reach.MarkConn(conn, swarm.StateReachable)
	go backup.AcceptStreams(d.ctx, conn, d.st, d.annHandler, d.joinHandler, nil, nil)
	d.mu.Lock()
	d.conns = append(d.conns, conn)
	d.mu.Unlock()
	slog.InfoContext(d.ctx, "peer connected",
		"method", string(method),
		"peer_addr", p.Addr,
		"peer_pub", hex.EncodeToString(p.PubKey),
		"role", p.Role,
	)
}

// dial runs the direct → hole-punch → TURN fallback chain, marks
// reachability, and registers the resulting conn.
func (d *outboundDialer) dial(ctx context.Context, p peers.Peer) (*bsquic.Conn, error) {
	slog.DebugContext(ctx, "outbound dial: enter",
		"peer_pub", hex.EncodeToString(p.PubKey),
		"peer_addr", p.Addr,
		"role", p.Role,
	)
	conn, method, err := chainDial(ctx, chainDialOptions{
		target:        p,
		priv:          d.priv,
		directTimeout: d.timeout,
		punchTimeout:  d.punchTimeout,
		turnTimeout:   d.turnTimeout,
		punchOrch:     d.punchOrch,
		turnPC:        d.turnPC,
		connSet:       d.connSet,
	})
	if err != nil {
		d.reach.Mark(p.PubKey, swarm.StateUnreachable)
		slog.DebugContext(ctx, "outbound dial: chain failed",
			"peer_pub", hex.EncodeToString(p.PubKey),
			"peer_addr", p.Addr,
			"err", err,
		)
		return nil, err
	}
	d.register(conn, p, method)
	return conn, nil
}

// CloseAll closes every registered conn and clears connSet/reach entries.
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

// hasConn reports whether the dialer tracks a conn for pub.
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

// dialAllPeers dials each known peer best-effort.
// Returns the first error only when every dial failed.
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
// spawns an async dial for each shouldImmediateDial-selected peer.
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

// shouldImmediateDial returns the peer record to dial when ann is a
// PeerJoined for a known peer not yet in connSet or dialer.
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

// redialMissingPeers dials any peer not yet in connSet or dialer.
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
			slog.WarnContext(ctx, "redial sweep: dial peer failed",
				"peer_addr", p.Addr,
				"peer_pub", hex.EncodeToString(p.PubKey),
				"err", err)
		}
	}
}

// liveStorageConns returns the storage-candidate subset of connSet.
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

// runScanLoop runs ScanOnce every interval; each tick runs sweep, refreshes
// Conns, and runs onScanSuccess on success.
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

// purgeAll sends DeleteChunk for every chunk of every index entry, then
// clears the index.
func purgeAll(ctx context.Context, idx *index.Index, conns []*bsquic.Conn, progress io.Writer) error {
	entries, err := idx.List()
	if err != nil {
		return fmt.Errorf("list index: %w", err)
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
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

// warnIfOverCap warns when used exceeds capacity; capacity 0 is a no-op.
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

// BackupDirHasRegularFiles returns true once a regular file is found in dir.
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
