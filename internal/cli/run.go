package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/ca"
	"backupswarm/internal/daemon"
)

// envInviteToken is the env var read by `run` to auto-join an unjoined node.
const envInviteToken = "BACKUPSWARM_INVITE_TOKEN"

// envAdvertiseAddr is the env var read by `run` and `invite` as a fallback
// when --advertise-addr is omitted.
const envAdvertiseAddr = "BACKUPSWARM_ADVERTISE_ADDR"

func newRunCmd(dataDir *string) *cobra.Command {
	var (
		backupDir           string
		listenAddr          string
		advertiseAddr       string
		chunkSize           int
		scanInterval        time.Duration
		heartbeatInterval   time.Duration
		heartbeatMisses     int
		indexBackupInterval time.Duration
		scrubInterval       time.Duration
		chunkTTL            time.Duration
		chunkRenewInterval  time.Duration
		chunkExpireInterval time.Duration
		gracePeriod         time.Duration
		dialTimeout         time.Duration
		restore             bool
		purge               bool
		invite              bool
		tokenOut            string
		noCA                bool
		maxStorage          string
		redundancy          int
	)
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Run the sync daemon (serve chunks for peers and/or back up --backup-dir)",
		Long: "Run the sync daemon. Omit --backup-dir to run as a pure storage peer " +
			"that only serves chunks for others. The storage peer to back up to is read " +
			"from peers.db (populated by `invite`/`join`); no --peer flag is needed. " +
			"--invite issues an initial invite token at startup (auto-generates the " +
			"swarm CA on a fresh data dir unless --no-ca is set); the token is printed " +
			"to stdout and optionally written to --token-out. Subsequent invites against " +
			"this running daemon use the standalone `invite` command.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if advertiseAddr == "" {
				advertiseAddr = os.Getenv(envAdvertiseAddr)
			}
			if advertiseAddr != "" {
				if _, port, err := net.SplitHostPort(advertiseAddr); err != nil {
					return fmt.Errorf("--advertise-addr %q: %w", advertiseAddr, err)
				} else if listenAddr == "" {
					listenAddr = net.JoinHostPort("0.0.0.0", port)
				}
			}
			if listenAddr == "" {
				return fmt.Errorf("--listen is required (or set --advertise-addr)")
			}
			if !invite && tokenOut != "" {
				return fmt.Errorf("--token-out requires --invite")
			}
			if !invite && noCA {
				return fmt.Errorf("--no-ca requires --invite")
			}
			if redundancy < 1 {
				return fmt.Errorf("--redundancy must be >= 1, got %d", redundancy)
			}
			if heartbeatMisses < 1 {
				return fmt.Errorf("--heartbeat-misses must be >= 1, got %d", heartbeatMisses)
			}
			if gracePeriod < 0 {
				return fmt.Errorf("--grace-period must be >= 0, got %v", gracePeriod)
			}
			if chunkTTL < 0 {
				return fmt.Errorf("--chunk-ttl must be >= 0, got %v", chunkTTL)
			}
			if chunkRenewInterval < 0 {
				return fmt.Errorf("--chunk-renew-interval must be >= 0, got %v", chunkRenewInterval)
			}
			if chunkExpireInterval < 0 {
				return fmt.Errorf("--chunk-expire-interval must be >= 0, got %v", chunkExpireInterval)
			}
			maxBytes, err := parseSize(maxStorage)
			if err != nil {
				return fmt.Errorf("--max-storage: %w", err)
			}

			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}
			if tok := os.Getenv(envInviteToken); tok != "" {
				if err := maybeAutoJoin(cmd.Context(), dir, tok, listenAddr, dialTimeout); err != nil {
					return err
				}
			}
			return daemon.Run(cmd.Context(), daemon.Options{
				DataDir:             dir,
				BackupDir:           backupDir,
				ListenAddr:          listenAddr,
				AdvertiseAddr:       advertiseAddr,
				ChunkSize:           chunkSize,
				ScanInterval:        scanInterval,
				HeartbeatInterval:   heartbeatInterval,
				IndexBackupInterval: indexBackupInterval,
				ScrubInterval:       scrubInterval,
				ChunkTTL:            chunkTTL,
				RenewInterval:       chunkRenewInterval,
				ExpireInterval:      chunkExpireInterval,
				MissThreshold:       heartbeatMisses,
				GracePeriod:         gracePeriod,
				DialTimeout:         dialTimeout,
				Restore:             restore,
				Purge:               purge,
				IssueInitialInvite:  invite,
				InitialInviteOut:    tokenOut,
				NoCA:                noCA,
				MaxStorageBytes:     maxBytes,
				Redundancy:          redundancy,
				Progress:            cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVar(&backupDir, "backup-dir", "", "Directory tree to keep synced to the swarm. Index entries are stored relative to this root. Omit for a pure storage-peer role.")
	cmd.Flags().StringVar(&listenAddr, "listen", "", "UDP address for the inbound QUIC listener, e.g. 0.0.0.0:7777 (required unless --advertise-addr is set)")
	cmd.Flags().StringVar(&advertiseAddr, "advertise-addr", "", "Externally-routable host:port to embed in invite tokens; falls back to $BACKUPSWARM_ADVERTISE_ADDR. Defaults --listen to 0.0.0.0:<port> when --listen is empty.")
	cmd.Flags().IntVar(&chunkSize, "chunk-size", 1<<20, "Target chunk size in bytes (default 1 MiB)")
	cmd.Flags().DurationVar(&scanInterval, "scan-interval", 60*time.Second, "Period between incremental scan passes")
	cmd.Flags().DurationVar(&heartbeatInterval, "heartbeat-interval", 30*time.Second, "Period between liveness probes against every live conn")
	cmd.Flags().DurationVar(&indexBackupInterval, "index-backup-interval", 5*time.Minute, "Period between encrypted index-snapshot uploads to live storage peers (storage-only daemons skip)")
	cmd.Flags().DurationVar(&scrubInterval, "scrub-interval", 6*time.Hour, "Period between local chunk-store integrity scrubs (re-hash every blob, remove any whose content no longer matches its name)")
	cmd.Flags().DurationVar(&chunkTTL, "chunk-ttl", 30*24*time.Hour, "Storage-side lifetime for each PutOwned blob; owner Renew refreshes the deadline. 0 disables TTL safety net.")
	cmd.Flags().DurationVar(&chunkRenewInterval, "chunk-renew-interval", 6*24*time.Hour, "Cadence at which the owner re-sends RenewTTL for every chunk in the local index")
	cmd.Flags().DurationVar(&chunkExpireInterval, "chunk-expire-interval", 1*time.Hour, "Cadence at which the local store sweeps expired blobs out (storage-peer GC)")
	cmd.Flags().IntVar(&heartbeatMisses, "heartbeat-misses", 3, "Consecutive missed heartbeats required to mark a peer unreachable (must be >= 1)")
	cmd.Flags().DurationVar(&gracePeriod, "grace-period", 24*time.Hour, "Duration a peer must stay unreachable before being treated as lost (eligible for re-replication). 0 = lost immediately.")
	cmd.Flags().DurationVar(&dialTimeout, "dial-timeout", 30*time.Second, "Timeout for the initial dial to the storage peer")
	cmd.Flags().BoolVar(&restore, "restore", false, "Restore every indexed file under --backup-dir before the scan loop starts (required when backup-dir is empty but the index is populated)")
	cmd.Flags().BoolVar(&purge, "purge", false, "Clear all indexed chunks from the swarm and reset the index (required alternative to --restore when backup-dir empty)")
	cmd.Flags().BoolVar(&invite, "invite", false, "Issue an initial invite token at startup; print it to stdout and continue into the daemon")
	cmd.Flags().StringVar(&tokenOut, "token-out", "", "Write the initial invite token to this file (atomic); requires --invite")
	cmd.Flags().BoolVar(&noCA, "no-ca", false, "Skip swarm CA generation; use pubkey-pin trust. Locks the swarm into pin mode for life. Requires --invite.")
	cmd.Flags().StringVar(&maxStorage, "max-storage", "0", "Cap on bytes stored locally for swarm peers; accepts k/m/g/t suffixes (e.g. 10g). 0 = unlimited.")
	cmd.Flags().IntVar(&redundancy, "redundancy", 1, "Number of unique storage peers each chunk is placed on (must be >= 1)")
	return cmd
}

// maybeAutoJoin runs the bootstrap join handshake when peers.db is empty.
// Idempotent: peers.db with any prior entry skips the handshake.
func maybeAutoJoin(ctx context.Context, dataDir, tokStr, advertisedAddr string, timeout time.Duration) error {
	sess, err := openPeerSession(dataDir)
	if err != nil {
		return err
	}
	defer func() { _ = sess.Close() }()
	list, err := sess.peerStore.List()
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}
	if len(list) > 0 {
		slog.InfoContext(ctx, "auto-join skipped; peers.db already populated",
			"peer_count", len(list))
		return nil
	}
	joinCtx, cancel := withTimeout(ctx, timeout)
	defer cancel()
	result, err := bootstrap.DoJoin(joinCtx, tokStr, sess.id.PrivateKey, advertisedAddr, sess.peerStore)
	if err != nil {
		return fmt.Errorf("auto-join: %w", err)
	}
	if len(result.SignedCert) > 0 {
		if err := ca.SaveNodeCert(sess.dir, result.SignedCert); err != nil {
			return fmt.Errorf("save node cert: %w", err)
		}
	}
	slog.InfoContext(ctx, "auto-joined peer",
		"peer_pub", hex.EncodeToString(result.Introducer.PubKey),
		"peer_addr", result.Introducer.Addr,
		"peer_list_size", len(result.Peers),
		"signed_cert", len(result.SignedCert) > 0,
	)
	return nil
}
