package cli

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/ca"
	"backupswarm/internal/daemon"
	"backupswarm/internal/nat"
	"backupswarm/internal/node"
	bsquic "backupswarm/internal/quic"
)

// advertiseAddrAuto is the special --advertise-addr / env value triggering
// STUN-based discovery of the externally-routable host.
const advertiseAddrAuto = "auto"

// defaultSTUNServer is queried when --stun-server is omitted.
const defaultSTUNServer = "stun.l.google.com:19302"

// stunResolveTimeout caps the synchronous STUN call done at startup.
const stunResolveTimeout = 10 * time.Second

// cliDiscoverFunc is the test seam for STUN binding requests in CLI commands.
var cliDiscoverFunc = nat.Discover

// listenFunc is the test seam for pre-binding the QUIC listener in the CLI.
var listenFunc = bsquic.Listen

// envInviteToken is the env var read by `run` to auto-join an unjoined node.
const envInviteToken = "BACKUPSWARM_INVITE_TOKEN"

// envAdvertiseAddr is the env var read by `run` and `invite` as a fallback
// when --advertise-addr is omitted.
const envAdvertiseAddr = "BACKUPSWARM_ADVERTISE_ADDR"

// envListenAddr is the env var read by `run` as a fallback when --listen
// is omitted.
const envListenAddr = "BACKUPSWARM_LISTEN"

// envPort is the env var read by `run` as a fallback when --port is omitted.
const envPort = "BACKUPSWARM_PORT"

// defaultPort is the default UDP port for both listen and advertise when
// neither --listen nor --advertise-addr carries an explicit port.
const defaultPort = 7777

// resolveListenAdvertise produces the final listen and advertise host:port
// strings. Bare hosts combine with port; host:port forms pass through;
// "auto" is preserved for downstream STUN resolution.
func resolveListenAdvertise(listenIn, advertiseIn string, port int) (listen, advertise string, err error) {
	portStr := strconv.Itoa(port)
	switch {
	case advertiseIn == advertiseAddrAuto:
		advertise = advertiseAddrAuto
	case advertiseIn != "":
		if _, _, splitErr := net.SplitHostPort(advertiseIn); splitErr == nil {
			advertise = advertiseIn
		} else {
			advertise = net.JoinHostPort(advertiseIn, portStr)
		}
	}

	switch {
	case listenIn == "":
		bindPort := portStr
		if advertise != "" && advertise != advertiseAddrAuto {
			if _, advPort, splitErr := net.SplitHostPort(advertise); splitErr == nil {
				bindPort = advPort
			}
		}
		listen = net.JoinHostPort("0.0.0.0", bindPort)
	default:
		if _, _, splitErr := net.SplitHostPort(listenIn); splitErr == nil {
			listen = listenIn
		} else {
			listen = net.JoinHostPort(listenIn, portStr)
		}
	}
	return listen, advertise, nil
}

func newRunCmd(dataDir *string) *cobra.Command {
	var (
		backupDir           string
		listenAddr          string
		advertiseAddr       string
		port                int
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
		restoreRetryTimeout time.Duration
		restoreRetryBackoff time.Duration
		restore             bool
		purge               bool
		acknowledgeDeletes  bool
		invite              bool
		tokenOut            string
		noCA                bool
		maxStorage          string
		redundancy          int
		stunServer          string
		turnServer          string
		turnUser            string
		turnPass            string
		turnRealm           string
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
			if listenAddr == "" {
				listenAddr = os.Getenv(envListenAddr)
			}
			if !cmd.Flags().Changed("port") {
				if envVal := os.Getenv(envPort); envVal != "" {
					parsed, err := strconv.Atoi(envVal)
					if err != nil {
						return fmt.Errorf("$%s %q: %w", envPort, envVal, err)
					}
					port = parsed
				}
			}
			if port < 0 || port > 65535 {
				return fmt.Errorf("--port out of range [0, 65535]: %d", port)
			}
			isAuto := advertiseAddr == advertiseAddrAuto
			resolvedListen, resolvedAdvertise, err := resolveListenAdvertise(listenAddr, advertiseAddr, port)
			if err != nil {
				return err
			}
			listenAddr = resolvedListen
			advertiseAddr = resolvedAdvertise
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
			maxBytes, noStorage, err := parseMaxStorage(maxStorage)
			if err != nil {
				return fmt.Errorf("--max-storage: %w", err)
			}

			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}

			var preBoundListener *bsquic.Listener
			daemonSTUNServer := ""
			if isAuto {
				resolved, listener, err := resolveAutoAdvertise(cmd.Context(), dir, listenAddr, stunServer)
				if err != nil {
					return err
				}
				advertiseAddr = resolved
				listenAddr = listener.Addr().String()
				preBoundListener = listener
				daemonSTUNServer = stunServer
			}

			if tok := os.Getenv(envInviteToken); tok != "" {
				joinAddr := advertiseAddr
				if joinAddr == "" {
					joinAddr = listenAddr
				}
				if err := maybeAutoJoin(cmd.Context(), dir, tok, joinAddr, dialTimeout); err != nil {
					return err
				}
			}
			if turnServer != "" {
				if turnUser == "" || turnPass == "" || turnRealm == "" {
					return fmt.Errorf("--turn-server requires --turn-user, --turn-pass, and --turn-realm")
				}
			}
			return daemon.Run(cmd.Context(), daemon.Options{
				DataDir:             dir,
				BackupDir:           backupDir,
				ListenAddr:          listenAddr,
				AdvertiseAddr:       advertiseAddr,
				Listener:            preBoundListener,
				STUNServer:          daemonSTUNServer,
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
				RestoreRetryTimeout: restoreRetryTimeout,
				RestoreRetryBackoff: restoreRetryBackoff,
				Restore:             restore,
				Purge:               purge,
				AcknowledgeDeletes:  acknowledgeDeletes,
				IssueInitialInvite:  invite,
				InitialInviteOut:    tokenOut,
				NoCA:                noCA,
				MaxStorageBytes:     maxBytes,
				NoStorage:           noStorage,
				Redundancy:          redundancy,
				Progress:            cmd.OutOrStdout(),
				TURN: daemon.TURNOptions{
					Server:   turnServer,
					Username: turnUser,
					Password: turnPass,
					Realm:    turnRealm,
				},
			})
		},
	}
	cmd.Flags().StringVar(&backupDir, "backup-dir", "", "Directory tree to keep synced to the swarm. Index entries are stored relative to this root. Omit for a pure storage-peer role.")
	cmd.Flags().StringVar(&listenAddr, "listen", "", "Bind host or host:port for the inbound QUIC listener; falls back to $BACKUPSWARM_LISTEN. Bare host (e.g. 0.0.0.0) combines with --port; full host:port overrides --port.")
	cmd.Flags().StringVar(&advertiseAddr, "advertise-addr", "", "Externally-routable host or host:port embedded in invite tokens; falls back to $BACKUPSWARM_ADVERTISE_ADDR. Bare host combines with --port; 'auto' discovers the host via STUN.")
	cmd.Flags().IntVar(&port, "port", defaultPort, "UDP port for both listen and advertise when not embedded in those flags; falls back to $BACKUPSWARM_PORT.")
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
	cmd.Flags().DurationVar(&restoreRetryTimeout, "restore-retry-timeout", 0, "When --restore is set, the maximum total time to retry files whose chunks are unreachable on the first pass (peers may come back online via heartbeat-driven re-dial). 0 disables retries.")
	cmd.Flags().DurationVar(&restoreRetryBackoff, "restore-retry-backoff", time.Second, "Initial backoff between restore retries; doubles up to 30 s")
	cmd.Flags().BoolVar(&purge, "purge", false, "Clear all indexed chunks from the swarm and reset the index (required alternative to --restore when backup-dir empty)")
	cmd.Flags().BoolVar(&acknowledgeDeletes, "acknowledge-deletes", false, "Confirm that indexed files now missing from disk were intentionally deleted; the next scan tick propagates DeleteChunk to peers")
	cmd.Flags().BoolVar(&invite, "invite", false, "Issue an initial invite token at startup; print it to stdout and continue into the daemon")
	cmd.Flags().StringVar(&tokenOut, "token-out", "", "Write the initial invite token to this file (atomic); requires --invite")
	cmd.Flags().BoolVar(&noCA, "no-ca", false, "Skip swarm CA generation; use pubkey-pin trust. Locks the swarm into pin mode for life. Requires --invite.")
	cmd.Flags().StringVar(&maxStorage, "max-storage", "unlimited", "Cap on bytes stored locally for swarm peers; accepts k/m/g/t suffixes (e.g. 10g). 'unlimited' (default) places no cap; 0 disables storage entirely (refuse all chunks for others).")
	cmd.Flags().IntVar(&redundancy, "redundancy", 1, "Number of unique storage peers each chunk is placed on (must be >= 1)")
	cmd.Flags().StringVar(&stunServer, "stun-server", defaultSTUNServer, "host:port of the STUN server queried when --advertise-addr=auto, also used by the periodic refresh loop that broadcasts AddressChanged on detected NAT IP changes")
	cmd.Flags().StringVar(&turnServer, "turn-server", "", "host:port of a TURN server to allocate a relay against at startup; empty disables the relay")
	cmd.Flags().StringVar(&turnUser, "turn-user", "", "Username for the TURN long-term credential (required with --turn-server)")
	cmd.Flags().StringVar(&turnPass, "turn-pass", "", "Password for the TURN long-term credential (required with --turn-server)")
	cmd.Flags().StringVar(&turnRealm, "turn-realm", "", "Realm for the TURN long-term credential (required with --turn-server)")
	return cmd
}

// resolveAutoAdvertise pre-binds the QUIC listener at listenAddr, queries
// stunServer for the externally-routable host, and combines the result
// with the bound port.
func resolveAutoAdvertise(ctx context.Context, dataDir, listenAddr, stunServer string) (string, *bsquic.Listener, error) {
	if stunServer == "" {
		return "", nil, fmt.Errorf("--advertise-addr=auto requires --stun-server")
	}
	id, _, err := node.Ensure(dataDir)
	if err != nil {
		return "", nil, fmt.Errorf("ensure identity: %w", err)
	}
	listener, err := listenFunc(listenAddr, id.PrivateKey, nil, nil)
	if err != nil {
		return "", nil, fmt.Errorf("listen: %w", err)
	}
	_, port, splitErr := net.SplitHostPort(listener.Addr().String())
	if splitErr != nil {
		_ = listener.Close()
		return "", nil, fmt.Errorf("split listen addr: %w", splitErr)
	}
	dctx, cancel := context.WithTimeout(ctx, stunResolveTimeout)
	defer cancel()
	host, err := cliDiscoverFunc(dctx, stunServer)
	if err != nil {
		_ = listener.Close()
		return "", nil, fmt.Errorf("nat: resolve auto advertise: %w", err)
	}
	slog.InfoContext(ctx, "nat: discovered external advertise address",
		"host", host,
		"server", stunServer,
		"port", port,
	)
	return net.JoinHostPort(host, port), listener, nil
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
