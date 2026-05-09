package cli

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/ca"
	bsconfig "backupswarm/internal/config"
	"backupswarm/internal/daemon"
	"backupswarm/internal/nat"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/pkg/token"
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

// cliPortMapDiscoverFunc is the test seam for UPnP/NAT-PMP discovery.
var cliPortMapDiscoverFunc = nat.DiscoverPortMapper

// cliPortMapDiscoverTimeout caps the SSDP/NAT-PMP probe at startup.
// goupnp's IGDv2 + IGDv1 SSDP probes each wait the full M-SEARCH MX time
// (~2 s on most networks) before returning collected responses, so the
// budget needs to absorb both plus the NAT-PMP fallthrough probe.
var cliPortMapDiscoverTimeout = 8 * time.Second

// cliPortMapAttemptTimeout caps the initial Map call.
var cliPortMapAttemptTimeout = 5 * time.Second

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

// portMappingAuto and portMappingOff are the accepted --port-mapping values.
const (
	portMappingAuto = "auto"
	portMappingOff  = "off"
)

// defaultPort is the default UDP port for both listen and advertise when
// neither --listen nor --advertise-addr carries an explicit port.
const defaultPort = 7777

// loadConfig reads the explicit --config path, falling back to
// <data-dir>/config.toml when that path exists. It returns the daemon-config
// values resolved against the precedence chain CLI > env > config > default.
func loadConfig(cmd *cobra.Command, dir, explicit string) (bsconfig.Config, error) {
	path := explicit
	if path == "" {
		candidate := filepath.Join(dir, "config.toml")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
		}
	}
	return bsconfig.Resolve(cmd, path)
}

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
		restoreRetryTimeout time.Duration
		restoreRetryBackoff time.Duration
		restore             bool
		purge               bool
		acknowledgeDeletes  bool
		invite              bool
		tokenOut            string
		noCA                bool
		configPath          string
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

			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}

			cfg, err := loadConfig(cmd, dir, configPath)
			if err != nil {
				return err
			}
			explicitLogLevel := cmd.Flags().Changed("log-level") ||
				os.Getenv(LogLevelEnvVar) != "" ||
				cfg.Log.Level != bsconfig.Default().Log.Level
			if explicitLogLevel {
				if level, perr := parseLogLevel(cfg.Log.Level); perr == nil {
					installLogger(cmd.ErrOrStderr(), level)
				}
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
			if cfg.Storage.Redundancy < 1 {
				return fmt.Errorf("--redundancy must be >= 1, got %d", cfg.Storage.Redundancy)
			}
			if cfg.NAT.HeartbeatMisses < 1 {
				return fmt.Errorf("--heartbeat-misses must be >= 1, got %d", cfg.NAT.HeartbeatMisses)
			}
			if cfg.NAT.GracePeriod < 0 {
				return fmt.Errorf("--grace-period must be >= 0, got %v", cfg.NAT.GracePeriod)
			}
			if cfg.Storage.ChunkTTL < 0 {
				return fmt.Errorf("--chunk-ttl must be >= 0, got %v", cfg.Storage.ChunkTTL)
			}
			if cfg.Storage.ChunkRenewInterval < 0 {
				return fmt.Errorf("--chunk-renew-interval must be >= 0, got %v", cfg.Storage.ChunkRenewInterval)
			}
			if cfg.Storage.ChunkExpireInterval < 0 {
				return fmt.Errorf("--chunk-expire-interval must be >= 0, got %v", cfg.Storage.ChunkExpireInterval)
			}
			maxBytes, noStorage, err := parseMaxStorage(cfg.Storage.MaxStorage)
			if err != nil {
				return fmt.Errorf("--max-storage: %w", err)
			}
			uploadRateBytes, err := parseRate(cfg.NAT.UploadRate)
			if err != nil {
				return fmt.Errorf("--upload-rate: %w", err)
			}
			downloadRateBytes, err := parseRate(cfg.NAT.DownloadRate)
			if err != nil {
				return fmt.Errorf("--download-rate: %w", err)
			}

			switch cfg.NAT.PortMapping {
			case portMappingAuto, portMappingOff:
			default:
				return fmt.Errorf("--port-mapping must be %q or %q, got %q", portMappingAuto, portMappingOff, cfg.NAT.PortMapping)
			}

			var preBoundListener *bsquic.Listener
			daemonSTUNServer := ""
			var portMapResult *nat.Mapping
			var portMapper nat.PortMapper
			if isAuto {
				result, err := resolveAutoAdvertise(cmd.Context(), dir, listenAddr, cfg.NAT.STUNServer, cfg.NAT.PortMapping)
				if err != nil {
					return err
				}
				advertiseAddr = result.advertise
				listenAddr = result.listener.Addr().String()
				preBoundListener = result.listener
				daemonSTUNServer = cfg.NAT.STUNServer
				portMapResult = result.mapping
				portMapper = result.mapper
			}

			if tok := os.Getenv(envInviteToken); tok != "" {
				joinAddr := advertiseAddr
				if joinAddr == "" {
					joinAddr = listenAddr
				}
				if err := maybeAutoJoin(cmd.Context(), dir, tok, joinAddr, cfg.NAT.DialTimeout); err != nil {
					return err
				}
			}
			if cfg.TURN.Server != "" {
				if cfg.TURN.User == "" || cfg.TURN.Pass == "" || cfg.TURN.Realm == "" {
					return fmt.Errorf("--turn-server requires --turn-user, --turn-pass, and --turn-realm")
				}
			}
			noShareTURNCreds := false
			switch cfg.TURN.CredShare {
			case "on", "":
			case "off":
				noShareTURNCreds = true
			default:
				return fmt.Errorf("--turn-cred-share must be 'on' or 'off', got %q", cfg.TURN.CredShare)
			}
			return daemon.Run(cmd.Context(), daemon.Options{
				DataDir:             dir,
				BackupDir:           backupDir,
				ListenAddr:          listenAddr,
				AdvertiseAddr:       advertiseAddr,
				Listener:            preBoundListener,
				STUNServer:          daemonSTUNServer,
				ChunkSize:           cfg.Backup.ChunkSize,
				ScanInterval:        cfg.Storage.ScanInterval,
				HeartbeatInterval:   cfg.NAT.HeartbeatInterval,
				IndexBackupInterval: cfg.Storage.IndexBackupInterval,
				ScrubInterval:       cfg.Storage.ScrubInterval,
				ChunkTTL:            cfg.Storage.ChunkTTL,
				RenewInterval:       cfg.Storage.ChunkRenewInterval,
				ExpireInterval:      cfg.Storage.ChunkExpireInterval,
				MissThreshold:       cfg.NAT.HeartbeatMisses,
				GracePeriod:         cfg.NAT.GracePeriod,
				DialTimeout:         cfg.NAT.DialTimeout,
				PunchTimeout:        cfg.NAT.PunchTimeout,
				TURNDialTimeout:     cfg.NAT.TURNDialTimeout,
				RelayDialTimeout:    cfg.NAT.RelayDialTimeout,
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
				UploadRateBytes:     uploadRateBytes,
				DownloadRateBytes:   downloadRateBytes,
				StatsInterval:       cfg.Metrics.StatsInterval,
				BackoffBase:         cfg.NAT.BackoffBase,
				BackoffMax:          cfg.NAT.BackoffMax,
				BackoffJitter:       cfg.NAT.BackoffJitter,
				Redundancy:          cfg.Storage.Redundancy,
				Progress:            cmd.OutOrStdout(),
				TURN: daemon.TURNOptions{
					Server:   cfg.TURN.Server,
					Username: cfg.TURN.User,
					Password: cfg.TURN.Pass,
					Realm:    cfg.TURN.Realm,
				},
				NoShareTURNCreds: noShareTURNCreds,
				PortMapping:      portMapResult,
				PortMapper:       portMapper,
				MetricsAddr:      cfg.Metrics.Addr,
				IncludePatterns:  cfg.Backup.Include,
				ExcludePatterns:  cfg.Backup.Exclude,
				ProgressTrackerFactory: buildProgressFactory(progressOptions{
					stderr:     resolveStderr(cmd.ErrOrStderr()),
					noProgress: cfg.Backup.NoProgress,
					interval:   cfg.Backup.ProgressInterval,
				}),
			})
		},
	}
	def := bsconfig.Default()
	cmd.Flags().StringVar(&backupDir, "backup-dir", "", "Directory tree to keep synced to the swarm. Index entries are stored relative to this root. Omit for a pure storage-peer role.")
	cmd.Flags().StringVar(&listenAddr, "listen", "", "Bind host or host:port for the inbound QUIC listener; falls back to $BACKUPSWARM_LISTEN. Bare host (e.g. 0.0.0.0) combines with --port; full host:port overrides --port.")
	cmd.Flags().StringVar(&advertiseAddr, "advertise-addr", "", "Externally-routable host or host:port embedded in invite tokens; falls back to $BACKUPSWARM_ADVERTISE_ADDR. Bare host combines with --port; 'auto' discovers the host via STUN.")
	cmd.Flags().IntVar(&port, "port", defaultPort, "UDP port for both listen and advertise when not embedded in those flags; falls back to $BACKUPSWARM_PORT.")
	cmd.Flags().Int("chunk-size", def.Backup.ChunkSize, "Target chunk size in bytes (default 1 MiB)")
	cmd.Flags().Duration("scan-interval", def.Storage.ScanInterval, "Period between incremental scan passes")
	cmd.Flags().Duration("heartbeat-interval", def.NAT.HeartbeatInterval, "Period between liveness probes against every live conn")
	cmd.Flags().Duration("index-backup-interval", def.Storage.IndexBackupInterval, "Period between encrypted index-snapshot uploads to live storage peers (storage-only daemons skip)")
	cmd.Flags().Duration("scrub-interval", def.Storage.ScrubInterval, "Period between local chunk-store integrity scrubs (re-hash every blob, remove any whose content no longer matches its name)")
	cmd.Flags().Duration("chunk-ttl", def.Storage.ChunkTTL, "Storage-side lifetime for each PutOwned blob; owner Renew refreshes the deadline. 0 disables TTL safety net.")
	cmd.Flags().Duration("chunk-renew-interval", def.Storage.ChunkRenewInterval, "Cadence at which the owner re-sends RenewTTL for every chunk in the local index")
	cmd.Flags().Duration("chunk-expire-interval", def.Storage.ChunkExpireInterval, "Cadence at which the local store sweeps expired blobs out (storage-peer GC)")
	cmd.Flags().Int("heartbeat-misses", def.NAT.HeartbeatMisses, "Consecutive missed heartbeats required to mark a peer unreachable (must be >= 1)")
	cmd.Flags().Duration("grace-period", def.NAT.GracePeriod, "Duration a peer must stay unreachable before being treated as lost (eligible for re-replication). 0 = lost immediately.")
	cmd.Flags().Duration("dial-timeout", def.NAT.DialTimeout, "Timeout for the direct dial step in the connection fallback chain")
	cmd.Flags().Duration("punch-timeout", def.NAT.PunchTimeout, "Timeout for the hole-punch step in the connection fallback chain")
	cmd.Flags().Duration("turn-dial-timeout", def.NAT.TURNDialTimeout, "Timeout for the TURN-relay step in the connection fallback chain")
	cmd.Flags().Duration("relay-dial-timeout", def.NAT.RelayDialTimeout, "Timeout for the steady-state relay step (peer's advertised RelayAddr) in the connection fallback chain")
	cmd.Flags().BoolVar(&restore, "restore", false, "Restore every indexed file under --backup-dir before the scan loop starts (required when backup-dir is empty but the index is populated)")
	cmd.Flags().DurationVar(&restoreRetryTimeout, "restore-retry-timeout", 0, "When --restore is set, the maximum total time to retry files whose chunks are unreachable on the first pass (peers may come back online via heartbeat-driven re-dial). 0 disables retries.")
	cmd.Flags().DurationVar(&restoreRetryBackoff, "restore-retry-backoff", time.Second, "Initial backoff between restore retries; doubles up to 30 s")
	cmd.Flags().BoolVar(&purge, "purge", false, "Clear all indexed chunks from the swarm and reset the index (required alternative to --restore when backup-dir empty)")
	cmd.Flags().BoolVar(&acknowledgeDeletes, "acknowledge-deletes", false, "Confirm that indexed files now missing from disk were intentionally deleted; the next scan tick propagates DeleteChunk to peers")
	cmd.Flags().BoolVar(&invite, "invite", false, "Issue an initial invite token at startup; print it to stdout and continue into the daemon")
	cmd.Flags().StringVar(&tokenOut, "token-out", "", "Write the initial invite token to this file (atomic); requires --invite")
	cmd.Flags().BoolVar(&noCA, "no-ca", false, "Skip swarm CA generation; use pubkey-pin trust. Locks the swarm into pin mode for life. Requires --invite.")
	cmd.Flags().String("max-storage", def.Storage.MaxStorage, "Cap on bytes stored locally for swarm peers; accepts k/m/g/t suffixes (e.g. 10g). 'unlimited' (default) places no cap; 0 disables storage entirely (refuse all chunks for others).")
	cmd.Flags().Int("redundancy", def.Storage.Redundancy, "Number of unique storage peers each chunk is placed on (must be >= 1)")
	cmd.Flags().String("stun-server", def.NAT.STUNServer, "host:port of the STUN server queried when --advertise-addr=auto, also used by the periodic refresh loop that broadcasts AddressChanged on detected NAT IP changes")
	cmd.Flags().String("turn-server", def.TURN.Server, "host:port of a TURN server to allocate a relay against at startup; empty disables the relay")
	cmd.Flags().String("turn-user", def.TURN.User, "Username for the TURN long-term credential (required with --turn-server)")
	cmd.Flags().String("turn-pass", def.TURN.Pass, "Password for the TURN long-term credential (required with --turn-server)")
	cmd.Flags().String("turn-realm", def.TURN.Realm, "Realm for the TURN long-term credential (required with --turn-server)")
	cmd.Flags().String("turn-cred-share", def.TURN.CredShare, "Whether the daemon embeds its TURN credentials in issued invite tokens. 'on' (default) shares; 'off' suppresses.")
	cmd.Flags().String("upload-rate", def.NAT.UploadRate, "Cap node-wide outbound bytes/sec across every conn; accepts k/m/g/t suffixes (e.g. 5m). 'unlimited' (default) places no cap.")
	cmd.Flags().String("download-rate", def.NAT.DownloadRate, "Cap node-wide inbound bytes/sec across every conn; accepts k/m/g/t suffixes (e.g. 5m). 'unlimited' (default) places no cap.")
	cmd.Flags().Duration("stats-interval", def.Metrics.StatsInterval, "Cadence for the periodic INFO 'activity' log line (files backed up, chunks stored, average bandwidth). 0 disables.")
	cmd.Flags().Duration("backoff-base", def.NAT.BackoffBase, "Initial delay applied to a peer after a failed dial before the redial sweep retries. Subsequent failures double the delay up to --backoff-max. 0 disables the gate.")
	cmd.Flags().Duration("backoff-max", def.NAT.BackoffMax, "Per-peer cap on the exponential redial backoff. Must be >= --backoff-base when both are set.")
	cmd.Flags().Bool("backoff-jitter", def.NAT.BackoffJitter, "Scale each backoff delay by a random factor in [0.5, 1.0] to avoid synchronized retry storms.")
	cmd.Flags().String("port-mapping", def.NAT.PortMapping, "Acquire a UPnP / NAT-PMP port mapping for the bound port at startup; 'auto' (default) tries the local gateway and refreshes the lease, 'off' disables. The mapped external IP:port is preferred over STUN when --advertise-addr=auto.")
	cmd.Flags().String("metrics-addr", def.Metrics.Addr, "host:port to serve Prometheus metrics on /metrics (e.g. ':9090'); falls back to $BACKUPSWARM_METRICS_ADDR. Empty disables the endpoint.")
	cmd.Flags().StringSlice("exclude", def.Backup.Exclude, "Gitignore-style pattern to exclude from backup (repeatable). Composes with <backup-dir>/.backupignore; flag rules win on overlap.")
	cmd.Flags().StringSlice("include", def.Backup.Include, "Gitignore-style negation pattern that re-includes paths previously excluded (repeatable).")
	cmd.Flags().Bool("no-progress", def.Backup.NoProgress, "Force the structured-log progress emitter even on a TTY (covers CI logs and scripted runs).")
	cmd.Flags().Duration("progress-interval", def.Backup.ProgressInterval, "Cadence for the non-TTY progress 'progress' log line during one-shot phases (first-backup, restore, purge). 0 disables periodic emission; the final line still fires on completion.")
	cmd.Flags().StringVar(&configPath, "config", "", "Path to TOML config file. When unset, defaults to <data-dir>/config.toml when present; missing file is non-fatal.")
	return cmd
}

// autoAdvertiseResult bundles the resolved advertise address with the
// pre-bound listener and (optional) port mapping owned by the daemon.
type autoAdvertiseResult struct {
	advertise string
	listener  *bsquic.Listener
	mapping   *nat.Mapping
	mapper    nat.PortMapper
}

// resolveAutoAdvertise pre-binds the QUIC listener at listenAddr and
// resolves the externally-routable host:port via UPnP/NAT-PMP first
// (when portMapping is "auto"), falling back to STUN (when stunServer
// is set). Returns the resolved address plus the pre-bound listener and
// — if port mapping succeeded — a Mapping/PortMapper pair the daemon
// owns for refresh + Unmap.
func resolveAutoAdvertise(ctx context.Context, dataDir, listenAddr, stunServer, portMapping string) (autoAdvertiseResult, error) {
	id, _, err := node.Ensure(dataDir)
	if err != nil {
		return autoAdvertiseResult{}, fmt.Errorf("ensure identity: %w", err)
	}
	listener, err := listenFunc(listenAddr, id.PrivateKey, nil, nil)
	if err != nil {
		return autoAdvertiseResult{}, fmt.Errorf("listen: %w", err)
	}
	_, portStr, splitErr := net.SplitHostPort(listener.Addr().String())
	if splitErr != nil {
		_ = listener.Close()
		return autoAdvertiseResult{}, fmt.Errorf("split listen addr: %w", splitErr)
	}
	port, convErr := strconv.Atoi(portStr)
	if convErr != nil {
		_ = listener.Close()
		return autoAdvertiseResult{}, fmt.Errorf("parse listen port %q: %w", portStr, convErr)
	}

	if portMapping == portMappingAuto {
		if mapping, mapper, err := tryAcquirePortMapping(ctx, port); err == nil {
			advertise := net.JoinHostPort(mapping.ExternalIP.String(), strconv.Itoa(mapping.ExternalPort))
			slog.InfoContext(ctx, "nat: discovered external advertise address",
				"host", mapping.ExternalIP.String(),
				"port", mapping.ExternalPort,
				"protocol", mapping.Protocol,
				"source", "port-mapping",
			)
			return autoAdvertiseResult{
				advertise: advertise,
				listener:  listener,
				mapping:   &mapping,
				mapper:    mapper,
			}, nil
		} else {
			slog.InfoContext(ctx, "nat: port mapping unavailable; falling back to STUN",
				"err", err,
			)
		}
	}

	if stunServer == "" {
		_ = listener.Close()
		return autoAdvertiseResult{}, fmt.Errorf("--advertise-addr=auto requires --stun-server (or a working UPnP/NAT-PMP gateway via --port-mapping=auto)")
	}
	dctx, cancel := context.WithTimeout(ctx, stunResolveTimeout)
	defer cancel()
	host, err := cliDiscoverFunc(dctx, stunServer)
	if err != nil {
		_ = listener.Close()
		return autoAdvertiseResult{}, fmt.Errorf("nat: resolve auto advertise: %w", err)
	}
	slog.InfoContext(ctx, "nat: discovered external advertise address",
		"host", host,
		"server", stunServer,
		"port", portStr,
		"source", "stun",
	)
	return autoAdvertiseResult{
		advertise: net.JoinHostPort(host, portStr),
		listener:  listener,
	}, nil
}

// tryAcquirePortMapping discovers a UPnP / NAT-PMP gateway and acquires a
// Mapping for internalPort. Used by resolveAutoAdvertise.
func tryAcquirePortMapping(ctx context.Context, internalPort int) (nat.Mapping, nat.PortMapper, error) {
	dctx, cancel := context.WithTimeout(ctx, cliPortMapDiscoverTimeout)
	defer cancel()
	mapper, err := cliPortMapDiscoverFunc(dctx)
	if err != nil {
		return nat.Mapping{}, nil, fmt.Errorf("discover: %w", err)
	}
	mctx, mcancel := context.WithTimeout(ctx, cliPortMapAttemptTimeout)
	defer mcancel()
	mapping, err := mapper.Map(mctx, internalPort)
	if err != nil {
		return nat.Mapping{}, nil, fmt.Errorf("map: %w", err)
	}
	return mapping, mapper, nil
}

// peerListContainsPub reports whether any peer in list has pubkey pub.
func peerListContainsPub(list []peers.Peer, pub []byte) bool {
	for _, p := range list {
		if bytes.Equal(p.PubKey, pub) {
			return true
		}
	}
	return false
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
		tok, err := token.Decode(tokStr)
		if err != nil {
			return fmt.Errorf("decode invite token: %w", err)
		}
		if peerListContainsPub(list, tok.Pub) {
			slog.InfoContext(ctx, "auto-join skipped; invite is for current swarm",
				"peer_count", len(list),
				"introducer_pub", hex.EncodeToString(tok.Pub))
			return nil
		}
		return fmt.Errorf("invite is for a different swarm (introducer pub %s not in peers.db); "+
			"clear --data-dir %q to switch swarms or unset %s",
			hex.EncodeToString(tok.Pub), dataDir, envInviteToken)
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
