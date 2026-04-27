package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/daemon"
)

func newRunCmd(dataDir *string) *cobra.Command {
	var (
		backupDir    string
		listenAddr   string
		chunkSize    int
		scanInterval time.Duration
		dialTimeout  time.Duration
		restore      bool
		purge        bool
		invite       bool
		tokenOut     string
		noCA         bool
		maxStorage   string
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
			if listenAddr == "" {
				return fmt.Errorf("--listen is required")
			}
			if !invite && tokenOut != "" {
				return fmt.Errorf("--token-out requires --invite")
			}
			if !invite && noCA {
				return fmt.Errorf("--no-ca requires --invite")
			}
			maxBytes, err := parseSize(maxStorage)
			if err != nil {
				return fmt.Errorf("--max-storage: %w", err)
			}

			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}
			return daemon.Run(cmd.Context(), daemon.Options{
				DataDir:            dir,
				BackupDir:          backupDir,
				ListenAddr:         listenAddr,
				ChunkSize:          chunkSize,
				ScanInterval:       scanInterval,
				DialTimeout:        dialTimeout,
				Restore:            restore,
				Purge:              purge,
				IssueInitialInvite: invite,
				InitialInviteOut:   tokenOut,
				NoCA:               noCA,
				MaxStorageBytes:    maxBytes,
				Progress:           cmd.OutOrStdout(),
			})
		},
	}
	cmd.Flags().StringVar(&backupDir, "backup-dir", "", "Directory whose contents are kept synced to the swarm (optional; omit for pure storage-peer role)")
	cmd.Flags().StringVar(&listenAddr, "listen", "", "UDP address for the inbound QUIC listener, e.g. 0.0.0.0:7777 (required)")
	cmd.Flags().IntVar(&chunkSize, "chunk-size", 1<<20, "Target chunk size in bytes (default 1 MiB)")
	cmd.Flags().DurationVar(&scanInterval, "scan-interval", 60*time.Second, "Period between incremental scan passes")
	cmd.Flags().DurationVar(&dialTimeout, "dial-timeout", 30*time.Second, "Timeout for the initial dial to the storage peer")
	cmd.Flags().BoolVar(&restore, "restore", false, "Start in restore mode (required if backup-dir empty but index populated)")
	cmd.Flags().BoolVar(&purge, "purge", false, "Clear all indexed chunks from the swarm and reset the index (required alternative to --restore when backup-dir empty)")
	cmd.Flags().BoolVar(&invite, "invite", false, "Issue an initial invite token at startup; print it to stdout and continue into the daemon")
	cmd.Flags().StringVar(&tokenOut, "token-out", "", "Write the initial invite token to this file (atomic); requires --invite")
	cmd.Flags().BoolVar(&noCA, "no-ca", false, "Skip swarm CA generation; use pubkey-pin trust. Locks the swarm into pin mode for life. Requires --invite.")
	cmd.Flags().StringVar(&maxStorage, "max-storage", "0", "Cap on bytes stored locally for swarm peers; accepts k/m/g/t suffixes (e.g. 10g). 0 = unlimited.")
	return cmd
}
