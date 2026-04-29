package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/daemon"
	"backupswarm/internal/index"
	"backupswarm/internal/node"
)

func newStatusCmd(dataDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show local node identity, storage usage, and quota ratios",
		Long: "Print this node's identity, configured data dir, local " +
			"chunk-store usage, own-backup totals (files, bytes, chunks, " +
			"replication), and the soft-quota ratio of stored-for-others " +
			"vs own-backup-size. When the daemon is running, also reports " +
			"its current mode, listen address, and last successful scan.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}
			return runStatusCmd(dir, cmd.OutOrStdout())
		},
	}
}

func runStatusCmd(dataDir string, out io.Writer) error {
	id, err := node.Load(dataDir)
	if err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	snap, snapErr := daemon.ReadRuntimeSnapshot(dataDir)
	if snapErr != nil && !errors.Is(snapErr, daemon.ErrNoRuntimeSnapshot) {
		return fmt.Errorf("read runtime snapshot: %w", snapErr)
	}
	daemonRunning := snapErr == nil

	own := snap.OwnBackup
	if !daemonRunning {
		own, err = ownBackupFromIndex(dataDir)
		if err != nil {
			return err
		}
	}

	return writeStatus(out, statusReport{
		NodeID:        id.ShortID(),
		DataDir:       dataDir,
		DaemonRunning: daemonRunning,
		DaemonMode:    snap.Mode,
		DaemonListen:  snap.ListenAddr,
		LastScanAt:    snap.LastScanAt,
		StoreUsed:     snap.LocalStore.Used,
		StoreCapacity: snap.LocalStore.Capacity,
		StoreKnown:    daemonRunning,
		OwnFiles:      own.Files,
		OwnBytes:      own.Bytes,
		OwnChunks:     own.Chunks,
		ReplMin:       own.ReplMin,
		ReplMax:       own.ReplMax,
		ReplAvg:       own.ReplAvg,
	})
}

// ownBackupFromIndex aggregates the read-only index into snapshot totals.
func ownBackupFromIndex(dataDir string) (daemon.RuntimeOwnBackupSnapshot, error) {
	idx, err := index.OpenReadOnly(filepath.Join(dataDir, "index.db"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return daemon.RuntimeOwnBackupSnapshot{}, nil
		}
		return daemon.RuntimeOwnBackupSnapshot{}, fmt.Errorf("open index: %w", err)
	}
	defer func() { _ = idx.Close() }()
	entries, err := idx.List()
	if err != nil {
		return daemon.RuntimeOwnBackupSnapshot{}, fmt.Errorf("list index: %w", err)
	}
	return daemon.ComputeOwnBackup(entries), nil
}

type statusReport struct {
	NodeID        string
	DataDir       string
	DaemonRunning bool
	DaemonMode    string
	DaemonListen  string
	LastScanAt    time.Time
	StoreUsed     int64
	StoreCapacity int64
	StoreKnown    bool
	OwnFiles      int
	OwnBytes      int64
	OwnChunks     int
	ReplMin       int
	ReplMax       int
	ReplAvg       float64
}

func writeStatus(w io.Writer, r statusReport) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "node_id:\t%s\n", r.NodeID)
	fmt.Fprintf(tw, "data_dir:\t%s\n", r.DataDir)
	fmt.Fprintln(tw)
	if r.DaemonRunning {
		fmt.Fprintf(tw, "daemon:\trunning\n")
		fmt.Fprintf(tw, "  mode:\t%s\n", r.DaemonMode)
		fmt.Fprintf(tw, "  listen:\t%s\n", r.DaemonListen)
		if r.LastScanAt.IsZero() {
			fmt.Fprintf(tw, "  last_scan:\tnever\n")
		} else {
			fmt.Fprintf(tw, "  last_scan:\t%s\n", r.LastScanAt.UTC().Format(time.RFC3339))
		}
	} else {
		fmt.Fprintf(tw, "daemon:\tnot running\n")
	}
	fmt.Fprintln(tw)
	if r.StoreKnown {
		fmt.Fprintf(tw, "local_store_used:\t%s\n", formatBytes(r.StoreUsed))
		fmt.Fprintf(tw, "local_store_capacity:\t%s\n", formatBytesOrUnlimited(r.StoreCapacity))
		if r.StoreCapacity > 0 {
			fmt.Fprintf(tw, "local_store_available:\t%s\n", formatBytes(r.StoreCapacity-r.StoreUsed))
		}
	} else {
		fmt.Fprintf(tw, "local_store_used:\tunknown (start the daemon to populate)\n")
	}
	fmt.Fprintln(tw)
	fmt.Fprintf(tw, "own_backup_files:\t%d\n", r.OwnFiles)
	fmt.Fprintf(tw, "own_backup_size:\t%s\n", formatBytes(r.OwnBytes))
	fmt.Fprintf(tw, "own_backup_chunks:\t%d\n", r.OwnChunks)
	if r.OwnChunks > 0 {
		fmt.Fprintf(tw, "replication:\tavg %.1f (min %d, max %d)\n", r.ReplAvg, r.ReplMin, r.ReplMax)
	} else {
		fmt.Fprintf(tw, "replication:\t-\n")
	}
	fmt.Fprintln(tw)
	if r.OwnBytes > 0 && r.StoreKnown {
		ratio := float64(r.StoreUsed) / float64(r.OwnBytes)
		fmt.Fprintf(tw, "quota_ratio:\t%.2f (stored_for_others / own_backup)\n", ratio)
	} else {
		fmt.Fprintf(tw, "quota_ratio:\tn/a\n")
	}
	return tw.Flush()
}
