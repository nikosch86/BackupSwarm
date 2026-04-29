package cli

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/daemon"
	"backupswarm/internal/peers"
)

func newPeersCmd(dataDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "peers",
		Short: "List known peers, reachability, and capacity",
		Long: "Show known swarm peers and their state. When the daemon is " +
			"running, the live runtime snapshot drives reachability and " +
			"last-probed remote capacity. When no daemon is running, the " +
			"command falls back to the on-disk peer registry and reports " +
			"identity/role/address only.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}
			return runPeersCmd(dir, cmd.OutOrStdout())
		},
	}
}

func runPeersCmd(dataDir string, out io.Writer) error {
	snap, err := daemon.ReadRuntimeSnapshot(dataDir)
	if err == nil {
		return printPeersFromSnapshot(out, snap)
	}
	if !errors.Is(err, daemon.ErrNoRuntimeSnapshot) {
		return fmt.Errorf("read runtime snapshot: %w", err)
	}
	return printPeersFromStore(out, dataDir)
}

func printPeersFromSnapshot(out io.Writer, snap daemon.RuntimeSnapshot) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE_ID\tROLE\tADDR\tREACH\tCAPACITY")
	for _, p := range snap.Peers {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			shortenHex(p.PubKeyHex),
			emptyDash(p.Role),
			emptyDash(p.Addr),
			p.Reach,
			capacityCell(p.HasCapacity, p.RemoteUsed, p.RemoteMax),
		)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush table: %w", err)
	}
	if !snap.LastScanAt.IsZero() {
		fmt.Fprintf(out, "\nlast scan: %s\n", snap.LastScanAt.UTC().Format(time.RFC3339))
	}
	return nil
}

func printPeersFromStore(out io.Writer, dataDir string) error {
	ps, err := peers.OpenReadOnly(filepath.Join(dataDir, peers.DefaultFilename))
	if err != nil {
		return fmt.Errorf("open peers.db: %w", err)
	}
	defer func() { _ = ps.Close() }()
	list, err := ps.List()
	if err != nil {
		return fmt.Errorf("list peers: %w", err)
	}
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NODE_ID\tROLE\tADDR\tREACH\tCAPACITY")
	for _, p := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			shortenHex(hex.EncodeToString(p.PubKey)),
			p.Role.String(),
			emptyDash(p.Addr),
			"unknown",
			"-",
		)
	}
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush table: %w", err)
	}
	fmt.Fprintln(out, "\n(daemon not running; reachability and capacity unavailable)")
	return nil
}

const shortPubHexLen = 16

func shortenHex(s string) string {
	if len(s) <= shortPubHexLen {
		return s
	}
	return s[:shortPubHexLen]
}

func emptyDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func capacityCell(has bool, used, max int64) string {
	if !has {
		return "-"
	}
	return fmt.Sprintf("%s / %s", formatBytes(used), formatBytesOrUnlimited(max))
}

const (
	kib = int64(1) << 10
	mib = int64(1) << 20
	gib = int64(1) << 30
	tib = int64(1) << 40
)

// formatBytes renders n with a binary-prefix suffix (B/KiB/MiB/GiB/TiB).
func formatBytes(n int64) string {
	switch {
	case n < kib:
		return fmt.Sprintf("%d B", n)
	case n < mib:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(kib))
	case n < gib:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(mib))
	case n < tib:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(gib))
	default:
		return fmt.Sprintf("%.1f TiB", float64(n)/float64(tib))
	}
}

// formatBytesOrUnlimited treats n==0 as the unlimited sentinel.
func formatBytesOrUnlimited(n int64) string {
	if n == 0 {
		return "unlimited"
	}
	return formatBytes(n)
}
