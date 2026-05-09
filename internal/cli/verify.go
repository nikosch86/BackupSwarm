package cli

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"backupswarm/internal/daemon"
	"backupswarm/internal/index"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	"backupswarm/internal/verify"
)

// underReplicatedListCap caps the under-replicated file list in
// human-readable mode; the remainder collapses into a "+N more" line.
const underReplicatedListCap = 20

// missingPeersListCap caps the unreachable-holder list in human mode.
const missingPeersListCap = 20

func newVerifyCmd(dataDir *string) *cobra.Command {
	var redundancy int
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Report owner-side replication health of backed-up chunks",
		Long: "Walk the local index and classify every chunk against " +
			"the configured redundancy target using the daemon's runtime " +
			"snapshot for peer reachability. Reports under-replicated " +
			"files and the unreachable holders blocking healthy " +
			"replication. Falls back to the on-disk peer registry when " +
			"no daemon is running (reachability is reported as 'unknown' " +
			"in that mode — bbolt carries identity, not liveness).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if redundancy < 1 {
				return fmt.Errorf("--redundancy must be >= 1, got %d", redundancy)
			}
			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}
			return runVerifyCmd(dir, redundancy, asJSON, cmd.OutOrStdout())
		},
	}
	cmd.Flags().IntVar(&redundancy, "redundancy", 1, "Replication target each chunk is checked against (must be >= 1)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Emit the full Report as JSON instead of human-readable text")
	return cmd
}

func runVerifyCmd(dataDir string, redundancy int, asJSON bool, out io.Writer) error {
	if _, err := node.Load(dataDir); err != nil {
		return fmt.Errorf("load identity: %w", err)
	}

	snap, snapErr := daemon.ReadRuntimeSnapshot(dataDir)
	if snapErr != nil && !errors.Is(snapErr, daemon.ErrNoRuntimeSnapshot) {
		return fmt.Errorf("read runtime snapshot: %w", snapErr)
	}
	daemonRunning := snapErr == nil

	var reach verify.ReachLookup
	if daemonRunning {
		reach = lookupFromSnapshot(snap)
	} else {
		l, err := lookupFromPeersDB(dataDir)
		if err != nil {
			return err
		}
		reach = l
	}

	entries, err := readIndexEntries(dataDir)
	if err != nil {
		return err
	}

	report := verify.Compute(reach, entries, redundancy)
	if asJSON {
		return writeVerifyJSON(out, report)
	}
	return writeVerifyText(out, report, daemonRunning)
}

// lookupFromSnapshot builds a reachability lookup keyed on hex(pubkey)
// from a runtime snapshot. Peers absent from the snapshot resolve to
// (state="", ok=false).
func lookupFromSnapshot(snap daemon.RuntimeSnapshot) verify.ReachLookup {
	m := make(map[string]string, len(snap.Peers))
	for _, p := range snap.Peers {
		m[p.PubKeyHex] = p.Reach
	}
	return func(hp string) (string, bool) {
		s, ok := m[hp]
		return s, ok
	}
}

// lookupFromPeersDB returns a lookup that resolves every known peer
// to "unknown". A missing peers.db yields a lookup that knows no peers.
func lookupFromPeersDB(dataDir string) (verify.ReachLookup, error) {
	path := filepath.Join(dataDir, peers.DefaultFilename)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return func(string) (string, bool) { return "", false }, nil
	}
	ps, err := peers.OpenReadOnly(path)
	if err != nil {
		return nil, fmt.Errorf("open peers.db: %w", err)
	}
	defer func() { _ = ps.Close() }()
	list, err := ps.List()
	if err != nil {
		return nil, fmt.Errorf("list peers: %w", err)
	}
	known := make(map[string]struct{}, len(list))
	for _, p := range list {
		known[hex.EncodeToString(p.PubKey)] = struct{}{}
	}
	return func(hp string) (string, bool) {
		if _, ok := known[hp]; ok {
			return "unknown", true
		}
		return "", false
	}, nil
}

// readIndexEntries opens index.db read-only and returns its entries;
// a missing index file yields an empty slice.
func readIndexEntries(dataDir string) ([]index.FileEntry, error) {
	path := filepath.Join(dataDir, "index.db")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	idx, err := index.OpenReadOnly(path)
	if err != nil {
		return nil, fmt.Errorf("open index: %w", err)
	}
	defer func() { _ = idx.Close() }()
	entries, err := idx.List()
	if err != nil {
		return nil, fmt.Errorf("list index: %w", err)
	}
	return entries, nil
}

func writeVerifyJSON(out io.Writer, r verify.Report) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}

func writeVerifyText(out io.Writer, r verify.Report, daemonRunning bool) error {
	tw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "redundancy:\t%d\n", r.Redundancy)
	fmt.Fprintf(tw, "total_files:\t%d\n", r.TotalFiles)
	fmt.Fprintf(tw, "total_chunks:\t%d\n", r.TotalChunks)
	fmt.Fprintf(tw, "at_target:\t%d\n", r.AtTarget)
	fmt.Fprintf(tw, "under_replicated:\t%d\n", r.UnderReplicated)
	fmt.Fprintf(tw, "over_replicated:\t%d\n", r.OverReplicated)
	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush totals: %w", err)
	}
	if !daemonRunning {
		fmt.Fprintln(out, "\n(daemon not running; reachability reported as 'unknown' from peers.db)")
	}
	if len(r.UnderReplicatedFiles) > 0 {
		fmt.Fprintln(out, "\nUNDER-REPLICATED FILES")
		ftw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(ftw, "PATH\tCHUNKS_UNDER\tMIN_HEALTHY")
		shown := r.UnderReplicatedFiles
		extra := 0
		if len(shown) > underReplicatedListCap {
			extra = len(shown) - underReplicatedListCap
			shown = shown[:underReplicatedListCap]
		}
		for _, f := range shown {
			fmt.Fprintf(ftw, "%s\t%d\t%d\n", f.Path, f.UnderReplicatedChunks, f.MinHealthy)
		}
		if err := ftw.Flush(); err != nil {
			return fmt.Errorf("flush files: %w", err)
		}
		if extra > 0 {
			fmt.Fprintf(out, "+%d more\n", extra)
		}
	}
	if len(r.MissingPeers) > 0 {
		fmt.Fprintln(out, "\nMISSING PEERS")
		ptw := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
		fmt.Fprintln(ptw, "NODE_ID\tCHUNKS_AFFECTED")
		type kv struct {
			pub    string
			chunks int
		}
		items := make([]kv, 0, len(r.MissingPeers))
		for k, v := range r.MissingPeers {
			items = append(items, kv{pub: k, chunks: v})
		}
		sort.Slice(items, func(i, j int) bool {
			if items[i].chunks != items[j].chunks {
				return items[i].chunks > items[j].chunks
			}
			return items[i].pub < items[j].pub
		})
		shown := items
		extra := 0
		if len(shown) > missingPeersListCap {
			extra = len(shown) - missingPeersListCap
			shown = shown[:missingPeersListCap]
		}
		for _, it := range shown {
			fmt.Fprintf(ptw, "%s\t%d\n", shortenHex(it.pub), it.chunks)
		}
		if err := ptw.Flush(); err != nil {
			return fmt.Errorf("flush peers: %w", err)
		}
		if extra > 0 {
			fmt.Fprintf(out, "+%d more\n", extra)
		}
	}
	return nil
}
