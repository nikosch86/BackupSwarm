package daemon

import (
	"context"
	"log/slog"

	"backupswarm/internal/index"
)

// RuntimeOwnBackupSnapshot is the daemon's own-backup totals slice of
// the runtime snapshot.
type RuntimeOwnBackupSnapshot struct {
	Files   int     `json:"files"`
	Bytes   int64   `json:"bytes"`
	Chunks  int     `json:"chunks"`
	ReplMin int     `json:"repl_min"`
	ReplMax int     `json:"repl_max"`
	ReplAvg float64 `json:"repl_avg"`
}

// ComputeOwnBackup aggregates per-file totals and per-chunk replication
// stats from a list of index entries. Empty input returns the zero value.
// A file with no chunks contributes to Files but not to Chunks/Repl*.
func ComputeOwnBackup(entries []index.FileEntry) RuntimeOwnBackupSnapshot {
	var t RuntimeOwnBackupSnapshot
	if len(entries) == 0 {
		return t
	}
	t.Files = len(entries)
	replMin := -1
	var sumPeers int
	for _, e := range entries {
		t.Bytes += e.Size
		for _, c := range e.Chunks {
			t.Chunks++
			r := len(c.Peers)
			if replMin < 0 || r < replMin {
				replMin = r
			}
			if r > t.ReplMax {
				t.ReplMax = r
			}
			sumPeers += r
		}
	}
	if replMin > 0 {
		t.ReplMin = replMin
	}
	if t.Chunks > 0 {
		t.ReplAvg = float64(sumPeers) / float64(t.Chunks)
	}
	return t
}

// ownBackupFromIndex returns a closure that lists the index and
// aggregates totals. List failures log a warn and return the zero value.
func ownBackupFromIndex(ctx context.Context, idx *index.Index) func() RuntimeOwnBackupSnapshot {
	return func() RuntimeOwnBackupSnapshot {
		entries, err := idx.List()
		if err != nil {
			slog.WarnContext(ctx, "list index for snapshot own-backup", "err", err)
			return RuntimeOwnBackupSnapshot{}
		}
		return ComputeOwnBackup(entries)
	}
}
