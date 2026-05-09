// Package verify computes owner-side replication health from index
// entries against a peer-reachability snapshot.
package verify

import (
	"encoding/hex"
	"sort"

	"backupswarm/internal/index"
	"backupswarm/internal/swarm"
)

// ReachLookup returns the snapshot reachability state for a peer keyed
// by hex(pubkey); ok=false when the peer is absent from the snapshot.
type ReachLookup func(hexPub string) (state string, ok bool)

// reachableState is the snapshot value that counts as healthy.
var reachableState = swarm.StateReachable.String()

// FileFinding describes one under-replicated file. MinHealthy is the
// minimum healthy peer count across this file's under-replicated chunks.
type FileFinding struct {
	Path                  string `json:"path"`
	UnderReplicatedChunks int    `json:"under_replicated_chunks"`
	MinHealthy            int    `json:"min_healthy"`
}

// Report is the owner-side health summary.
type Report struct {
	Redundancy           int            `json:"redundancy"`
	TotalFiles           int            `json:"total_files"`
	TotalChunks          int            `json:"total_chunks"`
	AtTarget             int            `json:"at_target_chunks"`
	UnderReplicated      int            `json:"under_replicated_chunks"`
	OverReplicated       int            `json:"over_replicated_chunks"`
	UnderReplicatedFiles []FileFinding  `json:"under_replicated_files,omitempty"`
	MissingPeers         map[string]int `json:"missing_peers,omitempty"`
}

// Compute classifies every chunk in entries against redundancy.
// A peer counts as healthy only when its snapshot state is "reachable".
func Compute(reach ReachLookup, entries []index.FileEntry, redundancy int) Report {
	r := Report{
		Redundancy:   redundancy,
		MissingPeers: map[string]int{},
	}
	if reach == nil {
		reach = func(string) (string, bool) { return "", false }
	}
	type findingAcc struct {
		under int
		min   int
		set   bool
	}
	perFile := map[string]*findingAcc{}
	r.TotalFiles = len(entries)
	for _, e := range entries {
		for _, c := range e.Chunks {
			r.TotalChunks++
			healthy := 0
			seen := make(map[string]struct{}, len(c.Peers))
			unique := 0
			for _, p := range c.Peers {
				hp := hex.EncodeToString(p)
				if _, dup := seen[hp]; dup {
					continue
				}
				seen[hp] = struct{}{}
				unique++
				state, ok := reach(hp)
				if ok && state == reachableState {
					healthy++
					continue
				}
				r.MissingPeers[hp]++
			}
			switch {
			case healthy >= redundancy && unique > redundancy:
				r.OverReplicated++
			case healthy >= redundancy:
				r.AtTarget++
			default:
				r.UnderReplicated++
				acc, ok := perFile[e.Path]
				if !ok {
					acc = &findingAcc{}
					perFile[e.Path] = acc
				}
				acc.under++
				if !acc.set || healthy < acc.min {
					acc.min = healthy
					acc.set = true
				}
			}
		}
	}
	if len(perFile) > 0 {
		paths := make([]string, 0, len(perFile))
		for p := range perFile {
			paths = append(paths, p)
		}
		sort.Strings(paths)
		r.UnderReplicatedFiles = make([]FileFinding, 0, len(paths))
		for _, p := range paths {
			acc := perFile[p]
			r.UnderReplicatedFiles = append(r.UnderReplicatedFiles, FileFinding{
				Path:                  p,
				UnderReplicatedChunks: acc.under,
				MinHealthy:            acc.min,
			})
		}
	}
	if len(r.MissingPeers) == 0 {
		r.MissingPeers = nil
	}
	return r
}
