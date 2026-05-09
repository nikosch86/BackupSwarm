package daemon

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	"backupswarm/internal/cliprogress"
	"backupswarm/internal/index"
)

// ProgressTrackerFactory builds a one-shot progress tracker for a phase
// ("first-backup", "restore", "purge"). Nil disables progress entirely.
type ProgressTrackerFactory func(phase string, totals cliprogress.Totals) cliprogress.Tracker

// backupDirTotals walks dir, applies filter, and returns the count and
// total plaintext byte size of regular files that would be backed up.
// Empty dir returns zero totals; nil filter includes everything.
func backupDirTotals(dir string, filter func(rel string, isDir bool) bool) (cliprogress.Totals, error) {
	if dir == "" {
		return cliprogress.Totals{}, nil
	}
	var totals cliprogress.Totals
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("rel %q under %q: %w", path, dir, err)
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Errorf("walk produced %q outside %q", path, dir)
		}
		if filter != nil && !filter(rel, d.IsDir()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		if !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("info %q: %w", path, err)
		}
		totals.Files++
		totals.Bytes += info.Size()
		return nil
	})
	return totals, err
}

// indexTotals returns the count and total recorded plaintext byte size
// of every entry in idx.
func indexTotals(idx *index.Index) (cliprogress.Totals, error) {
	entries, err := idx.List()
	if err != nil {
		return cliprogress.Totals{}, fmt.Errorf("list index: %w", err)
	}
	var totals cliprogress.Totals
	for _, e := range entries {
		totals.Files++
		totals.Bytes += e.Size
	}
	return totals, nil
}

// startTracker builds a Tracker via factory and returns the per-file
// callback (bytes int64) plus a Done function. Nil factory yields a nil
// callback and a no-op Done so callers can safely defer it unconditionally.
func startTracker(factory ProgressTrackerFactory, phase string, totals cliprogress.Totals) (onProgress func(int64), done func()) {
	if factory == nil {
		return nil, func() {}
	}
	tracker := factory(phase, totals)
	if tracker == nil {
		return nil, func() {}
	}
	return func(b int64) { tracker.Add(b, 1) }, tracker.Done
}
