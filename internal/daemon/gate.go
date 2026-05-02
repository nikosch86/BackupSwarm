package daemon

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"backupswarm/internal/index"
)

// EnumerateMissingIndexEntries returns relative paths of indexed files
// absent from disk under root. Absolute and parent-traversal entries are
// skipped to match backup.Prune's path-containment filter.
func EnumerateMissingIndexEntries(root string, idx *index.Index) ([]string, error) {
	entries, err := idx.List()
	if err != nil {
		return nil, fmt.Errorf("index list: %w", err)
	}
	var missing []string
	for _, e := range entries {
		if filepath.IsAbs(e.Path) || e.Path == ".." || strings.HasPrefix(e.Path, ".."+string(filepath.Separator)) {
			continue
		}
		full := filepath.Join(root, e.Path)
		if _, statErr := os.Stat(full); statErr == nil {
			continue
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("stat %q: %w", full, statErr)
		}
		missing = append(missing, e.Path)
	}
	return missing, nil
}

// GateOptions configures ResolveMissingFilesGate.
type GateOptions struct {
	Missing            []string
	Restore            bool
	Purge              bool
	AcknowledgeDeletes bool
	Stdin              io.Reader
	Prompt             io.Writer
	IsTTY              func() bool
}

// ResolveMissingFilesGate maps Missing plus the resolution flags to a Mode.
// Flags win first; with no flag and missing files, prompt on TTY or return
// a refuse error wrapping ErrRefuseStart.
func ResolveMissingFilesGate(opts GateOptions) (Mode, error) {
	if opts.Restore && opts.Purge {
		return 0, ErrConflictingFlags
	}
	if len(opts.Missing) == 0 {
		return ModeReconcile, nil
	}
	if opts.Restore {
		return ModeRestore, nil
	}
	if opts.Purge {
		return ModePurge, nil
	}
	if opts.AcknowledgeDeletes {
		return ModeReconcile, nil
	}
	isTTY := opts.IsTTY
	if isTTY == nil {
		isTTY = stdinIsTTY
	}
	if !isTTY() {
		return 0, refuseError(opts.Missing)
	}
	return promptForChoice(opts)
}

func promptForChoice(opts GateOptions) (Mode, error) {
	stdin := opts.Stdin
	if stdin == nil {
		stdin = os.Stdin
	}
	out := opts.Prompt
	if out == nil {
		out = os.Stderr
	}
	fmt.Fprintf(out, "%d indexed file(s) missing from disk:\n", len(opts.Missing))
	for _, p := range firstN(opts.Missing, 3) {
		fmt.Fprintf(out, "  - %s\n", p)
	}
	if len(opts.Missing) > 3 {
		fmt.Fprintf(out, "  - ... and %d more\n", len(opts.Missing)-3)
	}
	fmt.Fprint(out, "[r]estore from peers / [p]urge / [a]cknowledge deletes / [q]uit? ")

	scanner := bufio.NewScanner(stdin)
	for scanner.Scan() {
		switch strings.ToLower(strings.TrimSpace(scanner.Text())) {
		case "r":
			return ModeRestore, nil
		case "p":
			return ModePurge, nil
		case "a":
			return ModeReconcile, nil
		case "q", "":
			return 0, fmt.Errorf("aborted by operator: %w", ErrRefuseStart)
		}
		fmt.Fprint(out, "[r]estore / [p]urge / [a]cknowledge deletes / [q]uit? ")
	}
	return 0, fmt.Errorf("aborted by operator: %w", ErrRefuseStart)
}

func refuseError(missing []string) error {
	samples := firstN(missing, 3)
	extra := ""
	if len(missing) > 3 {
		extra = fmt.Sprintf(", and %d more", len(missing)-3)
	}
	return fmt.Errorf("%w: %d indexed file(s) missing from disk (e.g. %s%s); pass --restore, --purge, or --acknowledge-deletes",
		ErrRefuseStart, len(missing), strings.Join(samples, ", "), extra)
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func stdinIsTTY() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}
