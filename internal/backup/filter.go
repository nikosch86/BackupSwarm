package backup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
)

// BackupIgnoreFile is the optional per-root file holding gitignore-style rules.
const BackupIgnoreFile = ".backupignore"

// ErrEmptyPattern is returned by NewFilter when an --include or --exclude flag
// holds a blank pattern.
var ErrEmptyPattern = errors.New("backup: empty include/exclude pattern")

// NewFilter returns a predicate that reports true when an entry should be
// kept; nil means no rules apply. Rule order: .backupignore, --exclude,
// --include (gitignore '!'); last match wins so flag include beats all.
func NewFilter(backupDir string, include, exclude []string) (func(rel string, isDir bool) bool, error) {
	var patterns []gitignore.Pattern

	if backupDir != "" {
		ps, err := loadBackupIgnore(filepath.Join(backupDir, BackupIgnoreFile))
		if err != nil {
			return nil, err
		}
		patterns = append(patterns, ps...)
	}

	for _, p := range exclude {
		if strings.TrimSpace(p) == "" {
			return nil, fmt.Errorf("%w: --exclude", ErrEmptyPattern)
		}
		patterns = append(patterns, gitignore.ParsePattern(p, nil))
	}
	for _, p := range include {
		if strings.TrimSpace(p) == "" {
			return nil, fmt.Errorf("%w: --include", ErrEmptyPattern)
		}
		if !strings.HasPrefix(p, "!") {
			p = "!" + p
		}
		patterns = append(patterns, gitignore.ParsePattern(p, nil))
	}

	if len(patterns) == 0 {
		return nil, nil
	}

	matcher := gitignore.NewMatcher(patterns)
	return func(rel string, isDir bool) bool {
		if rel == "" || rel == "." {
			return true
		}
		comps := strings.Split(filepath.ToSlash(rel), "/")
		return !matcher.Match(comps, isDir)
	}, nil
}

func loadBackupIgnore(path string) ([]gitignore.Pattern, error) {
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("open %q: %w", path, err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("read %q: %w", path, err)
	}
	var patterns []gitignore.Pattern
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimRight(line, "\r")
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		patterns = append(patterns, gitignore.ParsePattern(line, nil))
	}
	return patterns, nil
}
