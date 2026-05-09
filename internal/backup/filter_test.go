package backup_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"backupswarm/internal/backup"
)

func TestNewFilter_NilWhenNoRules(t *testing.T) {
	t.Parallel()
	f, err := backup.NewFilter("", nil, nil)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if f != nil {
		t.Fatalf("expected nil filter when no rules supplied")
	}
}

func TestNewFilter_ExcludeOnly(t *testing.T) {
	t.Parallel()
	f, err := backup.NewFilter("", nil, []string{"*.tmp"})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil filter")
	}
	if !f("notes.txt", false) {
		t.Errorf("notes.txt should be included")
	}
	if f("scratch.tmp", false) {
		t.Errorf("scratch.tmp should be excluded by *.tmp")
	}
}

func TestNewFilter_IncludeOnly_DoesNotImplicitlyExcludeOthers(t *testing.T) {
	t.Parallel()
	f, err := backup.NewFilter("", []string{"keep.txt"}, nil)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if !f("keep.txt", false) {
		t.Errorf("keep.txt should be included")
	}
	if !f("anything.txt", false) {
		t.Errorf("anything.txt must still be included; --include is negation, not whitelist")
	}
}

func TestNewFilter_FlagsOverrideBackupIgnore(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".backupignore"), []byte("important.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := backup.NewFilter(dir, []string{"important.txt"}, nil)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if !f("important.txt", false) {
		t.Errorf("--include should override .backupignore exclusion")
	}
}

func TestNewFilter_BackupIgnoreOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := "*.log\n# this is a comment\n\nbuild/\n"
	if err := os.WriteFile(filepath.Join(dir, ".backupignore"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := backup.NewFilter(dir, nil, nil)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if !f("notes.txt", false) {
		t.Errorf("notes.txt should be included")
	}
	if f("server.log", false) {
		t.Errorf("server.log should be excluded by *.log")
	}
	if f("build", true) {
		t.Errorf("build/ should be excluded by dir-anchored pattern")
	}
	if !f("build", false) {
		t.Errorf("dir-anchored 'build/' must not exclude a file named build")
	}
}

func TestNewFilter_MissingBackupIgnoreIsNonFatal(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f, err := backup.NewFilter(dir, nil, []string{"*.tmp"})
	if err != nil {
		t.Fatalf("missing .backupignore should be non-fatal: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil filter from --exclude alone")
	}
}

func TestNewFilter_DoubleStarSubtree(t *testing.T) {
	t.Parallel()
	f, err := backup.NewFilter("", nil, []string{"build/**"})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if !f("src/main.go", false) {
		t.Errorf("src/main.go should be included")
	}
	if f("build/sub/x.tmp", false) {
		t.Errorf("build/sub/x.tmp should be excluded by build/**")
	}
}

func TestNewFilter_NegationInBackupIgnore(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	body := "*.log\n!keep.log\n"
	if err := os.WriteFile(filepath.Join(dir, ".backupignore"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := backup.NewFilter(dir, nil, nil)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if f("server.log", false) == true {
		t.Errorf("server.log should be excluded")
	}
	if !f("keep.log", false) {
		t.Errorf("keep.log should be re-included by !keep.log")
	}
}

func TestNewFilter_FileExcludePlusFlagInclude(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".backupignore"), []byte("*.tmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f, err := backup.NewFilter(dir, []string{"keep.tmp"}, nil)
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if f("scratch.tmp", false) {
		t.Errorf("scratch.tmp should still be excluded by *.tmp")
	}
	if !f("keep.tmp", false) {
		t.Errorf("keep.tmp should be re-included by --include")
	}
}

func TestNewFilter_RejectsEmptyExcludePattern(t *testing.T) {
	t.Parallel()
	_, err := backup.NewFilter("", nil, []string{"foo", ""})
	if err == nil {
		t.Fatal("empty --exclude pattern should error")
	}
}

func TestNewFilter_RejectsEmptyIncludePattern(t *testing.T) {
	t.Parallel()
	_, err := backup.NewFilter("", []string{""}, nil)
	if err == nil {
		t.Fatal("empty --include pattern should error")
	}
}

func TestNewFilter_BackupIgnoreReadErrorPropagates(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("chmod fault-injection skipped as root")
	}
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, ".backupignore")
	if err := os.WriteFile(path, []byte("*.tmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o644) })

	_, err := backup.NewFilter(dir, nil, nil)
	if err == nil {
		t.Fatal("unreadable .backupignore should surface as error")
	}
	if errors.Is(err, os.ErrNotExist) {
		t.Errorf("expected permission error, got ErrNotExist: %v", err)
	}
}

func TestNewFilter_RootAlwaysIncluded(t *testing.T) {
	t.Parallel()
	f, err := backup.NewFilter("", nil, []string{"*"})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if !f(".", true) {
		t.Error("root '.' must always be included regardless of rules")
	}
	if !f("", true) {
		t.Error("empty rel must always be included")
	}
}

func TestNewFilter_ExcludeWithLeadingSlashIsRootAnchored(t *testing.T) {
	t.Parallel()
	f, err := backup.NewFilter("", nil, []string{"/secret.txt"})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if f("secret.txt", false) {
		t.Errorf("/secret.txt should exclude top-level secret.txt")
	}
	if !f("nested/secret.txt", false) {
		t.Errorf("/secret.txt must NOT exclude nested/secret.txt (root-anchored)")
	}
}

func TestNewFilter_FlagIncludeWinsOverFlagExclude(t *testing.T) {
	t.Parallel()
	f, err := backup.NewFilter("", []string{"shared.txt"}, []string{"shared.txt"})
	if err != nil {
		t.Fatalf("NewFilter: %v", err)
	}
	if !f("shared.txt", false) {
		t.Errorf("--include must beat --exclude for the same pattern (include-always-wins composition)")
	}
}

func TestNewFilter_BackupIgnoreAsDirectoryErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".backupignore"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := backup.NewFilter(dir, nil, nil)
	if err == nil {
		t.Fatal(".backupignore as a directory should error")
	}
}

func TestNewFilter_BackupIgnoreFollowsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	target := filepath.Join(dir, "rules.txt")
	if err := os.WriteFile(target, []byte("*.tmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, ".backupignore")); err != nil {
		t.Skip("symlinks unsupported on this platform: " + err.Error())
	}

	f, err := backup.NewFilter(dir, nil, nil)
	if err != nil {
		t.Fatalf("NewFilter via symlinked .backupignore: %v", err)
	}
	if f == nil {
		t.Fatal("expected non-nil filter from symlinked .backupignore")
	}
	if f("scratch.tmp", false) {
		t.Error("symlinked .backupignore rule '*.tmp' should exclude scratch.tmp")
	}
}

func TestNewFilter_BackupIgnoreDanglingSymlinkIsNoOp(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "missing"), filepath.Join(dir, ".backupignore")); err != nil {
		t.Skip("symlinks unsupported on this platform: " + err.Error())
	}

	f, err := backup.NewFilter(dir, nil, nil)
	if err != nil {
		t.Fatalf("dangling symlink should be treated as missing file: %v", err)
	}
	if f != nil {
		t.Error("expected nil filter when only a dangling .backupignore exists")
	}
}
