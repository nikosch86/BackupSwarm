package daemon_test

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"backupswarm/internal/daemon"
)

func TestClassify_AllFourBasicStates(t *testing.T) {
	tests := []struct {
		name       string
		localPop   bool
		indexPop   bool
		restore    bool
		purge      bool
		want       daemon.Mode
		wantErr    bool
		wantSentry error
	}{
		{
			name:     "idle: nothing local, nothing indexed",
			localPop: false, indexPop: false,
			want: daemon.ModeIdle,
		},
		{
			name:     "first-backup: local populated, index empty",
			localPop: true, indexPop: false,
			want: daemon.ModeFirstBackup,
		},
		{
			name:     "reconcile: local and index both populated",
			localPop: true, indexPop: true,
			want: daemon.ModeReconcile,
		},
		{
			name:     "restore: local empty, index populated, --restore",
			localPop: false, indexPop: true, restore: true,
			want: daemon.ModeRestore,
		},
		{
			name:     "purge: local empty, index populated, --purge",
			localPop: false, indexPop: true, purge: true,
			want: daemon.ModePurge,
		},
		{
			name:     "refuse: local empty, index populated, no flag",
			localPop: false, indexPop: true,
			wantErr: true, wantSentry: daemon.ErrRefuseStart,
		},
		{
			name:     "refuse: --restore and --purge both set is a caller error",
			localPop: false, indexPop: true, restore: true, purge: true,
			wantErr: true, wantSentry: daemon.ErrConflictingFlags,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := daemon.Classify(tc.localPop, tc.indexPop, tc.restore, tc.purge)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Classify: want error, got nil")
				}
				if tc.wantSentry != nil && !errors.Is(err, tc.wantSentry) {
					t.Errorf("Classify err = %v, want wraps %v", err, tc.wantSentry)
				}
				return
			}
			if err != nil {
				t.Fatalf("Classify: %v", err)
			}
			if got != tc.want {
				t.Errorf("Classify = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestBackupDirHasRegularFiles_Empty(t *testing.T) {
	dir := t.TempDir()
	got, err := daemon.BackupDirHasRegularFiles(dir)
	if err != nil {
		t.Fatalf("BackupDirHasRegularFiles: %v", err)
	}
	if got {
		t.Error("empty dir reported populated")
	}
}

func TestBackupDirHasRegularFiles_WithNestedFile(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "sub", "nested.txt")
	if err := os.MkdirAll(filepath.Dir(nested), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(nested, []byte("hi"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := daemon.BackupDirHasRegularFiles(dir)
	if err != nil {
		t.Fatalf("BackupDirHasRegularFiles: %v", err)
	}
	if !got {
		t.Error("dir with nested file reported empty")
	}
}

func TestBackupDirHasRegularFiles_OnlySymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	got, err := daemon.BackupDirHasRegularFiles(dir)
	if err != nil {
		t.Fatalf("BackupDirHasRegularFiles: %v", err)
	}
	if got {
		t.Error("dir with only a symlink reported populated (expected false; only regular files count)")
	}
}

func TestBackupDirHasRegularFiles_MissingDir(t *testing.T) {
	// Missing backup dir is an error, not "empty": the daemon should
	// fail loudly rather than silently treat "wrong path" as "nothing
	// to back up."
	_, err := daemon.BackupDirHasRegularFiles(filepath.Join(t.TempDir(), "does-not-exist"))
	if err == nil {
		t.Fatal("BackupDirHasRegularFiles accepted missing path")
	}
}
