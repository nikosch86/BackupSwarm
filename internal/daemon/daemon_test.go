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

// TestBackupDirHasRegularFiles asserts the helper's behavior across empty, populated, symlink-only, missing, unreadable, and file-target inputs.
func TestBackupDirHasRegularFiles(t *testing.T) {
	tests := []struct {
		name    string
		setup   func(t *testing.T) (path string, skip bool)
		want    bool
		wantErr bool
	}{
		{
			name: "empty",
			setup: func(t *testing.T) (string, bool) {
				return t.TempDir(), false
			},
		},
		{
			name: "nested regular file",
			setup: func(t *testing.T) (string, bool) {
				dir := t.TempDir()
				nested := filepath.Join(dir, "sub", "nested.txt")
				if err := os.MkdirAll(filepath.Dir(nested), 0o700); err != nil {
					t.Fatalf("mkdir: %v", err)
				}
				if err := os.WriteFile(nested, []byte("hi"), 0o600); err != nil {
					t.Fatalf("write: %v", err)
				}
				return dir, false
			},
			want: true,
		},
		{
			name: "only symlinks",
			setup: func(t *testing.T) (string, bool) {
				dir := t.TempDir()
				target := filepath.Join(t.TempDir(), "target.txt")
				if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
					t.Fatalf("write target: %v", err)
				}
				link := filepath.Join(dir, "link.txt")
				if err := os.Symlink(target, link); err != nil {
					t.Fatalf("symlink: %v", err)
				}
				return dir, false
			},
			want: false,
		},
		{
			name: "missing dir",
			setup: func(t *testing.T) (string, bool) {
				return filepath.Join(t.TempDir(), "does-not-exist"), false
			},
			wantErr: true,
		},
		{
			name: "unreadable subdir",
			setup: func(t *testing.T) (string, bool) {
				if os.Geteuid() == 0 {
					return "", true
				}
				dir := t.TempDir()
				sub := filepath.Join(dir, "locked")
				if err := os.Mkdir(sub, 0o000); err != nil {
					t.Fatalf("mkdir locked: %v", err)
				}
				t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
				return dir, false
			},
			wantErr: true,
		},
		{
			name: "path is regular file",
			setup: func(t *testing.T) (string, bool) {
				path := filepath.Join(t.TempDir(), "file.bin")
				if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
					t.Fatalf("seed: %v", err)
				}
				return path, false
			},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path, skip := tc.setup(t)
			if skip {
				t.Skip("root bypasses POSIX file-permission checks")
			}
			got, err := daemon.BackupDirHasRegularFiles(path)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got nil (got=%v)", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("BackupDirHasRegularFiles: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}
