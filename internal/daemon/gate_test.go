package daemon_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backupswarm/internal/daemon"
	"backupswarm/internal/index"
)

func TestEnumerateMissingIndexEntries(t *testing.T) {
	t.Run("empty index returns nothing", func(t *testing.T) {
		root := t.TempDir()
		ix, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		t.Cleanup(func() { _ = ix.Close() })

		got, err := daemon.EnumerateMissingIndexEntries(root, ix)
		if err != nil {
			t.Fatalf("enumerate: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})

	t.Run("all files present returns nothing", func(t *testing.T) {
		root := t.TempDir()
		seedFile(t, root, "a.txt", "hi")
		seedFile(t, root, "sub/b.txt", "bye")

		ix := openSeededIndex(t, "a.txt", "sub/b.txt")
		got, err := daemon.EnumerateMissingIndexEntries(root, ix)
		if err != nil {
			t.Fatalf("enumerate: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})

	t.Run("mix of present and missing returns only missing", func(t *testing.T) {
		root := t.TempDir()
		seedFile(t, root, "kept.txt", "x")

		ix := openSeededIndex(t, "kept.txt", "gone.txt", "sub/also-gone.bin")
		got, err := daemon.EnumerateMissingIndexEntries(root, ix)
		if err != nil {
			t.Fatalf("enumerate: %v", err)
		}
		want := []string{"gone.txt", "sub/also-gone.bin"}
		assertSameStrings(t, got, want)
	})

	t.Run("skips absolute and parent-traversal paths", func(t *testing.T) {
		root := t.TempDir()
		ix := openSeededIndex(t, "/etc/passwd", "..", "../escape", "ok-but-missing.bin")
		got, err := daemon.EnumerateMissingIndexEntries(root, ix)
		if err != nil {
			t.Fatalf("enumerate: %v", err)
		}
		want := []string{"ok-but-missing.bin"}
		assertSameStrings(t, got, want)
	})

	t.Run("propagates non-ENOENT stat errors", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("root bypasses POSIX file-permission checks")
		}
		root := t.TempDir()
		locked := filepath.Join(root, "locked")
		if err := os.Mkdir(locked, 0o000); err != nil {
			t.Fatalf("mkdir locked: %v", err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })

		ix := openSeededIndex(t, "locked/inside.bin")
		_, err := daemon.EnumerateMissingIndexEntries(root, ix)
		if err == nil {
			t.Fatal("want non-nil error from stat in unreadable dir")
		}
		if errors.Is(err, os.ErrNotExist) {
			t.Errorf("err = %v, want a permission-class error not ErrNotExist", err)
		}
	})

	t.Run("wraps idx.List error from closed index", func(t *testing.T) {
		ix, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		if err := ix.Close(); err != nil {
			t.Fatalf("close: %v", err)
		}
		_, err = daemon.EnumerateMissingIndexEntries(t.TempDir(), ix)
		if err == nil {
			t.Fatal("want error from List on closed index")
		}
		if !strings.Contains(err.Error(), "index list") {
			t.Errorf("err = %v, want wrap prefix \"index list\"", err)
		}
	})
}

func TestResolveMissingFilesGate(t *testing.T) {
	tests := []struct {
		name      string
		opts      daemon.GateOptions
		want      daemon.Mode
		wantErr   bool
		errSentry error
		errSubstr []string
	}{
		{
			name: "no missing files returns reconcile",
			opts: daemon.GateOptions{Missing: nil},
			want: daemon.ModeReconcile,
		},
		{
			name: "restore flag wins",
			opts: daemon.GateOptions{Missing: []string{"a.txt"}, Restore: true},
			want: daemon.ModeRestore,
		},
		{
			name: "purge flag wins",
			opts: daemon.GateOptions{Missing: []string{"a.txt"}, Purge: true},
			want: daemon.ModePurge,
		},
		{
			name: "acknowledge-deletes flag wins",
			opts: daemon.GateOptions{Missing: []string{"a.txt"}, AcknowledgeDeletes: true},
			want: daemon.ModeReconcile,
		},
		{
			name: "restore+purge conflict",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt"}, Restore: true, Purge: true,
			},
			wantErr: true, errSentry: daemon.ErrConflictingFlags,
		},
		{
			name: "non-tty no flag refuses with helpful message",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt", "b.txt", "c.txt", "d.txt"},
				IsTTY:   func() bool { return false },
			},
			wantErr: true, errSentry: daemon.ErrRefuseStart,
			errSubstr: []string{"4 indexed file(s)", "a.txt", "b.txt", "c.txt", "and 1 more", "--restore", "--purge", "--acknowledge-deletes"},
		},
		{
			name: "non-tty no flag refuses, fewer than three paths shows all",
			opts: daemon.GateOptions{
				Missing: []string{"only.txt"},
				IsTTY:   func() bool { return false },
			},
			wantErr: true, errSentry: daemon.ErrRefuseStart,
			errSubstr: []string{"1 indexed file(s)", "only.txt"},
		},
		{
			name: "tty + r picks restore",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt"},
				IsTTY:   func() bool { return true },
				Stdin:   strings.NewReader("r\n"),
				Prompt:  io.Discard,
			},
			want: daemon.ModeRestore,
		},
		{
			name: "tty + R picks restore (case-insensitive)",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt"},
				IsTTY:   func() bool { return true },
				Stdin:   strings.NewReader("R\n"),
				Prompt:  io.Discard,
			},
			want: daemon.ModeRestore,
		},
		{
			name: "tty + p picks purge",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt"},
				IsTTY:   func() bool { return true },
				Stdin:   strings.NewReader("p\n"),
				Prompt:  io.Discard,
			},
			want: daemon.ModePurge,
		},
		{
			name: "tty + a picks acknowledge",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt"},
				IsTTY:   func() bool { return true },
				Stdin:   strings.NewReader("a\n"),
				Prompt:  io.Discard,
			},
			want: daemon.ModeReconcile,
		},
		{
			name: "tty + q quits",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt"},
				IsTTY:   func() bool { return true },
				Stdin:   strings.NewReader("q\n"),
				Prompt:  io.Discard,
			},
			wantErr: true, errSentry: daemon.ErrRefuseStart,
		},
		{
			name: "tty + EOF quits",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt"},
				IsTTY:   func() bool { return true },
				Stdin:   strings.NewReader(""),
				Prompt:  io.Discard,
			},
			wantErr: true, errSentry: daemon.ErrRefuseStart,
		},
		{
			name: "tty + empty line quits",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt"},
				IsTTY:   func() bool { return true },
				Stdin:   strings.NewReader("\n"),
				Prompt:  io.Discard,
			},
			wantErr: true, errSentry: daemon.ErrRefuseStart,
		},
		{
			name: "tty + unknown then valid",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt"},
				IsTTY:   func() bool { return true },
				Stdin:   strings.NewReader("x\nr\n"),
				Prompt:  io.Discard,
			},
			want: daemon.ModeRestore,
		},
		{
			name: "tty prompt with more than three missing prints overflow line",
			opts: daemon.GateOptions{
				Missing: []string{"a.txt", "b.txt", "c.txt", "d.txt", "e.txt"},
				IsTTY:   func() bool { return true },
				Stdin:   strings.NewReader("p\n"),
				Prompt:  io.Discard,
			},
			want: daemon.ModePurge,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := daemon.ResolveMissingFilesGate(tc.opts)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got mode=%v", got)
				}
				if tc.errSentry != nil && !errors.Is(err, tc.errSentry) {
					t.Errorf("err = %v, want wraps %v", err, tc.errSentry)
				}
				for _, s := range tc.errSubstr {
					if !strings.Contains(err.Error(), s) {
						t.Errorf("err = %q, want substr %q", err, s)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("gate: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func seedFile(t *testing.T, root, rel, body string) {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o700); err != nil {
		t.Fatalf("mkdir %q: %v", filepath.Dir(full), err)
	}
	if err := os.WriteFile(full, []byte(body), 0o600); err != nil {
		t.Fatalf("write %q: %v", full, err)
	}
}

func openSeededIndex(t *testing.T, paths ...string) *index.Index {
	t.Helper()
	ix, err := index.Open(filepath.Join(t.TempDir(), "index.db"))
	if err != nil {
		t.Fatalf("open index: %v", err)
	}
	t.Cleanup(func() { _ = ix.Close() })
	for _, p := range paths {
		if err := ix.Put(index.FileEntry{Path: p, Size: 1}); err != nil {
			t.Fatalf("put %q: %v", p, err)
		}
	}
	return ix
}

func assertSameStrings(t *testing.T, got, want []string) {
	t.Helper()
	gotMap := make(map[string]int, len(got))
	for _, s := range got {
		gotMap[s]++
	}
	wantMap := make(map[string]int, len(want))
	for _, s := range want {
		wantMap[s]++
	}
	for s, n := range wantMap {
		if gotMap[s] != n {
			t.Errorf("%q: got %d, want %d (got=%v)", s, gotMap[s], n, got)
		}
	}
	for s, n := range gotMap {
		if wantMap[s] != n {
			t.Errorf("unexpected %q x%d (got=%v)", s, n, got)
		}
	}
}
