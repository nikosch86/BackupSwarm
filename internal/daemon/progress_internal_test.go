package daemon

import (
	"os"
	"path/filepath"
	"testing"

	"backupswarm/internal/cliprogress"
	"backupswarm/internal/index"
)

// TestBackupDirTotals_CountsFilesAndBytes asserts a basic walk sums
// regular-file count and byte size.
func TestBackupDirTotals_CountsFilesAndBytes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatalf("write a: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o700); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "b.bin"), make([]byte, 4096), 0o600); err != nil {
		t.Fatalf("write b: %v", err)
	}

	totals, err := backupDirTotals(dir, nil)
	if err != nil {
		t.Fatalf("backupDirTotals: %v", err)
	}
	if totals.Files != 2 {
		t.Errorf("Files = %d, want 2", totals.Files)
	}
	if want := int64(5 + 4096); totals.Bytes != want {
		t.Errorf("Bytes = %d, want %d", totals.Bytes, want)
	}
}

// TestBackupDirTotals_FilterExcludesIndividualFile asserts a filter
// rejecting a non-directory regular file omits it from totals while
// keeping its siblings counted.
func TestBackupDirTotals_FilterExcludesIndividualFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatalf("write keep: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skip.tmp"), []byte("skipme"), 0o600); err != nil {
		t.Fatalf("write skip: %v", err)
	}

	filter := func(rel string, isDir bool) bool {
		return rel != "skip.tmp"
	}
	totals, err := backupDirTotals(dir, filter)
	if err != nil {
		t.Fatalf("backupDirTotals: %v", err)
	}
	if totals.Files != 1 {
		t.Errorf("Files = %d, want 1 (skip.tmp excluded)", totals.Files)
	}
	if totals.Bytes != 4 {
		t.Errorf("Bytes = %d, want 4 (only keep.txt)", totals.Bytes)
	}
}

// TestBackupDirTotals_FilterPrunesSubtree asserts a directory-skip
// returned by the filter excludes the entire subtree from totals.
func TestBackupDirTotals_FilterPrunesSubtree(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep.txt"), []byte("keep"), 0o600); err != nil {
		t.Fatalf("write keep: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "build"), 0o700); err != nil {
		t.Fatalf("mkdir build: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "build", "out.bin"), make([]byte, 1024), 0o600); err != nil {
		t.Fatalf("write build/out: %v", err)
	}

	filter := func(rel string, isDir bool) bool {
		return rel != "build"
	}
	totals, err := backupDirTotals(dir, filter)
	if err != nil {
		t.Fatalf("backupDirTotals: %v", err)
	}
	if totals.Files != 1 {
		t.Errorf("Files = %d, want 1 (build/ excluded)", totals.Files)
	}
	if totals.Bytes != 4 {
		t.Errorf("Bytes = %d, want 4 (only keep.txt)", totals.Bytes)
	}
}

// TestBackupDirTotals_EmptyDirReturnsZero asserts an empty backup dir
// reports zero totals (no walk error).
func TestBackupDirTotals_EmptyDirReturnsZero(t *testing.T) {
	totals, err := backupDirTotals(t.TempDir(), nil)
	if err != nil {
		t.Fatalf("backupDirTotals: %v", err)
	}
	if totals != (cliprogress.Totals{}) {
		t.Errorf("expected zero totals, got %+v", totals)
	}
}

// TestBackupDirTotals_EmptyPathReturnsZero asserts an empty dir argument
// short-circuits without attempting to walk.
func TestBackupDirTotals_EmptyPathReturnsZero(t *testing.T) {
	totals, err := backupDirTotals("", nil)
	if err != nil {
		t.Fatalf("backupDirTotals: %v", err)
	}
	if totals != (cliprogress.Totals{}) {
		t.Errorf("expected zero totals, got %+v", totals)
	}
}

// TestBackupDirTotals_NonExistentErrors asserts a missing dir surfaces
// the underlying walk error.
func TestBackupDirTotals_NonExistentErrors(t *testing.T) {
	if _, err := backupDirTotals(filepath.Join(t.TempDir(), "missing"), nil); err == nil {
		t.Fatal("expected error for missing dir")
	}
}

// TestBackupDirTotals_SkipsSymlinks asserts non-regular entries (e.g.
// symlinks) are not counted.
func TestBackupDirTotals_SkipsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	totals, err := backupDirTotals(dir, nil)
	if err != nil {
		t.Fatalf("backupDirTotals: %v", err)
	}
	if totals.Files != 1 {
		t.Errorf("Files = %d, want 1 (symlink skipped)", totals.Files)
	}
}

// TestIndexTotals_SumsEntries asserts indexTotals returns count and total
// plaintext byte size of every index entry.
func TestIndexTotals_SumsEntries(t *testing.T) {
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, "idx.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	for _, e := range []index.FileEntry{
		{Path: "a.txt", Size: 100},
		{Path: "b.bin", Size: 2048},
	} {
		if err := idx.Put(e); err != nil {
			t.Fatalf("Put %q: %v", e.Path, err)
		}
	}

	totals, err := indexTotals(idx)
	if err != nil {
		t.Fatalf("indexTotals: %v", err)
	}
	if totals.Files != 2 {
		t.Errorf("Files = %d, want 2", totals.Files)
	}
	if totals.Bytes != 2148 {
		t.Errorf("Bytes = %d, want 2148", totals.Bytes)
	}
}

// TestIndexTotals_ClosedIndexErrors asserts a closed index surfaces a list error.
func TestIndexTotals_ClosedIndexErrors(t *testing.T) {
	dir := t.TempDir()
	idx, err := index.Open(filepath.Join(dir, "idx.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	if err := idx.Close(); err != nil {
		t.Fatalf("idx.Close: %v", err)
	}
	if _, err := indexTotals(idx); err == nil {
		t.Fatal("expected error from closed index")
	}
}

// fakeTracker captures Add/Done invocations.
type fakeTracker struct {
	adds      []int64
	addsFiles []int
	doneCalls int
}

func (f *fakeTracker) Add(bytes int64, files int) {
	f.adds = append(f.adds, bytes)
	f.addsFiles = append(f.addsFiles, files)
}

func (f *fakeTracker) Done() { f.doneCalls++ }

// TestStartTracker_NilFactoryReturnsNoop asserts a nil factory yields a
// nil callback and a safe-to-call no-op done.
func TestStartTracker_NilFactoryReturnsNoop(t *testing.T) {
	onProgress, done := startTracker(nil, "first-backup", cliprogress.Totals{Files: 1, Bytes: 1})
	if onProgress != nil {
		t.Errorf("expected nil onProgress for nil factory")
	}
	done() // must not panic
}

// TestStartTracker_FactoryReturningNilTrackerNoop asserts a factory that
// returns a nil Tracker degrades the same as a nil factory (defensive).
func TestStartTracker_FactoryReturningNilTrackerNoop(t *testing.T) {
	factory := ProgressTrackerFactory(func(string, cliprogress.Totals) cliprogress.Tracker { return nil })
	onProgress, done := startTracker(factory, "purge", cliprogress.Totals{})
	if onProgress != nil {
		t.Errorf("expected nil onProgress when factory returns nil tracker")
	}
	done() // must not panic
}

// TestStartTracker_PassesPhaseAndTotals asserts factory receives the
// declared phase + totals; Add(bytes, 1) propagates per call; Done fires
// once.
func TestStartTracker_PassesPhaseAndTotals(t *testing.T) {
	var (
		gotPhase  string
		gotTotals cliprogress.Totals
	)
	tr := &fakeTracker{}
	factory := ProgressTrackerFactory(func(phase string, totals cliprogress.Totals) cliprogress.Tracker {
		gotPhase = phase
		gotTotals = totals
		return tr
	})
	onProgress, done := startTracker(factory, "restore", cliprogress.Totals{Files: 5, Bytes: 500})

	if gotPhase != "restore" {
		t.Errorf("phase: got %q, want %q", gotPhase, "restore")
	}
	if gotTotals != (cliprogress.Totals{Files: 5, Bytes: 500}) {
		t.Errorf("totals: got %+v", gotTotals)
	}
	onProgress(100)
	onProgress(200)
	done()
	if got, want := tr.adds, []int64{100, 200}; !sliceEqI64(got, want) {
		t.Errorf("Add calls: got %v, want %v", got, want)
	}
	if got, want := tr.addsFiles, []int{1, 1}; !sliceEqInt(got, want) {
		t.Errorf("Add files: got %v, want %v", got, want)
	}
	if tr.doneCalls != 1 {
		t.Errorf("Done calls = %d, want 1", tr.doneCalls)
	}
}

func sliceEqI64(a, b []int64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func sliceEqInt(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
