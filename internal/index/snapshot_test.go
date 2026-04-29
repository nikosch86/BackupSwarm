package index_test

import (
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/index"
)

func TestMarshalSnapshot_RoundTrip(t *testing.T) {
	entries := []index.FileEntry{
		{
			Path:    "alpha/one.bin",
			Size:    4096,
			ModTime: time.Date(2026, 4, 15, 10, 30, 0, 0, time.UTC),
			Chunks: []index.ChunkRef{
				{
					PlaintextHash:  sha256.Sum256([]byte("p0")),
					CiphertextHash: sha256.Sum256([]byte("c0")),
					Size:           1024,
					Peers:          [][]byte{[]byte("peer-a"), []byte("peer-b")},
				},
			},
		},
		{
			Path:    "beta/two.bin",
			Size:    8192,
			ModTime: time.Date(2026, 4, 16, 11, 45, 0, 0, time.UTC),
			Chunks: []index.ChunkRef{
				{
					PlaintextHash:  sha256.Sum256([]byte("p1")),
					CiphertextHash: sha256.Sum256([]byte("c1")),
					Size:           2048,
					Peers:          [][]byte{[]byte("peer-c")},
				},
			},
		},
	}

	blob, err := index.MarshalSnapshot(entries)
	if err != nil {
		t.Fatalf("MarshalSnapshot: %v", err)
	}
	if len(blob) == 0 {
		t.Fatal("MarshalSnapshot returned empty blob")
	}

	got, err := index.UnmarshalSnapshot(blob)
	if err != nil {
		t.Fatalf("UnmarshalSnapshot: %v", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("got %d entries, want %d", len(got), len(entries))
	}
	for i, want := range entries {
		if got[i].Path != want.Path {
			t.Errorf("entry %d Path = %q, want %q", i, got[i].Path, want.Path)
		}
		if got[i].Size != want.Size {
			t.Errorf("entry %d Size = %d, want %d", i, got[i].Size, want.Size)
		}
		if !got[i].ModTime.Equal(want.ModTime) {
			t.Errorf("entry %d ModTime = %v, want %v", i, got[i].ModTime, want.ModTime)
		}
		if len(got[i].Chunks) != len(want.Chunks) {
			t.Fatalf("entry %d Chunks len = %d, want %d", i, len(got[i].Chunks), len(want.Chunks))
		}
		for j, wc := range want.Chunks {
			gc := got[i].Chunks[j]
			if gc.PlaintextHash != wc.PlaintextHash {
				t.Errorf("entry %d chunk %d PlaintextHash mismatch", i, j)
			}
			if gc.CiphertextHash != wc.CiphertextHash {
				t.Errorf("entry %d chunk %d CiphertextHash mismatch", i, j)
			}
			if gc.Size != wc.Size {
				t.Errorf("entry %d chunk %d Size = %d, want %d", i, j, gc.Size, wc.Size)
			}
			if len(gc.Peers) != len(wc.Peers) {
				t.Fatalf("entry %d chunk %d Peers len = %d, want %d", i, j, len(gc.Peers), len(wc.Peers))
			}
			for k, wp := range wc.Peers {
				if string(gc.Peers[k]) != string(wp) {
					t.Errorf("entry %d chunk %d peer %d = %q, want %q", i, j, k, gc.Peers[k], wp)
				}
			}
		}
	}
}

func TestMarshalSnapshot_EmptyEntries(t *testing.T) {
	blob, err := index.MarshalSnapshot(nil)
	if err != nil {
		t.Fatalf("MarshalSnapshot(nil): %v", err)
	}
	got, err := index.UnmarshalSnapshot(blob)
	if err != nil {
		t.Fatalf("UnmarshalSnapshot: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d entries, want 0", len(got))
	}
}

func TestUnmarshalSnapshot_EmptyBlob(t *testing.T) {
	if _, err := index.UnmarshalSnapshot(nil); err == nil {
		t.Fatal("UnmarshalSnapshot accepted nil blob")
	}
	if _, err := index.UnmarshalSnapshot([]byte{}); err == nil {
		t.Fatal("UnmarshalSnapshot accepted empty blob")
	}
}

func TestUnmarshalSnapshot_VersionMismatch(t *testing.T) {
	entries := []index.FileEntry{{Path: "x"}}
	blob, err := index.MarshalSnapshot(entries)
	if err != nil {
		t.Fatalf("MarshalSnapshot: %v", err)
	}
	// Flip the version byte to an unknown value.
	blob[0] = 0xff
	_, err = index.UnmarshalSnapshot(blob)
	if err == nil {
		t.Fatal("UnmarshalSnapshot accepted unknown version")
	}
	if !errors.Is(err, index.ErrUnknownSnapshotVersion) {
		t.Errorf("err = %v, want wraps ErrUnknownSnapshotVersion", err)
	}
}

func TestUnmarshalSnapshot_TruncatedBody(t *testing.T) {
	entries := []index.FileEntry{{Path: "x", Size: 7}}
	blob, err := index.MarshalSnapshot(entries)
	if err != nil {
		t.Fatalf("MarshalSnapshot: %v", err)
	}
	// Drop the last byte of the gob-encoded body.
	if _, err := index.UnmarshalSnapshot(blob[:len(blob)-1]); err == nil {
		t.Fatal("UnmarshalSnapshot accepted truncated body")
	}
}

func TestApplySnapshot_WritesEntries(t *testing.T) {
	ix := newIndex(t)
	entries := []index.FileEntry{
		makeEntry(t, "one", 1),
		makeEntry(t, "two", 2),
	}
	for i := range entries {
		entries[i].Size = int64(100 + i)
		entries[i].ModTime = time.Date(2026, 4, 17, 9, 0, i, 0, time.UTC)
	}

	if err := index.ApplySnapshot(ix, entries); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}

	for _, want := range entries {
		got, err := ix.Get(want.Path)
		if err != nil {
			t.Fatalf("Get %q: %v", want.Path, err)
		}
		if got.Size != want.Size {
			t.Errorf("entry %q Size = %d, want %d", want.Path, got.Size, want.Size)
		}
		if !got.ModTime.Equal(want.ModTime) {
			t.Errorf("entry %q ModTime = %v, want %v", want.Path, got.ModTime, want.ModTime)
		}
		if len(got.Chunks) != len(want.Chunks) {
			t.Errorf("entry %q Chunks len = %d, want %d", want.Path, len(got.Chunks), len(want.Chunks))
		}
	}
}

// TestApplySnapshot_PutErrorWrapped asserts an underlying ix.Put failure
// from ApplySnapshot is surfaced as a wrapped error mentioning the path.
func TestApplySnapshot_PutErrorWrapped(t *testing.T) {
	ix := newIndex(t)
	if err := ix.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	err := index.ApplySnapshot(ix, []index.FileEntry{{Path: "shut.bin", Size: 1}})
	if err == nil {
		t.Fatal("ApplySnapshot succeeded on closed index")
	}
	if !strings.Contains(err.Error(), "apply snapshot entry") {
		t.Errorf("err = %v, want 'apply snapshot entry' wrap", err)
	}
}

func TestApplySnapshot_OverwritesExisting(t *testing.T) {
	ix := newIndex(t)
	first := makeEntry(t, "shared", 2)
	first.Size = 10
	if err := ix.Put(first); err != nil {
		t.Fatalf("Put first: %v", err)
	}

	second := makeEntry(t, "shared", 5)
	second.Size = 99
	if err := index.ApplySnapshot(ix, []index.FileEntry{second}); err != nil {
		t.Fatalf("ApplySnapshot: %v", err)
	}

	got, err := ix.Get("shared")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Size != 99 {
		t.Errorf("Size = %d, want 99 (overwrite)", got.Size)
	}
	if len(got.Chunks) != 5 {
		t.Errorf("Chunks len = %d, want 5", len(got.Chunks))
	}
}
