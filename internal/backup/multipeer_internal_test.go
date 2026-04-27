package backup

import (
	"context"
	"errors"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
)

// TestPlaceChunk_WeightedRandomError asserts placeChunk surfaces an
// upstream WeightedRandom failure (here, nil rng) without attempting any
// sends.
func TestPlaceChunk_WeightedRandomError(t *testing.T) {
	pool := []candidate{{conn: nil, available: 1}}
	_, _, err := placeChunk(context.Background(), pool, 1, []byte("blob"), nil)
	if err == nil {
		t.Fatal("placeChunk returned nil with nil rng")
	}
}

// TestBackupFile_ContextCancelled asserts backupFile bails with the
// context error when invoked with an already-cancelled ctx.
func TestBackupFile_ContextCancelled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.bin")
	if err := os.WriteFile(path, []byte("payload"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	idx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	rpub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	opts := RunOptions{
		Path:         path,
		Redundancy:   1,
		RecipientPub: rpub,
		Index:        idx,
		ChunkSize:    1 << 20,
	}
	err = backupFile(ctx, opts, path, nil, mrand.New(mrand.NewPCG(1, 2)))
	if err == nil {
		t.Fatal("backupFile returned nil despite cancelled ctx")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

// TestIsPeerNotFound_KnownInputs covers the wire-code matcher used by
// deleteChunkOnPeers to treat a peer "not_found" reply as success.
func TestIsPeerNotFound_KnownInputs(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"plain not_found", errors.New("not_found"), true},
		{"wrapped peer reject", errors.New("peer rejected delete: not_found"), true},
		{"prefixed", errors.New("peer rejected delete: not_found extra context"), true},
		{"different code", errors.New("peer rejected delete: owner_mismatch"), false},
		{"unrelated message", errors.New("connection reset"), false},
		{"empty string", errors.New(""), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPeerNotFound(tc.err); got != tc.want {
				t.Errorf("isPeerNotFound(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
