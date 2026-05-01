package replication_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/replication"
	"backupswarm/internal/swarm"
)

// TestCleanup_E2E_StaleReplicaDroppedOnReconnect: re-replicate past
// grace, then run cleanup against the now-recovered original holder and
// assert the stale blob is gone and the index drops the recovered pub.
func TestCleanup_E2E_StaleReplicaDroppedOnReconnect(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	peerA := newRepPeer(t, ctx)
	peerB := newRepPeer(t, ctx)
	peerC := newRepPeer(t, ctx)

	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	connA := dialRepPeer(t, peerA, ownerPriv)
	connB := dialRepPeer(t, peerB, ownerPriv)
	connC := dialRepPeer(t, peerC, ownerPriv)

	idx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	rpub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	// Initial backup at R=2: chunk lands on A and B (B will be the live
	// source when A is lost).
	src := t.TempDir()
	wantBytes := bytes.Repeat([]byte("stale-cleanup-payload"), 32)
	if err := os.WriteFile(filepath.Join(src, "doc.bin"), wantBytes, 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := backup.Run(ctx, backup.RunOptions{
		Path:         src,
		Conns:        []*bsquic.Conn{connA, connB},
		Redundancy:   2,
		RecipientPub: rpub,
		Index:        idx,
		ChunkSize:    1 << 20,
	}); err != nil {
		t.Fatalf("backup.Run: %v", err)
	}
	entry, err := idx.Get("doc.bin")
	if err != nil {
		t.Fatalf("idx.Get post-backup: %v", err)
	}
	wantHash := entry.Chunks[0].CiphertextHash
	if has, _ := peerA.store.Has(wantHash); !has {
		t.Fatal("peerA missing chunk after initial backup")
	}

	// Mark A lost past grace; B remains reachable as the live source.
	clock := &advancingClock{t: time.Unix(1_000_000, 0)}
	reach := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	reach.Mark(peerA.pub, swarm.StateUnreachable)
	reach.Mark(peerB.pub, swarm.StateReachable)
	reach.Mark(peerC.pub, swarm.StateReachable)
	clock.Advance(2 * time.Hour)
	if !reach.IsLost(peerA.pub) {
		t.Fatal("peerA should be lost after grace")
	}

	if err := replication.Run(ctx, replication.RunOptions{
		Index:      idx,
		Conns:      []replication.Conn{connA, connB, connC},
		LostFn:     reach.IsLost,
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("replication.Run: %v", err)
	}
	entry, _ = idx.Get("doc.bin")
	if len(entry.Chunks[0].Peers) != 3 {
		t.Fatalf("peers after re-rep = %d (%x), want 3 [A,B,C]",
			len(entry.Chunks[0].Peers), entry.Chunks[0].Peers)
	}

	// Cleanup against the just-recovered peer A: DeleteChunk lands on A,
	// A drops from the index, A's blob is gone.
	reach.Mark(peerA.pub, swarm.StateReachable)
	if err := replication.RunCleanup(ctx, replication.CleanupOptions{
		Index:      idx,
		Conn:       connA,
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("RunCleanup: %v", err)
	}
	if has, _ := peerA.store.Has(wantHash); has {
		t.Error("peerA still has chunk after cleanup; expected DeleteChunk to have removed it")
	}
	entry, _ = idx.Get("doc.bin")
	if len(entry.Chunks[0].Peers) != 2 {
		t.Fatalf("peers after cleanup = %d (%x), want 2",
			len(entry.Chunks[0].Peers), entry.Chunks[0].Peers)
	}
	for _, p := range entry.Chunks[0].Peers {
		if bytes.Equal(p, peerA.pub) {
			t.Error("peerA pubkey still present in index after cleanup")
		}
	}

	// Second cleanup pass against the same peer is a no-op (no surplus left).
	if err := replication.RunCleanup(ctx, replication.CleanupOptions{
		Index:      idx,
		Conn:       connA,
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("second RunCleanup: %v", err)
	}
	entry, _ = idx.Get("doc.bin")
	if len(entry.Chunks[0].Peers) != 2 {
		t.Errorf("second cleanup pass mutated peers; got %x", entry.Chunks[0].Peers)
	}
}
