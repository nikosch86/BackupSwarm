package backup_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/placement"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// peerInst is one storage peer in a multi-peer rig.
type peerInst struct {
	store    *store.Store
	pubKey   ed25519.PublicKey
	priv     ed25519.PrivateKey
	listener *bsquic.Listener
}

// multiRig brings up N peers and an owner with a conn to each.
type multiRig struct {
	t            *testing.T
	peers        []*peerInst
	ownerIndex   *index.Index
	ownerConns   []*bsquic.Conn
	recipientPub *[32]byte
	ownerPub     ed25519.PublicKey
}

func newMultiRig(t *testing.T, n int) *multiRig {
	t.Helper()
	if n <= 0 {
		t.Fatalf("need at least 1 peer, got %d", n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}

	peers := make([]*peerInst, n)
	conns := make([]*bsquic.Conn, n)
	for i := 0; i < n; i++ {
		peers[i] = newPeerInst(t, ctx, 0) // 0 = unlimited capacity
		dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := bsquic.Dial(dialCtx, peers[i].listener.Addr().String(), ownerPriv, peers[i].pubKey, nil)
		dialCancel()
		if err != nil {
			t.Fatalf("Dial peer %d: %v", i, err)
		}
		t.Cleanup(func() { _ = conn.Close() })
		conns[i] = conn
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

	return &multiRig{
		t:            t,
		peers:        peers,
		ownerIndex:   idx,
		ownerConns:   conns,
		recipientPub: rpub,
		ownerPub:     ownerPub,
	}
}

func newPeerInst(t *testing.T, ctx context.Context, maxBytes int64) *peerInst {
	t.Helper()
	dir := t.TempDir()
	st, err := store.NewWithMax(filepath.Join(dir, "blobs"), maxBytes)
	if err != nil {
		t.Fatalf("store.NewWithMax: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", priv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	go func() { _ = backup.Serve(ctx, listener, st, nil, nil, nil) }()
	t.Cleanup(func() { _ = listener.Close() })
	return &peerInst{store: st, pubKey: pub, priv: priv, listener: listener}
}

// peersHolding returns the indexes of peers in the rig that have the blob.
func (r *multiRig) peersHolding(t *testing.T, hash [32]byte) []int {
	t.Helper()
	var out []int
	for i, p := range r.peers {
		has, err := p.store.Has(hash)
		if err != nil {
			t.Fatalf("peer %d Has: %v", i, err)
		}
		if has {
			out = append(out, i)
		}
	}
	return out
}

func TestRun_MultiPeer_RedundancyEqualsPoolSize_AllPeersGetChunk(t *testing.T) {
	rig := newMultiRig(t, 3)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        rig.ownerConns,
		Redundancy:   3,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry, err := rig.ownerIndex.Get(path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if len(entry.Chunks) != 1 {
		t.Fatalf("want 1 chunk, got %d", len(entry.Chunks))
	}
	ref := entry.Chunks[0]
	if len(ref.Peers) != 3 {
		t.Fatalf("ChunkRef.Peers: want 3, got %d", len(ref.Peers))
	}
	holders := rig.peersHolding(t, ref.CiphertextHash)
	if len(holders) != 3 {
		t.Errorf("want all 3 peers to hold blob, got %v", holders)
	}
}

func TestRun_MultiPeer_RedundancyOne_OnePeerHoldsChunk(t *testing.T) {
	rig := newMultiRig(t, 3)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        rig.ownerConns,
		Redundancy:   1,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry, err := rig.ownerIndex.Get(path)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	ref := entry.Chunks[0]
	if len(ref.Peers) != 1 {
		t.Fatalf("ChunkRef.Peers: want 1, got %d", len(ref.Peers))
	}
	holders := rig.peersHolding(t, ref.CiphertextHash)
	if len(holders) != 1 {
		t.Errorf("want exactly 1 peer to hold blob, got %v", holders)
	}
}

func TestRun_MultiPeer_DefaultRedundancyIsOne(t *testing.T) {
	rig := newMultiRig(t, 3)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:  path,
		Conns: rig.ownerConns,
		// Redundancy unset → defaults to 1.
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, _ := rig.ownerIndex.Get(path)
	if len(entry.Chunks[0].Peers) != 1 {
		t.Errorf("default redundancy: want 1 peer recorded, got %d", len(entry.Chunks[0].Peers))
	}
}

func TestRun_MultiPeer_RedundancyExceedsPool(t *testing.T) {
	rig := newMultiRig(t, 2)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	err := backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        rig.ownerConns,
		Redundancy:   5,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	})
	if err == nil {
		t.Fatal("Run with redundancy > peers returned nil")
	}
	if !errors.Is(err, placement.ErrInsufficientPeers) {
		t.Errorf("err = %v, want wrapping ErrInsufficientPeers", err)
	}
}

func TestRun_MultiPeer_NoConns(t *testing.T) {
	idx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	rpub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	err = backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        nil,
		Redundancy:   1,
		RecipientPub: rpub,
		Index:        idx,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	})
	if err == nil {
		t.Fatal("Run with no conns returned nil")
	}
}

func TestRun_MultiPeer_DistributesAcrossChunks(t *testing.T) {
	// 3 equal-capacity peers, R=1, many chunks: each peer should pick up
	// at least one chunk (heavy bias would be a placement bug).
	rig := newMultiRig(t, 3)
	root := t.TempDir()
	path := filepath.Join(root, "big.bin")
	writeFile(t, path, (1<<20)*30) // 30 chunks

	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        rig.ownerConns,
		Redundancy:   1,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
		Rng:          mrand.New(mrand.NewPCG(7, 11)),
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry, _ := rig.ownerIndex.Get(path)
	if len(entry.Chunks) != 30 {
		t.Fatalf("want 30 chunks, got %d", len(entry.Chunks))
	}

	counts := make(map[int]int, 3)
	for _, ref := range entry.Chunks {
		holders := rig.peersHolding(t, ref.CiphertextHash)
		if len(holders) != 1 {
			t.Errorf("chunk holders = %v, want 1", holders)
			continue
		}
		counts[holders[0]]++
	}
	for i := 0; i < 3; i++ {
		if counts[i] == 0 {
			t.Errorf("peer %d got no chunks (heavy distribution skew)", i)
		}
	}
}

func TestRun_MultiPeer_FullPeerExcludedFromPlacement(t *testing.T) {
	// 2 peers; one full from a pre-seeded blob exceeding its cap.
	// R=1 must place the new chunk on the remaining peer.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Peer A: large capacity, plenty of room.
	peerA := newPeerInst(t, ctx, 10<<20)
	// Peer B: tiny capacity, pre-filled to be over the cap.
	peerB := newPeerInst(t, ctx, 1) // 1 byte cap → any put fails
	if _, err := peerB.store.PutOwned([]byte("seed"), peerB.pubKey); err == nil {
		t.Fatalf("expected pre-seed of peerB to error (over cap)")
	}

	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	connA, err := bsquic.Dial(dialCtx, peerA.listener.Addr().String(), ownerPriv, peerA.pubKey, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial A: %v", err)
	}
	t.Cleanup(func() { _ = connA.Close() })
	dialCtx, dialCancel = context.WithTimeout(context.Background(), 5*time.Second)
	connB, err := bsquic.Dial(dialCtx, peerB.listener.Addr().String(), ownerPriv, peerB.pubKey, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial B: %v", err)
	}
	t.Cleanup(func() { _ = connB.Close() })

	idx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	rpub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        []*bsquic.Conn{connA, connB},
		Redundancy:   1,
		RecipientPub: rpub,
		Index:        idx,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}

	entry, _ := idx.Get(path)
	ref := entry.Chunks[0]
	hasA, _ := peerA.store.Has(ref.CiphertextHash)
	hasB, _ := peerB.store.Has(ref.CiphertextHash)
	if !hasA {
		t.Error("peerA (capacity available) should hold chunk")
	}
	if hasB {
		t.Error("peerB (over cap) should not hold chunk")
	}
}

// TestPrune_MultiPeer_NotFoundCountsAsSuccess asserts a peer reporting
// "not_found" on delete is treated as success: the index entry is
// removed when the other peer accepts the delete.
func TestPrune_MultiPeer_NotFoundCountsAsSuccess(t *testing.T) {
	rig := newMultiRig(t, 2)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        rig.ownerConns,
		Redundancy:   2,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, _ := rig.ownerIndex.Get(path)
	ref := entry.Chunks[0]

	// Drop the blob from peer 0 directly so its delete will return not_found.
	if err := rig.peers[0].store.DeleteForOwner(ref.CiphertextHash, rig.ownerPub); err != nil {
		t.Fatalf("peer0 DeleteForOwner: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:     root,
		Conns:    rig.ownerConns,
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	}); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if _, err := rig.ownerIndex.Get(path); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("entry not removed despite peer 0 not_found + peer 1 success: %v", err)
	}
}

// TestPrune_MultiPeer_NoLiveConnBranchTriggers asserts Prune still
// removes the entry when one of ChunkRef.Peers has no matching conn,
// as long as another peer accepts the delete.
func TestPrune_MultiPeer_NoLiveConnBranchTriggers(t *testing.T) {
	rig := newMultiRig(t, 2)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        rig.ownerConns,
		Redundancy:   2,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("rm: %v", err)
	}
	// Prune with only peer 0's conn. Chunk on peer 1 has no live conn but
	// peer 0's delete succeeds → entry removed.
	if err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:     root,
		Conns:    rig.ownerConns[:1],
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	}); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	if _, err := rig.ownerIndex.Get(path); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("entry not removed despite peer 0 success: %v", err)
	}
}

// TestPrune_MultiPeer_AllPeersOffline asserts Prune surfaces an error
// (and keeps the index entry) when no peer in ChunkRef.Peers has a
// matching live conn.
func TestPrune_MultiPeer_AllPeersOffline(t *testing.T) {
	rig := newMultiRig(t, 1)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        rig.ownerConns,
		Redundancy:   1,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("rm: %v", err)
	}

	// Bring up an unrelated peer + conn; ChunkRef.Peers references the
	// real peer (not in Conns).
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stranger := newPeerInst(t, ctx, 0)
	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	strangerConn, err := bsquic.Dial(dialCtx, stranger.listener.Addr().String(), ownerPriv, stranger.pubKey, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial stranger: %v", err)
	}
	t.Cleanup(func() { _ = strangerConn.Close() })

	err = backup.Prune(context.Background(), backup.PruneOptions{
		Root:     root,
		Conns:    []*bsquic.Conn{strangerConn},
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune succeeded when no recorded peer had a live conn")
	}
	// Entry should NOT be deleted; user can retry next sweep.
	if _, err := rig.ownerIndex.Get(path); errors.Is(err, index.ErrFileNotFound) {
		t.Error("entry deleted despite no successful peer delete")
	}
}

// TestProbeCandidates_FullPeerSkipped asserts a peer with finite cap
// reporting used==max is excluded from the placement pool.
func TestProbeCandidates_FullPeerSkipped(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// Cap of 5 bytes; first put fills the store exactly.
	full := newPeerInst(t, ctx, 5)
	if _, err := full.store.PutOwned([]byte("fill5"), full.pubKey); err != nil {
		t.Fatalf("seed put: %v", err)
	}

	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	conn, err := bsquic.Dial(dialCtx, full.listener.Addr().String(), ownerPriv, full.pubKey, nil)
	dialCancel()
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	idx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })
	rpub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	// Pool=[full peer], R=1 → no candidates left after probe → ErrInsufficientPeers.
	err = backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        []*bsquic.Conn{conn},
		Redundancy:   1,
		RecipientPub: rpub,
		Index:        idx,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	})
	if err == nil {
		t.Fatal("Run with full-only pool returned nil")
	}
	if !errors.Is(err, placement.ErrInsufficientPeers) {
		t.Errorf("err = %v, want wrapping ErrInsufficientPeers", err)
	}
}

func TestPrune_MultiPeer_DeletesFromAllPeers(t *testing.T) {
	rig := newMultiRig(t, 3)
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	writeFile(t, path, 1<<20)

	if err := backup.Run(context.Background(), backup.RunOptions{
		Path:         path,
		Conns:        rig.ownerConns,
		Redundancy:   3,
		RecipientPub: rig.recipientPub,
		Index:        rig.ownerIndex,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	entry, _ := rig.ownerIndex.Get(path)
	ref := entry.Chunks[0]

	if err := os.Remove(path); err != nil {
		t.Fatalf("rm: %v", err)
	}
	if err := backup.Prune(context.Background(), backup.PruneOptions{
		Root:     root,
		Conns:    rig.ownerConns,
		Index:    rig.ownerIndex,
		Progress: io.Discard,
	}); err != nil {
		t.Fatalf("Prune: %v", err)
	}
	for i, p := range rig.peers {
		has, _ := p.store.Has(ref.CiphertextHash)
		if has {
			t.Errorf("peer %d still has blob after Prune", i)
		}
	}
	if _, err := rig.ownerIndex.Get(path); !errors.Is(err, index.ErrFileNotFound) {
		t.Errorf("index entry not removed: err = %v", err)
	}
}
