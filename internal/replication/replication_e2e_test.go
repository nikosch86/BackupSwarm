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
	"backupswarm/internal/store"
	"backupswarm/internal/swarm"
)

// repPeer is one storage peer in the replication e2e rig.
type repPeer struct {
	pub      ed25519.PublicKey
	listener *bsquic.Listener
	store    *store.Store
}

func newRepPeer(t *testing.T, ctx context.Context) *repPeer {
	t.Helper()
	st, err := store.New(filepath.Join(t.TempDir(), "blobs"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", priv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	go func() { _ = backup.Serve(ctx, listener, st, nil, nil, nil) }()

	return &repPeer{pub: pub, listener: listener, store: st}
}

// advancingClock is a manual time source for grace-period arithmetic.
type advancingClock struct{ t time.Time }

func (c *advancingClock) Now() time.Time          { return c.t }
func (c *advancingClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

func dialRepPeer(t *testing.T, p *repPeer, ownerPriv ed25519.PrivateKey) *bsquic.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := bsquic.Dial(ctx, p.listener.Addr().String(), ownerPriv, p.pub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func TestReplication_E2E_RepairsLostPeer(t *testing.T) {
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

	src := t.TempDir()
	srcPath := filepath.Join(src, "doc.bin")
	wantBytes := bytes.Repeat([]byte("e2e-replication-test-payload"), 16)
	if err := os.WriteFile(srcPath, wantBytes, 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	// Initial backup ships the chunk to peers A and B (R=2). Peer C
	// has no replica yet.
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
	if len(entry.Chunks) != 1 {
		t.Fatalf("chunks after backup = %d, want 1", len(entry.Chunks))
	}
	wantHash := entry.Chunks[0].CiphertextHash

	if has, err := peerA.store.Has(wantHash); err != nil || !has {
		t.Fatalf("peerA missing chunk after backup: has=%v err=%v", has, err)
	}
	if has, err := peerB.store.Has(wantHash); err != nil || !has {
		t.Fatalf("peerB missing chunk after backup: has=%v err=%v", has, err)
	}
	if has, _ := peerC.store.Has(wantHash); has {
		t.Fatal("peerC unexpectedly has chunk before replication")
	}

	// Mark peer A unreachable, then advance the reach clock past grace
	// so reach.IsLost(peerA) flips true. Replication then fetches from
	// B and places on C.
	now := time.Unix(1_000_000, 0)
	clock := &advancingClock{t: now}
	reach := swarm.NewReachabilityMapWithGrace(3, time.Hour, clock.Now)
	reach.Mark(peerB.pub, swarm.StateReachable)
	reach.Mark(peerC.pub, swarm.StateReachable)
	reach.Mark(peerA.pub, swarm.StateUnreachable)
	if reach.IsLost(peerA.pub) {
		t.Fatal("peerA should not be lost yet (grace not expired)")
	}
	clock.Advance(2 * time.Hour)
	if !reach.IsLost(peerA.pub) {
		t.Fatal("peerA should be lost after grace + advance")
	}

	if err := replication.Run(ctx, replication.RunOptions{
		Index:      idx,
		Conns:      []replication.Conn{connA, connB, connC},
		LostFn:     reach.IsLost,
		Redundancy: 2,
	}); err != nil {
		t.Fatalf("replication.Run: %v", err)
	}

	entry, err = idx.Get("doc.bin")
	if err != nil {
		t.Fatalf("idx.Get post-replication: %v", err)
	}
	peers := entry.Chunks[0].Peers
	if len(peers) != 3 {
		t.Fatalf("peers after replication = %d (%v), want 3 (A,B,C)", len(peers), peers)
	}
	gotC := false
	for _, p := range peers {
		if bytes.Equal(p, peerC.pub) {
			gotC = true
			break
		}
	}
	if !gotC {
		t.Errorf("peerC pubkey not added to chunk peers: %v", peers)
	}

	if has, err := peerC.store.Has(wantHash); err != nil || !has {
		t.Errorf("peerC store missing chunk after replication: has=%v err=%v", has, err)
	}
}
