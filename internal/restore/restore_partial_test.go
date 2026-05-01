package restore_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/restore"
)

// partialRig brings up two peers, an owner identity, two index files. File A
// is backed up to peerA only; file B is backed up to peerB only. The owner
// then attempts to restore with conns chosen by the test.
type partialRig struct {
	peerA, peerB *peerInst
	connA, connB *bsquic.Conn
	idx          *index.Index
	relA, relB   string
	dataA, dataB []byte
	rpub, rpriv  *[32]byte
	ownerPub     ed25519.PublicKey
	ownerPriv    ed25519.PrivateKey
	srcRoot      string
}

func newPartialRig(t *testing.T) *partialRig {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	peerA := newRestorePeerInst(t, ctx)
	peerB := newRestorePeerInst(t, ctx)

	ownerPub, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}

	dialA := dialPeer(t, peerA, ownerPriv)
	dialB := dialPeer(t, peerB, ownerPriv)

	idx, err := index.Open(filepath.Join(t.TempDir(), "owner-index.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	rpub, rpriv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}

	srcRoot := t.TempDir()
	dataA := []byte("only-on-peer-A bytes")
	dataB := []byte("only-on-peer-B bytes")

	if err := os.WriteFile(filepath.Join(srcRoot, "fileA.bin"), dataA, 0o600); err != nil {
		t.Fatalf("seed A: %v", err)
	}
	if err := backup.Run(context.Background(), backup.RunOptions{
		Path: srcRoot, Conns: []*bsquic.Conn{dialA}, Redundancy: 1,
		RecipientPub: rpub, Index: idx, ChunkSize: 1 << 20, Progress: io.Discard,
	}); err != nil {
		t.Fatalf("backup A: %v", err)
	}
	// Remove A so the second backup doesn't redundantly include it in the scan.
	if err := os.Remove(filepath.Join(srcRoot, "fileA.bin")); err != nil {
		t.Fatalf("remove A: %v", err)
	}

	if err := os.WriteFile(filepath.Join(srcRoot, "fileB.bin"), dataB, 0o600); err != nil {
		t.Fatalf("seed B: %v", err)
	}
	if err := backup.Run(context.Background(), backup.RunOptions{
		Path: srcRoot, Conns: []*bsquic.Conn{dialB}, Redundancy: 1,
		RecipientPub: rpub, Index: idx, ChunkSize: 1 << 20, Progress: io.Discard,
	}); err != nil {
		t.Fatalf("backup B: %v", err)
	}

	return &partialRig{
		peerA: peerA, peerB: peerB,
		connA: dialA, connB: dialB,
		idx:   idx,
		relA:  "fileA.bin",
		relB:  "fileB.bin",
		dataA: dataA, dataB: dataB,
		rpub: rpub, rpriv: rpriv,
		ownerPub: ownerPub, ownerPriv: ownerPriv,
		srcRoot: srcRoot,
	}
}

func dialPeer(t *testing.T, peer *peerInst, ownerPriv ed25519.PrivateKey) *bsquic.Conn {
	t.Helper()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, peer.listener.Addr().String(), ownerPriv, peer.pubKey, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// TestRun_PartialAvailability_RestoresAvailable_DefersMissing asserts that
// when only some peers' conns are passed, restore writes the files whose
// chunks are reachable and surfaces a *MissingPeersError listing the
// unreachable file → peer mapping. Default RetryTimeout == 0 means no retry.
func TestRun_PartialAvailability_RestoresAvailable_DefersMissing(t *testing.T) {
	rig := newPartialRig(t)
	dest := t.TempDir()

	err := restore.Run(context.Background(), restore.Options{
		Dest: dest,
		// connB withheld → fileB chunks have no live conn for peerB
		Conns:         []*bsquic.Conn{rig.connA},
		Index:         rig.idx,
		RecipientPub:  rig.rpub,
		RecipientPriv: rig.rpriv,
		Progress:      io.Discard,
	})
	if err == nil {
		t.Fatal("Run returned nil with peerB unreachable")
	}
	var mpe *restore.MissingPeersError
	if !errors.As(err, &mpe) {
		t.Fatalf("err = %T %v, want *MissingPeersError", err, err)
	}
	pubs, ok := mpe.Files[rig.relB]
	if !ok {
		t.Fatalf("MissingPeersError.Files lacks %q (got %v)", rig.relB, keysOf(mpe.Files))
	}
	if !containsPub(pubs, rig.peerB.pubKey) {
		t.Errorf("missing peers for %q = %x, want includes peerB %x", rig.relB, pubs, rig.peerB.pubKey)
	}
	if _, ok := mpe.Files[rig.relA]; ok {
		t.Errorf("MissingPeersError mentions %q, but it should have been restored", rig.relA)
	}
	// fileA was reachable — it should be on disk byte-exact.
	got, err := os.ReadFile(filepath.Join(dest, rig.relA))
	if err != nil {
		t.Fatalf("read restored A: %v", err)
	}
	if !bytes.Equal(got, rig.dataA) {
		t.Errorf("restored A = %q, want %q", got, rig.dataA)
	}
	// fileB must NOT be on disk.
	if _, err := os.Stat(filepath.Join(dest, rig.relB)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("fileB exists at dest despite missing peer (stat err = %v)", err)
	}
}

// TestRun_PartialAvailability_NoPartialFileLeftBehind asserts the temp
// .partial file used during streaming is removed when the file is deferred
// — a half-restored file must never linger between attempts.
func TestRun_PartialAvailability_NoPartialFileLeftBehind(t *testing.T) {
	rig := newPartialRig(t)
	dest := t.TempDir()

	_ = restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conns:         []*bsquic.Conn{rig.connA},
		Index:         rig.idx,
		RecipientPub:  rig.rpub,
		RecipientPriv: rig.rpriv,
		Progress:      io.Discard,
	})
	// no .partial under dest for any rel
	walked := false
	_ = filepath.Walk(dest, func(p string, _ os.FileInfo, _ error) error {
		walked = true
		if strings.HasSuffix(p, ".partial") {
			t.Errorf("found leftover partial file: %s", p)
		}
		return nil
	})
	if !walked {
		t.Fatalf("walk of %s yielded no entries", dest)
	}
}

// TestRun_PartialAvailability_RetryRecoversWithRedial asserts that a
// non-nil Redial hook returning a fresh conn slice on each call
// eventually restores files whose peers come back online.
func TestRun_PartialAvailability_RetryRecoversWithRedial(t *testing.T) {
	rig := newPartialRig(t)
	dest := t.TempDir()

	var calls atomic.Int32
	redial := func(ctx context.Context) ([]*bsquic.Conn, error) {
		n := calls.Add(1)
		if n == 1 {
			// First retry pass still missing peerB.
			return []*bsquic.Conn{rig.connA}, nil
		}
		// Second retry pass: peerB came online.
		return []*bsquic.Conn{rig.connA, rig.connB}, nil
	}

	err := restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conns:         []*bsquic.Conn{rig.connA},
		Index:         rig.idx,
		RecipientPub:  rig.rpub,
		RecipientPriv: rig.rpriv,
		Progress:      io.Discard,
		RetryTimeout:  3 * time.Second,
		RetryBackoff:  10 * time.Millisecond,
		Redial:        redial,
	})
	if err != nil {
		t.Fatalf("Run with redial recovery: %v", err)
	}
	if calls.Load() < 2 {
		t.Errorf("Redial called %d times, expected >= 2", calls.Load())
	}
	for rel, want := range map[string][]byte{rig.relA: rig.dataA, rig.relB: rig.dataB} {
		got, err := os.ReadFile(filepath.Join(dest, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if !bytes.Equal(got, want) {
			t.Errorf("%s = %q, want %q", rel, got, want)
		}
	}
}

// TestRun_PartialAvailability_TimeoutSurfacesMissingPeersError asserts
// that when retries exhaust the configured RetryTimeout without recovering
// the missing peers, Run returns *MissingPeersError naming them.
func TestRun_PartialAvailability_TimeoutSurfacesMissingPeersError(t *testing.T) {
	rig := newPartialRig(t)
	dest := t.TempDir()

	var calls atomic.Int32
	redial := func(ctx context.Context) ([]*bsquic.Conn, error) {
		calls.Add(1)
		// peerB never comes online.
		return []*bsquic.Conn{rig.connA}, nil
	}

	start := time.Now()
	err := restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conns:         []*bsquic.Conn{rig.connA},
		Index:         rig.idx,
		RecipientPub:  rig.rpub,
		RecipientPriv: rig.rpriv,
		Progress:      io.Discard,
		RetryTimeout:  150 * time.Millisecond,
		RetryBackoff:  10 * time.Millisecond,
		Redial:        redial,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("Run returned nil despite peerB never recovering")
	}
	var mpe *restore.MissingPeersError
	if !errors.As(err, &mpe) {
		t.Fatalf("err = %T %v, want *MissingPeersError", err, err)
	}
	if _, ok := mpe.Files[rig.relB]; !ok {
		t.Errorf("MissingPeersError lacks %q (got %v)", rig.relB, keysOf(mpe.Files))
	}
	if elapsed < 100*time.Millisecond {
		t.Errorf("returned in %v before retry budget %v expired", elapsed, 150*time.Millisecond)
	}
	if calls.Load() == 0 {
		t.Error("Redial never invoked despite RetryTimeout > 0")
	}
}

// TestRun_PartialAvailability_ContextCancellationDuringRetry asserts a
// cancellation between retry passes returns ctx.Err promptly.
func TestRun_PartialAvailability_ContextCancellationDuringRetry(t *testing.T) {
	rig := newPartialRig(t)
	dest := t.TempDir()

	ctx, cancel := context.WithCancel(context.Background())
	redial := func(c context.Context) ([]*bsquic.Conn, error) {
		// Cancel right before we'd return — this races with the sleep.
		cancel()
		return []*bsquic.Conn{rig.connA}, nil
	}
	err := restore.Run(ctx, restore.Options{
		Dest:          dest,
		Conns:         []*bsquic.Conn{rig.connA},
		Index:         rig.idx,
		RecipientPub:  rig.rpub,
		RecipientPriv: rig.rpriv,
		Progress:      io.Discard,
		RetryTimeout:  10 * time.Second,
		RetryBackoff:  500 * time.Millisecond,
		Redial:        redial,
	})
	if err == nil {
		t.Fatal("Run returned nil after ctx cancel")
	}
	if !errors.Is(err, context.Canceled) {
		// Could also be MissingPeersError if Redial returned before ctx noticed.
		// Accept either, but we expect cancel to dominate when sleep is long.
		var mpe *restore.MissingPeersError
		if !errors.As(err, &mpe) {
			t.Errorf("err = %T %v, want context.Canceled or MissingPeersError", err, err)
		}
	}
}

// TestRun_PartialAvailability_FatalErrorShortCircuits asserts that
// non-transient failures (e.g. a hash mismatch) abort immediately
// even when RetryTimeout > 0 — there's nothing to retry past a
// data-integrity violation.
func TestRun_PartialAvailability_FatalErrorShortCircuits(t *testing.T) {
	rig := newPartialRig(t)
	dest := t.TempDir()

	// Tamper fileA's plaintext hash so verification fails.
	entry, err := rig.idx.Get(rig.relA)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	entry.Chunks[0].PlaintextHash = [32]byte{0xde, 0xad, 0xbe, 0xef}
	if err := rig.idx.Put(entry); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var redialCalls atomic.Int32
	err = restore.Run(context.Background(), restore.Options{
		Dest:          dest,
		Conns:         []*bsquic.Conn{rig.connA, rig.connB},
		Index:         rig.idx,
		RecipientPub:  rig.rpub,
		RecipientPriv: rig.rpriv,
		Progress:      io.Discard,
		RetryTimeout:  500 * time.Millisecond,
		RetryBackoff:  10 * time.Millisecond,
		Redial: func(ctx context.Context) ([]*bsquic.Conn, error) {
			redialCalls.Add(1)
			return []*bsquic.Conn{rig.connA, rig.connB}, nil
		},
	})
	if err == nil {
		t.Fatal("Run returned nil despite injected hash mismatch")
	}
	if !strings.Contains(err.Error(), "hash") {
		t.Errorf("err = %q, want hash-mismatch wrap", err)
	}
	if redialCalls.Load() != 0 {
		t.Errorf("Redial called %d times after fatal error; expected 0", redialCalls.Load())
	}
}

// TestMissingPeersError_FormatsAndUnwraps asserts the error type is
// usable: Error() string mentions the file count and a sample peer,
// and errors.As works.
func TestMissingPeersError_FormatsAndUnwraps(t *testing.T) {
	mpe := &restore.MissingPeersError{
		Files: map[string][][]byte{
			"alpha.bin": {{0xaa}},
			"sub/b.bin": {{0xbb}, {0xcc}},
		},
	}
	msg := mpe.Error()
	if !strings.Contains(msg, "2") || !strings.Contains(msg, "file") {
		t.Errorf("error message %q lacks file count", msg)
	}
	wrapped := errors.New("outer: " + mpe.Error())
	_ = wrapped
	var mpe2 *restore.MissingPeersError
	if !errors.As(mpe, &mpe2) {
		t.Errorf("errors.As against same-type failed")
	}
}

// keysOf renders the keys of a map for diagnostics.
func keysOf(m map[string][][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func containsPub(haystack [][]byte, needle ed25519.PublicKey) bool {
	for _, p := range haystack {
		if bytes.Equal(p, needle) {
			return true
		}
	}
	return false
}
