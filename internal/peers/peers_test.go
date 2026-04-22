package peers_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"backupswarm/internal/peers"
)

func mustKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return pub
}

func openTestStore(t *testing.T) *peers.Store {
	t.Helper()
	s, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestOpen_CreatesFileAtSecurePerms(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "nested", "peers.db")
	s, err := peers.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	if runtime.GOOS != "windows" {
		info, err := os.Stat(dbPath)
		if err != nil {
			t.Fatalf("stat: %v", err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("db perm = %o, want 0600", perm)
		}
	}
}

func TestAddGet_RoundTrip(t *testing.T) {
	s := openTestStore(t)
	peer := peers.Peer{Addr: "127.0.0.1:7777", PubKey: mustKey(t)}

	if err := s.Add(peer); err != nil {
		t.Fatalf("Add: %v", err)
	}
	got, err := s.Get(peer.PubKey)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Addr != peer.Addr {
		t.Errorf("Addr = %q, want %q", got.Addr, peer.Addr)
	}
	if !bytes.Equal(got.PubKey, peer.PubKey) {
		t.Error("PubKey round-trip mismatch")
	}
}

func TestAdd_UpsertsByPubKey(t *testing.T) {
	s := openTestStore(t)
	pub := mustKey(t)
	if err := s.Add(peers.Peer{Addr: "old:1", PubKey: pub}); err != nil {
		t.Fatalf("Add first: %v", err)
	}
	if err := s.Add(peers.Peer{Addr: "new:2", PubKey: pub}); err != nil {
		t.Fatalf("Add second: %v", err)
	}
	listed, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != 1 {
		t.Errorf("List len = %d after upsert, want 1", len(listed))
	}
	if listed[0].Addr != "new:2" {
		t.Errorf("Addr = %q, want %q (upsert should overwrite)", listed[0].Addr, "new:2")
	}
}

func TestAdd_RejectsInvalidPubkey(t *testing.T) {
	s := openTestStore(t)
	if err := s.Add(peers.Peer{Addr: "x:1", PubKey: []byte{1, 2, 3}}); err == nil {
		t.Error("Add accepted wrong-size pubkey")
	}
	if err := s.Add(peers.Peer{Addr: "x:1", PubKey: nil}); err == nil {
		t.Error("Add accepted nil pubkey")
	}
}

// Empty Addr is deliberately permitted — it represents "we know this
// pubkey but don't have a dialable address yet." See peers.Store.Add for
// the rationale; bootstrap's join flow relies on this for joiners that
// haven't yet bound a daemon listen port.
func TestAdd_AcceptsEmptyAddr(t *testing.T) {
	s := openTestStore(t)
	pub := mustKey(t)
	if err := s.Add(peers.Peer{Addr: "", PubKey: pub}); err != nil {
		t.Fatalf("Add with empty addr: %v", err)
	}
	got, err := s.Get(pub)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Addr != "" {
		t.Errorf("Addr round-trip = %q, want empty", got.Addr)
	}
}

func TestGet_Missing(t *testing.T) {
	s := openTestStore(t)
	if _, err := s.Get(mustKey(t)); err == nil {
		t.Fatal("Get on unknown pubkey returned nil error")
	} else if !errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("Get err = %v, want wraps ErrPeerNotFound", err)
	}
}

func TestList_Empty(t *testing.T) {
	s := openTestStore(t)
	got, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if got == nil {
		t.Error("List on empty store returned nil, want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("List len = %d, want 0", len(got))
	}
}

func TestList_ReturnsAllSortedByPubKey(t *testing.T) {
	s := openTestStore(t)
	// Insert three peers with deterministic pubkey prefixes so sort order
	// is checkable.
	var all []peers.Peer
	for i := range 3 {
		pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
		pub[0] = byte(3 - i) // insert in reverse order
		p := peers.Peer{Addr: string(rune('a'+i)) + ":1", PubKey: pub}
		if err := s.Add(p); err != nil {
			t.Fatalf("Add %d: %v", i, err)
		}
		all = append(all, p)
	}
	listed, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != len(all) {
		t.Fatalf("List len = %d, want %d", len(listed), len(all))
	}
	// Expect byte-lex order on pubkey, not insertion order.
	sort.Slice(all, func(i, j int) bool { return bytes.Compare(all[i].PubKey, all[j].PubKey) < 0 })
	for i, got := range listed {
		if !bytes.Equal(got.PubKey, all[i].PubKey) {
			t.Errorf("List[%d] pubkey mismatch", i)
		}
	}
}

func TestRemove_DeletesEntry(t *testing.T) {
	s := openTestStore(t)
	peer := peers.Peer{Addr: "x:1", PubKey: mustKey(t)}
	if err := s.Add(peer); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := s.Remove(peer.PubKey); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if _, err := s.Get(peer.PubKey); !errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("Get after Remove err = %v, want ErrPeerNotFound", err)
	}
}

func TestRemove_Missing(t *testing.T) {
	s := openTestStore(t)
	if err := s.Remove(mustKey(t)); !errors.Is(err, peers.ErrPeerNotFound) {
		t.Errorf("Remove missing err = %v, want wraps ErrPeerNotFound", err)
	}
}

func TestRemove_RejectsInvalidPubkey(t *testing.T) {
	s := openTestStore(t)
	if err := s.Remove([]byte{1, 2, 3}); err == nil {
		t.Error("Remove accepted wrong-size pubkey")
	}
}

func TestPeers_PersistAcrossReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "peers.db")
	first, err := peers.Open(path)
	if err != nil {
		t.Fatalf("Open #1: %v", err)
	}
	peer := peers.Peer{Addr: "remembered:9999", PubKey: mustKey(t)}
	if err := first.Add(peer); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close #1: %v", err)
	}

	second, err := peers.Open(path)
	if err != nil {
		t.Fatalf("Open #2: %v", err)
	}
	t.Cleanup(func() { _ = second.Close() })

	got, err := second.Get(peer.PubKey)
	if err != nil {
		t.Fatalf("Get across reopen: %v", err)
	}
	if got.Addr != peer.Addr {
		t.Errorf("persisted Addr = %q, want %q", got.Addr, peer.Addr)
	}
}

func TestOpen_FailsWhenParentIsFile(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed blocker: %v", err)
	}
	if _, err := peers.Open(filepath.Join(blocker, "peers.db")); err == nil {
		t.Error("Open accepted a file as parent dir")
	}
}

func TestOperationsAfterClose_Error(t *testing.T) {
	s := openTestStore(t)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Add(peers.Peer{Addr: "x:1", PubKey: mustKey(t)}); err == nil {
		t.Error("Add on closed store succeeded")
	}
	if _, err := s.Get(mustKey(t)); err == nil {
		t.Error("Get on closed store succeeded")
	}
	if err := s.Remove(mustKey(t)); err == nil {
		t.Error("Remove on closed store succeeded")
	}
	if _, err := s.List(); err == nil {
		t.Error("List on closed store succeeded")
	}
}
