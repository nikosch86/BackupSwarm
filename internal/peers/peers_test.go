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
	peer := peers.Peer{Addr: "127.0.0.1:7777", PubKey: mustKey(t), Role: peers.RolePeer}

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
	if got.Role != peer.Role {
		t.Errorf("Role = %v, want %v", got.Role, peer.Role)
	}
}

// TestAddGet_PreservesRole asserts every defined Role survives Add/Get round-trip.
func TestAddGet_PreservesRole(t *testing.T) {
	s := openTestStore(t)
	cases := []peers.Role{peers.RolePeer, peers.RoleIntroducer, peers.RoleStorage}
	for _, role := range cases {
		pub := mustKey(t)
		p := peers.Peer{Addr: "x:1", PubKey: pub, Role: role}
		if err := s.Add(p); err != nil {
			t.Fatalf("Add %v: %v", role, err)
		}
		got, err := s.Get(pub)
		if err != nil {
			t.Fatalf("Get %v: %v", role, err)
		}
		if got.Role != role {
			t.Errorf("Role round-trip = %v, want %v", got.Role, role)
		}
	}
}

// TestList_PreservesRole asserts roles survive a List read.
func TestList_PreservesRole(t *testing.T) {
	s := openTestStore(t)
	want := map[peers.Role]string{
		peers.RolePeer:       "p:1",
		peers.RoleIntroducer: "i:1",
		peers.RoleStorage:    "s:1",
	}
	pubsByAddr := make(map[string]ed25519.PublicKey, len(want))
	for role, addr := range want {
		pub := mustKey(t)
		pubsByAddr[addr] = pub
		if err := s.Add(peers.Peer{Addr: addr, PubKey: pub, Role: role}); err != nil {
			t.Fatalf("Add %v: %v", role, err)
		}
	}
	listed, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(listed) != len(want) {
		t.Fatalf("List len = %d, want %d", len(listed), len(want))
	}
	for _, p := range listed {
		expectedRole := peers.RolePeer
		switch p.Addr {
		case "i:1":
			expectedRole = peers.RoleIntroducer
		case "s:1":
			expectedRole = peers.RoleStorage
		case "p:1":
			expectedRole = peers.RolePeer
		default:
			t.Errorf("unexpected addr in list: %q", p.Addr)
		}
		if p.Role != expectedRole {
			t.Errorf("addr %q: Role = %v, want %v", p.Addr, p.Role, expectedRole)
		}
	}
}

// TestRole_IsStorageCandidate asserts only RoleIntroducer and RoleStorage
// return true; every other role returns false.
func TestRole_IsStorageCandidate(t *testing.T) {
	cases := []struct {
		role peers.Role
		want bool
	}{
		{peers.RoleUnspecified, false},
		{peers.RolePeer, false},
		{peers.RoleIntroducer, true},
		{peers.RoleStorage, true},
		{peers.Role(99), false},
	}
	for _, tc := range cases {
		if got := tc.role.IsStorageCandidate(); got != tc.want {
			t.Errorf("(%v).IsStorageCandidate() = %v, want %v", tc.role, got, tc.want)
		}
	}
}

// TestRole_String asserts String returns a stable label for every
// defined role plus the unknown fallback.
func TestRole_String(t *testing.T) {
	cases := []struct {
		role peers.Role
		want string
	}{
		{peers.RoleUnspecified, "unspecified"},
		{peers.RolePeer, "peer"},
		{peers.RoleIntroducer, "introducer"},
		{peers.RoleStorage, "storage"},
	}
	for _, tc := range cases {
		if got := tc.role.String(); got != tc.want {
			t.Errorf("(%v).String() = %q, want %q", tc.role, got, tc.want)
		}
	}
	if got := peers.Role(99).String(); got == "" {
		t.Error("Role(99).String() = empty; want unknown(...) fallback")
	}
}

// TestAdd_RejectsUnknownRole asserts Add fails when the Peer carries an undefined Role.
func TestAdd_RejectsUnknownRole(t *testing.T) {
	s := openTestStore(t)
	if err := s.Add(peers.Peer{Addr: "x:1", PubKey: mustKey(t), Role: peers.Role(99)}); err == nil {
		t.Error("Add accepted undefined Role(99)")
	}
}

// TestAdd_RejectsUnspecifiedRole asserts a zero-valued Role is refused.
func TestAdd_RejectsUnspecifiedRole(t *testing.T) {
	s := openTestStore(t)
	if err := s.Add(peers.Peer{Addr: "x:1", PubKey: mustKey(t)}); err == nil {
		t.Error("Add accepted zero-value Role")
	}
}

func TestAdd_UpsertsByPubKey(t *testing.T) {
	s := openTestStore(t)
	pub := mustKey(t)
	if err := s.Add(peers.Peer{Addr: "old:1", PubKey: pub, Role: peers.RolePeer}); err != nil {
		t.Fatalf("Add first: %v", err)
	}
	if err := s.Add(peers.Peer{Addr: "new:2", PubKey: pub, Role: peers.RoleIntroducer}); err != nil {
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
	if listed[0].Role != peers.RoleIntroducer {
		t.Errorf("Role = %v, want RoleIntroducer (upsert should overwrite)", listed[0].Role)
	}
}

func TestAdd_RejectsInvalidPubkey(t *testing.T) {
	s := openTestStore(t)
	if err := s.Add(peers.Peer{Addr: "x:1", PubKey: []byte{1, 2, 3}, Role: peers.RolePeer}); err == nil {
		t.Error("Add accepted wrong-size pubkey")
	}
	if err := s.Add(peers.Peer{Addr: "x:1", PubKey: nil, Role: peers.RolePeer}); err == nil {
		t.Error("Add accepted nil pubkey")
	}
}

// TestAdd_AcceptsEmptyAddr asserts Add accepts a peer record with an empty Addr.
func TestAdd_AcceptsEmptyAddr(t *testing.T) {
	s := openTestStore(t)
	pub := mustKey(t)
	if err := s.Add(peers.Peer{Addr: "", PubKey: pub, Role: peers.RolePeer}); err != nil {
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
	var all []peers.Peer
	for i := range 3 {
		pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
		pub[0] = byte(3 - i)
		p := peers.Peer{Addr: string(rune('a'+i)) + ":1", PubKey: pub, Role: peers.RolePeer}
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
	sort.Slice(all, func(i, j int) bool { return bytes.Compare(all[i].PubKey, all[j].PubKey) < 0 })
	for i, got := range listed {
		if !bytes.Equal(got.PubKey, all[i].PubKey) {
			t.Errorf("List[%d] pubkey mismatch", i)
		}
	}
}

func TestRemove_DeletesEntry(t *testing.T) {
	s := openTestStore(t)
	peer := peers.Peer{Addr: "x:1", PubKey: mustKey(t), Role: peers.RolePeer}
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
	peer := peers.Peer{Addr: "remembered:9999", PubKey: mustKey(t), Role: peers.RoleIntroducer}
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
	if got.Role != peer.Role {
		t.Errorf("persisted Role = %v, want %v", got.Role, peer.Role)
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
	if err := s.Add(peers.Peer{Addr: "x:1", PubKey: mustKey(t), Role: peers.RolePeer}); err == nil {
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
