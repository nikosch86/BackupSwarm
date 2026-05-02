package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/peers"
	"backupswarm/pkg/token"
)

// mintTestToken returns a syntactically valid invite token whose introducer
// pubkey is introPub. The Addr is a non-routable sentinel so any join attempt
// would surface promptly via dial-timeout failure.
func mintTestToken(t *testing.T, introPub ed25519.PublicKey) string {
	t.Helper()
	var swarmID, secret [32]byte
	if _, err := rand.Read(swarmID[:]); err != nil {
		t.Fatalf("rand swarm id: %v", err)
	}
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatalf("rand secret: %v", err)
	}
	tokStr, err := token.Encode(token.Token{
		Addr:    "127.0.0.1:1",
		Pub:     introPub,
		SwarmID: swarmID,
		Secret:  secret,
	})
	if err != nil {
		t.Fatalf("encode token: %v", err)
	}
	return tokStr
}

// seedPeer writes peer (pub) into a fresh peers.db under dir.
func seedPeer(t *testing.T, dir string, pub ed25519.PublicKey, role peers.Role) {
	t.Helper()
	store, err := peers.Open(filepath.Join(dir, peers.DefaultFilename))
	if err != nil {
		t.Fatalf("open peers.db: %v", err)
	}
	defer func() { _ = store.Close() }()
	if err := store.Add(peers.Peer{Addr: "10.0.0.1:7777", PubKey: pub, Role: role}); err != nil {
		t.Fatalf("seed peer: %v", err)
	}
}

// TestMaybeAutoJoin_SameSwarm_LogsAndContinues asserts that an invite for the
// already-joined swarm (introducer pubkey already in peers.db) returns nil,
// emits an INFO log naming the swarm-already-joined case, and does NOT attempt
// the network join.
func TestMaybeAutoJoin_SameSwarm_LogsAndContinues(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	seedPeer(t, dir, pub, peers.RoleIntroducer)

	logBuf := &syncBuffer{}
	captureSlog(t, logBuf)

	tok := mintTestToken(t, pub)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := maybeAutoJoin(ctx, dir, tok, "127.0.0.1:7777", time.Second); err != nil {
		t.Fatalf("maybeAutoJoin same swarm: %v", err)
	}
	if !strings.Contains(logBuf.String(), "auto-join skipped; invite is for current swarm") {
		t.Errorf("expected same-swarm log, got:\n%s", logBuf.String())
	}
}

// TestMaybeAutoJoin_PopulatedDB_BadToken_Fails asserts that with peers.db
// already populated, an undecodable token surfaces a decode error rather
// than silently continuing.
func TestMaybeAutoJoin_PopulatedDB_BadToken_Fails(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	seedPeer(t, dir, pub, peers.RoleIntroducer)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = maybeAutoJoin(ctx, dir, "not-a-real-token", "127.0.0.1:7777", time.Second)
	if err == nil {
		t.Fatal("want decode error, got nil")
	}
	if !strings.Contains(err.Error(), "decode invite token") {
		t.Errorf("want decode error, got: %v", err)
	}
}

// TestMaybeAutoJoin_DifferentSwarm_Fails asserts that an invite whose
// introducer pubkey does not match any peer in peers.db is refused with a
// clear error mentioning the data-dir, instead of silently joining or
// silently ignoring.
func TestMaybeAutoJoin_DifferentSwarm_Fails(t *testing.T) {
	dir := t.TempDir()
	existingPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen existing: %v", err)
	}
	seedPeer(t, dir, existingPub, peers.RoleIntroducer)

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen other: %v", err)
	}
	tok := mintTestToken(t, otherPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = maybeAutoJoin(ctx, dir, tok, "127.0.0.1:7777", time.Second)
	if err == nil {
		t.Fatal("maybeAutoJoin different swarm: want error, got nil")
	}
	if !strings.Contains(err.Error(), "different swarm") {
		t.Errorf("error should mention 'different swarm', got: %v", err)
	}
	if !strings.Contains(err.Error(), "data-dir") {
		t.Errorf("error should reference data-dir, got: %v", err)
	}
}
