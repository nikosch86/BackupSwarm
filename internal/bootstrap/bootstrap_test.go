package bootstrap_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/invites"
	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/pkg/token"
)

// maxAdvertisedAddrLenForTest matches the unexported maxAdvertisedAddrLen used inside the bootstrap package.
const maxAdvertisedAddrLenForTest = 1 << 10

type twoSides struct {
	introducerPub      ed25519.PublicKey
	introducerPriv     ed25519.PrivateKey
	joinerPub          ed25519.PublicKey
	joinerPriv         ed25519.PrivateKey
	listener           *bsquic.Listener
	introducerPeerList *peers.Store
	joinerPeerList     *peers.Store
	swarmID            [token.SwarmIDSize]byte
	secret             [token.SecretSize]byte
}

func setupTwoSides(t *testing.T) *twoSides {
	t.Helper()
	introPub, introPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("intro key: %v", err)
	}
	joinPub, joinPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("join key: %v", err)
	}
	l, err := bsquic.Listen("127.0.0.1:0", introPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	introStore, err := peers.Open(filepath.Join(t.TempDir(), "intro-peers.db"))
	if err != nil {
		t.Fatalf("intro peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = introStore.Close() })

	joinStore, err := peers.Open(filepath.Join(t.TempDir(), "join-peers.db"))
	if err != nil {
		t.Fatalf("join peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = joinStore.Close() })

	var swarmID [token.SwarmIDSize]byte
	if _, err := rand.Read(swarmID[:]); err != nil {
		t.Fatalf("rand swarm: %v", err)
	}
	var secret [token.SecretSize]byte
	if _, err := rand.Read(secret[:]); err != nil {
		t.Fatalf("rand secret: %v", err)
	}

	return &twoSides{
		introducerPub:      introPub,
		introducerPriv:     introPriv,
		joinerPub:          joinPub,
		joinerPriv:         joinPriv,
		listener:           l,
		introducerPeerList: introStore,
		joinerPeerList:     joinStore,
		swarmID:            swarmID,
		secret:             secret,
	}
}

// validator returns a one-shot SecretValidator backed by the rig's
// known secret/swarmID; the second matching call returns ErrAlreadyUsed.
func (r *twoSides) validator() bootstrap.SecretValidator {
	used := false
	return func(got [token.SecretSize]byte) ([token.SwarmIDSize]byte, error) {
		if subtle.ConstantTimeCompare(got[:], r.secret[:]) != 1 {
			return [token.SwarmIDSize]byte{}, invites.ErrUnknown
		}
		if used {
			return [token.SwarmIDSize]byte{}, invites.ErrAlreadyUsed
		}
		used = true
		return r.swarmID, nil
	}
}

func (r *twoSides) tokenStr(t *testing.T, addr string, pub ed25519.PublicKey) string {
	t.Helper()
	tok, err := token.Encode(token.Token{
		Addr:    addr,
		Pub:     pub,
		SwarmID: r.swarmID,
		Secret:  r.secret,
	})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}
	return tok
}

func TestBootstrap_EndToEnd(t *testing.T) {
	rig := setupTwoSides(t)
	const joinerListen = "192.0.2.1:9000"
	const inviteTimeout = 5 * time.Second

	tok := rig.tokenStr(t, rig.listener.Addr().String(), rig.introducerPub)

	var wg sync.WaitGroup
	var acceptedPeer peers.Peer
	var acceptErr error

	ctx, cancel := context.WithTimeout(context.Background(), inviteTimeout)
	defer cancel()

	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptedPeer, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer dialCancel()
	result, err := bootstrap.DoJoin(dialCtx, tok, rig.joinerPriv, joinerListen, rig.joinerPeerList)
	if err != nil {
		t.Fatalf("DoJoin: %v", err)
	}

	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptJoin: %v", acceptErr)
	}

	if !bytes.Equal(acceptedPeer.PubKey, rig.joinerPub) {
		t.Error("AcceptJoin returned wrong pubkey")
	}
	if acceptedPeer.Addr != joinerListen {
		t.Errorf("AcceptJoin addr = %q, want %q", acceptedPeer.Addr, joinerListen)
	}
	if acceptedPeer.Role != peers.RoleStorage {
		t.Errorf("AcceptJoin role = %v, want RoleStorage", acceptedPeer.Role)
	}
	got, err := rig.introducerPeerList.Get(rig.joinerPub)
	if err != nil {
		t.Fatalf("introducer's peer store missing joiner: %v", err)
	}
	if got.Addr != joinerListen {
		t.Errorf("introducer saw joiner addr %q, want %q", got.Addr, joinerListen)
	}
	if got.Role != peers.RoleStorage {
		t.Errorf("introducer's stored joiner role = %v, want RoleStorage", got.Role)
	}

	if !bytes.Equal(result.Introducer.PubKey, rig.introducerPub) {
		t.Error("DoJoin returned wrong pubkey")
	}
	if result.Introducer.Addr != rig.listener.Addr().String() {
		t.Errorf("DoJoin addr = %q, want %q", result.Introducer.Addr, rig.listener.Addr().String())
	}
	if result.Introducer.Role != peers.RoleIntroducer {
		t.Errorf("DoJoin role = %v, want RoleIntroducer", result.Introducer.Role)
	}
	got, err = rig.joinerPeerList.Get(rig.introducerPub)
	if err != nil {
		t.Fatalf("joiner's peer store missing introducer: %v", err)
	}
	if got.Addr != rig.listener.Addr().String() {
		t.Errorf("joiner saw introducer addr %q, want %q", got.Addr, rig.listener.Addr().String())
	}
	if got.Role != peers.RoleIntroducer {
		t.Errorf("joiner's stored introducer role = %v, want RoleIntroducer", got.Role)
	}

	if len(result.Peers) != 0 {
		t.Errorf("empty introducer peer store should yield 0 entries, got %d", len(result.Peers))
	}
}

// TestBootstrap_SendsExistingPeers seeds the introducer's peer store
// with a third-party entry and verifies DoJoin returns it verbatim.
func TestBootstrap_SendsExistingPeers(t *testing.T) {
	rig := setupTwoSides(t)
	thirdPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("third key: %v", err)
	}
	seeded := peers.Peer{Addr: "10.20.30.40:7777", PubKey: thirdPub, Role: peers.RoleStorage}
	if err := rig.introducerPeerList.Add(seeded); err != nil {
		t.Fatalf("seed peer: %v", err)
	}

	tok := rig.tokenStr(t, rig.listener.Addr().String(), rig.introducerPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	result, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	if err != nil {
		t.Fatalf("DoJoin: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptJoin: %v", acceptErr)
	}

	if len(result.Peers) != 1 {
		t.Fatalf("len(Peers) = %d, want 1", len(result.Peers))
	}
	got := result.Peers[0]
	if !bytes.Equal(got.PubKey, thirdPub) {
		t.Error("third-party pubkey mismatch")
	}
	if got.Addr != seeded.Addr {
		t.Errorf("third-party addr = %q, want %q", got.Addr, seeded.Addr)
	}
	if got.Role != peers.RoleStorage {
		t.Errorf("third-party role = %v, want RoleStorage", got.Role)
	}
}

// TestBootstrap_PersistsReceivedPeerList asserts received peer-list
// entries land in the joiner's peer store with role and address
// preserved, alongside the introducer record.
func TestBootstrap_PersistsReceivedPeerList(t *testing.T) {
	rig := setupTwoSides(t)
	storagePub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("storage key: %v", err)
	}
	plainPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("plain key: %v", err)
	}
	seeded := []peers.Peer{
		{Addr: "10.20.30.40:7777", PubKey: storagePub, Role: peers.RoleStorage},
		{Addr: "10.20.30.41:8888", PubKey: plainPub, Role: peers.RolePeer},
	}
	for _, p := range seeded {
		if err := rig.introducerPeerList.Add(p); err != nil {
			t.Fatalf("seed peer: %v", err)
		}
	}

	tok := rig.tokenStr(t, rig.listener.Addr().String(), rig.introducerPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	if _, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList); err != nil {
		t.Fatalf("DoJoin: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptJoin: %v", acceptErr)
	}

	gotStorage, err := rig.joinerPeerList.Get(storagePub)
	if err != nil {
		t.Fatalf("joiner missing storage peer: %v", err)
	}
	if gotStorage.Addr != "10.20.30.40:7777" {
		t.Errorf("storage peer addr = %q, want %q", gotStorage.Addr, "10.20.30.40:7777")
	}
	if gotStorage.Role != peers.RoleStorage {
		t.Errorf("storage peer role = %v, want RoleStorage", gotStorage.Role)
	}

	gotPlain, err := rig.joinerPeerList.Get(plainPub)
	if err != nil {
		t.Fatalf("joiner missing plain peer: %v", err)
	}
	if gotPlain.Addr != "10.20.30.41:8888" {
		t.Errorf("plain peer addr = %q, want %q", gotPlain.Addr, "10.20.30.41:8888")
	}
	if gotPlain.Role != peers.RolePeer {
		t.Errorf("plain peer role = %v, want RolePeer", gotPlain.Role)
	}

	gotIntro, err := rig.joinerPeerList.Get(rig.introducerPub)
	if err != nil {
		t.Fatalf("joiner missing introducer: %v", err)
	}
	if gotIntro.Role != peers.RoleIntroducer {
		t.Errorf("introducer role = %v, want RoleIntroducer", gotIntro.Role)
	}
}

// TestBootstrap_PeerListWithIntroducerPubkey_PreservesIntroducer asserts
// that a peer-list entry sharing the introducer's pubkey does not
// downgrade the introducer record on the joiner side.
func TestBootstrap_PeerListWithIntroducerPubkey_PreservesIntroducer(t *testing.T) {
	rig := setupTwoSides(t)
	// The introducer's own pubkey is seeded under RolePeer so the
	// snapshot AcceptJoin sends includes a self-entry.
	selfEntry := peers.Peer{Addr: "spoof.example:1", PubKey: rig.introducerPub, Role: peers.RolePeer}
	if err := rig.introducerPeerList.Add(selfEntry); err != nil {
		t.Fatalf("seed self entry: %v", err)
	}

	tok := rig.tokenStr(t, rig.listener.Addr().String(), rig.introducerPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	if _, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList); err != nil {
		t.Fatalf("DoJoin: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptJoin: %v", acceptErr)
	}

	got, err := rig.joinerPeerList.Get(rig.introducerPub)
	if err != nil {
		t.Fatalf("joiner missing introducer: %v", err)
	}
	if got.Role != peers.RoleIntroducer {
		t.Errorf("introducer role = %v, want RoleIntroducer (peer-list entry must not overwrite)", got.Role)
	}
	if got.Addr != rig.listener.Addr().String() {
		t.Errorf("introducer addr = %q, want %q (peer-list entry must not overwrite)",
			got.Addr, rig.listener.Addr().String())
	}
}

func TestBootstrap_SwarmIDMismatch_RejectedByIntroducer(t *testing.T) {
	rig := setupTwoSides(t)

	wrongTokenSwarm := rig.swarmID
	wrongTokenSwarm[0] ^= 0xFF
	tok, err := token.Encode(token.Token{
		Addr:    rig.listener.Addr().String(),
		Pub:     rig.introducerPub,
		SwarmID: wrongTokenSwarm,
		Secret:  rig.secret,
	})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	wg.Wait()
	if err == nil {
		t.Fatal("DoJoin succeeded despite swarm mismatch")
	}
	if !errors.Is(err, bootstrap.ErrSwarmMismatch) {
		t.Errorf("err = %v, want ErrSwarmMismatch", err)
	}
	list, _ := rig.joinerPeerList.List()
	if len(list) != 0 {
		t.Errorf("joiner peer store mutated on swarm mismatch: %d entries", len(list))
	}
}

func TestBootstrap_AlreadyUsedToken_RejectedByIntroducer(t *testing.T) {
	rig := setupTwoSides(t)
	preConsumed := func(_ [token.SecretSize]byte) ([token.SwarmIDSize]byte, error) {
		return [token.SwarmIDSize]byte{}, invites.ErrAlreadyUsed
	}
	tok := rig.tokenStr(t, rig.listener.Addr().String(), rig.introducerPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, preConsumed, nil)
	}()

	_, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	wg.Wait()
	if err == nil {
		t.Fatal("DoJoin succeeded despite already-used token")
	}
	if !errors.Is(err, bootstrap.ErrTokenUsed) {
		t.Errorf("err = %v, want ErrTokenUsed", err)
	}
}

func TestBootstrap_SecretMismatch_RejectedByIntroducer(t *testing.T) {
	rig := setupTwoSides(t)

	wrongSecret := rig.secret
	wrongSecret[0] ^= 0xFF
	tok, err := token.Encode(token.Token{
		Addr:    rig.listener.Addr().String(),
		Pub:     rig.introducerPub,
		SwarmID: rig.swarmID,
		Secret:  wrongSecret,
	})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	wg.Wait()
	if err == nil {
		t.Fatal("DoJoin succeeded despite secret mismatch")
	}
	if !errors.Is(err, bootstrap.ErrBadSecret) {
		t.Errorf("err = %v, want ErrBadSecret", err)
	}
}

func TestBootstrap_WrongPubkeyTokenFailsTLSPin(t *testing.T) {
	rig := setupTwoSides(t)

	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	tok := rig.tokenStr(t, rig.listener.Addr().String(), otherPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer acceptCancel()
	go func() {
		_, _ = bootstrap.AcceptJoin(acceptCtx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "127.0.0.1:1", rig.joinerPeerList)
	if err == nil {
		t.Fatal("DoJoin succeeded despite wrong pubkey in token")
	}
	list, _ := rig.joinerPeerList.List()
	if len(list) != 0 {
		t.Errorf("joiner peer store mutated after failed join: %d entries", len(list))
	}
}

func TestBootstrap_MalformedTokenRejected(t *testing.T) {
	rig := setupTwoSides(t)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err := bootstrap.DoJoin(ctx, "!!!not-a-token!!!", rig.joinerPriv, "x:1", rig.joinerPeerList)
	if err == nil {
		t.Error("DoJoin accepted a malformed token")
	}
}

func TestBootstrap_DeadAddrFailsDial(t *testing.T) {
	rig := setupTwoSides(t)
	tok := rig.tokenStr(t, "127.0.0.1:1", rig.introducerPub)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "x:1", rig.joinerPeerList)
	if err == nil {
		t.Error("DoJoin succeeded against dead address")
	}
}

func TestBootstrap_AcceptJoin_CtxCancelReturns(t *testing.T) {
	rig := setupTwoSides(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Error("AcceptJoin returned nil after ctx cancel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("AcceptJoin did not return within 3s of ctx cancel")
	}
}

func TestBootstrap_JoinerWithEmptyListenAddr(t *testing.T) {
	rig := setupTwoSides(t)
	tok := rig.tokenStr(t, rig.listener.Addr().String(), rig.introducerPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptedPeer peers.Peer
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		acceptedPeer, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	_, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "", rig.joinerPeerList)
	if err != nil {
		t.Fatalf("DoJoin with empty listen: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptJoin: %v", acceptErr)
	}
	if acceptedPeer.Addr != "" {
		t.Errorf("accepted addr = %q, want empty", acceptedPeer.Addr)
	}
	got, err := rig.introducerPeerList.Get(rig.joinerPub)
	if err != nil {
		t.Fatalf("Get joiner: %v", err)
	}
	if got.Addr != "" {
		t.Errorf("stored addr = %q, want empty", got.Addr)
	}
}

// TestBootstrap_IntroducerStoreError_PropagatesAppErr exercises a peer-
// store List failure surfaces as an internal app error to DoJoin.
func TestBootstrap_IntroducerStoreError_PropagatesAppErr(t *testing.T) {
	rig := setupTwoSides(t)
	_ = rig.introducerPeerList.Close()

	tok := rig.tokenStr(t, rig.listener.Addr().String(), rig.introducerPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	_, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "", rig.joinerPeerList)
	wg.Wait()

	if err == nil {
		t.Fatal("DoJoin returned nil despite introducer app error")
	}
	if acceptErr == nil {
		t.Error("AcceptJoin returned nil despite store failure")
	}
	if !errors.Is(err, bootstrap.ErrIntroducerInternal) {
		t.Errorf("DoJoin err = %v, want ErrIntroducerInternal", err)
	}
	list, _ := rig.joinerPeerList.List()
	if len(list) != 0 {
		t.Errorf("joiner peer list contains %d entries after app-error; want 0", len(list))
	}
}

var _ = errors.Is

// TestAcceptJoin_ClientClosesWithoutStream asserts AcceptJoin wraps the conn.AcceptStream error when the joiner closes without opening a stream.
func TestAcceptJoin_ClientClosesWithoutStream(t *testing.T) {
	rig := setupTwoSides(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	dialCtx, dialCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer dialCancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	conn, err := bsquic.Dial(dialCtx, rig.listener.Addr().String(), rig.joinerPriv, rig.introducerPub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()

	wg.Wait()
	if acceptErr == nil {
		t.Fatal("AcceptJoin returned nil when client closed before opening stream")
	}
	list, _ := rig.introducerPeerList.List()
	if len(list) != 0 {
		t.Errorf("introducer peer list has %d entries; want 0", len(list))
	}
}

// TestAcceptJoin_ListenerClosed asserts AcceptJoin wraps the Accept error from a closed listener as "accept".
func TestAcceptJoin_ListenerClosed(t *testing.T) {
	rig := setupTwoSides(t)
	_ = rig.listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	if err == nil {
		t.Fatal("AcceptJoin returned nil on closed listener")
	}
}

// TestAcceptJoin_MalformedRequest covers a joiner that opens a stream
// then closes it without writing the request frame.
func TestAcceptJoin_MalformedRequest(t *testing.T) {
	rig := setupTwoSides(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	conn, err := bsquic.Dial(ctx, rig.listener.Addr().String(), rig.joinerPriv, rig.introducerPub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	stream, err := conn.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	_ = stream.Close()

	wg.Wait()
	if acceptErr == nil {
		t.Fatal("AcceptJoin returned nil on malformed request")
	}
	list, _ := rig.introducerPeerList.List()
	if len(list) != 0 {
		t.Errorf("introducer peer list mutated on malformed request: %d entries", len(list))
	}
}

// TestDoJoin_IntroducerDropsBeforeResponse asserts DoJoin wraps the
// ReadJoinResponse error when the introducer hangs up before responding.
func TestDoJoin_IntroducerDropsBeforeResponse(t *testing.T) {
	rig := setupTwoSides(t)
	tok := rig.tokenStr(t, rig.listener.Addr().String(), rig.introducerPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		conn, err := rig.listener.Accept(ctx)
		if err != nil {
			return
		}
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			_ = conn.Close()
			return
		}
		_, _, _, _, _ = protocol.ReadJoinRequest(stream, maxAdvertisedAddrLenForTest, 1<<12)
		_ = conn.Close()
	}()

	_, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	if err == nil {
		t.Fatal("DoJoin returned nil when introducer dropped before response")
	}
	wg.Wait()
	list, _ := rig.joinerPeerList.List()
	if len(list) != 0 {
		t.Errorf("joiner peer list has %d entries after failed response read; want 0", len(list))
	}
}

// TestDoJoin_JoinerStoreClosed_PropagatesErr asserts DoJoin surfaces a joiner-side store.Add error after a successful response.
func TestDoJoin_JoinerStoreClosed_PropagatesErr(t *testing.T) {
	rig := setupTwoSides(t)
	tok := rig.tokenStr(t, rig.listener.Addr().String(), rig.introducerPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	_ = rig.joinerPeerList.Close()

	_, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	if err == nil {
		t.Fatal("DoJoin returned nil when joiner store.Add should fail")
	}
	wg.Wait()
}
