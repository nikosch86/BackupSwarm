package swarm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
)

// withStoreAddFunc swaps storeAddFunc for the duration of a test.
func withStoreAddFunc(t *testing.T, fn func(s *peers.Store, p peers.Peer) error) {
	t.Helper()
	prev := storeAddFunc
	storeAddFunc = fn
	t.Cleanup(func() { storeAddFunc = prev })
}

// withWriteMsgTypeFunc swaps writeMsgTypeFunc for the duration of a test.
func withWriteMsgTypeFunc(t *testing.T, fn func(io.Writer, protocol.MessageType) error) {
	t.Helper()
	prev := writeMsgTypeFunc
	writeMsgTypeFunc = fn
	t.Cleanup(func() { writeMsgTypeFunc = prev })
}

// withWriteAnnouncementFrame swaps writeAnnouncementFrame for the duration of a test.
func withWriteAnnouncementFrame(t *testing.T, fn func(io.Writer, protocol.PeerAnnouncement) error) {
	t.Helper()
	prev := writeAnnouncementFrame
	writeAnnouncementFrame = fn
	t.Cleanup(func() { writeAnnouncementFrame = prev })
}

// withRandReadFunc swaps randReadFunc for the duration of a test.
func withRandReadFunc(t *testing.T, fn func([]byte) (int, error)) {
	t.Helper()
	prev := randReadFunc
	randReadFunc = fn
	t.Cleanup(func() { randReadFunc = prev })
}

// TestBroadcastPeerJoined_RandReadErrorSurfacesWrapped exercises the
// rand.Read failure branch.
func TestBroadcastPeerJoined_RandReadErrorSurfacesWrapped(t *testing.T) {
	sentinel := errors.New("forced rand failure")
	withRandReadFunc(t, func([]byte) (int, error) { return 0, sentinel })

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	joiner := peers.Peer{Addr: "192.0.2.7:9000", PubKey: pub, Role: peers.RolePeer}
	gotErr := BroadcastPeerJoined(context.Background(), nil, joiner)
	if gotErr == nil {
		t.Fatal("BroadcastPeerJoined succeeded despite injected rand failure")
	}
	if !errors.Is(gotErr, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", gotErr)
	}
}

func openInternalStore(t *testing.T) *peers.Store {
	t.Helper()
	s, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func mustInternalKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub
}

func pubArrayInternal(pub ed25519.PublicKey) [32]byte {
	var arr [32]byte
	copy(arr[:], pub)
	return arr
}

// TestApply_PeerJoined_AddErrorSurfacesWrapped covers the Add-failure
// branch on PeerJoined when the store rejects the new record.
func TestApply_PeerJoined_AddErrorSurfacesWrapped(t *testing.T) {
	store := openInternalStore(t)
	sentinel := errors.New("forced add failure")
	withStoreAddFunc(t, func(s *peers.Store, p peers.Peer) error { return sentinel })

	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		PubKey: pubArrayInternal(mustInternalKey(t)),
		Role:   byte(peers.RolePeer),
		Addr:   "10.0.0.5:4242",
	}
	err := Apply(ann, store)
	if err == nil {
		t.Fatal("Apply succeeded despite injected Add failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Apply err = %v, want wraps sentinel", err)
	}
}

// TestApply_AddressChanged_AddErrorSurfacesWrapped covers the Add-failure
// branch on AddressChanged after a successful Get.
func TestApply_AddressChanged_AddErrorSurfacesWrapped(t *testing.T) {
	store := openInternalStore(t)
	pub := mustInternalKey(t)
	if err := store.Add(peers.Peer{Addr: "10.0.0.1:1", PubKey: pub, Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("seed Add: %v", err)
	}

	sentinel := errors.New("forced add failure")
	withStoreAddFunc(t, func(s *peers.Store, p peers.Peer) error { return sentinel })

	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnounceAddressChanged,
		PubKey: pubArrayInternal(pub),
		Addr:   "192.0.2.7:9000",
	}
	err := Apply(ann, store)
	if err == nil {
		t.Fatal("Apply succeeded despite injected Add failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("Apply err = %v, want wraps sentinel", err)
	}
}

// internalQuicPair is a minimal listener/dial rig for the internal test
// package; it cannot share helpers with the external swarm_test package.
type internalQuicPair struct {
	introSide *bsquic.Conn
	subSide   *bsquic.Conn
}

func setupInternalQuicPair(t *testing.T) *internalQuicPair {
	t.Helper()
	introPub, introPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("intro key: %v", err)
	}
	l, err := bsquic.Listen("127.0.0.1:0", introPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })

	_, subPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("sub key: %v", err)
	}

	dialedCh := make(chan *bsquic.Conn, 1)
	dialErrCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := bsquic.Dial(ctx, l.Addr().String(), subPriv, introPub, nil)
		if err != nil {
			dialErrCh <- err
			return
		}
		dialedCh <- c
	}()
	acceptCtx, acceptCancel := context.WithTimeout(context.Background(), 5*time.Second)
	introConn, err := l.Accept(acceptCtx)
	acceptCancel()
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	var subConn *bsquic.Conn
	select {
	case subConn = <-dialedCh:
	case err := <-dialErrCh:
		t.Fatalf("Dial: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("Dial timed out")
	}
	t.Cleanup(func() {
		_ = introConn.Close()
		_ = subConn.Close()
	})
	return &internalQuicPair{introSide: introConn, subSide: subConn}
}

// drainAcceptedStream eagerly reads the inbound stream so that QUIC's
// flow control completes the broadcast on the sender side.
func drainAcceptedStream(t *testing.T, sub *bsquic.Conn) {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		s, err := sub.AcceptStream(ctx)
		if err != nil {
			return
		}
		defer func() { _ = s.Close() }()
		_, _ = io.Copy(io.Discard, s)
	}()
	t.Cleanup(wg.Wait)
}

// TestSendAnnouncement_WriteMessageTypeError exercises the
// WriteMessageType error branch via the writeMsgTypeFunc seam.
func TestSendAnnouncement_WriteMessageTypeError(t *testing.T) {
	rig := setupInternalQuicPair(t)
	drainAcceptedStream(t, rig.subSide)

	sentinel := errors.New("forced msg type write failure")
	withWriteMsgTypeFunc(t, func(io.Writer, protocol.MessageType) error { return sentinel })

	joinerPub := mustInternalKey(t)
	joiner := peers.Peer{Addr: "192.0.2.7:9000", PubKey: joinerPub, Role: peers.RolePeer}
	if err := BroadcastPeerJoined(context.Background(), []*bsquic.Conn{rig.introSide}, joiner); err != nil {
		t.Fatalf("BroadcastPeerJoined: %v", err)
	}
}

// TestSendAnnouncement_WriteFrameError exercises the WriteAnnouncement
// frame error branch via the writeAnnouncementFrame seam.
func TestSendAnnouncement_WriteFrameError(t *testing.T) {
	rig := setupInternalQuicPair(t)
	drainAcceptedStream(t, rig.subSide)

	sentinel := errors.New("forced frame write failure")
	withWriteAnnouncementFrame(t, func(io.Writer, protocol.PeerAnnouncement) error { return sentinel })

	joinerPub := mustInternalKey(t)
	joiner := peers.Peer{Addr: "192.0.2.7:9000", PubKey: joinerPub, Role: peers.RolePeer}
	if err := BroadcastPeerJoined(context.Background(), []*bsquic.Conn{rig.introSide}, joiner); err != nil {
		t.Fatalf("BroadcastPeerJoined: %v", err)
	}
}
