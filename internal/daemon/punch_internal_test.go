package daemon

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/nat"
	"backupswarm/internal/peers"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/swarm"
)

// makePunchOrch returns an orchestrator wired to the supplied peerStore
// with a real bsquic listener bound on 127.0.0.1:0 (so PacketConn works).
// Caller closes the listener via t.Cleanup.
func makePunchOrch(t *testing.T, peerStore *peers.Store) *punchOrchestrator {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", priv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	po := newPunchOrchestrator(context.Background(), listener, swarm.NewConnSet(), peerStore, priv, listener.Addr().String())
	po.attempts = 1
	po.interval = time.Microsecond
	return po
}

// punchRequestFrame builds a body containing a PunchPayload for handleRequest.
func punchRequestFrame(t *testing.T, p protocol.PunchPayload) *bytes.Buffer {
	t.Helper()
	buf := &bytes.Buffer{}
	if err := protocol.WritePunchPayload(buf, p); err != nil {
		t.Fatalf("WritePunchPayload: %v", err)
	}
	return buf
}

// readPunchAppErr parses the response written into rwBuf and returns its
// app-error string ("" on OK).
func readPunchAppErr(t *testing.T, rwBuf *bytes.Buffer) string {
	t.Helper()
	appErr, err := protocol.ReadPunchResponse(rwBuf)
	if err != nil {
		t.Fatalf("ReadPunchResponse: %v", err)
	}
	return appErr
}

// rwBuf is a tiny io.ReadWriter that reads from `rd` and writes into `wd`.
type rwBuf struct {
	rd *bytes.Buffer
	wd *bytes.Buffer
}

func (b *rwBuf) Read(p []byte) (int, error)  { return b.rd.Read(p) }
func (b *rwBuf) Write(p []byte) (int, error) { return b.wd.Write(p) }

func TestPunchOrchestrator_HandleRequest_RejectsUnknownTarget(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	po := makePunchOrch(t, ps)
	po.forwardSignal = func(context.Context, []byte, protocol.PunchPayload) error {
		t.Error("forwardSignal called for unknown target")
		return nil
	}
	target := mustGenPub(t)
	var targetArr [32]byte
	copy(targetArr[:], target)
	in := punchRequestFrame(t, protocol.PunchPayload{PeerPub: targetArr, Addr: "203.0.113.1:9000"})
	out := &bytes.Buffer{}
	if err := po.handleRequest(context.Background(), &rwBuf{rd: in, wd: out}, []byte("initiator-pub")); err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if got := readPunchAppErr(t, out); got != "unknown_target" {
		t.Errorf("appErr = %q, want unknown_target", got)
	}
}

func TestPunchOrchestrator_HandleRequest_TargetOffline(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	target := mustGenPub(t)
	if err := ps.Add(peers.Peer{PubKey: target, Role: peers.RoleStorage, Addr: "203.0.113.1:9000"}); err != nil {
		t.Fatalf("ps.Add: %v", err)
	}
	po := makePunchOrch(t, ps)
	// Default forwardSignal hits connSet, which is empty → errPunchTargetOffline.
	var targetArr [32]byte
	copy(targetArr[:], target)
	in := punchRequestFrame(t, protocol.PunchPayload{PeerPub: targetArr, Addr: "203.0.113.2:9000"})
	out := &bytes.Buffer{}
	if err := po.handleRequest(context.Background(), &rwBuf{rd: in, wd: out}, []byte("initiator-pub")); err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if got := readPunchAppErr(t, out); got != "target_offline" {
		t.Errorf("appErr = %q, want target_offline", got)
	}
}

func TestPunchOrchestrator_HandleRequest_HappyPath(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	target := mustGenPub(t)
	if err := ps.Add(peers.Peer{PubKey: target, Role: peers.RoleStorage, Addr: "203.0.113.1:9000"}); err != nil {
		t.Fatalf("ps.Add: %v", err)
	}
	po := makePunchOrch(t, ps)
	var (
		mu            sync.Mutex
		gotTargetPub  []byte
		gotPayloadArg protocol.PunchPayload
		forwardCalled bool
	)
	po.forwardSignal = func(_ context.Context, targetPub []byte, payload protocol.PunchPayload) error {
		mu.Lock()
		defer mu.Unlock()
		gotTargetPub = append([]byte(nil), targetPub...)
		gotPayloadArg = payload
		forwardCalled = true
		return nil
	}
	var targetArr [32]byte
	copy(targetArr[:], target)
	initiatorPub := mustGenPub(t)
	initiatorAddr := "198.51.100.7:51820"
	in := punchRequestFrame(t, protocol.PunchPayload{PeerPub: targetArr, Addr: initiatorAddr})
	out := &bytes.Buffer{}
	if err := po.handleRequest(context.Background(), &rwBuf{rd: in, wd: out}, initiatorPub); err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if got := readPunchAppErr(t, out); got != "" {
		t.Errorf("appErr = %q, want empty (OK)", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if !forwardCalled {
		t.Fatal("forwardSignal not called")
	}
	if !bytes.Equal(gotTargetPub, target) {
		t.Errorf("forwardSignal targetPub = %x, want %x", gotTargetPub, []byte(target))
	}
	if !bytes.Equal(gotPayloadArg.PeerPub[:], initiatorPub) {
		t.Errorf("signal PeerPub = %x, want initiator %x", gotPayloadArg.PeerPub, []byte(initiatorPub))
	}
	if gotPayloadArg.Addr != initiatorAddr {
		t.Errorf("signal Addr = %q, want %q", gotPayloadArg.Addr, initiatorAddr)
	}
}

func TestPunchOrchestrator_HandleRequest_ForwardError(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	target := mustGenPub(t)
	if err := ps.Add(peers.Peer{PubKey: target, Role: peers.RoleStorage, Addr: "203.0.113.1:9000"}); err != nil {
		t.Fatalf("ps.Add: %v", err)
	}
	po := makePunchOrch(t, ps)
	po.forwardSignal = func(context.Context, []byte, protocol.PunchPayload) error {
		return errors.New("network boom")
	}
	var targetArr [32]byte
	copy(targetArr[:], target)
	in := punchRequestFrame(t, protocol.PunchPayload{PeerPub: targetArr, Addr: "198.51.100.7:9000"})
	out := &bytes.Buffer{}
	if err := po.handleRequest(context.Background(), &rwBuf{rd: in, wd: out}, []byte("initiator-pub")); err != nil {
		t.Fatalf("handleRequest: %v", err)
	}
	if got := readPunchAppErr(t, out); got != "internal" {
		t.Errorf("appErr = %q, want internal", got)
	}
}

func TestPunchOrchestrator_HandleSignal_InvalidAddr(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	po := makePunchOrch(t, ps)
	prev := punchFireFn
	punchFireFn = func(context.Context, nat.PacketWriter, *net.UDPAddr, int, time.Duration) error {
		t.Error("punchFireFn called despite invalid addr")
		return nil
	}
	t.Cleanup(func() { punchFireFn = prev })

	var initArr [32]byte
	copy(initArr[:], mustGenPub(t))
	in := punchRequestFrame(t, protocol.PunchPayload{PeerPub: initArr, Addr: "not a valid addr"})
	out := &bytes.Buffer{}
	if err := po.handleSignal(context.Background(), &rwBuf{rd: in, wd: out}, nil); err != nil {
		t.Fatalf("handleSignal: %v", err)
	}
	if got := readPunchAppErr(t, out); got != "invalid_addr" {
		t.Errorf("appErr = %q, want invalid_addr", got)
	}
}

func TestPunchOrchestrator_HandleSignal_HappyPath(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	po := makePunchOrch(t, ps)

	gotTarget := make(chan *net.UDPAddr, 1)
	prev := punchFireFn
	punchFireFn = func(_ context.Context, _ nat.PacketWriter, target *net.UDPAddr, _ int, _ time.Duration) error {
		gotTarget <- target
		return nil
	}
	t.Cleanup(func() { punchFireFn = prev })

	var initArr [32]byte
	copy(initArr[:], mustGenPub(t))
	in := punchRequestFrame(t, protocol.PunchPayload{PeerPub: initArr, Addr: "203.0.113.42:51820"})
	out := &bytes.Buffer{}
	if err := po.handleSignal(context.Background(), &rwBuf{rd: in, wd: out}, nil); err != nil {
		t.Fatalf("handleSignal: %v", err)
	}
	if got := readPunchAppErr(t, out); got != "" {
		t.Errorf("appErr = %q, want empty (OK)", got)
	}
	po.pendingPunches.Wait()
	select {
	case a := <-gotTarget:
		if a.String() != "203.0.113.42:51820" {
			t.Errorf("punch target = %s, want 203.0.113.42:51820", a)
		}
	default:
		t.Fatal("punchFireFn was not called")
	}
}

// handleSignal's target-side punch goroutine logs a warning and exits
// cleanly when punchFireFn errors.
func TestPunchOrchestrator_HandleSignal_PunchGoroutineLogsError(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	po := makePunchOrch(t, ps)

	w := &syncWriter{}
	captureSlog(t, w)

	prev := punchFireFn
	punchFireFn = func(context.Context, nat.PacketWriter, *net.UDPAddr, int, time.Duration) error {
		return errors.New("punch boom")
	}
	t.Cleanup(func() { punchFireFn = prev })

	var initArr [32]byte
	copy(initArr[:], mustGenPub(t))
	in := punchRequestFrame(t, protocol.PunchPayload{PeerPub: initArr, Addr: "203.0.113.42:51820"})
	out := &bytes.Buffer{}
	if err := po.handleSignal(context.Background(), &rwBuf{rd: in, wd: out}, nil); err != nil {
		t.Fatalf("handleSignal: %v", err)
	}
	po.pendingPunches.Wait()
	logged := w.String()
	if !strings.Contains(logged, "nat_punch failed") {
		t.Errorf("missing nat_punch failed log: %q", logged)
	}
	if !strings.Contains(logged, "punch boom") {
		t.Errorf("missing wrapped error in log: %q", logged)
	}
}

// RequestPunch returns an error when the target is not in peerStore.
func TestPunchOrchestrator_RequestPunch_UnknownTarget(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	po := makePunchOrch(t, ps)

	stranger := mustGenPub(t)
	conn, err := po.RequestPunch(context.Background(), stranger, nil)
	if err == nil {
		t.Fatal("RequestPunch accepted unknown target")
	}
	if conn != nil {
		t.Errorf("RequestPunch returned non-nil conn on error")
	}
	if !strings.Contains(err.Error(), "unknown target") {
		t.Errorf("err = %v, want contains 'unknown target'", err)
	}
}

// RequestPunch errors when the stored target peer has no advertise addr.
func TestPunchOrchestrator_RequestPunch_TargetEmptyAddr(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	target := mustGenPub(t)
	if err := ps.Add(peers.Peer{PubKey: target, Role: peers.RoleStorage, Addr: ""}); err != nil {
		t.Fatalf("ps.Add: %v", err)
	}
	po := makePunchOrch(t, ps)

	conn, err := po.RequestPunch(context.Background(), target, nil)
	if err == nil {
		t.Fatal("RequestPunch accepted target with empty addr")
	}
	if conn != nil {
		t.Errorf("RequestPunch returned non-nil conn on error")
	}
	if !strings.Contains(err.Error(), "no advertise addr") {
		t.Errorf("err = %v, want contains 'no advertise addr'", err)
	}
}

// RequestPunch errors when the orchestrator's own advertiseAddr is empty.
func TestPunchOrchestrator_RequestPunch_OwnEmptyAdvertiseAddr(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	target := mustGenPub(t)
	if err := ps.Add(peers.Peer{PubKey: target, Role: peers.RoleStorage, Addr: "203.0.113.1:9000"}); err != nil {
		t.Fatalf("ps.Add: %v", err)
	}
	po := makePunchOrch(t, ps)
	po.advertiseAddr = ""

	conn, err := po.RequestPunch(context.Background(), target, nil)
	if err == nil {
		t.Fatal("RequestPunch accepted empty own advertiseAddr")
	}
	if conn != nil {
		t.Errorf("RequestPunch returned non-nil conn on error")
	}
	if !strings.Contains(err.Error(), "own advertise addr is empty") {
		t.Errorf("err = %v, want contains 'own advertise addr is empty'", err)
	}
}

// RequestPunch wraps the punchSendRequestFn error.
func TestPunchOrchestrator_RequestPunch_SendRequestFails(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	target := mustGenPub(t)
	if err := ps.Add(peers.Peer{PubKey: target, Role: peers.RoleStorage, Addr: "203.0.113.1:9000"}); err != nil {
		t.Fatalf("ps.Add: %v", err)
	}
	po := makePunchOrch(t, ps)

	prevSend := punchSendRequestFn
	sentinel := errors.New("send req boom")
	punchSendRequestFn = func(context.Context, *bsquic.Conn, protocol.PunchPayload) error {
		return sentinel
	}
	t.Cleanup(func() { punchSendRequestFn = prevSend })

	conn, err := po.RequestPunch(context.Background(), target, nil)
	if err == nil {
		t.Fatal("RequestPunch ignored send-request error")
	}
	if conn != nil {
		t.Errorf("RequestPunch returned non-nil conn on error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

// RequestPunch wraps the net.ResolveUDPAddr error when the stored
// target.Addr is non-empty but unparseable.
func TestPunchOrchestrator_RequestPunch_ResolveTargetFails(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	target := mustGenPub(t)
	if err := ps.Add(peers.Peer{PubKey: target, Role: peers.RoleStorage, Addr: "not-a-udp-addr"}); err != nil {
		t.Fatalf("ps.Add: %v", err)
	}
	po := makePunchOrch(t, ps)

	prevSend := punchSendRequestFn
	punchSendRequestFn = func(context.Context, *bsquic.Conn, protocol.PunchPayload) error {
		return nil
	}
	t.Cleanup(func() { punchSendRequestFn = prevSend })

	conn, err := po.RequestPunch(context.Background(), target, nil)
	if err == nil {
		t.Fatal("RequestPunch accepted unresolvable target addr")
	}
	if conn != nil {
		t.Errorf("RequestPunch returned non-nil conn on error")
	}
	if !strings.Contains(err.Error(), "resolve target") {
		t.Errorf("err = %v, want contains 'resolve target'", err)
	}
}

// RequestPunch wraps a punchFireFn failure.
func TestPunchOrchestrator_RequestPunch_FireFails(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	target := mustGenPub(t)
	if err := ps.Add(peers.Peer{PubKey: target, Role: peers.RoleStorage, Addr: "203.0.113.1:9000"}); err != nil {
		t.Fatalf("ps.Add: %v", err)
	}
	po := makePunchOrch(t, ps)

	prevSend := punchSendRequestFn
	punchSendRequestFn = func(context.Context, *bsquic.Conn, protocol.PunchPayload) error {
		return nil
	}
	t.Cleanup(func() { punchSendRequestFn = prevSend })

	prevFire := punchFireFn
	sentinel := errors.New("fire boom")
	punchFireFn = func(context.Context, nat.PacketWriter, *net.UDPAddr, int, time.Duration) error {
		return sentinel
	}
	t.Cleanup(func() { punchFireFn = prevFire })

	conn, err := po.RequestPunch(context.Background(), target, nil)
	if err == nil {
		t.Fatal("RequestPunch ignored fire error")
	}
	if conn != nil {
		t.Errorf("RequestPunch returned non-nil conn on error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

// RequestPunch wraps a punchDialFn failure that occurs after fire succeeds.
func TestPunchOrchestrator_RequestPunch_DialFails(t *testing.T) {
	ps, err := peers.Open(filepath.Join(t.TempDir(), "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	t.Cleanup(func() { _ = ps.Close() })
	target := mustGenPub(t)
	if err := ps.Add(peers.Peer{PubKey: target, Role: peers.RoleStorage, Addr: "203.0.113.1:9000"}); err != nil {
		t.Fatalf("ps.Add: %v", err)
	}
	po := makePunchOrch(t, ps)

	prevSend := punchSendRequestFn
	punchSendRequestFn = func(context.Context, *bsquic.Conn, protocol.PunchPayload) error {
		return nil
	}
	t.Cleanup(func() { punchSendRequestFn = prevSend })

	prevFire := punchFireFn
	punchFireFn = func(context.Context, nat.PacketWriter, *net.UDPAddr, int, time.Duration) error {
		return nil
	}
	t.Cleanup(func() { punchFireFn = prevFire })

	prevDial := punchDialFn
	sentinel := errors.New("dial boom")
	punchDialFn = func(context.Context, string, ed25519.PrivateKey, ed25519.PublicKey, *bsquic.TrustConfig) (*bsquic.Conn, error) {
		return nil, sentinel
	}
	t.Cleanup(func() { punchDialFn = prevDial })

	conn, err := po.RequestPunch(context.Background(), target, nil)
	if err == nil {
		t.Fatal("RequestPunch ignored dial error")
	}
	if conn != nil {
		t.Errorf("RequestPunch returned non-nil conn on error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}
