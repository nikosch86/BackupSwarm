package protocol_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"backupswarm/internal/protocol"
)

func TestWriteReadPutChunkRequest_RoundTrip(t *testing.T) {
	blob := []byte("opaque encrypted chunk bytes")

	var buf bytes.Buffer
	if err := protocol.WritePutChunkRequest(&buf, blob); err != nil {
		t.Fatalf("WritePutChunkRequest: %v", err)
	}
	got, err := protocol.ReadPutChunkRequest(&buf, 1<<20)
	if err != nil {
		t.Fatalf("ReadPutChunkRequest: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("round-trip blob mismatch: got %q, want %q", got, blob)
	}
}

func TestReadPutChunkRequest_RejectsOversizedBlob(t *testing.T) {
	blob := []byte("this payload is slightly too big")

	var buf bytes.Buffer
	if err := protocol.WritePutChunkRequest(&buf, blob); err != nil {
		t.Fatalf("WritePutChunkRequest: %v", err)
	}
	_, err := protocol.ReadPutChunkRequest(&buf, len(blob)-1)
	if err == nil {
		t.Fatal("ReadPutChunkRequest accepted an oversized blob")
	}
	if !errors.Is(err, protocol.ErrBlobTooLarge) {
		t.Errorf("ReadPutChunkRequest err = %v, want ErrBlobTooLarge", err)
	}
}

func TestReadPutChunkRequest_RejectsTruncatedHeader(t *testing.T) {
	_, err := protocol.ReadPutChunkRequest(bytes.NewReader([]byte{0x00, 0x00}), 1<<20)
	if err == nil {
		t.Error("ReadPutChunkRequest accepted truncated header")
	}
}

func TestReadPutChunkRequest_RejectsTruncatedBody(t *testing.T) {
	frame := []byte{0x00, 0x00, 0x00, 0x0a, 0xaa, 0xbb, 0xcc}
	_, err := protocol.ReadPutChunkRequest(bytes.NewReader(frame), 1<<20)
	if err == nil {
		t.Error("ReadPutChunkRequest accepted truncated body")
	}
}

func TestWriteReadPutChunkResponse_Success(t *testing.T) {
	hash := sha256.Sum256([]byte("blob"))

	var buf bytes.Buffer
	if err := protocol.WritePutChunkResponse(&buf, hash, ""); err != nil {
		t.Fatalf("WritePutChunkResponse: %v", err)
	}
	gotHash, appErr, err := protocol.ReadPutChunkResponse(&buf)
	if err != nil {
		t.Fatalf("ReadPutChunkResponse: %v", err)
	}
	if gotHash != hash {
		t.Errorf("hash mismatch after round-trip")
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
}

func TestWriteReadPutChunkResponse_ErrorPath(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePutChunkResponse(&buf, [32]byte{}, "store is full"); err != nil {
		t.Fatalf("WritePutChunkResponse: %v", err)
	}
	_, appErr, err := protocol.ReadPutChunkResponse(&buf)
	if err != nil {
		t.Fatalf("ReadPutChunkResponse: %v", err)
	}
	if appErr != "store is full" {
		t.Errorf("appErr = %q, want %q", appErr, "store is full")
	}
}

func TestReadPutChunkResponse_RejectsTruncated(t *testing.T) {
	_, _, err := protocol.ReadPutChunkResponse(bytes.NewReader(nil))
	if err == nil {
		t.Error("ReadPutChunkResponse accepted empty stream")
	}
	if errors.Is(err, io.EOF) {
	}

	partial := append([]byte{0}, bytes.Repeat([]byte{0xaa}, 5)...)
	if _, _, err := protocol.ReadPutChunkResponse(bytes.NewReader(partial)); err == nil {
		t.Error("ReadPutChunkResponse accepted truncated success body")
	}

	errFrame := []byte{1, 0x00, 0x00, 0x00, 0x0a, 'a', 'b', 'c'}
	if _, _, err := protocol.ReadPutChunkResponse(bytes.NewReader(errFrame)); err == nil {
		t.Error("ReadPutChunkResponse accepted truncated error body")
	}
}

func TestReadPutChunkResponse_RejectsUnknownStatus(t *testing.T) {
	frame := []byte{0xff}
	_, _, err := protocol.ReadPutChunkResponse(bytes.NewReader(frame))
	if err == nil {
		t.Error("ReadPutChunkResponse accepted unknown status byte")
	}
}

// errWriter returns err on its N-th Write call (0-indexed) and succeeds on every other call.
type errWriter struct {
	failAt int
	err    error
	calls  int
}

func (w *errWriter) Write(p []byte) (int, error) {
	defer func() { w.calls++ }()
	if w.calls == w.failAt {
		return 0, w.err
	}
	return len(p), nil
}

func TestWritePutChunkRequest_PropagatesHeaderWriteError(t *testing.T) {
	sentinel := errors.New("header write boom")
	w := &errWriter{failAt: 0, err: sentinel}
	err := protocol.WritePutChunkRequest(w, []byte("payload"))
	if err == nil {
		t.Fatal("WritePutChunkRequest returned nil on header-write error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("WritePutChunkRequest err = %v, want wraps sentinel", err)
	}
}

func TestWritePutChunkRequest_PropagatesBodyWriteError(t *testing.T) {
	sentinel := errors.New("body write boom")
	w := &errWriter{failAt: 1, err: sentinel}
	err := protocol.WritePutChunkRequest(w, []byte("payload"))
	if err == nil {
		t.Fatal("WritePutChunkRequest returned nil on body-write error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("WritePutChunkRequest err = %v, want wraps sentinel", err)
	}
}

func TestWritePutChunkResponse_PropagatesSuccessWriteErrors(t *testing.T) {
	sentinel := errors.New("status write boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WritePutChunkResponse(w, [32]byte{}, ""); !errors.Is(err, sentinel) {
		t.Errorf("status write err = %v, want wraps sentinel", err)
	}
	sentinel2 := errors.New("hash write boom")
	w = &errWriter{failAt: 1, err: sentinel2}
	if err := protocol.WritePutChunkResponse(w, [32]byte{}, ""); !errors.Is(err, sentinel2) {
		t.Errorf("hash write err = %v, want wraps sentinel2", err)
	}
}

func TestWritePutChunkResponse_PropagatesErrorFrameWriteErrors(t *testing.T) {
	for i, name := range []string{"status", "length", "body"} {
		sentinel := errors.New(name + " write boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WritePutChunkResponse(w, [32]byte{}, "oops")
		if !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

// TestMessageType_DistinctValues asserts every MessageType has a unique
// byte and lists them by hand so a future addition collides loudly.
func TestMessageType_DistinctValues(t *testing.T) {
	want := map[protocol.MessageType]string{
		protocol.MsgPutChunk:         "MsgPutChunk",
		protocol.MsgDeleteChunk:      "MsgDeleteChunk",
		protocol.MsgGetChunk:         "MsgGetChunk",
		protocol.MsgPeerAnnouncement: "MsgPeerAnnouncement",
		protocol.MsgJoinRequest:      "MsgJoinRequest",
	}
	if got := len(want); got != 5 {
		t.Errorf("expected 5 distinct message types, got %d", got)
	}
}

func TestJoinRequestMessageType_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteMessageType(&buf, protocol.MsgJoinRequest); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	got, err := protocol.ReadMessageType(&buf)
	if err != nil {
		t.Fatalf("ReadMessageType: %v", err)
	}
	if got != protocol.MsgJoinRequest {
		t.Errorf("type = %v, want MsgJoinRequest", got)
	}
}

func TestReadPutChunkResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	_, _, err := protocol.ReadPutChunkResponse(bytes.NewReader(frame))
	if err == nil {
		t.Error("ReadPutChunkResponse accepted oversized error message length")
	}
}

func TestWritePutChunkRequest_RejectsEmptyBlob(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePutChunkRequest(&buf, nil); err == nil {
		t.Error("WritePutChunkRequest accepted nil blob")
	}
	if err := protocol.WritePutChunkRequest(&buf, []byte{}); err == nil {
		t.Error("WritePutChunkRequest accepted empty blob")
	}
}

// TestWriteJoinResponse_PropagatesSuccessWriteError covers the status-write
// failure on the success path.
func TestWriteJoinResponse_PropagatesSuccessWriteError(t *testing.T) {
	sentinel := errors.New("response status boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WriteJoinResponse(w, nil, ""); !errors.Is(err, sentinel) {
		t.Errorf("WriteJoinResponse success err = %v, want wraps sentinel", err)
	}
}

// TestWriteJoinResponse_PropagatesErrorFrameWriteErrors covers a write
// failure at every error-frame stage.
func TestWriteJoinResponse_PropagatesErrorFrameWriteErrors(t *testing.T) {
	for i, name := range []string{"status", "length", "body"} {
		sentinel := errors.New(name + " response err boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WriteJoinResponse(w, nil, "swarm_mismatch")
		if !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

func TestReadJoinResponse_RejectsTruncatedErrorLength(t *testing.T) {
	frame := []byte{1, 0x00, 0x00}
	if _, _, err := protocol.ReadJoinResponse(bytes.NewReader(frame), 1<<12); err == nil {
		t.Error("ReadJoinResponse accepted truncated error length prefix")
	}
}

func TestReadJoinResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	if _, _, err := protocol.ReadJoinResponse(bytes.NewReader(frame), 1<<12); err == nil {
		t.Error("ReadJoinResponse accepted oversized error length")
	}
}

// TestWriteJoinRequest_PropagatesWriteErrors covers a write failure at
// every stage of the join request frame.
func TestWriteJoinRequest_PropagatesWriteErrors(t *testing.T) {
	for i, name := range []string{"swarm", "secret", "addrLen", "addrBody"} {
		sentinel := errors.New(name + " request boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WriteJoinRequest(w, [32]byte{}, [32]byte{}, "x", nil)
		if !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

// TestWritePeerListMessage_PropagatesEntryWriteError covers a failure
// on each entry-stage write.
func TestWritePeerListMessage_PropagatesEntryWriteError(t *testing.T) {
	in := []protocol.PeerEntry{{PubKey: filledArray(0x11), Role: 1, Addr: "x"}}
	for i, name := range []string{"count", "pubkey", "role", "addrLen", "addr"} {
		sentinel := errors.New(name + " peer entry boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WritePeerListMessage(w, in)
		if !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

func filledArray(b byte) [32]byte {
	var a [32]byte
	for i := range a {
		a[i] = b
	}
	return a
}

func TestWriteReadJoinRequest_RoundTrip(t *testing.T) {
	swarmID := filledArray(0xAA)
	secret := filledArray(0xBB)

	var buf bytes.Buffer
	if err := protocol.WriteJoinRequest(&buf, swarmID, secret, "node-a.internal:7777", nil); err != nil {
		t.Fatalf("WriteJoinRequest: %v", err)
	}
	gotSwarm, gotSecret, gotAddr, _, err := protocol.ReadJoinRequest(&buf, 1<<10, 1<<12)
	if err != nil {
		t.Fatalf("ReadJoinRequest: %v", err)
	}
	if gotSwarm != swarmID {
		t.Error("swarm round-trip mismatch")
	}
	if gotSecret != secret {
		t.Error("secret round-trip mismatch")
	}
	if gotAddr != "node-a.internal:7777" {
		t.Errorf("addr = %q", gotAddr)
	}
}

func TestWriteReadJoinRequest_AcceptsEmptyAddr(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinRequest(&buf, [32]byte{}, [32]byte{}, "", nil); err != nil {
		t.Fatalf("WriteJoinRequest: %v", err)
	}
	_, _, addr, _, err := protocol.ReadJoinRequest(&buf, 1<<10, 1<<12)
	if err != nil {
		t.Fatalf("ReadJoinRequest: %v", err)
	}
	if addr != "" {
		t.Errorf("addr = %q, want empty", addr)
	}
}

func TestReadJoinRequest_RejectsTruncated(t *testing.T) {
	if _, _, _, _, err := protocol.ReadJoinRequest(bytes.NewReader([]byte{0x00}), 1<<10, 1<<12); err == nil {
		t.Error("ReadJoinRequest accepted truncated swarmID")
	}
	tooShort := append(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 30)...)
	if _, _, _, _, err := protocol.ReadJoinRequest(bytes.NewReader(tooShort), 1<<10, 1<<12); err == nil {
		t.Error("ReadJoinRequest accepted truncated secret")
	}
	missingAddrLen := append(bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)...)
	if _, _, _, _, err := protocol.ReadJoinRequest(bytes.NewReader(missingAddrLen), 1<<10, 1<<12); err == nil {
		t.Error("ReadJoinRequest accepted missing addr length")
	}
	bodyShort := append(missingAddrLen, 0x00, 0x00, 0x00, 0x05, 'a', 'b')
	if _, _, _, _, err := protocol.ReadJoinRequest(bytes.NewReader(bodyShort), 1<<10, 1<<12); err == nil {
		t.Error("ReadJoinRequest accepted truncated addr body")
	}
}

func TestReadJoinRequest_RejectsOversizedAddr(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinRequest(&buf, [32]byte{}, [32]byte{}, "this-addr-is-too-long", nil); err != nil {
		t.Fatalf("WriteJoinRequest: %v", err)
	}
	if _, _, _, _, err := protocol.ReadJoinRequest(&buf, 5, 1<<12); err == nil {
		t.Error("ReadJoinRequest accepted oversized addr")
	}
}

func TestWriteReadJoinResponse_Success(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinResponse(&buf, nil, ""); err != nil {
		t.Fatalf("WriteJoinResponse: %v", err)
	}
	_, appErr, err := protocol.ReadJoinResponse(&buf, 1<<12)
	if err != nil {
		t.Fatalf("ReadJoinResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
}

func TestWriteReadJoinResponse_ErrorPath(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinResponse(&buf, nil, "swarm_mismatch"); err != nil {
		t.Fatalf("WriteJoinResponse: %v", err)
	}
	_, appErr, err := protocol.ReadJoinResponse(&buf, 1<<12)
	if err != nil {
		t.Fatalf("ReadJoinResponse: %v", err)
	}
	if appErr != "swarm_mismatch" {
		t.Errorf("appErr = %q", appErr)
	}
}

func TestReadJoinResponse_RejectsUnknownStatus(t *testing.T) {
	if _, _, err := protocol.ReadJoinResponse(bytes.NewReader([]byte{0xff}), 1<<12); err == nil {
		t.Error("ReadJoinResponse accepted unknown status byte")
	}
}

func TestReadJoinResponse_RejectsTruncated(t *testing.T) {
	if _, _, err := protocol.ReadJoinResponse(bytes.NewReader(nil), 1<<12); err == nil {
		t.Error("ReadJoinResponse accepted empty stream")
	}
	frame := []byte{1, 0x00, 0x00, 0x00, 0x05, 'a', 'b'}
	if _, _, err := protocol.ReadJoinResponse(bytes.NewReader(frame), 1<<12); err == nil {
		t.Error("ReadJoinResponse accepted truncated error body")
	}
}

func samplePeerEntries() []protocol.PeerEntry {
	return []protocol.PeerEntry{
		{PubKey: filledArray(0x11), Role: 1, Addr: "10.0.0.1:7777"},
		{PubKey: filledArray(0x22), Role: 2, Addr: "10.0.0.2:7777"},
		{PubKey: filledArray(0x33), Role: 3, Addr: ""},
	}
}

func TestWriteReadPeerListMessage_RoundTrip(t *testing.T) {
	in := samplePeerEntries()

	var buf bytes.Buffer
	if err := protocol.WritePeerListMessage(&buf, in); err != nil {
		t.Fatalf("WritePeerListMessage: %v", err)
	}
	out, err := protocol.ReadPeerListMessage(&buf, 1<<10, 1<<10)
	if err != nil {
		t.Fatalf("ReadPeerListMessage: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("entry count = %d, want %d", len(out), len(in))
	}
	for i := range in {
		if out[i].PubKey != in[i].PubKey {
			t.Errorf("entry %d pubkey mismatch", i)
		}
		if out[i].Role != in[i].Role {
			t.Errorf("entry %d role = %d, want %d", i, out[i].Role, in[i].Role)
		}
		if out[i].Addr != in[i].Addr {
			t.Errorf("entry %d addr = %q, want %q", i, out[i].Addr, in[i].Addr)
		}
	}
}

func TestWriteReadPeerListMessage_EmptyList(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePeerListMessage(&buf, nil); err != nil {
		t.Fatalf("WritePeerListMessage: %v", err)
	}
	out, err := protocol.ReadPeerListMessage(&buf, 1<<10, 1<<10)
	if err != nil {
		t.Fatalf("ReadPeerListMessage: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("len(out) = %d, want 0", len(out))
	}
}

func TestWritePeerListMessage_RejectsZeroRole(t *testing.T) {
	bad := []protocol.PeerEntry{{PubKey: filledArray(0x11), Role: 0, Addr: "x"}}
	if err := protocol.WritePeerListMessage(&bytes.Buffer{}, bad); err == nil {
		t.Error("WritePeerListMessage accepted zero role")
	}
}

func TestReadPeerListMessage_RejectsZeroRole(t *testing.T) {
	frame := []byte{0, 0, 0, 1}
	frame = append(frame, bytes.Repeat([]byte{0x11}, 32)...)
	frame = append(frame, 0x00)
	frame = append(frame, 0, 0, 0, 0)
	if _, err := protocol.ReadPeerListMessage(bytes.NewReader(frame), 1<<10, 1<<10); err == nil {
		t.Error("ReadPeerListMessage accepted zero role")
	}
}

func TestReadPeerListMessage_RejectsOversizedCount(t *testing.T) {
	frame := []byte{0, 0, 0, 5}
	if _, err := protocol.ReadPeerListMessage(bytes.NewReader(frame), 4, 1<<10); err == nil {
		t.Error("ReadPeerListMessage accepted oversized count")
	}
}

func TestReadPeerListMessage_RejectsOversizedAddr(t *testing.T) {
	in := []protocol.PeerEntry{{PubKey: filledArray(0x11), Role: 1, Addr: "way-too-long-to-fit"}}
	var buf bytes.Buffer
	if err := protocol.WritePeerListMessage(&buf, in); err != nil {
		t.Fatalf("WritePeerListMessage: %v", err)
	}
	if _, err := protocol.ReadPeerListMessage(&buf, 1<<10, 5); err == nil {
		t.Error("ReadPeerListMessage accepted oversized addr")
	}
}

func TestReadPeerListMessage_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadPeerListMessage(bytes.NewReader([]byte{0, 0}), 1<<10, 1<<10); err == nil {
		t.Error("ReadPeerListMessage accepted truncated count header")
	}
	frame := []byte{0, 0, 0, 1}
	frame = append(frame, bytes.Repeat([]byte{0x11}, 31)...)
	if _, err := protocol.ReadPeerListMessage(bytes.NewReader(frame), 1<<10, 1<<10); err == nil {
		t.Error("ReadPeerListMessage accepted truncated pubkey")
	}
}
