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

func TestReadPutChunkResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	_, _, err := protocol.ReadPutChunkResponse(bytes.NewReader(frame))
	if err == nil {
		t.Error("ReadPutChunkResponse accepted oversized error message length")
	}
}

func TestWriteReadJoinHello_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinHello(&buf, "node-a.internal:7777"); err != nil {
		t.Fatalf("WriteJoinHello: %v", err)
	}
	got, err := protocol.ReadJoinHello(&buf, 1<<10)
	if err != nil {
		t.Fatalf("ReadJoinHello: %v", err)
	}
	if got != "node-a.internal:7777" {
		t.Errorf("addr round-trip = %q", got)
	}
}

func TestWriteJoinHello_AcceptsEmpty(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinHello(&buf, ""); err != nil {
		t.Errorf("WriteJoinHello empty: %v", err)
	}
	got, err := protocol.ReadJoinHello(&buf, 1<<10)
	if err != nil {
		t.Fatalf("ReadJoinHello: %v", err)
	}
	if got != "" {
		t.Errorf("empty roundtrip got %q", got)
	}
}

func TestReadJoinHello_RejectsOversized(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinHello(&buf, "this-is-a-long-address-string"); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_, err := protocol.ReadJoinHello(&buf, 5)
	if err == nil {
		t.Error("ReadJoinHello accepted oversized addr")
	}
}

func TestReadJoinHello_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadJoinHello(bytes.NewReader([]byte{0x00}), 1<<10); err == nil {
		t.Error("ReadJoinHello accepted truncated header")
	}
	frame := []byte{0x00, 0x00, 0x00, 0x0a, 'a', 'b', 'c'}
	if _, err := protocol.ReadJoinHello(bytes.NewReader(frame), 1<<10); err == nil {
		t.Error("ReadJoinHello accepted truncated body")
	}
}

func TestWriteReadJoinAck_Success(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinAck(&buf, ""); err != nil {
		t.Fatalf("WriteJoinAck: %v", err)
	}
	appErr, err := protocol.ReadJoinAck(&buf)
	if err != nil {
		t.Fatalf("ReadJoinAck: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
}

func TestWriteReadJoinAck_ErrorPath(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinAck(&buf, "quota exceeded"); err != nil {
		t.Fatalf("WriteJoinAck: %v", err)
	}
	appErr, err := protocol.ReadJoinAck(&buf)
	if err != nil {
		t.Fatalf("ReadJoinAck: %v", err)
	}
	if appErr != "quota exceeded" {
		t.Errorf("appErr = %q, want %q", appErr, "quota exceeded")
	}
}

func TestReadJoinAck_RejectsUnknownStatus(t *testing.T) {
	if _, err := protocol.ReadJoinAck(bytes.NewReader([]byte{0xff})); err == nil {
		t.Error("ReadJoinAck accepted unknown status byte")
	}
}

func TestReadJoinAck_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadJoinAck(bytes.NewReader(nil)); err == nil {
		t.Error("ReadJoinAck accepted empty stream")
	}
	errFrame := []byte{1, 0x00, 0x00, 0x00, 0x05, 'a', 'b'}
	if _, err := protocol.ReadJoinAck(bytes.NewReader(errFrame)); err == nil {
		t.Error("ReadJoinAck accepted truncated error body")
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

// TestWriteJoinHello_PropagatesHeaderWriteError asserts a header-write failure surfaces from WriteJoinHello.
func TestWriteJoinHello_PropagatesHeaderWriteError(t *testing.T) {
	sentinel := errors.New("hello header boom")
	w := &errWriter{failAt: 0, err: sentinel}
	err := protocol.WriteJoinHello(w, "node-a:1")
	if !errors.Is(err, sentinel) {
		t.Errorf("WriteJoinHello err = %v, want wraps sentinel", err)
	}
}

// TestWriteJoinHello_PropagatesBodyWriteError asserts a body-write failure surfaces from WriteJoinHello.
func TestWriteJoinHello_PropagatesBodyWriteError(t *testing.T) {
	sentinel := errors.New("hello body boom")
	w := &errWriter{failAt: 1, err: sentinel}
	err := protocol.WriteJoinHello(w, "node-a:1")
	if !errors.Is(err, sentinel) {
		t.Errorf("WriteJoinHello err = %v, want wraps sentinel", err)
	}
}

// TestWriteJoinHello_EmptyAddr_NoBodyWrite asserts an empty addr causes only the header write.
func TestWriteJoinHello_EmptyAddr_NoBodyWrite(t *testing.T) {
	sentinel := errors.New("body should not be written")
	w := &errWriter{failAt: 1, err: sentinel}
	if err := protocol.WriteJoinHello(w, ""); err != nil {
		t.Errorf("WriteJoinHello empty addr err = %v, want nil", err)
	}
}

// TestWriteJoinAck_PropagatesSuccessWriteError asserts the status-write error surfaces from WriteJoinAck on the success path.
func TestWriteJoinAck_PropagatesSuccessWriteError(t *testing.T) {
	sentinel := errors.New("ack status boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WriteJoinAck(w, ""); !errors.Is(err, sentinel) {
		t.Errorf("WriteJoinAck success err = %v, want wraps sentinel", err)
	}
}

// TestWriteJoinAck_PropagatesErrorFrameWriteErrors asserts a write failure at every error-frame stage surfaces from WriteJoinAck.
func TestWriteJoinAck_PropagatesErrorFrameWriteErrors(t *testing.T) {
	for i, name := range []string{"status", "length", "body"} {
		sentinel := errors.New(name + " ack err boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WriteJoinAck(w, "quota exceeded")
		if !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

// TestReadJoinAck_RejectsTruncatedErrorLength asserts a truncated error-length prefix is rejected by ReadJoinAck.
func TestReadJoinAck_RejectsTruncatedErrorLength(t *testing.T) {
	frame := []byte{1, 0x00, 0x00}
	if _, err := protocol.ReadJoinAck(bytes.NewReader(frame)); err == nil {
		t.Error("ReadJoinAck accepted truncated error length prefix")
	}
}

// TestReadJoinAck_RejectsOversizedErrorMessage asserts an oversized error length is rejected by ReadJoinAck.
func TestReadJoinAck_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	if _, err := protocol.ReadJoinAck(bytes.NewReader(frame)); err == nil {
		t.Error("ReadJoinAck accepted oversized error length")
	}
}
