package protocol_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"backupswarm/internal/protocol"
)

func TestMessageType_ReadWriteRoundTrip(t *testing.T) {
	for _, msg := range []protocol.MessageType{
		protocol.MsgPutChunk,
		protocol.MsgDeleteChunk,
		protocol.MsgGetChunk,
	} {
		var buf bytes.Buffer
		if err := protocol.WriteMessageType(&buf, msg); err != nil {
			t.Fatalf("WriteMessageType(%v): %v", msg, err)
		}
		got, err := protocol.ReadMessageType(&buf)
		if err != nil {
			t.Fatalf("ReadMessageType(%v): %v", msg, err)
		}
		if got != msg {
			t.Errorf("type = %v, want %v", got, msg)
		}
	}
}

func TestReadMessageType_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadMessageType(bytes.NewReader(nil)); err == nil {
		t.Error("ReadMessageType accepted empty stream")
	}
}

func TestWriteReadDeleteChunkRequest_RoundTrip(t *testing.T) {
	hash := sha256.Sum256([]byte("delete me"))

	var buf bytes.Buffer
	if err := protocol.WriteDeleteChunkRequest(&buf, hash); err != nil {
		t.Fatalf("WriteDeleteChunkRequest: %v", err)
	}
	got, err := protocol.ReadDeleteChunkRequest(&buf)
	if err != nil {
		t.Fatalf("ReadDeleteChunkRequest: %v", err)
	}
	if got != hash {
		t.Errorf("hash round-trip mismatch: got %x, want %x", got, hash)
	}
}

func TestReadDeleteChunkRequest_RejectsTruncated(t *testing.T) {
	// Only 5 of the 32 bytes of hash.
	_, err := protocol.ReadDeleteChunkRequest(bytes.NewReader(bytes.Repeat([]byte{0xaa}, 5)))
	if err == nil {
		t.Error("ReadDeleteChunkRequest accepted truncated hash")
	}
	if errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		// io.ReadFull returns ErrUnexpectedEOF on partial reads; plain EOF
		// would mean "no bytes at all." The reader should surface some form
		// of short-read error either way.
	}
}

func TestWriteDeleteChunkRequest_PropagatesHashWriteError(t *testing.T) {
	sentinel := errors.New("hash write boom")
	w := &errWriter{failAt: 0, err: sentinel}
	err := protocol.WriteDeleteChunkRequest(w, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestWriteMessageType_PropagatesWriteError(t *testing.T) {
	sentinel := errors.New("msg-type write boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WriteMessageType(w, protocol.MsgPutChunk); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestWriteReadDeleteChunkResponse_Success(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteDeleteChunkResponse(&buf, ""); err != nil {
		t.Fatalf("WriteDeleteChunkResponse: %v", err)
	}
	appErr, err := protocol.ReadDeleteChunkResponse(&buf)
	if err != nil {
		t.Fatalf("ReadDeleteChunkResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
}

func TestWriteReadDeleteChunkResponse_ErrorPath(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteDeleteChunkResponse(&buf, "owner mismatch"); err != nil {
		t.Fatalf("WriteDeleteChunkResponse: %v", err)
	}
	appErr, err := protocol.ReadDeleteChunkResponse(&buf)
	if err != nil {
		t.Fatalf("ReadDeleteChunkResponse: %v", err)
	}
	if appErr != "owner mismatch" {
		t.Errorf("appErr = %q, want %q", appErr, "owner mismatch")
	}
}

func TestReadDeleteChunkResponse_RejectsUnknownStatus(t *testing.T) {
	if _, err := protocol.ReadDeleteChunkResponse(bytes.NewReader([]byte{0xff})); err == nil {
		t.Error("ReadDeleteChunkResponse accepted unknown status byte")
	}
}

func TestReadDeleteChunkResponse_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadDeleteChunkResponse(bytes.NewReader(nil)); err == nil {
		t.Error("ReadDeleteChunkResponse accepted empty stream")
	}
	// Error status, truncated length prefix.
	if _, err := protocol.ReadDeleteChunkResponse(bytes.NewReader([]byte{1, 0x00, 0x00})); err == nil {
		t.Error("ReadDeleteChunkResponse accepted truncated length prefix")
	}
}

func TestReadDeleteChunkResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	if _, err := protocol.ReadDeleteChunkResponse(bytes.NewReader(frame)); err == nil {
		t.Error("ReadDeleteChunkResponse accepted oversized error length")
	}
}

func TestWriteDeleteChunkResponse_PropagatesAllWriteErrors(t *testing.T) {
	// Success path: single status byte write (stage 0).
	sentinel := errors.New("status boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WriteDeleteChunkResponse(w, ""); !errors.Is(err, sentinel) {
		t.Errorf("success-status err = %v, want wraps sentinel", err)
	}
	// Error path: status (0), length (1), body (2).
	for i, name := range []string{"status", "length", "body"} {
		sentinel := errors.New(name + " err boom")
		w := &errWriter{failAt: i, err: sentinel}
		if err := protocol.WriteDeleteChunkResponse(w, "oops"); !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}
