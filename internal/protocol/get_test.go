package protocol_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"backupswarm/internal/protocol"
)

func TestWriteReadGetChunkRequest_RoundTrip(t *testing.T) {
	hash := sha256.Sum256([]byte("fetch me"))

	var buf bytes.Buffer
	if err := protocol.WriteGetChunkRequest(&buf, hash); err != nil {
		t.Fatalf("WriteGetChunkRequest: %v", err)
	}
	got, err := protocol.ReadGetChunkRequest(&buf)
	if err != nil {
		t.Fatalf("ReadGetChunkRequest: %v", err)
	}
	if got != hash {
		t.Errorf("hash round-trip mismatch: got %x, want %x", got, hash)
	}
}

func TestReadGetChunkRequest_RejectsTruncated(t *testing.T) {
	_, err := protocol.ReadGetChunkRequest(bytes.NewReader(bytes.Repeat([]byte{0xaa}, 5)))
	if err == nil {
		t.Error("ReadGetChunkRequest accepted truncated hash")
	}
}

func TestWriteGetChunkRequest_PropagatesHashWriteError(t *testing.T) {
	sentinel := errors.New("get hash write boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WriteGetChunkRequest(w, [32]byte{}); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestWriteReadGetChunkResponse_Success(t *testing.T) {
	blob := []byte("opaque encrypted chunk bytes")

	var buf bytes.Buffer
	if err := protocol.WriteGetChunkResponse(&buf, blob, ""); err != nil {
		t.Fatalf("WriteGetChunkResponse: %v", err)
	}
	got, appErr, err := protocol.ReadGetChunkResponse(&buf, 1<<20)
	if err != nil {
		t.Fatalf("ReadGetChunkResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob mismatch: got %q, want %q", got, blob)
	}
}

func TestWriteReadGetChunkResponse_ErrorPath(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteGetChunkResponse(&buf, nil, "chunk not found"); err != nil {
		t.Fatalf("WriteGetChunkResponse: %v", err)
	}
	blob, appErr, err := protocol.ReadGetChunkResponse(&buf, 1<<20)
	if err != nil {
		t.Fatalf("ReadGetChunkResponse: %v", err)
	}
	if appErr != "chunk not found" {
		t.Errorf("appErr = %q, want %q", appErr, "chunk not found")
	}
	if len(blob) != 0 {
		t.Errorf("blob = %q, want empty on error path", blob)
	}
}

func TestReadGetChunkResponse_RejectsUnknownStatus(t *testing.T) {
	if _, _, err := protocol.ReadGetChunkResponse(bytes.NewReader([]byte{0xff}), 1<<20); err == nil {
		t.Error("ReadGetChunkResponse accepted unknown status byte")
	}
}

func TestReadGetChunkResponse_RejectsTruncated(t *testing.T) {
	if _, _, err := protocol.ReadGetChunkResponse(bytes.NewReader(nil), 1<<20); err == nil {
		t.Error("ReadGetChunkResponse accepted empty stream")
	}
	if _, _, err := protocol.ReadGetChunkResponse(bytes.NewReader([]byte{0, 0x00}), 1<<20); err == nil {
		t.Error("ReadGetChunkResponse accepted truncated success length prefix")
	}
	frame := []byte{0, 0x00, 0x00, 0x00, 0x0a, 'a', 'b', 'c'}
	if _, _, err := protocol.ReadGetChunkResponse(bytes.NewReader(frame), 1<<20); err == nil {
		t.Error("ReadGetChunkResponse accepted truncated success body")
	}
	if _, _, err := protocol.ReadGetChunkResponse(bytes.NewReader([]byte{1, 0x00, 0x00}), 1<<20); err == nil {
		t.Error("ReadGetChunkResponse accepted truncated error length prefix")
	}
}

func TestReadGetChunkResponse_RejectsOversizedBlob(t *testing.T) {
	blob := []byte("slightly oversized payload")
	var buf bytes.Buffer
	if err := protocol.WriteGetChunkResponse(&buf, blob, ""); err != nil {
		t.Fatalf("WriteGetChunkResponse: %v", err)
	}
	_, _, err := protocol.ReadGetChunkResponse(&buf, len(blob)-1)
	if err == nil {
		t.Fatal("ReadGetChunkResponse accepted oversized blob")
	}
	if !errors.Is(err, protocol.ErrBlobTooLarge) {
		t.Errorf("err = %v, want ErrBlobTooLarge", err)
	}
}

func TestReadGetChunkResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	if _, _, err := protocol.ReadGetChunkResponse(bytes.NewReader(frame), 1<<20); err == nil {
		t.Error("ReadGetChunkResponse accepted oversized error message length")
	}
}

func TestWriteGetChunkResponse_PropagatesAllWriteErrors(t *testing.T) {
	for i, name := range []string{"status", "length", "body"} {
		sentinel := errors.New(name + " success boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WriteGetChunkResponse(w, []byte("payload"), "")
		if !errors.Is(err, sentinel) {
			t.Errorf("success %s-stage err = %v, want wraps sentinel", name, err)
		}
	}
	for i, name := range []string{"status", "length", "body"} {
		sentinel := errors.New(name + " err boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WriteGetChunkResponse(w, nil, "oops")
		if !errors.Is(err, sentinel) {
			t.Errorf("error %s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}
