package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"backupswarm/internal/protocol"
)

func TestWriteReadPutIndexSnapshotRequest_RoundTrip(t *testing.T) {
	blob := []byte("opaque encrypted index snapshot bytes")

	var buf bytes.Buffer
	if err := protocol.WritePutIndexSnapshotRequest(&buf, blob); err != nil {
		t.Fatalf("WritePutIndexSnapshotRequest: %v", err)
	}
	got, err := protocol.ReadPutIndexSnapshotRequest(&buf, 1<<20)
	if err != nil {
		t.Fatalf("ReadPutIndexSnapshotRequest: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("round-trip blob mismatch: got %q, want %q", got, blob)
	}
}

func TestWritePutIndexSnapshotRequest_RejectsEmptyBlob(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePutIndexSnapshotRequest(&buf, nil); err == nil {
		t.Error("accepted nil blob")
	}
	if err := protocol.WritePutIndexSnapshotRequest(&buf, []byte{}); err == nil {
		t.Error("accepted empty blob")
	}
}

func TestReadPutIndexSnapshotRequest_RejectsOversizedBlob(t *testing.T) {
	blob := []byte("this snapshot blob is slightly too big")

	var buf bytes.Buffer
	if err := protocol.WritePutIndexSnapshotRequest(&buf, blob); err != nil {
		t.Fatalf("WritePutIndexSnapshotRequest: %v", err)
	}
	_, err := protocol.ReadPutIndexSnapshotRequest(&buf, len(blob)-1)
	if err == nil {
		t.Fatal("accepted oversized snapshot blob")
	}
	if !errors.Is(err, protocol.ErrIndexSnapshotTooLarge) {
		t.Errorf("err = %v, want wraps ErrIndexSnapshotTooLarge", err)
	}
}

func TestReadPutIndexSnapshotRequest_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadPutIndexSnapshotRequest(bytes.NewReader(nil), 1<<10); err == nil {
		t.Error("accepted empty stream")
	}
	frame := []byte{0, 0, 0, 0x10, 'a', 'b'}
	if _, err := protocol.ReadPutIndexSnapshotRequest(bytes.NewReader(frame), 1<<10); err == nil {
		t.Error("accepted truncated body")
	}
}

func TestWriteReadPutIndexSnapshotResponse_Success(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePutIndexSnapshotResponse(&buf, ""); err != nil {
		t.Fatalf("WritePutIndexSnapshotResponse: %v", err)
	}
	appErr, err := protocol.ReadPutIndexSnapshotResponse(&buf)
	if err != nil {
		t.Fatalf("ReadPutIndexSnapshotResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
}

func TestWriteReadPutIndexSnapshotResponse_ErrorPath(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePutIndexSnapshotResponse(&buf, "no_space"); err != nil {
		t.Fatalf("WritePutIndexSnapshotResponse: %v", err)
	}
	appErr, err := protocol.ReadPutIndexSnapshotResponse(&buf)
	if err != nil {
		t.Fatalf("ReadPutIndexSnapshotResponse: %v", err)
	}
	if appErr != "no_space" {
		t.Errorf("appErr = %q, want %q", appErr, "no_space")
	}
}

func TestReadPutIndexSnapshotResponse_RejectsUnknownStatus(t *testing.T) {
	if _, err := protocol.ReadPutIndexSnapshotResponse(bytes.NewReader([]byte{0xff})); err == nil {
		t.Error("accepted unknown status byte")
	}
}

func TestReadPutIndexSnapshotResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	if _, err := protocol.ReadPutIndexSnapshotResponse(bytes.NewReader(frame)); err == nil {
		t.Error("accepted oversized error message length")
	}
}

func TestWriteReadGetIndexSnapshotResponse_Success(t *testing.T) {
	blob := []byte("blob contents on the get path")

	var buf bytes.Buffer
	if err := protocol.WriteGetIndexSnapshotResponse(&buf, blob, ""); err != nil {
		t.Fatalf("WriteGetIndexSnapshotResponse: %v", err)
	}
	got, appErr, err := protocol.ReadGetIndexSnapshotResponse(&buf, 1<<20)
	if err != nil {
		t.Fatalf("ReadGetIndexSnapshotResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob round-trip mismatch")
	}
}

func TestWriteReadGetIndexSnapshotResponse_ErrorPath(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteGetIndexSnapshotResponse(&buf, nil, "not_found"); err != nil {
		t.Fatalf("WriteGetIndexSnapshotResponse: %v", err)
	}
	blob, appErr, err := protocol.ReadGetIndexSnapshotResponse(&buf, 1<<20)
	if err != nil {
		t.Fatalf("ReadGetIndexSnapshotResponse: %v", err)
	}
	if appErr != "not_found" {
		t.Errorf("appErr = %q, want %q", appErr, "not_found")
	}
	if blob != nil {
		t.Errorf("blob on err path = %q, want nil", blob)
	}
}

func TestReadGetIndexSnapshotResponse_RejectsOversizedBlob(t *testing.T) {
	blob := []byte("payload that exceeds caller cap")

	var buf bytes.Buffer
	if err := protocol.WriteGetIndexSnapshotResponse(&buf, blob, ""); err != nil {
		t.Fatalf("WriteGetIndexSnapshotResponse: %v", err)
	}
	_, _, err := protocol.ReadGetIndexSnapshotResponse(&buf, len(blob)-1)
	if err == nil {
		t.Fatal("accepted oversized blob")
	}
	if !errors.Is(err, protocol.ErrIndexSnapshotTooLarge) {
		t.Errorf("err = %v, want wraps ErrIndexSnapshotTooLarge", err)
	}
}

func TestReadGetIndexSnapshotResponse_RejectsUnknownStatus(t *testing.T) {
	if _, _, err := protocol.ReadGetIndexSnapshotResponse(bytes.NewReader([]byte{0xff}), 1<<20); err == nil {
		t.Error("accepted unknown status byte")
	}
}

func TestReadGetIndexSnapshotResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	if _, _, err := protocol.ReadGetIndexSnapshotResponse(bytes.NewReader(frame), 1<<20); err == nil {
		t.Error("accepted oversized error message length")
	}
}

func TestReadGetIndexSnapshotResponse_RejectsTruncated(t *testing.T) {
	if _, _, err := protocol.ReadGetIndexSnapshotResponse(bytes.NewReader(nil), 1<<20); err == nil {
		t.Error("accepted empty stream")
	}
	partial := []byte{0, 0, 0, 0, 0x05, 'a', 'b'}
	if _, _, err := protocol.ReadGetIndexSnapshotResponse(bytes.NewReader(partial), 1<<20); err == nil {
		t.Error("accepted truncated success body")
	}
}

func TestWritePutIndexSnapshotRequest_PropagatesWriteErrors(t *testing.T) {
	for i, name := range []string{"length", "body"} {
		sentinel := errors.New(name + " put req boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WritePutIndexSnapshotRequest(w, []byte("payload"))
		if !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

func TestWritePutIndexSnapshotResponse_PropagatesWriteErrors(t *testing.T) {
	sentinel := errors.New("status boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WritePutIndexSnapshotResponse(w, ""); !errors.Is(err, sentinel) {
		t.Errorf("success status err = %v, want wraps sentinel", err)
	}
	for i, name := range []string{"status", "length", "body"} {
		s := errors.New(name + " err frame boom")
		w := &errWriter{failAt: i, err: s}
		if err := protocol.WritePutIndexSnapshotResponse(w, "oops"); !errors.Is(err, s) {
			t.Errorf("err frame %s err = %v, want wraps sentinel", name, err)
		}
	}
}

func TestWriteGetIndexSnapshotResponse_PropagatesWriteErrors(t *testing.T) {
	for i, name := range []string{"status", "length", "body"} {
		s := errors.New(name + " get success boom")
		w := &errWriter{failAt: i, err: s}
		if err := protocol.WriteGetIndexSnapshotResponse(w, []byte("p"), ""); !errors.Is(err, s) {
			t.Errorf("success %s err = %v, want wraps sentinel", name, err)
		}
	}
	for i, name := range []string{"status", "length", "body"} {
		s := errors.New(name + " get err boom")
		w := &errWriter{failAt: i, err: s}
		if err := protocol.WriteGetIndexSnapshotResponse(w, nil, "boom"); !errors.Is(err, s) {
			t.Errorf("err %s err = %v, want wraps sentinel", name, err)
		}
	}
}

// TestReadPutIndexSnapshotResponse_RejectsEmptyStream asserts a stream
// that yields nothing is surfaced as a status-read error.
func TestReadPutIndexSnapshotResponse_RejectsEmptyStream(t *testing.T) {
	if _, err := protocol.ReadPutIndexSnapshotResponse(bytes.NewReader(nil)); err == nil {
		t.Error("accepted empty stream")
	}
}

// TestReadPutIndexSnapshotResponse_RejectsTruncatedErrorBody asserts a
// truncated error frame body is surfaced as a read error.
func TestReadPutIndexSnapshotResponse_RejectsTruncatedErrorBody(t *testing.T) {
	frame := []byte{1, 0x00, 0x00, 0x00, 0x05, 'a', 'b'}
	if _, err := protocol.ReadPutIndexSnapshotResponse(bytes.NewReader(frame)); err == nil {
		t.Error("accepted truncated error body")
	}
}

// TestReadPutIndexSnapshotResponse_RejectsTruncatedErrorLength asserts a
// missing error-length prefix is surfaced as a read error.
func TestReadPutIndexSnapshotResponse_RejectsTruncatedErrorLength(t *testing.T) {
	frame := []byte{1, 0x00, 0x00}
	if _, err := protocol.ReadPutIndexSnapshotResponse(bytes.NewReader(frame)); err == nil {
		t.Error("accepted truncated error length prefix")
	}
}

// TestReadGetIndexSnapshotResponse_RejectsTruncatedErrorBody asserts a
// truncated error frame body is surfaced as a read error.
func TestReadGetIndexSnapshotResponse_RejectsTruncatedErrorBody(t *testing.T) {
	frame := []byte{1, 0x00, 0x00, 0x00, 0x05, 'a', 'b'}
	if _, _, err := protocol.ReadGetIndexSnapshotResponse(bytes.NewReader(frame), 1<<20); err == nil {
		t.Error("accepted truncated error body")
	}
}

// TestReadGetIndexSnapshotResponse_RejectsTruncatedErrorLength asserts a
// missing error-length prefix is surfaced as a read error.
func TestReadGetIndexSnapshotResponse_RejectsTruncatedErrorLength(t *testing.T) {
	frame := []byte{1, 0x00, 0x00}
	if _, _, err := protocol.ReadGetIndexSnapshotResponse(bytes.NewReader(frame), 1<<20); err == nil {
		t.Error("accepted truncated error length prefix")
	}
}

// TestReadGetIndexSnapshotResponse_RejectsTruncatedSuccessLength asserts a
// missing success-length prefix is surfaced as a read error.
func TestReadGetIndexSnapshotResponse_RejectsTruncatedSuccessLength(t *testing.T) {
	frame := []byte{0, 0x00, 0x00}
	if _, _, err := protocol.ReadGetIndexSnapshotResponse(bytes.NewReader(frame), 1<<20); err == nil {
		t.Error("accepted truncated success length prefix")
	}
}

func TestPutIndexSnapshotMessageType_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteMessageType(&buf, protocol.MsgPutIndexSnapshot); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	got, err := protocol.ReadMessageType(&buf)
	if err != nil {
		t.Fatalf("ReadMessageType: %v", err)
	}
	if got != protocol.MsgPutIndexSnapshot {
		t.Errorf("type = %v, want MsgPutIndexSnapshot", got)
	}
}

func TestGetIndexSnapshotMessageType_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteMessageType(&buf, protocol.MsgGetIndexSnapshot); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	got, err := protocol.ReadMessageType(&buf)
	if err != nil {
		t.Fatalf("ReadMessageType: %v", err)
	}
	if got != protocol.MsgGetIndexSnapshot {
		t.Errorf("type = %v, want MsgGetIndexSnapshot", got)
	}
}
