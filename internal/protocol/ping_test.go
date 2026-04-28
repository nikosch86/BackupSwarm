package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"backupswarm/internal/protocol"
)

func TestMsgPing_DispatchByteRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteMessageType(&buf, protocol.MsgPing); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	got, err := protocol.ReadMessageType(&buf)
	if err != nil {
		t.Fatalf("ReadMessageType: %v", err)
	}
	if got != protocol.MsgPing {
		t.Errorf("got %v, want MsgPing", got)
	}
}

func TestWriteReadPingResponse_Success(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePingResponse(&buf, ""); err != nil {
		t.Fatalf("WritePingResponse: %v", err)
	}
	appErr, err := protocol.ReadPingResponse(&buf)
	if err != nil {
		t.Fatalf("ReadPingResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
}

func TestWriteReadPingResponse_ErrorPath(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePingResponse(&buf, "ping rejected"); err != nil {
		t.Fatalf("WritePingResponse: %v", err)
	}
	appErr, err := protocol.ReadPingResponse(&buf)
	if err != nil {
		t.Fatalf("ReadPingResponse: %v", err)
	}
	if appErr != "ping rejected" {
		t.Errorf("appErr = %q, want %q", appErr, "ping rejected")
	}
}

func TestReadPingResponse_RejectsUnknownStatus(t *testing.T) {
	if _, err := protocol.ReadPingResponse(bytes.NewReader([]byte{0xff})); err == nil {
		t.Error("ReadPingResponse accepted unknown status byte")
	}
}

func TestReadPingResponse_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadPingResponse(bytes.NewReader(nil)); err == nil {
		t.Error("accepted empty stream")
	}
	if _, err := protocol.ReadPingResponse(bytes.NewReader([]byte{1, 0, 0})); err == nil {
		t.Error("accepted truncated error length prefix")
	}
}

func TestReadPingResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	if _, err := protocol.ReadPingResponse(bytes.NewReader(frame)); err == nil {
		t.Error("accepted oversized error message length")
	}
}

// statusErr + length=4 but only 2 body bytes follow.
func TestReadPingResponse_RejectsTruncatedErrorBody(t *testing.T) {
	frame := []byte{1, 0x00, 0x00, 0x00, 0x04, 'o', 'k'}
	if _, err := protocol.ReadPingResponse(bytes.NewReader(frame)); err == nil {
		t.Error("accepted truncated error body")
	}
}

func TestWritePingResponse_PropagatesAllWriteErrors(t *testing.T) {
	sentinel := errors.New("status boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WritePingResponse(w, ""); !errors.Is(err, sentinel) {
		t.Errorf("success status err = %v, want wraps sentinel", err)
	}
	for i, name := range []string{"status", "length", "body"} {
		s := errors.New(name + " err boom")
		w := &errWriter{failAt: i, err: s}
		if err := protocol.WritePingResponse(w, "oops"); !errors.Is(err, s) {
			t.Errorf("error %s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}
