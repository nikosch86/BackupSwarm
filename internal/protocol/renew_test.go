package protocol_test

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"backupswarm/internal/protocol"
)

func TestWriteReadRenewTTLRequest_RoundTrip(t *testing.T) {
	hash := sha256.Sum256([]byte("renew me"))

	var buf bytes.Buffer
	if err := protocol.WriteRenewTTLRequest(&buf, hash); err != nil {
		t.Fatalf("WriteRenewTTLRequest: %v", err)
	}
	got, err := protocol.ReadRenewTTLRequest(&buf)
	if err != nil {
		t.Fatalf("ReadRenewTTLRequest: %v", err)
	}
	if got != hash {
		t.Errorf("hash round-trip mismatch: got %x, want %x", got, hash)
	}
}

func TestReadRenewTTLRequest_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadRenewTTLRequest(bytes.NewReader(bytes.Repeat([]byte{0xaa}, 5))); err == nil {
		t.Error("ReadRenewTTLRequest accepted truncated hash")
	}
}

func TestWriteRenewTTLRequest_PropagatesHashWriteError(t *testing.T) {
	sentinel := errors.New("renew hash write boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WriteRenewTTLRequest(w, [32]byte{}); !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestWriteReadRenewTTLResponse_Success(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteRenewTTLResponse(&buf, ""); err != nil {
		t.Fatalf("WriteRenewTTLResponse: %v", err)
	}
	appErr, err := protocol.ReadRenewTTLResponse(&buf)
	if err != nil {
		t.Fatalf("ReadRenewTTLResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
}

func TestWriteReadRenewTTLResponse_ErrorPath(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteRenewTTLResponse(&buf, "owner_mismatch"); err != nil {
		t.Fatalf("WriteRenewTTLResponse: %v", err)
	}
	appErr, err := protocol.ReadRenewTTLResponse(&buf)
	if err != nil {
		t.Fatalf("ReadRenewTTLResponse: %v", err)
	}
	if appErr != "owner_mismatch" {
		t.Errorf("appErr = %q, want owner_mismatch", appErr)
	}
}

func TestReadRenewTTLResponse_RejectsUnknownStatus(t *testing.T) {
	if _, err := protocol.ReadRenewTTLResponse(bytes.NewReader([]byte{0xff})); err == nil {
		t.Error("ReadRenewTTLResponse accepted unknown status byte")
	}
}

func TestReadRenewTTLResponse_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadRenewTTLResponse(bytes.NewReader(nil)); err == nil {
		t.Error("ReadRenewTTLResponse accepted empty stream")
	}
	if _, err := protocol.ReadRenewTTLResponse(bytes.NewReader([]byte{1, 0x00, 0x00})); err == nil {
		t.Error("ReadRenewTTLResponse accepted truncated length prefix")
	}
}

func TestReadRenewTTLResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	if _, err := protocol.ReadRenewTTLResponse(bytes.NewReader(frame)); err == nil {
		t.Error("ReadRenewTTLResponse accepted oversized error length")
	}
}

func TestWriteRenewTTLResponse_PropagatesAllWriteErrors(t *testing.T) {
	sentinel := errors.New("renew status boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WriteRenewTTLResponse(w, ""); !errors.Is(err, sentinel) {
		t.Errorf("success-status err = %v, want wraps sentinel", err)
	}
	for i, name := range []string{"status", "length", "body"} {
		sentinel := errors.New(name + " err boom")
		w := &errWriter{failAt: i, err: sentinel}
		if err := protocol.WriteRenewTTLResponse(w, "oops"); !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

func TestMsgRenewTTL_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteMessageType(&buf, protocol.MsgRenewTTL); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	got, err := protocol.ReadMessageType(&buf)
	if err != nil {
		t.Fatalf("ReadMessageType: %v", err)
	}
	if got != protocol.MsgRenewTTL {
		t.Errorf("type = %v, want MsgRenewTTL", got)
	}
}
