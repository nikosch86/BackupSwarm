package protocol_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"backupswarm/internal/protocol"
)

func TestMsgPunchRequest_DispatchByteRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteMessageType(&buf, protocol.MsgPunchRequest); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	got, err := protocol.ReadMessageType(&buf)
	if err != nil {
		t.Fatalf("ReadMessageType: %v", err)
	}
	if got != protocol.MsgPunchRequest {
		t.Errorf("type = %v, want MsgPunchRequest", got)
	}
}

func TestMsgPunchSignal_DispatchByteRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteMessageType(&buf, protocol.MsgPunchSignal); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	got, err := protocol.ReadMessageType(&buf)
	if err != nil {
		t.Fatalf("ReadMessageType: %v", err)
	}
	if got != protocol.MsgPunchSignal {
		t.Errorf("type = %v, want MsgPunchSignal", got)
	}
}

func TestPunchPayload_RoundTrip(t *testing.T) {
	want := protocol.PunchPayload{
		PeerPub: [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
			17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32},
		Addr: "203.0.113.7:51820",
	}
	var buf bytes.Buffer
	if err := protocol.WritePunchPayload(&buf, want); err != nil {
		t.Fatalf("WritePunchPayload: %v", err)
	}
	got, err := protocol.ReadPunchPayload(&buf, 1024)
	if err != nil {
		t.Fatalf("ReadPunchPayload: %v", err)
	}
	if got.PeerPub != want.PeerPub {
		t.Errorf("PeerPub = %x, want %x", got.PeerPub, want.PeerPub)
	}
	if got.Addr != want.Addr {
		t.Errorf("Addr = %q, want %q", got.Addr, want.Addr)
	}
}

func TestWritePunchPayload_RejectsEmptyAddr(t *testing.T) {
	var buf bytes.Buffer
	err := protocol.WritePunchPayload(&buf, protocol.PunchPayload{
		PeerPub: [32]byte{0xaa},
		Addr:    "",
	})
	if err == nil {
		t.Fatal("WritePunchPayload accepted empty Addr")
	}
}

func TestReadPunchPayload_RejectsAddrTooLarge(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePunchPayload(&buf, protocol.PunchPayload{
		PeerPub: [32]byte{0xbb},
		Addr:    strings.Repeat("x", 64),
	}); err != nil {
		t.Fatalf("WritePunchPayload: %v", err)
	}
	_, err := protocol.ReadPunchPayload(&buf, 32)
	if !errors.Is(err, protocol.ErrAddrTooLarge) {
		t.Fatalf("err = %v, want ErrAddrTooLarge", err)
	}
}

func TestPunchResponse_OKRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePunchResponse(&buf, ""); err != nil {
		t.Fatalf("WritePunchResponse: %v", err)
	}
	appErr, err := protocol.ReadPunchResponse(&buf)
	if err != nil {
		t.Fatalf("ReadPunchResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
}

func TestPunchResponse_AppErrRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WritePunchResponse(&buf, "target_offline"); err != nil {
		t.Fatalf("WritePunchResponse: %v", err)
	}
	appErr, err := protocol.ReadPunchResponse(&buf)
	if err != nil {
		t.Fatalf("ReadPunchResponse: %v", err)
	}
	if appErr != "target_offline" {
		t.Errorf("appErr = %q, want target_offline", appErr)
	}
}

// Per-stage write-error coverage for WritePunchPayload: pubkey, addr-len, addr.
func TestWritePunchPayload_PropagatesWriteErrors(t *testing.T) {
	for i, name := range []string{"pubkey", "addrLen", "addr"} {
		sentinel := errors.New(name + " punch payload boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WritePunchPayload(w, protocol.PunchPayload{
			PeerPub: [32]byte{0xaa},
			Addr:    "203.0.113.1:9000",
		})
		if !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

// Per-stage read-error coverage for ReadPunchPayload: truncated pubkey,
// truncated addr length, truncated addr body.
func TestReadPunchPayload_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadPunchPayload(bytes.NewReader([]byte{0x00, 0x00}), 1024); err == nil {
		t.Error("ReadPunchPayload accepted truncated pubkey")
	}
	missingAddrLen := bytes.Repeat([]byte{0x11}, 32)
	if _, err := protocol.ReadPunchPayload(bytes.NewReader(missingAddrLen), 1024); err == nil {
		t.Error("ReadPunchPayload accepted missing addr length")
	}
	bodyShort := append(bytes.Repeat([]byte{0x11}, 32), 0x00, 0x00, 0x00, 0x05, 'a', 'b')
	if _, err := protocol.ReadPunchPayload(bytes.NewReader(bodyShort), 1024); err == nil {
		t.Error("ReadPunchPayload accepted truncated addr body")
	}
}

// Per-stage write-error coverage for WritePunchResponse on the OK path:
// the single status byte write.
func TestWritePunchResponse_PropagatesSuccessWriteError(t *testing.T) {
	sentinel := errors.New("punch response status boom")
	w := &errWriter{failAt: 0, err: sentinel}
	if err := protocol.WritePunchResponse(w, ""); !errors.Is(err, sentinel) {
		t.Errorf("OK-status err = %v, want wraps sentinel", err)
	}
}

// Per-stage write-error coverage for WritePunchResponse error frame:
// status byte, length prefix, and error body.
func TestWritePunchResponse_PropagatesErrorFrameWriteErrors(t *testing.T) {
	for i, name := range []string{"status", "length", "body"} {
		sentinel := errors.New(name + " punch response err boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WritePunchResponse(w, "target_offline")
		if !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

// Per-stage read-error coverage for ReadPunchResponse: empty stream,
// truncated err length, truncated err body.
func TestReadPunchResponse_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadPunchResponse(bytes.NewReader(nil)); err == nil {
		t.Error("ReadPunchResponse accepted empty stream")
	}
	partialLen := []byte{1, 0x00, 0x00}
	if _, err := protocol.ReadPunchResponse(bytes.NewReader(partialLen)); err == nil {
		t.Error("ReadPunchResponse accepted truncated error length")
	}
	bodyShort := []byte{1, 0x00, 0x00, 0x00, 0x05, 'a', 'b'}
	if _, err := protocol.ReadPunchResponse(bytes.NewReader(bodyShort)); err == nil {
		t.Error("ReadPunchResponse accepted truncated error body")
	}
}

// ReadPunchResponse rejects an unknown status byte.
func TestReadPunchResponse_RejectsUnknownStatus(t *testing.T) {
	if _, err := protocol.ReadPunchResponse(bytes.NewReader([]byte{0xff})); err == nil {
		t.Error("ReadPunchResponse accepted unknown status byte")
	}
}

// ReadPunchResponse rejects an oversized error message length.
func TestReadPunchResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	if _, err := protocol.ReadPunchResponse(bytes.NewReader(frame)); err == nil {
		t.Error("ReadPunchResponse accepted oversized error length")
	}
}

// ReadPunchPayload rejects an empty (zero-length) addr.
func TestReadPunchPayload_RejectsEmptyAddr(t *testing.T) {
	frame := append(bytes.Repeat([]byte{0x11}, 32), 0x00, 0x00, 0x00, 0x00)
	if _, err := protocol.ReadPunchPayload(bytes.NewReader(frame), 1024); err == nil {
		t.Error("ReadPunchPayload accepted zero addrLen")
	}
}
