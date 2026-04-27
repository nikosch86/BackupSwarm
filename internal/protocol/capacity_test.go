package protocol_test

import (
	"bytes"
	"errors"
	"math"
	"testing"

	"backupswarm/internal/protocol"
)

func TestWriteReadGetCapacityResponse_Success(t *testing.T) {
	var buf bytes.Buffer
	const used, cap = int64(1234), int64(1 << 30)
	if err := protocol.WriteGetCapacityResponse(&buf, used, cap, ""); err != nil {
		t.Fatalf("WriteGetCapacityResponse: %v", err)
	}
	gotUsed, gotCap, appErr, err := protocol.ReadGetCapacityResponse(&buf)
	if err != nil {
		t.Fatalf("ReadGetCapacityResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
	if gotUsed != used {
		t.Errorf("used = %d, want %d", gotUsed, used)
	}
	if gotCap != cap {
		t.Errorf("cap = %d, want %d", gotCap, cap)
	}
}

func TestWriteReadGetCapacityResponse_UnlimitedCapacity(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteGetCapacityResponse(&buf, 0, 0, ""); err != nil {
		t.Fatalf("WriteGetCapacityResponse: %v", err)
	}
	gotUsed, gotCap, appErr, err := protocol.ReadGetCapacityResponse(&buf)
	if err != nil || appErr != "" {
		t.Fatalf("Read: appErr=%q err=%v", appErr, err)
	}
	if gotUsed != 0 || gotCap != 0 {
		t.Errorf("unlimited: got used=%d cap=%d, want 0/0", gotUsed, gotCap)
	}
}

func TestWriteReadGetCapacityResponse_LargeValues(t *testing.T) {
	var buf bytes.Buffer
	const used, cap = int64(math.MaxInt64 - 1), int64(math.MaxInt64)
	if err := protocol.WriteGetCapacityResponse(&buf, used, cap, ""); err != nil {
		t.Fatalf("WriteGetCapacityResponse: %v", err)
	}
	gotUsed, gotCap, _, err := protocol.ReadGetCapacityResponse(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if gotUsed != used || gotCap != cap {
		t.Errorf("got used=%d cap=%d, want used=%d cap=%d", gotUsed, gotCap, used, cap)
	}
}

func TestWriteReadGetCapacityResponse_ErrorPath(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteGetCapacityResponse(&buf, 0, 0, "capacity reporting disabled"); err != nil {
		t.Fatalf("WriteGetCapacityResponse: %v", err)
	}
	used, cap, appErr, err := protocol.ReadGetCapacityResponse(&buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if appErr != "capacity reporting disabled" {
		t.Errorf("appErr = %q", appErr)
	}
	if used != 0 || cap != 0 {
		t.Errorf("err path: got used=%d cap=%d, want 0/0", used, cap)
	}
}

func TestReadGetCapacityResponse_RejectsUnknownStatus(t *testing.T) {
	if _, _, _, err := protocol.ReadGetCapacityResponse(bytes.NewReader([]byte{0xff})); err == nil {
		t.Error("ReadGetCapacityResponse accepted unknown status byte")
	}
}

func TestReadGetCapacityResponse_RejectsTruncated(t *testing.T) {
	if _, _, _, err := protocol.ReadGetCapacityResponse(bytes.NewReader(nil)); err == nil {
		t.Error("accepted empty stream")
	}
	if _, _, _, err := protocol.ReadGetCapacityResponse(bytes.NewReader([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0})); err == nil {
		t.Error("accepted truncated success body (used + half cap)")
	}
	if _, _, _, err := protocol.ReadGetCapacityResponse(bytes.NewReader([]byte{1, 0, 0})); err == nil {
		t.Error("accepted truncated error length prefix")
	}
}

func TestReadGetCapacityResponse_RejectsOversizedErrorMessage(t *testing.T) {
	frame := []byte{1, 0x00, 0x10, 0x00, 0x01}
	if _, _, _, err := protocol.ReadGetCapacityResponse(bytes.NewReader(frame)); err == nil {
		t.Error("accepted oversized error message length")
	}
}

func TestWriteGetCapacityResponse_PropagatesAllWriteErrors(t *testing.T) {
	for i, name := range []string{"status", "used", "cap"} {
		sentinel := errors.New(name + " success boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WriteGetCapacityResponse(w, 1, 2, "")
		if !errors.Is(err, sentinel) {
			t.Errorf("success %s-stage err = %v, want wraps sentinel", name, err)
		}
	}
	for i, name := range []string{"status", "length", "body"} {
		sentinel := errors.New(name + " err boom")
		w := &errWriter{failAt: i, err: sentinel}
		err := protocol.WriteGetCapacityResponse(w, 0, 0, "oops")
		if !errors.Is(err, sentinel) {
			t.Errorf("error %s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}
