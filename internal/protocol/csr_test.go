package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"backupswarm/internal/protocol"
)

func TestWriteReadJoinRequest_CarriesCSR(t *testing.T) {
	csr := []byte("DER-encoded-CSR-bytes-here")
	var buf bytes.Buffer
	if err := protocol.WriteJoinRequest(&buf, [32]byte{}, [32]byte{}, "x:1", csr); err != nil {
		t.Fatalf("WriteJoinRequest: %v", err)
	}
	_, _, _, gotCSR, err := protocol.ReadJoinRequest(&buf, 1<<10, 1<<12)
	if err != nil {
		t.Fatalf("ReadJoinRequest: %v", err)
	}
	if !bytes.Equal(gotCSR, csr) {
		t.Errorf("csr round-trip mismatch: got %x, want %x", gotCSR, csr)
	}
}

func TestWriteReadJoinRequest_EmptyCSR_PinMode(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinRequest(&buf, [32]byte{}, [32]byte{}, "x:1", nil); err != nil {
		t.Fatalf("WriteJoinRequest: %v", err)
	}
	_, _, _, gotCSR, err := protocol.ReadJoinRequest(&buf, 1<<10, 1<<12)
	if err != nil {
		t.Fatalf("ReadJoinRequest: %v", err)
	}
	if len(gotCSR) != 0 {
		t.Errorf("csr length = %d, want 0", len(gotCSR))
	}
}

func TestReadJoinRequest_RejectsOversizedCSR(t *testing.T) {
	csr := bytes.Repeat([]byte{0xCC}, 32)
	var buf bytes.Buffer
	if err := protocol.WriteJoinRequest(&buf, [32]byte{}, [32]byte{}, "x:1", csr); err != nil {
		t.Fatalf("WriteJoinRequest: %v", err)
	}
	_, _, _, _, err := protocol.ReadJoinRequest(&buf, 1<<10, 16)
	if err == nil {
		t.Fatal("ReadJoinRequest accepted oversized csr")
	}
	if !errors.Is(err, protocol.ErrCSRTooLarge) {
		t.Errorf("err = %v, want ErrCSRTooLarge", err)
	}
}

func TestReadJoinRequest_RejectsTruncatedCSRLength(t *testing.T) {
	frame := bytes.Repeat([]byte{0x11}, 32) // swarm
	frame = append(frame, bytes.Repeat([]byte{0x22}, 32)...)
	frame = append(frame, 0x00, 0x00, 0x00, 0x00) // addr_len=0
	frame = append(frame, 0x00, 0x00)             // truncated csr_len
	if _, _, _, _, err := protocol.ReadJoinRequest(bytes.NewReader(frame), 1<<10, 1<<12); err == nil {
		t.Error("ReadJoinRequest accepted truncated csr length")
	}
}

func TestReadJoinRequest_RejectsTruncatedCSRBody(t *testing.T) {
	frame := bytes.Repeat([]byte{0x11}, 32)
	frame = append(frame, bytes.Repeat([]byte{0x22}, 32)...)
	frame = append(frame, 0x00, 0x00, 0x00, 0x00) // addr_len=0
	frame = append(frame, 0x00, 0x00, 0x00, 0x10) // csr_len=16
	frame = append(frame, 0xAA, 0xBB)             // only 2 csr bytes
	if _, _, _, _, err := protocol.ReadJoinRequest(bytes.NewReader(frame), 1<<10, 1<<12); err == nil {
		t.Error("ReadJoinRequest accepted truncated csr body")
	}
}

func TestWriteReadJoinResponse_CarriesSignedCert(t *testing.T) {
	cert := []byte("DER-encoded-leaf-cert-bytes")
	var buf bytes.Buffer
	if err := protocol.WriteJoinResponse(&buf, cert, ""); err != nil {
		t.Fatalf("WriteJoinResponse: %v", err)
	}
	gotCert, appErr, err := protocol.ReadJoinResponse(&buf, 1<<12)
	if err != nil {
		t.Fatalf("ReadJoinResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
	if !bytes.Equal(gotCert, cert) {
		t.Errorf("cert round-trip mismatch: got %x, want %x", gotCert, cert)
	}
}

func TestWriteReadJoinResponse_EmptyCert_PinMode(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteJoinResponse(&buf, nil, ""); err != nil {
		t.Fatalf("WriteJoinResponse: %v", err)
	}
	gotCert, appErr, err := protocol.ReadJoinResponse(&buf, 1<<12)
	if err != nil {
		t.Fatalf("ReadJoinResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
	if len(gotCert) != 0 {
		t.Errorf("cert length = %d, want 0", len(gotCert))
	}
}

func TestReadJoinResponse_RejectsOversizedCert(t *testing.T) {
	cert := bytes.Repeat([]byte{0xDD}, 32)
	var buf bytes.Buffer
	if err := protocol.WriteJoinResponse(&buf, cert, ""); err != nil {
		t.Fatalf("WriteJoinResponse: %v", err)
	}
	_, _, err := protocol.ReadJoinResponse(&buf, 16)
	if err == nil {
		t.Fatal("ReadJoinResponse accepted oversized cert")
	}
	if !errors.Is(err, protocol.ErrCertTooLarge) {
		t.Errorf("err = %v, want ErrCertTooLarge", err)
	}
}

func TestReadJoinResponse_RejectsTruncatedCertLength(t *testing.T) {
	frame := []byte{0x00, 0x00, 0x00} // status OK + 3 bytes (truncated len)
	if _, _, err := protocol.ReadJoinResponse(bytes.NewReader(frame), 1<<12); err == nil {
		t.Error("ReadJoinResponse accepted truncated cert length")
	}
}

func TestReadJoinResponse_RejectsTruncatedCertBody(t *testing.T) {
	frame := []byte{0x00, 0x00, 0x00, 0x00, 0x10, 0xAA, 0xBB} // status OK + len=16 + 2 bytes body
	if _, _, err := protocol.ReadJoinResponse(bytes.NewReader(frame), 1<<12); err == nil {
		t.Error("ReadJoinResponse accepted truncated cert body")
	}
}

// errWriterCSR returns err on its N-th Write (0-indexed), succeeds otherwise.
type errWriterCSR struct {
	failAt int
	err    error
	calls  int
}

func (w *errWriterCSR) Write(p []byte) (int, error) {
	defer func() { w.calls++ }()
	if w.calls == w.failAt {
		return 0, w.err
	}
	return len(p), nil
}

func TestWriteJoinRequest_PropagatesCSRWriteErrors(t *testing.T) {
	for i, name := range []string{"csrLen", "csrBody"} {
		sentinel := errors.New(name + " request boom")
		// stages 0..3 are swarm/secret/addrLen/addrBody; csr starts at 4.
		w := &errWriterCSR{failAt: 4 + i, err: sentinel}
		err := protocol.WriteJoinRequest(w, [32]byte{}, [32]byte{}, "x", []byte("c"))
		if !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

func TestWriteJoinResponse_PropagatesCertWriteErrors(t *testing.T) {
	cert := []byte("c")
	for i, name := range []string{"status", "certLen", "certBody"} {
		sentinel := errors.New(name + " response boom")
		w := &errWriterCSR{failAt: i, err: sentinel}
		err := protocol.WriteJoinResponse(w, cert, "")
		if !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}
