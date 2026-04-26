package protocol_test

import (
	"bytes"
	"errors"
	"testing"

	"backupswarm/internal/protocol"
)

func TestPeerAnnouncementMessageType(t *testing.T) {
	var buf bytes.Buffer
	if err := protocol.WriteMessageType(&buf, protocol.MsgPeerAnnouncement); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	got, err := protocol.ReadMessageType(&buf)
	if err != nil {
		t.Fatalf("ReadMessageType: %v", err)
	}
	if got != protocol.MsgPeerAnnouncement {
		t.Errorf("type = %v, want MsgPeerAnnouncement", got)
	}
}

func TestPeerAnnouncement_PeerJoined_RoundTrip(t *testing.T) {
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     testID(0x10),
		PubKey: testPub(0xaa),
		Role:   2, // RoleIntroducer
		Addr:   "10.0.0.5:4242",
	}
	var buf bytes.Buffer
	if err := protocol.WritePeerAnnouncement(&buf, ann); err != nil {
		t.Fatalf("WritePeerAnnouncement: %v", err)
	}
	got, err := protocol.ReadPeerAnnouncement(&buf, 1<<10)
	if err != nil {
		t.Fatalf("ReadPeerAnnouncement: %v", err)
	}
	if got != ann {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, ann)
	}
}

func TestPeerAnnouncement_PeerLeft_RoundTrip(t *testing.T) {
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerLeft,
		ID:     testID(0x20),
		PubKey: testPub(0xbb),
	}
	var buf bytes.Buffer
	if err := protocol.WritePeerAnnouncement(&buf, ann); err != nil {
		t.Fatalf("WritePeerAnnouncement: %v", err)
	}
	got, err := protocol.ReadPeerAnnouncement(&buf, 1<<10)
	if err != nil {
		t.Fatalf("ReadPeerAnnouncement: %v", err)
	}
	if got != ann {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, ann)
	}
}

func TestPeerAnnouncement_AddressChanged_RoundTrip(t *testing.T) {
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnounceAddressChanged,
		ID:     testID(0x30),
		PubKey: testPub(0xcc),
		Addr:   "192.0.2.7:9000",
	}
	var buf bytes.Buffer
	if err := protocol.WritePeerAnnouncement(&buf, ann); err != nil {
		t.Fatalf("WritePeerAnnouncement: %v", err)
	}
	got, err := protocol.ReadPeerAnnouncement(&buf, 1<<10)
	if err != nil {
		t.Fatalf("ReadPeerAnnouncement: %v", err)
	}
	if got != ann {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, ann)
	}
}

func TestWritePeerAnnouncement_RejectsUnknownKind(t *testing.T) {
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncementKind(99),
		PubKey: testPub(0x01),
	}
	if err := protocol.WritePeerAnnouncement(&bytes.Buffer{}, ann); err == nil {
		t.Error("WritePeerAnnouncement accepted unknown kind")
	}
}

func TestWritePeerAnnouncement_PeerJoined_RejectsZeroRole(t *testing.T) {
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		PubKey: testPub(0x02),
		Role:   0,
		Addr:   "127.0.0.1:1",
	}
	if err := protocol.WritePeerAnnouncement(&bytes.Buffer{}, ann); err == nil {
		t.Error("WritePeerAnnouncement accepted zero-role PeerJoined")
	}
}

func TestWritePeerAnnouncement_AddressChanged_RejectsEmptyAddr(t *testing.T) {
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnounceAddressChanged,
		PubKey: testPub(0x03),
		Addr:   "",
	}
	if err := protocol.WritePeerAnnouncement(&bytes.Buffer{}, ann); err == nil {
		t.Error("WritePeerAnnouncement accepted empty-addr AddressChanged")
	}
}

func TestReadPeerAnnouncement_RejectsUnknownKind(t *testing.T) {
	frame := append([]byte{99}, bytes.Repeat([]byte{0x11}, 16)...) // id
	frame = append(frame, bytes.Repeat([]byte{0xaa}, 32)...)       // pubkey
	frame = append(frame, 1)                                       // role
	frame = append(frame, 0, 0, 0, 0)                              // addr_len = 0
	if _, err := protocol.ReadPeerAnnouncement(bytes.NewReader(frame), 1<<10); err == nil {
		t.Error("ReadPeerAnnouncement accepted unknown kind")
	}
}

func TestReadPeerAnnouncement_PeerJoined_RejectsZeroRole(t *testing.T) {
	frame := append([]byte{byte(protocol.AnnouncePeerJoined)}, bytes.Repeat([]byte{0x11}, 16)...) // id
	frame = append(frame, bytes.Repeat([]byte{0xaa}, 32)...)                                      // pubkey
	frame = append(frame, 0)                                                                      // role = 0
	frame = append(frame, 0, 0, 0, 1)                                                             // addr_len = 1
	frame = append(frame, 'x')
	if _, err := protocol.ReadPeerAnnouncement(bytes.NewReader(frame), 1<<10); err == nil {
		t.Error("ReadPeerAnnouncement accepted zero-role PeerJoined")
	}
}

func TestReadPeerAnnouncement_AddressChanged_RejectsEmptyAddr(t *testing.T) {
	frame := append([]byte{byte(protocol.AnnounceAddressChanged)}, bytes.Repeat([]byte{0x11}, 16)...) // id
	frame = append(frame, bytes.Repeat([]byte{0xaa}, 32)...)                                          // pubkey
	frame = append(frame, 0)                                                                          // role
	frame = append(frame, 0, 0, 0, 0)                                                                 // addr_len = 0
	if _, err := protocol.ReadPeerAnnouncement(bytes.NewReader(frame), 1<<10); err == nil {
		t.Error("ReadPeerAnnouncement accepted empty-addr AddressChanged")
	}
}

func TestReadPeerAnnouncement_RejectsOversizedAddr(t *testing.T) {
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		PubKey: testPub(0x04),
		Role:   1,
		Addr:   "this is far too big",
	}
	var buf bytes.Buffer
	if err := protocol.WritePeerAnnouncement(&buf, ann); err != nil {
		t.Fatalf("WritePeerAnnouncement: %v", err)
	}
	_, err := protocol.ReadPeerAnnouncement(&buf, len(ann.Addr)-1)
	if err == nil {
		t.Fatal("ReadPeerAnnouncement accepted oversized addr")
	}
	if !errors.Is(err, protocol.ErrAddrTooLarge) {
		t.Errorf("err = %v, want ErrAddrTooLarge", err)
	}
}

func TestReadPeerAnnouncement_RejectsTruncated(t *testing.T) {
	if _, err := protocol.ReadPeerAnnouncement(bytes.NewReader(nil), 1<<10); err == nil {
		t.Error("ReadPeerAnnouncement accepted empty stream")
	}
	// kind only
	if _, err := protocol.ReadPeerAnnouncement(bytes.NewReader([]byte{1}), 1<<10); err == nil {
		t.Error("ReadPeerAnnouncement accepted kind-only frame")
	}
}

func TestWritePeerAnnouncement_PropagatesAllWriteErrors(t *testing.T) {
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     testID(0x05),
		PubKey: testPub(0x05),
		Role:   1,
		Addr:   "127.0.0.1:1",
	}
	for i, name := range []string{"kind", "id", "pubkey", "role", "addr_len", "addr"} {
		sentinel := errors.New(name + " err boom")
		w := &errWriter{failAt: i, err: sentinel}
		if err := protocol.WritePeerAnnouncement(w, ann); !errors.Is(err, sentinel) {
			t.Errorf("%s-stage err = %v, want wraps sentinel", name, err)
		}
	}
}

func TestPeerAnnouncement_IDRoundTrip(t *testing.T) {
	want := testID(0x42)
	ann := protocol.PeerAnnouncement{
		Kind:   protocol.AnnouncePeerJoined,
		ID:     want,
		PubKey: testPub(0xaa),
		Role:   1,
		Addr:   "127.0.0.1:1",
	}
	var buf bytes.Buffer
	if err := protocol.WritePeerAnnouncement(&buf, ann); err != nil {
		t.Fatalf("WritePeerAnnouncement: %v", err)
	}
	got, err := protocol.ReadPeerAnnouncement(&buf, 1<<10)
	if err != nil {
		t.Fatalf("ReadPeerAnnouncement: %v", err)
	}
	if got.ID != want {
		t.Errorf("ID = %x, want %x", got.ID, want)
	}
}

func testPub(seed byte) [32]byte {
	var p [32]byte
	for i := range p {
		p[i] = seed ^ byte(i)
	}
	return p
}

func testID(seed byte) [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = seed ^ byte(i)
	}
	return id
}
