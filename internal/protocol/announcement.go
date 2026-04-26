package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// AnnouncementKind tags the body of a PeerAnnouncement frame so a single
// MsgPeerAnnouncement stream can carry joined/left/address-change events.
type AnnouncementKind byte

const (
	// AnnouncePeerJoined records a new swarm member; Role and PubKey are
	// load-bearing, Addr is the peer's advertised listen address.
	AnnouncePeerJoined AnnouncementKind = 1
	// AnnouncePeerLeft records a peer departure; only PubKey is meaningful.
	AnnouncePeerLeft AnnouncementKind = 2
	// AnnounceAddressChanged updates a known peer's listen address; PubKey
	// and Addr are meaningful.
	AnnounceAddressChanged AnnouncementKind = 3
)

// AnnouncementIDSize is the length of an announcement's dedup ID in bytes.
const AnnouncementIDSize = 16

// PeerAnnouncement carries one membership event over the wire. Role is
// opaque to this package; consumers map the byte to peers.Role. ID is a
// random 16-byte token used by forwarders to break gossip loops.
type PeerAnnouncement struct {
	Kind   AnnouncementKind
	ID     [AnnouncementIDSize]byte
	PubKey [32]byte
	Role   byte
	Addr   string
}

// WritePeerAnnouncement frames ann on w as
// [1B kind][16B id][32B pubkey][1B role][4B BE addr_len][addr]. Unusable
// shapes (zero-role PeerJoined, empty-addr AddressChanged) are rejected.
func WritePeerAnnouncement(w io.Writer, ann PeerAnnouncement) error {
	if err := validateAnnouncement(ann); err != nil {
		return err
	}
	if _, err := w.Write([]byte{byte(ann.Kind)}); err != nil {
		return fmt.Errorf("write announcement kind: %w", err)
	}
	if _, err := w.Write(ann.ID[:]); err != nil {
		return fmt.Errorf("write announcement id: %w", err)
	}
	if _, err := w.Write(ann.PubKey[:]); err != nil {
		return fmt.Errorf("write announcement pubkey: %w", err)
	}
	if _, err := w.Write([]byte{ann.Role}); err != nil {
		return fmt.Errorf("write announcement role: %w", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ann.Addr)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write announcement addr length: %w", err)
	}
	if len(ann.Addr) > 0 {
		if _, err := w.Write([]byte(ann.Addr)); err != nil {
			return fmt.Errorf("write announcement addr: %w", err)
		}
	}
	return nil
}

// ReadPeerAnnouncement reads one announcement frame from r, capping the
// advertised addr length at maxAddrLen. Per-kind validation matches the
// writer so an unusable shape never propagates to consumers.
func ReadPeerAnnouncement(r io.Reader, maxAddrLen int) (PeerAnnouncement, error) {
	var ann PeerAnnouncement
	var kindBuf [1]byte
	if _, err := io.ReadFull(r, kindBuf[:]); err != nil {
		return ann, fmt.Errorf("read announcement kind: %w", err)
	}
	ann.Kind = AnnouncementKind(kindBuf[0])
	if _, err := io.ReadFull(r, ann.ID[:]); err != nil {
		return ann, fmt.Errorf("read announcement id: %w", err)
	}
	if _, err := io.ReadFull(r, ann.PubKey[:]); err != nil {
		return ann, fmt.Errorf("read announcement pubkey: %w", err)
	}
	var roleBuf [1]byte
	if _, err := io.ReadFull(r, roleBuf[:]); err != nil {
		return ann, fmt.Errorf("read announcement role: %w", err)
	}
	ann.Role = roleBuf[0]
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return ann, fmt.Errorf("read announcement addr length: %w", err)
	}
	addrLen := binary.BigEndian.Uint32(hdr[:])
	if maxAddrLen > 0 && int64(addrLen) > int64(maxAddrLen) {
		return ann, fmt.Errorf("%w: got %d, max %d", ErrAddrTooLarge, addrLen, maxAddrLen)
	}
	if addrLen > 0 {
		body := make([]byte, addrLen)
		if _, err := io.ReadFull(r, body); err != nil {
			return ann, fmt.Errorf("read announcement addr: %w", err)
		}
		ann.Addr = string(body)
	}
	if err := validateAnnouncement(ann); err != nil {
		return PeerAnnouncement{}, err
	}
	return ann, nil
}

func validateAnnouncement(ann PeerAnnouncement) error {
	switch ann.Kind {
	case AnnouncePeerJoined:
		if ann.Role == 0 {
			return fmt.Errorf("announcement: PeerJoined requires non-zero role")
		}
	case AnnouncePeerLeft:
		// PubKey is sufficient; Role/Addr ignored downstream.
	case AnnounceAddressChanged:
		if ann.Addr == "" {
			return fmt.Errorf("announcement: AddressChanged requires non-empty addr")
		}
	default:
		return fmt.Errorf("announcement: unknown kind %d", ann.Kind)
	}
	return nil
}
