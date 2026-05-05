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
// RelayAddr is the peer's TURN-relayed listen address; empty when the
// peer has no allocation.
type PeerAnnouncement struct {
	Kind      AnnouncementKind
	ID        [AnnouncementIDSize]byte
	PubKey    [32]byte
	Role      byte
	Addr      string
	RelayAddr string
}

// WritePeerAnnouncement frames ann on w as [1B kind][16B id][32B pubkey]
// [1B role][4B BE addr_len][addr][4B BE relay_len][relay]. Zero-role
// PeerJoined and both-empty AddressChanged are rejected.
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
	binary.BigEndian.PutUint32(hdr[:], uint32(len(ann.RelayAddr)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write announcement relay length: %w", err)
	}
	if len(ann.RelayAddr) > 0 {
		if _, err := w.Write([]byte(ann.RelayAddr)); err != nil {
			return fmt.Errorf("write announcement relay: %w", err)
		}
	}
	return nil
}

// ReadPeerAnnouncement reads one announcement frame from r, capping
// each of Addr and RelayAddr at maxAddrLen. Per-kind validation
// matches the writer.
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
	addr, err := readLenPrefixedAddr(r, "addr", maxAddrLen)
	if err != nil {
		return ann, err
	}
	ann.Addr = addr
	relay, err := readLenPrefixedAddr(r, "relay", maxAddrLen)
	if err != nil {
		return ann, err
	}
	ann.RelayAddr = relay
	if err := validateAnnouncement(ann); err != nil {
		return PeerAnnouncement{}, err
	}
	return ann, nil
}

// readLenPrefixedAddr reads a 4-byte BE length followed by `length`
// bytes, capped at max. label appears in error wraps so callers can
// tell which field truncated.
func readLenPrefixedAddr(r io.Reader, label string, max int) (string, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", fmt.Errorf("read announcement %s length: %w", label, err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if max > 0 && int64(n) > int64(max) {
		return "", fmt.Errorf("%w: got %d, max %d", ErrAddrTooLarge, n, max)
	}
	if n == 0 {
		return "", nil
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", fmt.Errorf("read announcement %s: %w", label, err)
	}
	return string(body), nil
}

func validateAnnouncement(ann PeerAnnouncement) error {
	switch ann.Kind {
	case AnnouncePeerJoined:
		if ann.Role == 0 {
			return fmt.Errorf("announcement: PeerJoined requires non-zero role")
		}
	case AnnouncePeerLeft:
		// PubKey is sufficient; Role/Addr/RelayAddr ignored downstream.
	case AnnounceAddressChanged:
		if ann.Addr == "" && ann.RelayAddr == "" {
			return fmt.Errorf("announcement: AddressChanged requires non-empty addr or relay addr")
		}
	default:
		return fmt.Errorf("announcement: unknown kind %d", ann.Kind)
	}
	return nil
}
