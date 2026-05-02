package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// PunchPayload is the wire body shared by MsgPunchRequest and
// MsgPunchSignal. The dispatcher distinguishes the two via the
// MessageType byte; PeerPub and Addr are interpreted at the call site
// (target_pub/initiator_addr for a request; initiator_pub/initiator_addr
// for a signal).
type PunchPayload struct {
	PeerPub [32]byte
	Addr    string
}

// WritePunchPayload frames p on w as [32B pubkey][4B BE addr_len][addr].
// Empty Addr is rejected — punching to nowhere is meaningless.
func WritePunchPayload(w io.Writer, p PunchPayload) error {
	if p.Addr == "" {
		return errors.New("punch payload: addr must be non-empty")
	}
	if _, err := w.Write(p.PeerPub[:]); err != nil {
		return fmt.Errorf("write punch pubkey: %w", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(p.Addr)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write punch addr length: %w", err)
	}
	if _, err := w.Write([]byte(p.Addr)); err != nil {
		return fmt.Errorf("write punch addr: %w", err)
	}
	return nil
}

// ReadPunchPayload reads one punch frame from r, capping the advertised
// addr length at maxAddrLen. Empty Addr is rejected at the read boundary.
func ReadPunchPayload(r io.Reader, maxAddrLen int) (PunchPayload, error) {
	var p PunchPayload
	if _, err := io.ReadFull(r, p.PeerPub[:]); err != nil {
		return p, fmt.Errorf("read punch pubkey: %w", err)
	}
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return p, fmt.Errorf("read punch addr length: %w", err)
	}
	addrLen := binary.BigEndian.Uint32(hdr[:])
	if maxAddrLen > 0 && int64(addrLen) > int64(maxAddrLen) {
		return p, fmt.Errorf("%w: got %d, max %d", ErrAddrTooLarge, addrLen, maxAddrLen)
	}
	if addrLen == 0 {
		return p, errors.New("punch payload: addr must be non-empty")
	}
	body := make([]byte, addrLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return p, fmt.Errorf("read punch addr: %w", err)
	}
	p.Addr = string(body)
	return p, nil
}

// WritePunchResponse writes [statusOK] on success or
// [statusErr][4B BE err_len][err bytes] on application error.
func WritePunchResponse(w io.Writer, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write punch response status: %w", err)
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write punch response status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write punch response error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write punch response error body: %w", err)
	}
	return nil
}

// ReadPunchResponse reads a punch response, returning the application
// error string (empty on success) or a transport error.
func ReadPunchResponse(r io.Reader) (string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return "", fmt.Errorf("read punch response status: %w", err)
	}
	switch status[0] {
	case statusOK:
		return "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", fmt.Errorf("read punch response error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return "", fmt.Errorf("punch response error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", fmt.Errorf("read punch response error body: %w", err)
		}
		return string(body), nil
	default:
		return "", fmt.Errorf("unknown punch response status byte %d", status[0])
	}
}
