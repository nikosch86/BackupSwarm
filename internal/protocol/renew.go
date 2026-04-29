package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// WriteRenewTTLRequest frames the content hash on w. Body is a fixed
// 32-byte sha256; the dispatch byte is written separately by the caller.
func WriteRenewTTLRequest(w io.Writer, hash [sha256.Size]byte) error {
	if _, err := w.Write(hash[:]); err != nil {
		return fmt.Errorf("write renew request hash: %w", err)
	}
	return nil
}

// ReadRenewTTLRequest reads a 32-byte hash from r.
func ReadRenewTTLRequest(r io.Reader) ([sha256.Size]byte, error) {
	var hash [sha256.Size]byte
	if _, err := io.ReadFull(r, hash[:]); err != nil {
		return hash, fmt.Errorf("read renew request hash: %w", err)
	}
	return hash, nil
}

// WriteRenewTTLResponse writes [statusOK] on success or
// [statusErr][4B BE err_len][err bytes] on application error.
func WriteRenewTTLResponse(w io.Writer, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write renew response status: %w", err)
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write renew response status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write renew response error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write renew response error body: %w", err)
	}
	return nil
}

// ReadRenewTTLResponse reads a renew response, returning the app-level
// error string (empty on success) or a transport error.
func ReadRenewTTLResponse(r io.Reader) (string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return "", fmt.Errorf("read renew response status: %w", err)
	}
	switch status[0] {
	case statusOK:
		return "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", fmt.Errorf("read renew response error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return "", fmt.Errorf("renew response error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", fmt.Errorf("read renew response error body: %w", err)
		}
		return string(body), nil
	default:
		return "", fmt.Errorf("unknown renew response status byte %d", status[0])
	}
}
