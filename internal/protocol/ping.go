package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// WritePingResponse writes [statusOK] on success or
// [statusErr][4B BE err_len][err bytes] on application error.
func WritePingResponse(w io.Writer, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write ping response status: %w", err)
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write ping response status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write ping response error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write ping response error body: %w", err)
	}
	return nil
}

// ReadPingResponse reads a ping response, returning the application
// error string (empty on success) or a transport error.
func ReadPingResponse(r io.Reader) (string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return "", fmt.Errorf("read ping response status: %w", err)
	}
	switch status[0] {
	case statusOK:
		return "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", fmt.Errorf("read ping response error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return "", fmt.Errorf("ping response error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", fmt.Errorf("read ping response error body: %w", err)
		}
		return string(body), nil
	default:
		return "", fmt.Errorf("unknown ping response status byte %d", status[0])
	}
}
