package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// ErrIndexSnapshotTooLarge is returned by ReadPutIndexSnapshotRequest and
// ReadGetIndexSnapshotResponse when the advertised blob length exceeds the
// caller-supplied cap.
var ErrIndexSnapshotTooLarge = errors.New("index snapshot blob exceeds maximum size")

// WritePutIndexSnapshotRequest frames blob onto w as
// [4 bytes BE length][blob bytes]. Empty blobs are rejected.
func WritePutIndexSnapshotRequest(w io.Writer, blob []byte) error {
	if len(blob) == 0 {
		return errors.New("put index snapshot blob must be non-empty")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(blob)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write put index snapshot length: %w", err)
	}
	if _, err := w.Write(blob); err != nil {
		return fmt.Errorf("write put index snapshot body: %w", err)
	}
	return nil
}

// ReadPutIndexSnapshotRequest reads a single request frame from r,
// capping the advertised blob length at maxBlobLen so a malicious peer
// cannot force a huge allocation via the length prefix.
func ReadPutIndexSnapshotRequest(r io.Reader, maxBlobLen int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read put index snapshot length: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if maxBlobLen > 0 && int64(n) > int64(maxBlobLen) {
		return nil, fmt.Errorf("%w: got %d, max %d", ErrIndexSnapshotTooLarge, n, maxBlobLen)
	}
	blob := make([]byte, n)
	if _, err := io.ReadFull(r, blob); err != nil {
		return nil, fmt.Errorf("read put index snapshot body: %w", err)
	}
	return blob, nil
}

// WritePutIndexSnapshotResponse writes [statusOK] on success or
// [statusErr][4B BE err_len][err bytes] on application error.
func WritePutIndexSnapshotResponse(w io.Writer, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write put index snapshot response status: %w", err)
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write put index snapshot response status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write put index snapshot response error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write put index snapshot response error body: %w", err)
	}
	return nil
}

// ReadPutIndexSnapshotResponse reads a response frame, returning the
// application-level error string (empty on success) or a transport error.
func ReadPutIndexSnapshotResponse(r io.Reader) (string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return "", fmt.Errorf("read put index snapshot response status: %w", err)
	}
	switch status[0] {
	case statusOK:
		return "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", fmt.Errorf("read put index snapshot response error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return "", fmt.Errorf("put index snapshot response error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", fmt.Errorf("read put index snapshot response error body: %w", err)
		}
		return string(body), nil
	default:
		return "", fmt.Errorf("unknown put index snapshot response status byte %d", status[0])
	}
}

// WriteGetIndexSnapshotResponse writes [statusOK][4B BE blob_len][blob]
// on success or [statusErr][4B BE err_len][err bytes] on application error.
func WriteGetIndexSnapshotResponse(w io.Writer, blob []byte, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write get index snapshot response status: %w", err)
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(blob)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return fmt.Errorf("write get index snapshot response length: %w", err)
		}
		if _, err := w.Write(blob); err != nil {
			return fmt.Errorf("write get index snapshot response body: %w", err)
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write get index snapshot response status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write get index snapshot response error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write get index snapshot response error body: %w", err)
	}
	return nil
}

// ReadGetIndexSnapshotResponse reads a single response frame from r,
// capping the advertised blob length at maxBlobLen. Returns the blob on
// success, or a nil blob plus appErr on application-level failure.
func ReadGetIndexSnapshotResponse(r io.Reader, maxBlobLen int) (blob []byte, appErr string, err error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return nil, "", fmt.Errorf("read get index snapshot response status: %w", err)
	}
	switch status[0] {
	case statusOK:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, "", fmt.Errorf("read get index snapshot response length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if maxBlobLen > 0 && int64(n) > int64(maxBlobLen) {
			return nil, "", fmt.Errorf("%w: got %d, max %d", ErrIndexSnapshotTooLarge, n, maxBlobLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, "", fmt.Errorf("read get index snapshot response body: %w", err)
		}
		return body, "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, "", fmt.Errorf("read get index snapshot response error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return nil, "", fmt.Errorf("get index snapshot response error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, "", fmt.Errorf("read get index snapshot response error body: %w", err)
		}
		return nil, string(body), nil
	default:
		return nil, "", fmt.Errorf("unknown get index snapshot response status byte %d", status[0])
	}
}
