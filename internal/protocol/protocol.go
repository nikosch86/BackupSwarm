// Package protocol defines the BackupSwarm peer-to-peer wire format.
//
// For M1.8 the vocabulary is a single message pair, PutChunkRequest and
// PutChunkResponse, exchanged on a dedicated QUIC stream per chunk. The
// request carries an opaque blob (the marshaled EncryptedChunk from
// internal/crypto) and the response carries either the sha256 of that
// blob (as stored on the peer) or an application-level error string.
//
// Framing is deliberately minimal and deterministic: big-endian length
// prefixes, no schema-ful encoders. The wire shape is expected to evolve
// in M3 when protobuf is introduced; the goal here is that the format is
// small enough to reason about and that the peer can detect malformed or
// maliciously-sized input without allocating attacker-controlled buffers.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Response status codes.
const (
	statusOK  byte = 0
	statusErr byte = 1

	// MaxErrorMessageLen caps the length of a peer-returned error string
	// so a misbehaving peer cannot force a huge allocation via the error
	// length prefix.
	MaxErrorMessageLen = 1 << 12 // 4 KiB
)

// ErrBlobTooLarge is returned by ReadPutChunkRequest when the advertised
// blob length exceeds the caller-supplied cap.
var ErrBlobTooLarge = errors.New("put chunk blob exceeds maximum size")

// ErrAddrTooLarge is returned by ReadJoinHello when the advertised address
// length exceeds the caller-supplied cap.
var ErrAddrTooLarge = errors.New("join hello addr exceeds maximum size")

// WritePutChunkRequest frames blob onto w. The frame is
// [4 bytes BE length][blob bytes]. Empty blobs are rejected; the peer
// stores blob bytes by sha256 and a zero-length blob has no useful
// content address.
func WritePutChunkRequest(w io.Writer, blob []byte) error {
	if len(blob) == 0 {
		return errors.New("put chunk blob must be non-empty")
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(blob)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write request header: %w", err)
	}
	if _, err := w.Write(blob); err != nil {
		return fmt.Errorf("write request body: %w", err)
	}
	return nil
}

// ReadPutChunkRequest reads a single request frame from r, returning the
// opaque blob bytes. maxBlobLen bounds the blob size; frames whose
// advertised length exceeds this cap are rejected with ErrBlobTooLarge
// before any body read is attempted.
func ReadPutChunkRequest(r io.Reader, maxBlobLen int) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read request header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if maxBlobLen > 0 && int64(n) > int64(maxBlobLen) {
		return nil, fmt.Errorf("%w: got %d, max %d", ErrBlobTooLarge, n, maxBlobLen)
	}
	blob := make([]byte, n)
	if _, err := io.ReadFull(r, blob); err != nil {
		return nil, fmt.Errorf("read request body: %w", err)
	}
	return blob, nil
}

// WritePutChunkResponse writes a response frame. On success (appErr == ""),
// the frame is [statusOK][32 bytes hash]. On application error, the frame is
// [statusErr][4 bytes BE error_len][error bytes].
func WritePutChunkResponse(w io.Writer, hash [32]byte, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write response status: %w", err)
		}
		if _, err := w.Write(hash[:]); err != nil {
			return fmt.Errorf("write response hash: %w", err)
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write response status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write response error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write response error body: %w", err)
	}
	return nil
}

// ReadPutChunkResponse reads a single response frame from r. On success it
// returns the peer-computed hash and an empty appErr. On an application-level
// failure it returns a zero hash and the error string from the peer.
// Transport-level failures (truncated frame, unknown status) are returned as
// the third value.
func ReadPutChunkResponse(r io.Reader) (hash [32]byte, appErr string, err error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return hash, "", fmt.Errorf("read response status: %w", err)
	}
	switch status[0] {
	case statusOK:
		if _, err := io.ReadFull(r, hash[:]); err != nil {
			return hash, "", fmt.Errorf("read response hash: %w", err)
		}
		return hash, "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return hash, "", fmt.Errorf("read response error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return hash, "", fmt.Errorf("response error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return hash, "", fmt.Errorf("read response error body: %w", err)
		}
		return hash, string(body), nil
	default:
		return hash, "", fmt.Errorf("unknown response status byte %d", status[0])
	}
}

// WriteJoinHello frames the joiner-advertised listen address on w.
// The frame layout is [4 bytes BE length][addr bytes]. An empty address
// is permitted — it signals "I have no daemon addr yet; record only my
// pubkey." The caller's TLS session already carries the joiner's
// authenticated pubkey, so this message carries only the addr.
func WriteJoinHello(w io.Writer, listenAddr string) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(listenAddr)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write hello header: %w", err)
	}
	if len(listenAddr) == 0 {
		return nil
	}
	if _, err := w.Write([]byte(listenAddr)); err != nil {
		return fmt.Errorf("write hello body: %w", err)
	}
	return nil
}

// ReadJoinHello reads a single JoinHello frame from r, returning the
// advertised address string. maxAddrLen caps the advertised length so a
// misbehaving joiner cannot drive a huge allocation.
func ReadJoinHello(r io.Reader, maxAddrLen int) (string, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return "", fmt.Errorf("read hello header: %w", err)
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if maxAddrLen > 0 && int64(n) > int64(maxAddrLen) {
		return "", fmt.Errorf("%w: got %d, max %d", ErrAddrTooLarge, n, maxAddrLen)
	}
	if n == 0 {
		return "", nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("read hello body: %w", err)
	}
	return string(buf), nil
}

// WriteJoinAck writes an acknowledgement frame. On success (appErr == ""),
// the frame is [statusOK]. On an application-level failure the frame is
// [statusErr][4 bytes BE err_len][err bytes], identical to the error path
// in WritePutChunkResponse.
func WriteJoinAck(w io.Writer, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write ack status: %w", err)
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write ack status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write ack error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write ack error body: %w", err)
	}
	return nil
}

// ReadJoinAck reads a single ack frame from r. Returns the peer-supplied
// error string on application failure (empty on success) or a transport
// error on malformed input.
func ReadJoinAck(r io.Reader) (string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return "", fmt.Errorf("read ack status: %w", err)
	}
	switch status[0] {
	case statusOK:
		return "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", fmt.Errorf("read ack error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return "", fmt.Errorf("ack error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", fmt.Errorf("read ack error body: %w", err)
		}
		return string(body), nil
	default:
		return "", fmt.Errorf("unknown ack status byte %d", status[0])
	}
}
