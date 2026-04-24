// Package protocol defines the BackupSwarm peer-to-peer wire format.
//
// For M1.8 the vocabulary was a single message pair, PutChunkRequest and
// PutChunkResponse, exchanged on a dedicated QUIC stream per chunk. M1.9
// adds DeleteChunkRequest/DeleteChunkResponse for owner-authorized
// removal; M1.10 adds GetChunkRequest/GetChunkResponse for restore. All
// three live on the same listener, so every server-bound stream starts
// with a single MessageType byte that the dispatcher reads first to
// route the body.
//
// Framing is deliberately minimal and deterministic: big-endian length
// prefixes, no schema-ful encoders. The wire shape is expected to evolve
// in M3 when protobuf is introduced; the goal here is that the format is
// small enough to reason about and that the peer can detect malformed or
// maliciously-sized input without allocating attacker-controlled buffers.
package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MessageType tags the first byte of every peer-bound data-plane stream
// so the server dispatcher can route PutChunk vs DeleteChunk without
// speculatively parsing both frame shapes.
type MessageType byte

const (
	// MsgPutChunk prefixes a PutChunkRequest body.
	MsgPutChunk MessageType = 0x01
	// MsgDeleteChunk prefixes a DeleteChunkRequest body.
	MsgDeleteChunk MessageType = 0x02
	// MsgGetChunk prefixes a GetChunkRequest body.
	MsgGetChunk MessageType = 0x03
)

// WriteMessageType writes t as a single byte.
func WriteMessageType(w io.Writer, t MessageType) error {
	if _, err := w.Write([]byte{byte(t)}); err != nil {
		return fmt.Errorf("write message type: %w", err)
	}
	return nil
}

// ReadMessageType reads one byte and returns it as a MessageType.
func ReadMessageType(r io.Reader) (MessageType, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("read message type: %w", err)
	}
	return MessageType(b[0]), nil
}

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

// WriteDeleteChunkRequest frames the content hash on w. The body is a
// fixed-length 32-byte sha256 hash; the dispatch byte (MsgDeleteChunk)
// is written separately by the caller so server-side routing stays
// symmetric with the PutChunk path.
func WriteDeleteChunkRequest(w io.Writer, hash [sha256.Size]byte) error {
	if _, err := w.Write(hash[:]); err != nil {
		return fmt.Errorf("write delete request hash: %w", err)
	}
	return nil
}

// ReadDeleteChunkRequest reads a 32-byte hash from r.
func ReadDeleteChunkRequest(r io.Reader) ([sha256.Size]byte, error) {
	var hash [sha256.Size]byte
	if _, err := io.ReadFull(r, hash[:]); err != nil {
		return hash, fmt.Errorf("read delete request hash: %w", err)
	}
	return hash, nil
}

// WriteDeleteChunkResponse writes a response frame with the same OK/Err
// shape as WriteJoinAck: [statusOK] on success, [statusErr][4B len][bytes]
// on application error (owner mismatch, chunk not found, etc.).
func WriteDeleteChunkResponse(w io.Writer, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write delete response status: %w", err)
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write delete response status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write delete response error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write delete response error body: %w", err)
	}
	return nil
}

// WriteGetChunkRequest frames the content hash on w. The body is a
// fixed-length 32-byte sha256 hash; the dispatch byte (MsgGetChunk) is
// written separately by the caller so server-side routing stays
// symmetric with the Put/Delete paths.
func WriteGetChunkRequest(w io.Writer, hash [sha256.Size]byte) error {
	if _, err := w.Write(hash[:]); err != nil {
		return fmt.Errorf("write get request hash: %w", err)
	}
	return nil
}

// ReadGetChunkRequest reads a 32-byte hash from r.
func ReadGetChunkRequest(r io.Reader) ([sha256.Size]byte, error) {
	var hash [sha256.Size]byte
	if _, err := io.ReadFull(r, hash[:]); err != nil {
		return hash, fmt.Errorf("read get request hash: %w", err)
	}
	return hash, nil
}

// WriteGetChunkResponse writes a response frame. On success (appErr == ""),
// the frame is [statusOK][4 bytes BE blob_len][blob bytes]. On application
// error, the frame is [statusErr][4 bytes BE error_len][error bytes].
func WriteGetChunkResponse(w io.Writer, blob []byte, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write get response status: %w", err)
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(blob)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return fmt.Errorf("write get response length: %w", err)
		}
		if _, err := w.Write(blob); err != nil {
			return fmt.Errorf("write get response body: %w", err)
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write get response status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write get response error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write get response error body: %w", err)
	}
	return nil
}

// ReadGetChunkResponse reads a single response frame from r, capping the
// advertised blob length at maxBlobLen so a malicious peer cannot force
// a huge allocation via the length prefix. On success it returns the
// blob and an empty appErr. On application-level failure it returns a
// nil blob and the error string.
func ReadGetChunkResponse(r io.Reader, maxBlobLen int) (blob []byte, appErr string, err error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return nil, "", fmt.Errorf("read get response status: %w", err)
	}
	switch status[0] {
	case statusOK:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, "", fmt.Errorf("read get response length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if maxBlobLen > 0 && int64(n) > int64(maxBlobLen) {
			return nil, "", fmt.Errorf("%w: got %d, max %d", ErrBlobTooLarge, n, maxBlobLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, "", fmt.Errorf("read get response body: %w", err)
		}
		return body, "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, "", fmt.Errorf("read get response error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return nil, "", fmt.Errorf("get response error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, "", fmt.Errorf("read get response error body: %w", err)
		}
		return nil, string(body), nil
	default:
		return nil, "", fmt.Errorf("unknown get response status byte %d", status[0])
	}
}

// ReadDeleteChunkResponse reads a delete response frame, returning the
// application-level error string (empty on success) or a transport error.
func ReadDeleteChunkResponse(r io.Reader) (string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return "", fmt.Errorf("read delete response status: %w", err)
	}
	switch status[0] {
	case statusOK:
		return "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return "", fmt.Errorf("read delete response error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return "", fmt.Errorf("delete response error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return "", fmt.Errorf("read delete response error body: %w", err)
		}
		return string(body), nil
	default:
		return "", fmt.Errorf("unknown delete response status byte %d", status[0])
	}
}
