// Package protocol defines the BackupSwarm peer-to-peer wire format. Each
// stream starts with a MessageType byte; bodies use big-endian length
// prefixes with caller-supplied size caps.
package protocol

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// MessageType tags the first byte of every peer-bound stream so the
// dispatcher can route to the right handler.
type MessageType byte

const (
	// MsgPutChunk prefixes a PutChunkRequest body.
	MsgPutChunk MessageType = 0x01
	// MsgDeleteChunk prefixes a DeleteChunkRequest body.
	MsgDeleteChunk MessageType = 0x02
	// MsgGetChunk prefixes a GetChunkRequest body.
	MsgGetChunk MessageType = 0x03
	// MsgPeerAnnouncement prefixes a PeerAnnouncement body.
	MsgPeerAnnouncement MessageType = 0x04
	// MsgJoinRequest prefixes a JoinRequest body. Lets the daemon's
	// dispatcher route join handshakes alongside backup traffic.
	MsgJoinRequest MessageType = 0x05
	// MsgGetCapacity prefixes a capacity-probe stream. The request body
	// is empty; the response reports the peer's used and max bytes.
	MsgGetCapacity MessageType = 0x06
	// MsgPing prefixes a liveness-probe stream. The request body is empty
	// (the type byte is the entire request); the response is a single
	// OK/Err status frame.
	MsgPing MessageType = 0x07
	// MsgPutIndexSnapshot prefixes a PutIndexSnapshot request body. The
	// owner is the conn's TLS-authenticated pubkey; peers store one
	// latest-wins slot per owner.
	MsgPutIndexSnapshot MessageType = 0x08
	// MsgGetIndexSnapshot prefixes a GetIndexSnapshot stream. The
	// request body is empty (the type byte IS the request); the response
	// returns the encrypted snapshot for the conn's authenticated owner.
	MsgGetIndexSnapshot MessageType = 0x09
	// MsgRenewTTL prefixes a RenewTTL request body (32-byte hash).
	// Owner-authenticated by the conn's TLS pubkey.
	MsgRenewTTL MessageType = 0x0a
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

	// MaxErrorMessageLen caps the length of a peer-returned error string.
	MaxErrorMessageLen = 1 << 12 // 4 KiB
)

// ErrBlobTooLarge is returned by ReadPutChunkRequest when the advertised
// blob length exceeds the caller-supplied cap.
var ErrBlobTooLarge = errors.New("put chunk blob exceeds maximum size")

// ErrAddrTooLarge is returned by ReadJoinHello when the advertised address
// length exceeds the caller-supplied cap.
var ErrAddrTooLarge = errors.New("join hello addr exceeds maximum size")

// ErrCSRTooLarge is returned by ReadJoinRequest when the advertised CSR
// length exceeds the caller-supplied cap.
var ErrCSRTooLarge = errors.New("join request csr exceeds maximum size")

// ErrCertTooLarge is returned by ReadJoinResponse when the signed leaf
// cert length exceeds the caller-supplied cap.
var ErrCertTooLarge = errors.New("join response cert exceeds maximum size")

// WritePutChunkRequest frames blob onto w as [4B BE length][blob bytes].
// Empty blobs are rejected.
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
// opaque blob bytes. Frames whose advertised length exceeds maxBlobLen
// are rejected with ErrBlobTooLarge without allocating the body.
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

// ReadPutChunkResponse reads a response frame. On success returns the
// peer-computed hash; on application error returns a zero hash and the
// error string. Transport errors are returned as the final value.
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

// WriteJoinRequest frames a join request on w as
// [32B swarmID][32B secret][4B BE addr_len][addr][4B BE csr_len][csr].
// csrDER is empty in pubkey-pin swarms.
func WriteJoinRequest(w io.Writer, swarmID, secret [32]byte, listenAddr string, csrDER []byte) error {
	if _, err := w.Write(swarmID[:]); err != nil {
		return fmt.Errorf("write join request swarm: %w", err)
	}
	if _, err := w.Write(secret[:]); err != nil {
		return fmt.Errorf("write join request secret: %w", err)
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(listenAddr)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write join request addr length: %w", err)
	}
	if len(listenAddr) > 0 {
		if _, err := w.Write([]byte(listenAddr)); err != nil {
			return fmt.Errorf("write join request addr: %w", err)
		}
	}
	binary.BigEndian.PutUint32(hdr[:], uint32(len(csrDER)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write join request csr length: %w", err)
	}
	if len(csrDER) > 0 {
		if _, err := w.Write(csrDER); err != nil {
			return fmt.Errorf("write join request csr: %w", err)
		}
	}
	return nil
}

// ReadJoinRequest reads a single join request frame from r. maxAddrLen
// caps the advertised listen address length; maxCSRLen caps the CSR DER
// length. csrDER is empty when the joiner did not send a CSR.
func ReadJoinRequest(r io.Reader, maxAddrLen, maxCSRLen int) (swarmID, secret [32]byte, listenAddr string, csrDER []byte, err error) {
	if _, err = io.ReadFull(r, swarmID[:]); err != nil {
		return swarmID, secret, "", nil, fmt.Errorf("read join request swarm: %w", err)
	}
	if _, err = io.ReadFull(r, secret[:]); err != nil {
		return swarmID, secret, "", nil, fmt.Errorf("read join request secret: %w", err)
	}
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return swarmID, secret, "", nil, fmt.Errorf("read join request addr length: %w", err)
	}
	addrLen := binary.BigEndian.Uint32(hdr[:])
	if maxAddrLen > 0 && int64(addrLen) > int64(maxAddrLen) {
		return swarmID, secret, "", nil, fmt.Errorf("%w: got %d, max %d", ErrAddrTooLarge, addrLen, maxAddrLen)
	}
	if addrLen > 0 {
		buf := make([]byte, addrLen)
		if _, err = io.ReadFull(r, buf); err != nil {
			return swarmID, secret, "", nil, fmt.Errorf("read join request addr: %w", err)
		}
		listenAddr = string(buf)
	}
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return swarmID, secret, listenAddr, nil, fmt.Errorf("read join request csr length: %w", err)
	}
	csrLen := binary.BigEndian.Uint32(hdr[:])
	if maxCSRLen > 0 && int64(csrLen) > int64(maxCSRLen) {
		return swarmID, secret, listenAddr, nil, fmt.Errorf("%w: got %d, max %d", ErrCSRTooLarge, csrLen, maxCSRLen)
	}
	if csrLen > 0 {
		csrDER = make([]byte, csrLen)
		if _, err = io.ReadFull(r, csrDER); err != nil {
			return swarmID, secret, listenAddr, nil, fmt.Errorf("read join request csr: %w", err)
		}
	}
	return swarmID, secret, listenAddr, csrDER, nil
}

// WriteJoinResponse writes [statusOK][4B BE cert_len][cert] on success
// (signedCertDER empty in pubkey-pin swarms) or
// [statusErr][4B BE err_len][err bytes] on application error.
func WriteJoinResponse(w io.Writer, signedCertDER []byte, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write join response status: %w", err)
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(signedCertDER)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return fmt.Errorf("write join response cert length: %w", err)
		}
		if len(signedCertDER) > 0 {
			if _, err := w.Write(signedCertDER); err != nil {
				return fmt.Errorf("write join response cert: %w", err)
			}
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write join response status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write join response error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write join response error body: %w", err)
	}
	return nil
}

// ReadJoinResponse reads a response frame from r, capping the signed
// leaf cert at maxCertLen. On application error the returned cert is nil
// and appErr is set; on success the cert is empty in pubkey-pin swarms.
func ReadJoinResponse(r io.Reader, maxCertLen int) ([]byte, string, error) {
	var status [1]byte
	if _, err := io.ReadFull(r, status[:]); err != nil {
		return nil, "", fmt.Errorf("read join response status: %w", err)
	}
	switch status[0] {
	case statusOK:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, "", fmt.Errorf("read join response cert length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if maxCertLen > 0 && int64(n) > int64(maxCertLen) {
			return nil, "", fmt.Errorf("%w: got %d, max %d", ErrCertTooLarge, n, maxCertLen)
		}
		if n == 0 {
			return nil, "", nil
		}
		cert := make([]byte, n)
		if _, err := io.ReadFull(r, cert); err != nil {
			return nil, "", fmt.Errorf("read join response cert: %w", err)
		}
		return cert, "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, "", fmt.Errorf("read join response error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return nil, "", fmt.Errorf("join response error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, "", fmt.Errorf("read join response error body: %w", err)
		}
		return nil, string(body), nil
	default:
		return nil, "", fmt.Errorf("unknown join response status byte %d", status[0])
	}
}

// PeerEntry is one element of a PeerListMessage. Role is opaque to this
// package; consumers map the byte to their own enum.
type PeerEntry struct {
	PubKey [32]byte
	Role   byte
	Addr   string
}

// WritePeerListMessage frames entries as [4B BE count][entry...] where
// each entry is [32B pubkey][1B role][4B BE addr_len][addr bytes]. A
// zero role is rejected.
func WritePeerListMessage(w io.Writer, entries []PeerEntry) error {
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(entries)))
	if _, err := w.Write(hdr[:]); err != nil {
		return fmt.Errorf("write peer list count: %w", err)
	}
	for i, e := range entries {
		if e.Role == 0 {
			return fmt.Errorf("write peer list entry %d: role is zero", i)
		}
		if _, err := w.Write(e.PubKey[:]); err != nil {
			return fmt.Errorf("write peer list entry %d pubkey: %w", i, err)
		}
		if _, err := w.Write([]byte{e.Role}); err != nil {
			return fmt.Errorf("write peer list entry %d role: %w", i, err)
		}
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], uint32(len(e.Addr)))
		if _, err := w.Write(lenBuf[:]); err != nil {
			return fmt.Errorf("write peer list entry %d addr length: %w", i, err)
		}
		if len(e.Addr) > 0 {
			if _, err := w.Write([]byte(e.Addr)); err != nil {
				return fmt.Errorf("write peer list entry %d addr: %w", i, err)
			}
		}
	}
	return nil
}

// ReadPeerListMessage reads a peer list frame from r. maxEntries caps the
// declared count; maxAddrLen caps each entry's addr. A zero role is
// rejected.
func ReadPeerListMessage(r io.Reader, maxEntries, maxAddrLen int) ([]PeerEntry, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("read peer list count: %w", err)
	}
	count := binary.BigEndian.Uint32(hdr[:])
	if maxEntries > 0 && int64(count) > int64(maxEntries) {
		return nil, fmt.Errorf("peer list count %d exceeds max %d", count, maxEntries)
	}
	out := make([]PeerEntry, 0, count)
	for i := uint32(0); i < count; i++ {
		var e PeerEntry
		if _, err := io.ReadFull(r, e.PubKey[:]); err != nil {
			return nil, fmt.Errorf("read peer list entry %d pubkey: %w", i, err)
		}
		var roleBuf [1]byte
		if _, err := io.ReadFull(r, roleBuf[:]); err != nil {
			return nil, fmt.Errorf("read peer list entry %d role: %w", i, err)
		}
		if roleBuf[0] == 0 {
			return nil, fmt.Errorf("read peer list entry %d: role is zero", i)
		}
		e.Role = roleBuf[0]
		var lenBuf [4]byte
		if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
			return nil, fmt.Errorf("read peer list entry %d addr length: %w", i, err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if maxAddrLen > 0 && int64(n) > int64(maxAddrLen) {
			return nil, fmt.Errorf("%w: entry %d got %d, max %d", ErrAddrTooLarge, i, n, maxAddrLen)
		}
		if n > 0 {
			body := make([]byte, n)
			if _, err := io.ReadFull(r, body); err != nil {
				return nil, fmt.Errorf("read peer list entry %d addr: %w", i, err)
			}
			e.Addr = string(body)
		}
		out = append(out, e)
	}
	return out, nil
}

// WriteDeleteChunkRequest frames the 32-byte content hash on w.
// The MsgDeleteChunk dispatch byte is written separately by the caller.
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

// WriteDeleteChunkResponse writes [statusOK] on success or
// [statusErr][4B len][bytes] on application error.
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

// WriteGetChunkRequest frames the 32-byte content hash on w.
// The MsgGetChunk dispatch byte is written separately by the caller.
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

// ReadGetChunkResponse reads a response frame, rejecting advertised blob
// lengths above maxBlobLen. On success returns the blob; on application
// error returns nil and the error string.
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

// WriteGetCapacityResponse writes [statusOK][8B BE used][8B BE max] on
// success (max=0 = unlimited) or [statusErr][4B BE error_len][error]
// on application error.
func WriteGetCapacityResponse(w io.Writer, used, max int64, appErr string) error {
	if appErr == "" {
		if _, err := w.Write([]byte{statusOK}); err != nil {
			return fmt.Errorf("write capacity response status: %w", err)
		}
		var buf [8]byte
		binary.BigEndian.PutUint64(buf[:], uint64(used))
		if _, err := w.Write(buf[:]); err != nil {
			return fmt.Errorf("write capacity response used: %w", err)
		}
		binary.BigEndian.PutUint64(buf[:], uint64(max))
		if _, err := w.Write(buf[:]); err != nil {
			return fmt.Errorf("write capacity response cap: %w", err)
		}
		return nil
	}
	if _, err := w.Write([]byte{statusErr}); err != nil {
		return fmt.Errorf("write capacity response status: %w", err)
	}
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(appErr)))
	if _, err := w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("write capacity response error length: %w", err)
	}
	if _, err := w.Write([]byte(appErr)); err != nil {
		return fmt.Errorf("write capacity response error body: %w", err)
	}
	return nil
}

// ReadGetCapacityResponse returns (used, max, "", nil) on success
// (max=0 = unlimited), (0, 0, errString, nil) on application error,
// or a transport error as the final return.
func ReadGetCapacityResponse(r io.Reader) (used, max int64, appErr string, err error) {
	var status [1]byte
	if _, err = io.ReadFull(r, status[:]); err != nil {
		return 0, 0, "", fmt.Errorf("read capacity response status: %w", err)
	}
	switch status[0] {
	case statusOK:
		var buf [8]byte
		if _, err = io.ReadFull(r, buf[:]); err != nil {
			return 0, 0, "", fmt.Errorf("read capacity response used: %w", err)
		}
		used = int64(binary.BigEndian.Uint64(buf[:]))
		if _, err = io.ReadFull(r, buf[:]); err != nil {
			return 0, 0, "", fmt.Errorf("read capacity response cap: %w", err)
		}
		max = int64(binary.BigEndian.Uint64(buf[:]))
		return used, max, "", nil
	case statusErr:
		var lenBuf [4]byte
		if _, err = io.ReadFull(r, lenBuf[:]); err != nil {
			return 0, 0, "", fmt.Errorf("read capacity response error length: %w", err)
		}
		n := binary.BigEndian.Uint32(lenBuf[:])
		if n > MaxErrorMessageLen {
			return 0, 0, "", fmt.Errorf("capacity response error length %d exceeds max %d", n, MaxErrorMessageLen)
		}
		body := make([]byte, n)
		if _, err = io.ReadFull(r, body); err != nil {
			return 0, 0, "", fmt.Errorf("read capacity response error body: %w", err)
		}
		return 0, 0, string(body), nil
	default:
		return 0, 0, "", fmt.Errorf("unknown capacity response status byte %d", status[0])
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
