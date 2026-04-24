// Package token serializes and deserializes shareable invite tokens
// carrying an introducer's listen address and Ed25519 public key. A
// leading version byte lets a node reject tokens in a format it does
// not understand with ErrUnknownVersion instead of misparsing them.
package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// wireVersion identifies the token layout. Bumped when the structure
// changes so old consumers fail closed on new tokens.
const wireVersion byte = 1

// maxAddrLen is the largest address a single token can carry. Addresses
// encode as a uint16 length prefix, so 65535 is the hard limit; we
// enforce it explicitly so Encode errors instead of silently truncating.
const maxAddrLen = 1<<16 - 1

// ErrUnknownVersion is returned by Decode when the leading version byte
// does not match the layout this build understands.
var ErrUnknownVersion = errors.New("unknown token version")

// Encode serializes addr and pub into a compact, ASCII-safe shareable
// string. Both fields are required; the address must be non-empty and the
// public key must be exactly ed25519.PublicKeySize bytes.
//
// Wire layout before base64-encoding:
//
//	[1 byte version][2 bytes BE addr_len][addr bytes][32 bytes pubkey]
func Encode(addr string, pub ed25519.PublicKey) (string, error) {
	if addr == "" {
		return "", errors.New("token: addr is required")
	}
	if len(addr) > maxAddrLen {
		return "", fmt.Errorf("token: addr length %d exceeds max %d", len(addr), maxAddrLen)
	}
	if len(pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("token: pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	raw := make([]byte, 0, 1+2+len(addr)+ed25519.PublicKeySize)
	raw = append(raw, wireVersion)
	var lenBuf [2]byte
	binary.BigEndian.PutUint16(lenBuf[:], uint16(len(addr)))
	raw = append(raw, lenBuf[:]...)
	raw = append(raw, addr...)
	raw = append(raw, pub...)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Decode parses a token produced by Encode. Returns the address and
// public key or an error describing why the token was rejected.
func Decode(s string) (addr string, pub ed25519.PublicKey, err error) {
	if s == "" {
		return "", nil, errors.New("token: empty input")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return "", nil, fmt.Errorf("token: not base64: %w", err)
	}
	if len(raw) < 1 {
		return "", nil, errors.New("token: truncated version")
	}
	if raw[0] != wireVersion {
		return "", nil, fmt.Errorf("%w: got %d, want %d", ErrUnknownVersion, raw[0], wireVersion)
	}
	raw = raw[1:]
	if len(raw) < 2 {
		return "", nil, errors.New("token: truncated addr length")
	}
	addrLen := binary.BigEndian.Uint16(raw[:2])
	raw = raw[2:]
	if int(addrLen) > len(raw) {
		return "", nil, fmt.Errorf("token: addr length %d exceeds remaining bytes %d", addrLen, len(raw))
	}
	addr = string(raw[:addrLen])
	raw = raw[addrLen:]
	if len(raw) != ed25519.PublicKeySize {
		return "", nil, fmt.Errorf("token: pubkey bytes %d, want %d", len(raw), ed25519.PublicKeySize)
	}
	pub = make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, raw)
	return addr, pub, nil
}

// EncodeRawForTest wraps an arbitrary raw payload in the same base64
// envelope Encode uses. Intended for tests that need to build adversarial
// or malformed tokens (unknown version, length-prefix overruns, etc.).
func EncodeRawForTest(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}
