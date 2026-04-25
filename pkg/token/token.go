// Package token serializes shareable invite tokens carrying an introducer's
// listen address, Ed25519 public key, swarm ID, single-use join secret, and
// optional swarm CA cert. Unknown version bytes Decode to ErrUnknownVersion.
package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// wireVersion is the layout tag at the head of every encoded token.
const wireVersion byte = 2

// maxAddrLen and maxCACertLen are the uint16 length-prefix ceilings.
const (
	maxAddrLen   = 1<<16 - 1
	maxCACertLen = 1<<16 - 1
)

// SwarmIDSize and SecretSize are the fixed widths of the matching Token fields.
const (
	SwarmIDSize = 32
	SecretSize  = 32
)

// ErrUnknownVersion is returned by Decode when the leading version byte
// does not match the layout this build understands.
var ErrUnknownVersion = errors.New("unknown token version")

// Token is the decoded shape of an invite. CACert is optional; all other
// fields are required.
type Token struct {
	Addr    string
	Pub     ed25519.PublicKey
	SwarmID [SwarmIDSize]byte
	Secret  [SecretSize]byte
	CACert  []byte
}

// Encode serializes t to a base64url string. Wire layout (pre-base64):
// version(1) | addr_len(2) | addr | pub(32) | swarmID(32) | secret(32) |
// ca_len(2) | ca.
func Encode(t Token) (string, error) {
	if t.Addr == "" {
		return "", errors.New("token: addr is required")
	}
	if len(t.Addr) > maxAddrLen {
		return "", fmt.Errorf("token: addr length %d exceeds max %d", len(t.Addr), maxAddrLen)
	}
	if len(t.Pub) != ed25519.PublicKeySize {
		return "", fmt.Errorf("token: pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(t.Pub))
	}
	if len(t.CACert) > maxCACertLen {
		return "", fmt.Errorf("token: ca cert length %d exceeds max %d", len(t.CACert), maxCACertLen)
	}

	size := 1 + 2 + len(t.Addr) + ed25519.PublicKeySize + SwarmIDSize + SecretSize + 2 + len(t.CACert)
	raw := make([]byte, 0, size)
	raw = append(raw, wireVersion)

	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(t.Addr)))
	raw = append(raw, u16[:]...)
	raw = append(raw, t.Addr...)
	raw = append(raw, t.Pub...)
	raw = append(raw, t.SwarmID[:]...)
	raw = append(raw, t.Secret[:]...)

	binary.BigEndian.PutUint16(u16[:], uint16(len(t.CACert)))
	raw = append(raw, u16[:]...)
	raw = append(raw, t.CACert...)

	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// Decode parses a token produced by Encode. Returns the populated
// Token or an error describing why the input was rejected.
func Decode(s string) (Token, error) {
	if s == "" {
		return Token{}, errors.New("token: empty input")
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return Token{}, fmt.Errorf("token: not base64: %w", err)
	}
	if len(raw) < 1 {
		return Token{}, errors.New("token: truncated version")
	}
	if raw[0] != wireVersion {
		return Token{}, fmt.Errorf("%w: got %d, want %d", ErrUnknownVersion, raw[0], wireVersion)
	}
	raw = raw[1:]

	if len(raw) < 2 {
		return Token{}, errors.New("token: truncated addr length")
	}
	addrLen := binary.BigEndian.Uint16(raw[:2])
	raw = raw[2:]
	if int(addrLen) > len(raw) {
		return Token{}, fmt.Errorf("token: addr length %d exceeds remaining bytes %d", addrLen, len(raw))
	}
	addr := string(raw[:addrLen])
	raw = raw[addrLen:]

	if len(raw) < ed25519.PublicKeySize {
		return Token{}, fmt.Errorf("token: truncated pubkey, have %d want %d", len(raw), ed25519.PublicKeySize)
	}
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(pub, raw[:ed25519.PublicKeySize])
	raw = raw[ed25519.PublicKeySize:]

	var t Token
	t.Addr = addr
	t.Pub = pub

	if len(raw) < SwarmIDSize {
		return Token{}, fmt.Errorf("token: truncated swarm id, have %d want %d", len(raw), SwarmIDSize)
	}
	copy(t.SwarmID[:], raw[:SwarmIDSize])
	raw = raw[SwarmIDSize:]

	if len(raw) < SecretSize {
		return Token{}, fmt.Errorf("token: truncated secret, have %d want %d", len(raw), SecretSize)
	}
	copy(t.Secret[:], raw[:SecretSize])
	raw = raw[SecretSize:]

	if len(raw) < 2 {
		return Token{}, errors.New("token: truncated ca cert length")
	}
	caLen := binary.BigEndian.Uint16(raw[:2])
	raw = raw[2:]
	if int(caLen) > len(raw) {
		return Token{}, fmt.Errorf("token: ca cert length %d exceeds remaining bytes %d", caLen, len(raw))
	}
	if caLen > 0 {
		t.CACert = make([]byte, caLen)
		copy(t.CACert, raw[:caLen])
	}
	raw = raw[caLen:]

	if len(raw) != 0 {
		return Token{}, fmt.Errorf("token: %d trailing bytes", len(raw))
	}
	return t, nil
}

// EncodeRawForTest wraps an arbitrary payload in the same base64 envelope
// Encode uses, for tests that craft malformed wire bytes.
func EncodeRawForTest(raw []byte) string {
	return base64.RawURLEncoding.EncodeToString(raw)
}

// DecodeRawForTest unwraps the EncodeRawForTest envelope.
func DecodeRawForTest(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
