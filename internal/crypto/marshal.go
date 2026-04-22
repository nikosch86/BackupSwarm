package crypto

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// ErrUnknownWireVersion is returned by UnmarshalEncryptedChunk when the
// leading version byte does not match a known wire format.
var ErrUnknownWireVersion = errors.New("unknown encrypted-chunk wire version")

// wireVersion is the leading byte of MarshalBinary output. Bumped when the
// on-wire layout changes so older receivers fail closed instead of
// mis-parsing unfamiliar bytes.
const wireVersion byte = 1

// MarshalBinary produces the canonical wire representation of the
// encrypted chunk:
//
//	[1 byte version][24 bytes nonce][4 bytes BE wrapped_key_len][wrapped_key][4 bytes BE ciphertext_len][ciphertext]
//
// The format is deterministic — two calls on the same struct value produce
// identical bytes. That is load-bearing: storage peers address blobs by
// sha256(marshaled bytes), so any non-determinism would break content
// addressing across the two ends of a backup stream.
func (ec *EncryptedChunk) MarshalBinary() ([]byte, error) {
	if len(ec.Nonce) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(ec.Nonce))
	}
	total := 1 + NonceSize + 4 + len(ec.WrappedKey) + 4 + len(ec.Ciphertext)
	out := make([]byte, 0, total)
	out = append(out, wireVersion)
	out = append(out, ec.Nonce...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ec.WrappedKey)))
	out = append(out, lenBuf[:]...)
	out = append(out, ec.WrappedKey...)
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(ec.Ciphertext)))
	out = append(out, lenBuf[:]...)
	out = append(out, ec.Ciphertext...)
	return out, nil
}

// UnmarshalEncryptedChunk parses the canonical wire representation produced
// by MarshalBinary. Fails with ErrUnknownWireVersion on version mismatch,
// or with a descriptive error on truncated input.
func UnmarshalEncryptedChunk(b []byte) (*EncryptedChunk, error) {
	if len(b) < 1 {
		return nil, errors.New("encrypted chunk: empty input")
	}
	if b[0] != wireVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnknownWireVersion, b[0], wireVersion)
	}
	b = b[1:]
	if len(b) < NonceSize {
		return nil, errors.New("encrypted chunk: truncated nonce")
	}
	nonce := make([]byte, NonceSize)
	copy(nonce, b[:NonceSize])
	b = b[NonceSize:]

	if len(b) < 4 {
		return nil, errors.New("encrypted chunk: truncated wrapped-key length")
	}
	wrappedLen := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if uint32(len(b)) < wrappedLen {
		return nil, errors.New("encrypted chunk: truncated wrapped key")
	}
	wrapped := make([]byte, wrappedLen)
	copy(wrapped, b[:wrappedLen])
	b = b[wrappedLen:]

	if len(b) < 4 {
		return nil, errors.New("encrypted chunk: truncated ciphertext length")
	}
	ctLen := binary.BigEndian.Uint32(b[:4])
	b = b[4:]
	if uint32(len(b)) < ctLen {
		return nil, errors.New("encrypted chunk: truncated ciphertext")
	}
	ct := make([]byte, ctLen)
	copy(ct, b[:ctLen])

	return &EncryptedChunk{Nonce: nonce, WrappedKey: wrapped, Ciphertext: ct}, nil
}
