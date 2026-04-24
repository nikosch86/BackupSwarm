// Package crypto implements chunk-level hybrid encryption: each chunk is
// sealed with a fresh XChaCha20-Poly1305 symmetric key, which is then
// wrapped for a recipient X25519 public key using NaCl anonymous box.
// Storage peers see only opaque ciphertext and opaque wrapped key.
// Recipient X25519 keys are distinct from the node's Ed25519 identity.
package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/nacl/box"
)

// randReader is the source of randomness used by every primitive in this
// package. It is a package-level seam so tests can substitute a failing
// reader to exercise rng-error branches; production code never reassigns it.
var randReader io.Reader = rand.Reader

// Sizes for the primitives this package uses.
const (
	SymmetricKeySize = chacha20poly1305.KeySize    // 32 bytes
	NonceSize        = chacha20poly1305.NonceSizeX // 24 bytes (XChaCha20)
	RecipientKeySize = 32                          // X25519 keys are 32 bytes
)

// ErrUnwrapFailed is returned by Decrypt when the wrapped per-chunk key
// cannot be opened with the provided recipient key pair (wrong key, or the
// wrapped key has been tampered with).
var ErrUnwrapFailed = errors.New("chunk key unwrap failed")

// ErrDecryptFailed is returned by Decrypt when the AEAD rejects the
// ciphertext or nonce — i.e. authentication failed because the chunk
// payload or nonce was tampered with after sealing.
var ErrDecryptFailed = errors.New("chunk decryption failed")

// EncryptedChunk is the opaque on-the-wire representation of an encrypted
// chunk. All three fields are required to decrypt; none of them, on their
// own or together, leak plaintext to a holder without the recipient's
// private key.
type EncryptedChunk struct {
	Ciphertext []byte // XChaCha20-Poly1305 sealed plaintext (includes 16-byte tag)
	Nonce      []byte // 24-byte XChaCha20 nonce, unique per encryption
	WrappedKey []byte // NaCl anonymous-box-sealed symmetric key
}

// GenerateRecipientKey returns a fresh X25519 key pair suitable for
// receiving wrapped chunk keys. The public key is shareable; the private
// key must stay on the owning node.
func GenerateRecipientKey() (publicKey, privateKey *[RecipientKeySize]byte, err error) {
	pub, priv, err := box.GenerateKey(randReader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return pub, priv, nil
}

// Encrypt seals plaintext for the given recipient public key. A fresh
// XChaCha20-Poly1305 key and 24-byte nonce are generated per call, so two
// encryptions of the same plaintext to the same recipient produce different
// ciphertexts and wrapped keys.
func Encrypt(plaintext []byte, recipientPub *[RecipientKeySize]byte) (*EncryptedChunk, error) {
	if recipientPub == nil {
		return nil, errors.New("recipient public key is required")
	}

	var key [SymmetricKeySize]byte
	if _, err := io.ReadFull(randReader, key[:]); err != nil {
		return nil, fmt.Errorf("generate chunk key: %w", err)
	}

	aead, err := chacha20poly1305.NewX(key[:])
	if err != nil {
		return nil, fmt.Errorf("init xchacha20poly1305: %w", err)
	}

	nonce := make([]byte, NonceSize)
	if _, err := io.ReadFull(randReader, nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, plaintext, nil)

	wrapped, err := box.SealAnonymous(nil, key[:], recipientPub, randReader)
	if err != nil {
		return nil, fmt.Errorf("wrap chunk key: %w", err)
	}

	return &EncryptedChunk{
		Ciphertext: ciphertext,
		Nonce:      nonce,
		WrappedKey: wrapped,
	}, nil
}

// Decrypt unwraps the per-chunk symmetric key with the recipient key pair
// and opens the AEAD ciphertext. Tampering with any of Ciphertext, Nonce,
// or WrappedKey causes Decrypt to fail with ErrDecryptFailed or
// ErrUnwrapFailed respectively.
func Decrypt(ec *EncryptedChunk, recipientPub, recipientPriv *[RecipientKeySize]byte) ([]byte, error) {
	if ec == nil {
		return nil, errors.New("encrypted chunk is nil")
	}
	if recipientPub == nil || recipientPriv == nil {
		return nil, errors.New("recipient key pair is required")
	}

	key, ok := box.OpenAnonymous(nil, ec.WrappedKey, recipientPub, recipientPriv)
	if !ok {
		return nil, ErrUnwrapFailed
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("init xchacha20poly1305: %w", err)
	}

	plaintext, err := aead.Open(nil, ec.Nonce, ec.Ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptFailed, err)
	}
	return plaintext, nil
}
