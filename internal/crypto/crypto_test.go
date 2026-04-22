package crypto_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"

	"backupswarm/internal/crypto"
)

func mustGenerateRecipient(t *testing.T) (pub, priv *[32]byte) {
	t.Helper()
	pub, priv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	if pub == nil || priv == nil {
		t.Fatal("GenerateRecipientKey returned nil keys")
	}
	return pub, priv
}

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	pub, priv := mustGenerateRecipient(t)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")

	ec, err := crypto.Encrypt(plaintext, pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := crypto.Decrypt(ec, pub, priv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch: got %q want %q", got, plaintext)
	}
}

func TestEncryptDecrypt_EmptyPlaintext(t *testing.T) {
	pub, priv := mustGenerateRecipient(t)

	ec, err := crypto.Encrypt(nil, pub)
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}
	got, err := crypto.Decrypt(ec, pub, priv)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(got))
	}
}

func TestEncryptDecrypt_LargePayload(t *testing.T) {
	pub, priv := mustGenerateRecipient(t)
	plaintext := make([]byte, 4<<20) // 4 MiB — max chunk size
	if _, err := rand.Read(plaintext); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	ec, err := crypto.Encrypt(plaintext, pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	got, err := crypto.Decrypt(ec, pub, priv)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("large round-trip mismatch")
	}
}

func TestEncrypt_NonceUniquePerCall(t *testing.T) {
	pub, _ := mustGenerateRecipient(t)
	plaintext := []byte("identical input")

	a, err := crypto.Encrypt(plaintext, pub)
	if err != nil {
		t.Fatalf("Encrypt a: %v", err)
	}
	b, err := crypto.Encrypt(plaintext, pub)
	if err != nil {
		t.Fatalf("Encrypt b: %v", err)
	}
	if bytes.Equal(a.Nonce, b.Nonce) {
		t.Fatal("nonces must be unique across encryptions")
	}
	if bytes.Equal(a.Ciphertext, b.Ciphertext) {
		t.Fatal("ciphertexts must differ for the same plaintext (random key + nonce)")
	}
	if bytes.Equal(a.WrappedKey, b.WrappedKey) {
		t.Fatal("wrapped keys must differ across encryptions (per-chunk symmetric key)")
	}
}

func TestDecrypt_WrongPrivateKey(t *testing.T) {
	pub, _ := mustGenerateRecipient(t)
	_, otherPriv := mustGenerateRecipient(t)

	ec, err := crypto.Encrypt([]byte("secret"), pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := crypto.Decrypt(ec, pub, otherPriv); !errors.Is(err, crypto.ErrUnwrapFailed) {
		t.Fatalf("expected ErrUnwrapFailed, got %v", err)
	}
}

func TestDecrypt_TamperedCiphertext(t *testing.T) {
	pub, priv := mustGenerateRecipient(t)
	ec, err := crypto.Encrypt([]byte("authenticated payload"), pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ec.Ciphertext[0] ^= 0xff

	if _, err := crypto.Decrypt(ec, pub, priv); !errors.Is(err, crypto.ErrDecryptFailed) {
		t.Fatalf("expected ErrDecryptFailed for tampered ciphertext, got %v", err)
	}
}

func TestDecrypt_TamperedNonce(t *testing.T) {
	pub, priv := mustGenerateRecipient(t)
	ec, err := crypto.Encrypt([]byte("nonce-bound payload"), pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ec.Nonce[0] ^= 0xff

	if _, err := crypto.Decrypt(ec, pub, priv); !errors.Is(err, crypto.ErrDecryptFailed) {
		t.Fatalf("expected ErrDecryptFailed for tampered nonce, got %v", err)
	}
}

func TestDecrypt_TamperedWrappedKey(t *testing.T) {
	pub, priv := mustGenerateRecipient(t)
	ec, err := crypto.Encrypt([]byte("wrap-protected payload"), pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	ec.WrappedKey[len(ec.WrappedKey)-1] ^= 0xff

	if _, err := crypto.Decrypt(ec, pub, priv); !errors.Is(err, crypto.ErrUnwrapFailed) {
		t.Fatalf("expected ErrUnwrapFailed for tampered wrapped key, got %v", err)
	}
}

func TestEncrypt_NilRecipientKey(t *testing.T) {
	if _, err := crypto.Encrypt([]byte("x"), nil); err == nil {
		t.Fatal("expected error for nil recipient public key")
	}
}

func TestDecrypt_NilEncryptedChunk(t *testing.T) {
	pub, priv := mustGenerateRecipient(t)
	if _, err := crypto.Decrypt(nil, pub, priv); err == nil {
		t.Fatal("expected error for nil encrypted chunk")
	}
}

func TestDecrypt_NilRecipientKeys(t *testing.T) {
	pub, priv := mustGenerateRecipient(t)
	ec, err := crypto.Encrypt([]byte("x"), pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if _, err := crypto.Decrypt(ec, nil, priv); err == nil {
		t.Fatal("expected error for nil recipient public key")
	}
	if _, err := crypto.Decrypt(ec, pub, nil); err == nil {
		t.Fatal("expected error for nil recipient private key")
	}
}

func TestGenerateRecipientKey_Unique(t *testing.T) {
	pubA, privA, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey A: %v", err)
	}
	pubB, privB, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey B: %v", err)
	}
	if *pubA == *pubB {
		t.Fatal("two generated public keys must differ")
	}
	if *privA == *privB {
		t.Fatal("two generated private keys must differ")
	}
}
