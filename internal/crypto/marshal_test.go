package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"backupswarm/internal/crypto"
)

func TestEncryptedChunk_MarshalBinary_RoundTrip(t *testing.T) {
	pub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	orig, err := crypto.Encrypt([]byte("the quick brown fox"), pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	wire, err := orig.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if len(wire) == 0 {
		t.Fatal("MarshalBinary returned zero bytes")
	}

	got, err := crypto.UnmarshalEncryptedChunk(wire)
	if err != nil {
		t.Fatalf("UnmarshalEncryptedChunk: %v", err)
	}
	if !bytes.Equal(got.Nonce, orig.Nonce) {
		t.Error("Nonce mismatch after round-trip")
	}
	if !bytes.Equal(got.WrappedKey, orig.WrappedKey) {
		t.Error("WrappedKey mismatch after round-trip")
	}
	if !bytes.Equal(got.Ciphertext, orig.Ciphertext) {
		t.Error("Ciphertext mismatch after round-trip")
	}
}

func TestUnmarshalEncryptedChunk_RejectsTruncated(t *testing.T) {
	pub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	ec, err := crypto.Encrypt([]byte("x"), pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wire, err := ec.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}

	truncated := wire[:len(wire)-1]
	if _, err := crypto.UnmarshalEncryptedChunk(truncated); err == nil {
		t.Fatal("UnmarshalEncryptedChunk accepted truncated wire bytes")
	}
}

func TestUnmarshalEncryptedChunk_RejectsEmpty(t *testing.T) {
	if _, err := crypto.UnmarshalEncryptedChunk(nil); err == nil {
		t.Error("UnmarshalEncryptedChunk accepted nil input")
	}
	if _, err := crypto.UnmarshalEncryptedChunk([]byte{}); err == nil {
		t.Error("UnmarshalEncryptedChunk accepted empty slice")
	}
}

func TestUnmarshalEncryptedChunk_RejectsWrongVersion(t *testing.T) {
	pub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	ec, err := crypto.Encrypt([]byte("x"), pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	wire, err := ec.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	corrupt := append([]byte{}, wire...)
	corrupt[0] = 0xff
	if _, err := crypto.UnmarshalEncryptedChunk(corrupt); err == nil {
		t.Error("UnmarshalEncryptedChunk accepted an unknown wire version")
	} else if !errors.Is(err, crypto.ErrUnknownWireVersion) {
		t.Errorf("UnmarshalEncryptedChunk err = %v, want ErrUnknownWireVersion", err)
	}
}

// TestEncryptedChunk_MarshalBinary_Deterministic asserts MarshalBinary is deterministic for the same struct.
func TestEncryptedChunk_MarshalBinary_Deterministic(t *testing.T) {
	ec := &crypto.EncryptedChunk{
		Nonce:      bytes.Repeat([]byte{0x11}, crypto.NonceSize),
		WrappedKey: []byte{0x01, 0x02, 0x03},
		Ciphertext: []byte{0xaa, 0xbb, 0xcc, 0xdd},
	}
	first, err := ec.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	second, err := ec.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary 2: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Error("MarshalBinary produced non-deterministic output")
	}
}

func TestEncryptedChunk_MarshalBinary_RejectsWrongNonceSize(t *testing.T) {
	ec := &crypto.EncryptedChunk{
		Nonce:      []byte{1, 2, 3},
		WrappedKey: []byte{0x01},
		Ciphertext: []byte{0xaa},
	}
	if _, err := ec.MarshalBinary(); err == nil {
		t.Error("MarshalBinary accepted wrong-size nonce")
	}
}
