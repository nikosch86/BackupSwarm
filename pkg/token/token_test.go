package token_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"

	"backupswarm/pkg/token"
)

func mustKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	return pub
}

func TestEncodeDecode_RoundTrip(t *testing.T) {
	pub := mustKey(t)
	addr := "node-a.local:7777"

	encoded, err := token.Encode(addr, pub)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded == "" {
		t.Fatal("Encode returned empty string")
	}
	for _, r := range encoded {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("Encode produced non-printable byte %q in token", r)
		}
	}

	gotAddr, gotPub, err := token.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if gotAddr != addr {
		t.Errorf("addr = %q, want %q", gotAddr, addr)
	}
	if !bytes.Equal(gotPub, pub) {
		t.Error("pubkey round-trip mismatch")
	}
}

func TestEncode_EmptyAddrRejected(t *testing.T) {
	pub := mustKey(t)
	if _, err := token.Encode("", pub); err == nil {
		t.Error("Encode accepted empty addr")
	}
}

func TestEncode_WrongPubkeySizeRejected(t *testing.T) {
	if _, err := token.Encode("127.0.0.1:1", []byte{1, 2, 3}); err == nil {
		t.Error("Encode accepted undersized pubkey")
	}
	if _, err := token.Encode("127.0.0.1:1", nil); err == nil {
		t.Error("Encode accepted nil pubkey")
	}
}

func TestDecode_EmptyStringRejected(t *testing.T) {
	if _, _, err := token.Decode(""); err == nil {
		t.Error("Decode accepted empty string")
	}
}

func TestDecode_NotBase64Rejected(t *testing.T) {
	if _, _, err := token.Decode("!!!not-base64!!!"); err == nil {
		t.Error("Decode accepted non-base64 input")
	}
}

func TestDecode_UnknownVersionRejected(t *testing.T) {
	// Hand-craft a payload with an unknown version byte.
	raw := []byte{0xff, 0x00, 0x01, 'x'}
	raw = append(raw, bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)...)
	encoded := token.EncodeRawForTest(raw)

	_, _, err := token.Decode(encoded)
	if err == nil {
		t.Fatal("Decode accepted unknown version")
	}
	if !errors.Is(err, token.ErrUnknownVersion) {
		t.Errorf("err = %v, want ErrUnknownVersion", err)
	}
}

func TestDecode_TruncatedPayload(t *testing.T) {
	pub := mustKey(t)
	full, err := token.Encode("127.0.0.1:7777", pub)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	truncated := full[:len(full)-4]
	if _, _, err := token.Decode(truncated); err == nil {
		t.Error("Decode accepted truncated payload")
	}
}

func TestDecode_LengthPrefixOverrun(t *testing.T) {
	raw := []byte{0x01, 0x04, 0x00, 'a', 'b'}
	raw = append(raw, bytes.Repeat([]byte{0x11}, ed25519.PublicKeySize)...)
	encoded := token.EncodeRawForTest(raw)

	if _, _, err := token.Decode(encoded); err == nil {
		t.Error("Decode accepted length-prefix overrun")
	}
}

func TestEncode_AddrLengthCap(t *testing.T) {
	huge := strings.Repeat("a", (1<<16)+1)
	if _, err := token.Encode(huge, mustKey(t)); err == nil {
		t.Error("Encode accepted over-sized addr")
	}
}
