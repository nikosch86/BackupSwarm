package token_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
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

func sample(t *testing.T, caCert []byte) token.Token {
	t.Helper()
	tok := token.Token{
		Addr:   "node-a.local:7777",
		Pub:    mustKey(t),
		CACert: caCert,
	}
	if _, err := rand.Read(tok.SwarmID[:]); err != nil {
		t.Fatalf("rand SwarmID: %v", err)
	}
	if _, err := rand.Read(tok.Secret[:]); err != nil {
		t.Fatalf("rand Secret: %v", err)
	}
	return tok
}

func TestEncodeDecode_RoundTripWithCA(t *testing.T) {
	caCert := bytes.Repeat([]byte{0xAA}, 800)
	in := sample(t, caCert)

	encoded, err := token.Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	if encoded == "" {
		t.Fatal("Encode returned empty string")
	}
	for _, r := range encoded {
		if r < 0x20 || r > 0x7e {
			t.Fatalf("Encode produced non-printable byte %q", r)
		}
	}

	out, err := token.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if out.Addr != in.Addr {
		t.Errorf("Addr = %q, want %q", out.Addr, in.Addr)
	}
	if !bytes.Equal(out.Pub, in.Pub) {
		t.Error("Pub round-trip mismatch")
	}
	if out.SwarmID != in.SwarmID {
		t.Error("SwarmID round-trip mismatch")
	}
	if out.Secret != in.Secret {
		t.Error("Secret round-trip mismatch")
	}
	if !bytes.Equal(out.CACert, in.CACert) {
		t.Error("CACert round-trip mismatch")
	}
}

func TestEncodeDecode_RoundTripNoCA(t *testing.T) {
	in := sample(t, nil)

	encoded, err := token.Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	out, err := token.Decode(encoded)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(out.CACert) != 0 {
		t.Errorf("CACert len = %d, want 0", len(out.CACert))
	}
	if out.Addr != in.Addr || !bytes.Equal(out.Pub, in.Pub) ||
		out.SwarmID != in.SwarmID || out.Secret != in.Secret {
		t.Error("non-CA fields round-trip mismatch")
	}
}

func TestEncode_EmptyAddrRejected(t *testing.T) {
	in := sample(t, nil)
	in.Addr = ""
	if _, err := token.Encode(in); err == nil {
		t.Error("Encode accepted empty addr")
	}
}

func TestEncode_WrongPubkeySizeRejected(t *testing.T) {
	in := sample(t, nil)
	in.Pub = []byte{1, 2, 3}
	if _, err := token.Encode(in); err == nil {
		t.Error("Encode accepted undersized pubkey")
	}
	in.Pub = nil
	if _, err := token.Encode(in); err == nil {
		t.Error("Encode accepted nil pubkey")
	}
}

func TestEncode_AddrLengthCap(t *testing.T) {
	in := sample(t, nil)
	in.Addr = strings.Repeat("a", (1<<16)+1)
	if _, err := token.Encode(in); err == nil {
		t.Error("Encode accepted over-sized addr")
	}
}

func TestEncode_OversizedCACertRejected(t *testing.T) {
	in := sample(t, bytes.Repeat([]byte{0xCC}, (1<<16)+1))
	if _, err := token.Encode(in); err == nil {
		t.Error("Encode accepted over-sized CA cert")
	}
}

func TestDecode_EmptyStringRejected(t *testing.T) {
	if _, err := token.Decode(""); err == nil {
		t.Error("Decode accepted empty string")
	}
}

func TestDecode_NotBase64Rejected(t *testing.T) {
	if _, err := token.Decode("!!!not-base64!!!"); err == nil {
		t.Error("Decode accepted non-base64 input")
	}
}

func TestDecode_UnknownVersionRejected(t *testing.T) {
	cases := []struct {
		name string
		ver  byte
	}{
		{"future", 0xff},
		{"legacy_v1", 0x01},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := []byte{tc.ver}
			raw = append(raw, bytes.Repeat([]byte{0x11}, 256)...)
			encoded := token.EncodeRawForTest(raw)

			_, err := token.Decode(encoded)
			if err == nil {
				t.Fatal("Decode accepted unknown version")
			}
			if !errors.Is(err, token.ErrUnknownVersion) {
				t.Errorf("err = %v, want ErrUnknownVersion", err)
			}
		})
	}
}

func TestDecode_TruncatedAtBoundaries(t *testing.T) {
	full, err := token.Encode(sample(t, bytes.Repeat([]byte{0xAA}, 64)))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	raw, err := token.DecodeRawForTest(full)
	if err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	for n := 0; n < len(raw); n++ {
		short := token.EncodeRawForTest(raw[:n])
		if _, err := token.Decode(short); err == nil {
			t.Fatalf("Decode accepted truncated payload of %d bytes", n)
		}
	}
}

func TestDecode_AddrLengthOverrun(t *testing.T) {
	// version=2, addr_len declares 0x0400 but only "ab" follow + junk.
	raw := []byte{0x02, 0x04, 0x00, 'a', 'b'}
	raw = append(raw, bytes.Repeat([]byte{0x11}, 32+32+32+2)...)
	if _, err := token.Decode(token.EncodeRawForTest(raw)); err == nil {
		t.Error("Decode accepted addr-length overrun")
	}
}

func TestDecode_CALengthOverrun(t *testing.T) {
	// Build a structurally valid prefix up to ca_len, then claim 1024 ca
	// bytes while supplying only 4.
	pub := mustKey(t)
	addr := "127.0.0.1:1"
	raw := []byte{0x02}
	var addrLen [2]byte
	binary.BigEndian.PutUint16(addrLen[:], uint16(len(addr)))
	raw = append(raw, addrLen[:]...)
	raw = append(raw, addr...)
	raw = append(raw, pub...)
	raw = append(raw, bytes.Repeat([]byte{0x33}, 32)...) // swarm id
	raw = append(raw, bytes.Repeat([]byte{0x44}, 32)...) // secret
	var caLen [2]byte
	binary.BigEndian.PutUint16(caLen[:], 1024)
	raw = append(raw, caLen[:]...)
	raw = append(raw, []byte{0xCC, 0xCC, 0xCC, 0xCC}...)

	if _, err := token.Decode(token.EncodeRawForTest(raw)); err == nil {
		t.Error("Decode accepted CA-length overrun")
	}
}

func TestDecode_TrailingBytesRejected(t *testing.T) {
	full, err := token.Encode(sample(t, nil))
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	raw, err := token.DecodeRawForTest(full)
	if err != nil {
		t.Fatalf("decode raw: %v", err)
	}
	raw = append(raw, 0xFF, 0xFF)
	if _, err := token.Decode(token.EncodeRawForTest(raw)); err == nil {
		t.Error("Decode accepted trailing bytes")
	}
}
