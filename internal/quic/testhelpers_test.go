package quic

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
)

func TestNewConnForTest_CarriesRemotePub(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	conn := NewConnForTest(pub)
	if !conn.RemotePub().Equal(pub) {
		t.Errorf("RemotePub() = %x, want %x", conn.RemotePub(), pub)
	}
}
