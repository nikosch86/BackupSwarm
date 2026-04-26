package bootstrap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/ca"
)

// signLeafForArbitraryPubkey builds a leaf cert for `pub` signed by
// caInst, bypassing SignNodeCert's expected-pubkey check. Used to craft
// forged-leaf scenarios that an offline attacker with a stolen CA key
// could mount.
func signLeafForArbitraryPubkey(t *testing.T, caInst *ca.CA, pub ed25519.PublicKey) []byte {
	t.Helper()
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "forged"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caInst.Cert, pub, caInst.PrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return der
}

func TestVerifySignedCert_HappyPath(t *testing.T) {
	caInst, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	csrDER, err := ca.CreateCSR(priv)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	leafDER, err := ca.SignNodeCert(caInst, csrDER, pub, ca.DefaultLeafValidity)
	if err != nil {
		t.Fatalf("SignNodeCert: %v", err)
	}
	if err := verifySignedCert(leafDER, caInst.CertDER, priv); err != nil {
		t.Errorf("verifySignedCert rejected a valid leaf: %v", err)
	}
}

func TestVerifySignedCert_RejectsLeafForOtherKey(t *testing.T) {
	// Attacker scenario: a CA signs a leaf for someone else's pubkey
	// (e.g. via a stolen CA key). The joiner must refuse to persist a
	// leaf that does not bind to its own identity.
	caInst, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	_, myPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("my key: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	leafDER := signLeafForArbitraryPubkey(t, caInst, otherPub)
	err = verifySignedCert(leafDER, caInst.CertDER, myPriv)
	if err == nil {
		t.Fatal("verifySignedCert accepted a leaf signed for a different pubkey")
	}
	if !strings.Contains(err.Error(), "match our identity") {
		t.Errorf("err = %v, want pubkey-mismatch error", err)
	}
}

func TestVerifySignedCert_RejectsLeafFromOtherCA(t *testing.T) {
	caClaimed, err := ca.Generate()
	if err != nil {
		t.Fatalf("claimed ca: %v", err)
	}
	caForger, err := ca.Generate()
	if err != nil {
		t.Fatalf("forger ca: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	leafDER := signLeafForArbitraryPubkey(t, caForger, pub)
	if err := verifySignedCert(leafDER, caClaimed.CertDER, priv); err == nil {
		t.Fatal("verifySignedCert accepted a leaf signed by an unrelated CA")
	}
}

func TestVerifySignedCert_RejectsGarbageLeaf(t *testing.T) {
	caInst, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := verifySignedCert([]byte("not-a-cert"), caInst.CertDER, priv); err == nil {
		t.Error("verifySignedCert accepted garbage leaf bytes")
	}
}

func TestVerifySignedCert_RejectsGarbageCAToken(t *testing.T) {
	caInst, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	leafDER := signLeafForArbitraryPubkey(t, caInst, pub)
	if err := verifySignedCert(leafDER, []byte("not-a-cert"), priv); err == nil {
		t.Error("verifySignedCert accepted garbage CA cert bytes")
	}
}

// TestVerifySignedCert_RejectsNonEd25519Leaf signs an RSA-keyed leaf
// with the swarm CA's ed25519 key. Chain verification passes, but the
// leaf-pubkey-is-ed25519 type assertion must reject it.
func TestVerifySignedCert_RejectsNonEd25519Leaf(t *testing.T) {
	caInst, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "rsa-leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, template, caInst.Cert, &rsaKey.PublicKey, caInst.PrivateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	_, myPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("my key: %v", err)
	}
	err = verifySignedCert(leafDER, caInst.CertDER, myPriv)
	if err == nil {
		t.Fatal("verifySignedCert accepted RSA-keyed leaf")
	}
	if !strings.Contains(err.Error(), "ed25519.PublicKey") {
		t.Errorf("err = %q, want mention of ed25519.PublicKey", err)
	}
}
