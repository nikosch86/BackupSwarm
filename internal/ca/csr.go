package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	nodeCertFile = "node.crt"

	// DefaultLeafValidity is the lifetime of a node leaf cert signed by SignNodeCert.
	DefaultLeafValidity = 365 * 24 * time.Hour

	// leafBackdate antedates NotBefore so small clock skew between
	// signer and verifier does not reject a freshly-issued leaf.
	leafBackdate = time.Hour
)

// ErrCSRPubkeyMismatch is returned by SignNodeCert when the CSR's public
// key does not match the expected node pubkey supplied by the caller.
var ErrCSRPubkeyMismatch = errors.New("csr public key does not match expected node pubkey")

// ErrNodeCertNotFound is returned by LoadNodeCert when no leaf cert
// exists at the given dir.
var ErrNodeCertNotFound = errors.New("node cert not found")

// CreateCSR returns a DER-encoded x509 CertificateRequest carrying priv's
// Ed25519 public key, self-signed by priv. Subject CN is informational.
func CreateCSR(priv ed25519.PrivateKey) ([]byte, error) {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("priv.Public() is %T, want ed25519.PublicKey", priv.Public())
	}
	template := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "backupswarm-" + hex.EncodeToString(pub[:8])},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		return nil, fmt.Errorf("create csr: %w", err)
	}
	return der, nil
}

// SignNodeCert verifies csrDER's self-signature, requires its Ed25519
// public key to equal expectedPub, then signs a leaf cert with c.
// The leaf carries digital-signature key usage and server+client EKUs.
func SignNodeCert(c *CA, csrDER []byte, expectedPub ed25519.PublicKey, validity time.Duration) ([]byte, error) {
	if c == nil {
		return nil, errors.New("ca is nil")
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("parse csr: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("verify csr signature: %w", err)
	}
	csrPub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("csr public key is %T, want ed25519.PublicKey", csr.PublicKey)
	}
	if !csrPub.Equal(expectedPub) {
		return nil, ErrCSRPubkeyMismatch
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("leaf serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now().Add(-leafBackdate),
		NotAfter:              time.Now().Add(validity),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, c.Cert, csrPub, c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert: %w", err)
	}
	return der, nil
}

// SaveNodeCert writes the leaf cert DER to <dir>/node.crt at 0644,
// creating dir at 0700 if missing.
func SaveNodeCert(dir string, certDER []byte) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create data dir %q: %w", dir, err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		return fmt.Errorf("chmod data dir %q: %w", dir, err)
	}
	path := filepath.Join(dir, nodeCertFile)
	if err := os.WriteFile(path, certDER, certPerm); err != nil {
		return fmt.Errorf("write node cert: %w", err)
	}
	return nil
}

// LoadNodeCert reads <dir>/node.crt. Returns ErrNodeCertNotFound when no
// leaf cert is present.
func LoadNodeCert(dir string) ([]byte, error) {
	path := filepath.Join(dir, nodeCertFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrNodeCertNotFound, path)
		}
		return nil, fmt.Errorf("read node cert: %w", err)
	}
	return data, nil
}
