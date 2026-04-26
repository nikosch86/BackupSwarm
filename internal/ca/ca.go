// Package ca manages the per-swarm Ed25519 root certificate authority.
// The CA is auto-generated on the founder's first invite and embedded in
// invite tokens. ca.key is 0600 alongside node.key; ca.crt is 0644.
package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

const (
	privateKeyFile = "ca.key"
	certFile       = "ca.crt"
	pinModeFile    = "swarm.pin-mode"

	dirPerm        os.FileMode = 0o700
	privateKeyPerm os.FileMode = 0o600
	certPerm       os.FileMode = 0o644
	markerPerm     os.FileMode = 0o644

	caValidity = 100 * 365 * 24 * time.Hour
)

// ErrCANotFound is returned by Load when no CA exists at the given dir.
var ErrCANotFound = errors.New("swarm CA not found")

// CA is an Ed25519 root certificate authority. PrivateKey signs per-node
// leaf certs; Cert/CertDER travel in invite tokens.
type CA struct {
	PrivateKey ed25519.PrivateKey
	Cert       *x509.Certificate
	CertDER    []byte
}

// Generate creates a self-signed Ed25519 root CA with 100-year validity
// suitable for signing per-node leaf certs.
func Generate() (*CA, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 ca key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("ca serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "BackupSwarm Swarm CA",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(caValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return nil, fmt.Errorf("create ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse generated ca cert: %w", err)
	}
	return &CA{
		PrivateKey: priv,
		Cert:       cert,
		CertDER:    der,
	}, nil
}

// Save writes the CA private key (0600) and cert (0644) to dir, creating
// the directory at 0700 if needed.
func Save(dir string, ca *CA) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create data dir %q: %w", dir, err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		return fmt.Errorf("chmod data dir %q: %w", dir, err)
	}
	privPath := filepath.Join(dir, privateKeyFile)
	if err := os.WriteFile(privPath, ca.PrivateKey, privateKeyPerm); err != nil {
		return fmt.Errorf("write ca private key: %w", err)
	}
	// Force the mode; WriteFile respects the process umask.
	if err := os.Chmod(privPath, privateKeyPerm); err != nil {
		return fmt.Errorf("chmod ca private key: %w", err)
	}
	certPath := filepath.Join(dir, certFile)
	if err := os.WriteFile(certPath, ca.CertDER, certPerm); err != nil {
		return fmt.Errorf("write ca cert: %w", err)
	}
	return nil
}

// Load reads ca.key and ca.crt from dir. Returns ErrCANotFound if either
// file is missing, an error on insecure key permissions, or an error if
// the cert's public key does not match the private key.
func Load(dir string) (*CA, error) {
	privPath := filepath.Join(dir, privateKeyFile)
	certPath := filepath.Join(dir, certFile)

	privInfo, err := os.Stat(privPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrCANotFound, privPath)
		}
		return nil, fmt.Errorf("stat ca private key: %w", err)
	}
	if _, err := os.Stat(certPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrCANotFound, certPath)
		}
		return nil, fmt.Errorf("stat ca cert: %w", err)
	}

	if runtime.GOOS != "windows" {
		if perm := privInfo.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("ca private key %s has insecure permissions %o (want 0600)", privPath, perm)
		}
	}

	priv, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("read ca private key: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ca private key %s: invalid size %d, want %d", privPath, len(priv), ed25519.PrivateKeySize)
	}
	der, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse ca cert: %w", err)
	}
	certPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ca cert public key is %T, want ed25519.PublicKey", cert.PublicKey)
	}
	keyPub, ok := ed25519.PrivateKey(priv).Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("ca private key public derivation is %T, want ed25519.PublicKey", ed25519.PrivateKey(priv).Public())
	}
	if !certPub.Equal(keyPub) {
		return nil, fmt.Errorf("ca cert public key does not match private key")
	}
	return &CA{
		PrivateKey: ed25519.PrivateKey(priv),
		Cert:       cert,
		CertDER:    der,
	}, nil
}

// Has reports whether a CA exists at dir (both ca.key and ca.crt present).
func Has(dir string) (bool, error) {
	privExists, err := fileExists(filepath.Join(dir, privateKeyFile))
	if err != nil {
		return false, err
	}
	certExists, err := fileExists(filepath.Join(dir, certFile))
	if err != nil {
		return false, err
	}
	return privExists && certExists, nil
}

// IsPinMode reports whether dir holds the swarm.pin-mode marker file
// indicating pubkey-pin trust mode.
func IsPinMode(dir string) (bool, error) {
	return fileExists(filepath.Join(dir, pinModeFile))
}

// MarkPinMode writes the swarm.pin-mode marker to dir, creating the
// directory at 0700 if needed. Idempotent.
func MarkPinMode(dir string) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create data dir %q: %w", dir, err)
	}
	if err := os.WriteFile(filepath.Join(dir, pinModeFile), nil, markerPerm); err != nil {
		return fmt.Errorf("write pin-mode marker: %w", err)
	}
	return nil
}

func fileExists(path string) (bool, error) {
	if _, err := os.Stat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("stat %s: %w", path, err)
	}
	return true, nil
}
