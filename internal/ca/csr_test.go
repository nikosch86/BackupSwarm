package ca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCreateCSR_RoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := CreateCSR(priv)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CheckSignature: %v", err)
	}
	csrPub, ok := csr.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("csr public key type %T, want ed25519.PublicKey", csr.PublicKey)
	}
	if !pub.Equal(csrPub) {
		t.Error("csr public key does not match priv.Public()")
	}
}

func TestSignNodeCert_HappyPath(t *testing.T) {
	swarmCA, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	csrDER, err := CreateCSR(priv)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	certDER, err := SignNodeCert(swarmCA, csrDER, pub, DefaultLeafValidity)
	if err != nil {
		t.Fatalf("SignNodeCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(swarmCA.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not chain to CA: %v", err)
	}
	leafPub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("leaf public key type %T", leaf.PublicKey)
	}
	if !pub.Equal(leafPub) {
		t.Error("leaf pubkey does not match expected")
	}
	gotSpan := leaf.NotAfter.Sub(leaf.NotBefore)
	wantSpan := DefaultLeafValidity + time.Hour // template adds a 1h backdate
	if d := gotSpan - wantSpan; d < -2*time.Hour || d > 2*time.Hour {
		t.Errorf("leaf validity span = %v, want approximately %v", gotSpan, wantSpan)
	}
}

func TestSignNodeCert_RejectsCSRPubkeyMismatch(t *testing.T) {
	swarmCA, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	_, csrPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("csr key: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("other key: %v", err)
	}
	csrDER, err := CreateCSR(csrPriv)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	_, err = SignNodeCert(swarmCA, csrDER, otherPub, DefaultLeafValidity)
	if err == nil {
		t.Fatal("SignNodeCert succeeded with mismatched expected pubkey, want error")
	}
	if !errors.Is(err, ErrCSRPubkeyMismatch) {
		t.Errorf("err = %v, want ErrCSRPubkeyMismatch", err)
	}
}

func TestSignNodeCert_RejectsTamperedCSRSignature(t *testing.T) {
	swarmCA, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	csrDER, err := CreateCSR(priv)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	tampered := bytes.Clone(csrDER)
	tampered[len(tampered)-1] ^= 0xFF
	if _, err := SignNodeCert(swarmCA, tampered, pub, DefaultLeafValidity); err == nil {
		t.Error("SignNodeCert accepted tampered CSR signature, want error")
	}
}

func TestSignNodeCert_RejectsGarbageCSR(t *testing.T) {
	swarmCA, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	if _, err := SignNodeCert(swarmCA, []byte("not-a-csr"), pub, DefaultLeafValidity); err == nil {
		t.Error("SignNodeCert accepted garbage bytes as CSR, want error")
	}
}

func TestSignNodeCert_RejectsNonEd25519CSR(t *testing.T) {
	swarmCA, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "rsa-imposter"},
	}, rsaKey)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}
	if _, err := SignNodeCert(swarmCA, csrDER, pub, DefaultLeafValidity); err == nil {
		t.Error("SignNodeCert signed an RSA-keyed CSR, want ed25519 type-assertion error")
	}
}

func TestSignNodeCert_NilCA(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	csrDER, err := CreateCSR(priv)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	if _, err := SignNodeCert(nil, csrDER, pub, DefaultLeafValidity); err == nil {
		t.Error("SignNodeCert(nil, ...) returned nil error")
	}
}

func TestSaveLoadNodeCert_RoundTrip(t *testing.T) {
	swarmCA, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	csrDER, err := CreateCSR(priv)
	if err != nil {
		t.Fatalf("CreateCSR: %v", err)
	}
	certDER, err := SignNodeCert(swarmCA, csrDER, pub, DefaultLeafValidity)
	if err != nil {
		t.Fatalf("SignNodeCert: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "node")
	if err := SaveNodeCert(dir, certDER); err != nil {
		t.Fatalf("SaveNodeCert: %v", err)
	}
	loaded, err := LoadNodeCert(dir)
	if err != nil {
		t.Fatalf("LoadNodeCert: %v", err)
	}
	if !bytes.Equal(loaded, certDER) {
		t.Error("loaded node cert differs from saved")
	}
}

func TestLoadNodeCert_NotFound(t *testing.T) {
	if _, err := LoadNodeCert(t.TempDir()); !errors.Is(err, ErrNodeCertNotFound) {
		t.Errorf("err = %v, want wraps ErrNodeCertNotFound", err)
	}
}

func TestSaveNodeCert_Is0644(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	dir := t.TempDir()
	if err := SaveNodeCert(dir, []byte{0x30, 0x82, 0x00, 0x00}); err != nil {
		t.Fatalf("SaveNodeCert: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, nodeCertFile))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("perm = %o, want 0644", perm)
	}
}

func TestSaveNodeCert_CreatesDir0700(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	dir := filepath.Join(t.TempDir(), "fresh-data-dir")
	if err := SaveNodeCert(dir, []byte{0x30, 0x82, 0x00, 0x00}); err != nil {
		t.Fatalf("SaveNodeCert: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("dir perm = %o, want 0700", perm)
	}
}

func TestSaveNodeCert_FailsWhenParentIsFile(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	if err := SaveNodeCert(filepath.Join(blocker, "node"), []byte{0x30}); err == nil {
		t.Error("SaveNodeCert into path with file-parent returned nil error")
	}
}

func TestSaveNodeCert_FailsWhenCertPathIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, nodeCertFile), 0o700); err != nil {
		t.Fatalf("mkdir node cert squatter: %v", err)
	}
	if err := SaveNodeCert(dir, []byte{0x30, 0x82, 0x00, 0x00}); err == nil {
		t.Error("SaveNodeCert succeeded when node cert path is a directory")
	}
}

// TestSaveNodeCert_ChmodFails exercises the chmod-data-dir error wrap
// by passing /proc/self/fd: MkdirAll is a no-op (path exists) but
// chmod on /proc paths returns EPERM for unprivileged callers.
func TestSaveNodeCert_ChmodFails(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("/proc-based chmod fault injection is Linux-only")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses /proc chmod restrictions")
	}
	err := SaveNodeCert("/proc/self/fd", []byte{0x30})
	if err == nil {
		t.Fatal("SaveNodeCert against /proc/self/fd returned nil error")
	}
	if !errors.Is(err, os.ErrPermission) && !strings.Contains(err.Error(), "chmod data dir") {
		t.Errorf("err = %v, want 'chmod data dir' wrap", err)
	}
}

func TestLoadNodeCert_ReadError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loop behavior not portable to Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, nodeCertFile)
	if err := os.Symlink(path, path); err != nil {
		t.Fatalf("create self-symlink: %v", err)
	}
	_, err := LoadNodeCert(dir)
	if err == nil {
		t.Fatal("LoadNodeCert accepted self-symlink, want error")
	}
	if errors.Is(err, ErrNodeCertNotFound) {
		t.Errorf("err = %v, want non-NotFound error for ELOOP", err)
	}
}
