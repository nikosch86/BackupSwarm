package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestGenerate_ReturnsValidEd25519CA(t *testing.T) {
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if len(ca.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("PrivateKey size = %d, want %d", len(ca.PrivateKey), ed25519.PrivateKeySize)
	}
	if ca.Cert == nil {
		t.Fatal("Cert is nil")
	}
	if !ca.Cert.IsCA {
		t.Error("Cert.IsCA = false, want true")
	}
	if ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Errorf("Cert.KeyUsage missing KeyUsageCertSign: %v", ca.Cert.KeyUsage)
	}
	if !ca.Cert.BasicConstraintsValid {
		t.Error("Cert.BasicConstraintsValid = false, want true")
	}
	pub, ok := ca.Cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("Cert.PublicKey is %T, want ed25519.PublicKey", ca.Cert.PublicKey)
	}
	derived, ok := ca.PrivateKey.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatalf("PrivateKey.Public() is %T, want ed25519.PublicKey", ca.PrivateKey.Public())
	}
	if !pub.Equal(derived) {
		t.Error("Cert.PublicKey does not match PrivateKey.Public()")
	}
	if len(ca.CertDER) == 0 {
		t.Error("CertDER is empty")
	}
	parsed, err := x509.ParseCertificate(ca.CertDER)
	if err != nil {
		t.Fatalf("ParseCertificate(CertDER): %v", err)
	}
	if !parsed.PublicKey.(ed25519.PublicKey).Equal(derived) {
		t.Error("CertDER does not round-trip through x509.ParseCertificate to the same pubkey")
	}
}

func TestGenerate_SelfSignedSignatureVerifies(t *testing.T) {
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := ca.Cert.CheckSignatureFrom(ca.Cert); err != nil {
		t.Errorf("self-signed signature check failed: %v", err)
	}
}

func TestGenerate_DistinctKeys(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate() a error: %v", err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatalf("Generate() b error: %v", err)
	}
	if a.PrivateKey.Equal(b.PrivateKey) {
		t.Error("two Generate() calls produced identical CA private keys")
	}
}

func TestSaveLoad_RoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
	orig, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := Save(dir, orig); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}
	if !orig.PrivateKey.Equal(loaded.PrivateKey) {
		t.Error("loaded CA private key differs from saved")
	}
	if !orig.Cert.Equal(loaded.Cert) {
		t.Error("loaded CA cert differs from saved")
	}
	origPub := orig.Cert.PublicKey.(ed25519.PublicKey)
	loadedPub := loaded.Cert.PublicKey.(ed25519.PublicKey)
	if !origPub.Equal(loadedPub) {
		t.Error("loaded CA cert public key differs from saved")
	}
	if string(orig.CertDER) != string(loaded.CertDER) {
		t.Error("CertDER differs after round-trip")
	}
}

func TestSave_CreatesDirWith0700(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	dir := filepath.Join(t.TempDir(), "fresh-data-dir")
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := Save(dir, ca); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("data dir perm = %o, want 0700", perm)
	}
}

func TestSave_PrivateKeyIs0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	dir := t.TempDir()
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := Save(dir, ca); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, privateKeyFile))
	if err != nil {
		t.Fatalf("stat ca private key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("ca private key perm = %o, want 0600", perm)
	}
}

func TestSave_CertIs0644(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	dir := t.TempDir()
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := Save(dir, ca); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, certFile))
	if err != nil {
		t.Fatalf("stat ca cert: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o644 {
		t.Errorf("ca cert perm = %o, want 0644", perm)
	}
}

func TestLoad_RejectsPermissivePrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	dir := t.TempDir()
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := Save(dir, ca); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, privateKeyFile), 0o644); err != nil {
		t.Fatalf("chmod ca private key: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("Load() accepted world-readable CA private key, want error")
	}
}

func TestLoad_MissingBothFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() on empty dir returned nil error")
	}
	if !errors.Is(err, ErrCANotFound) {
		t.Errorf("Load() missing-CA error = %v, want wraps ErrCANotFound", err)
	}
}

func TestLoad_MissingCertReturnsCANotFound(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write ca private key: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() with missing cert returned nil error")
	}
	if !errors.Is(err, ErrCANotFound) {
		t.Errorf("Load() missing-cert error = %v, want wraps ErrCANotFound", err)
	}
	if !strings.Contains(err.Error(), certFile) {
		t.Errorf("Load() missing-cert error = %q, want mention of %q", err, certFile)
	}
}

func TestLoad_MissingPrivateKeyReturnsCANotFound(t *testing.T) {
	dir := t.TempDir()
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), ca.CertDER, certPerm); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}
	_, err = Load(dir)
	if err == nil {
		t.Fatal("Load() with missing private key returned nil error")
	}
	if !errors.Is(err, ErrCANotFound) {
		t.Errorf("Load() missing-key error = %v, want wraps ErrCANotFound", err)
	}
	if !strings.Contains(err.Error(), privateKeyFile) {
		t.Errorf("Load() missing-key error = %q, want mention of %q", err, privateKeyFile)
	}
}

func TestLoad_CorruptPrivateKeySize(t *testing.T) {
	dir := t.TempDir()
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), []byte("too-short"), privateKeyPerm); err != nil {
		t.Fatalf("write ca private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), ca.CertDER, certPerm); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}
	_, err = Load(dir)
	if err == nil {
		t.Fatal("Load() accepted corrupt private key, want error")
	}
	if !strings.Contains(err.Error(), "invalid size") {
		t.Errorf("Load() error = %v, want 'invalid size'", err)
	}
}

func TestLoad_CorruptCertDER(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write ca private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), []byte("not-a-cert"), certPerm); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() accepted non-DER cert, want error")
	}
}

func TestLoad_CertPubkeyMismatchPrivateKey(t *testing.T) {
	// Cert pubkey must match the loaded private key.
	dir := t.TempDir()
	caA, err := Generate()
	if err != nil {
		t.Fatalf("Generate() A error: %v", err)
	}
	caB, err := Generate()
	if err != nil {
		t.Fatalf("Generate() B error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), caA.PrivateKey, privateKeyPerm); err != nil {
		t.Fatalf("write ca private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), caB.CertDER, certPerm); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Fatal("Load() accepted mismatched key/cert pair, want error")
	}
}

func TestHas_FalseWhenEmpty(t *testing.T) {
	dir := t.TempDir()
	got, err := Has(dir)
	if err != nil {
		t.Fatalf("Has() error: %v", err)
	}
	if got {
		t.Error("Has() = true on empty dir, want false")
	}
}

func TestHas_TrueAfterSave(t *testing.T) {
	dir := t.TempDir()
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := Save(dir, ca); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	got, err := Has(dir)
	if err != nil {
		t.Fatalf("Has() error: %v", err)
	}
	if !got {
		t.Error("Has() = false after Save, want true")
	}
}

func TestHas_FalseWhenOnlyKeyPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write ca private key: %v", err)
	}
	got, err := Has(dir)
	if err != nil {
		t.Fatalf("Has() error: %v", err)
	}
	if got {
		t.Error("Has() = true with only key file, want false")
	}
}

func TestHas_FalseWhenOnlyCertPresent(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, certFile), []byte("ignored"), certPerm); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}
	got, err := Has(dir)
	if err != nil {
		t.Fatalf("Has() error: %v", err)
	}
	if got {
		t.Error("Has() = true with only cert file, want false")
	}
}

func TestIsPinMode_FalseOnEmptyDir(t *testing.T) {
	dir := t.TempDir()
	got, err := IsPinMode(dir)
	if err != nil {
		t.Fatalf("IsPinMode: %v", err)
	}
	if got {
		t.Error("IsPinMode = true on empty dir, want false")
	}
}

func TestMarkPinMode_TogglesIsPinMode(t *testing.T) {
	dir := t.TempDir()
	if err := MarkPinMode(dir); err != nil {
		t.Fatalf("MarkPinMode: %v", err)
	}
	got, err := IsPinMode(dir)
	if err != nil {
		t.Fatalf("IsPinMode: %v", err)
	}
	if !got {
		t.Error("IsPinMode = false after MarkPinMode, want true")
	}
}

func TestMarkPinMode_Idempotent(t *testing.T) {
	dir := t.TempDir()
	if err := MarkPinMode(dir); err != nil {
		t.Fatalf("MarkPinMode #1: %v", err)
	}
	if err := MarkPinMode(dir); err != nil {
		t.Fatalf("MarkPinMode #2: %v", err)
	}
	got, err := IsPinMode(dir)
	if err != nil {
		t.Fatalf("IsPinMode: %v", err)
	}
	if !got {
		t.Error("IsPinMode = false after second MarkPinMode, want true")
	}
}

func TestMarkPinMode_CreatesMissingDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fresh")
	if err := MarkPinMode(dir); err != nil {
		t.Fatalf("MarkPinMode: %v", err)
	}
	if got, _ := IsPinMode(dir); !got {
		t.Error("IsPinMode = false after MarkPinMode on fresh dir, want true")
	}
}

func TestSave_FailsWhenParentIsFile(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	target := filepath.Join(blocker, "ca")
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate(): %v", err)
	}
	if err := Save(target, ca); err == nil {
		t.Error("Save() into path with file-parent returned nil error")
	}
}

func TestSave_FailsWhenPrivateKeyPathIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, privateKeyFile), 0o700); err != nil {
		t.Fatalf("mkdir ca private key squatter: %v", err)
	}
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := Save(dir, ca); err == nil {
		t.Error("Save() succeeded when ca private-key path is a directory")
	}
}

func TestSave_FailsWhenCertPathIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, certFile), 0o700); err != nil {
		t.Fatalf("mkdir ca cert squatter: %v", err)
	}
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := Save(dir, ca); err == nil {
		t.Error("Save() succeeded when ca cert path is a directory")
	}
}

func TestLoad_PrivateKeyStatNonNotFoundError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loop behavior not portable to Windows")
	}
	dir := t.TempDir()
	privPath := filepath.Join(dir, privateKeyFile)
	if err := os.Symlink(privPath, privPath); err != nil {
		t.Fatalf("create self-symlink: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() accepted self-symlink ca private key, want error")
	}
	if errors.Is(err, ErrCANotFound) {
		t.Errorf("Load() returned ErrCANotFound for ELOOP; want distinct stat error")
	}
	if !strings.Contains(err.Error(), "stat ca private key") {
		t.Errorf("Load() error = %q, want 'stat ca private key' prefix", err)
	}
}

func TestLoad_CertStatNonNotFoundError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loop behavior not portable to Windows")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write ca private key: %v", err)
	}
	certPath := filepath.Join(dir, certFile)
	if err := os.Symlink(certPath, certPath); err != nil {
		t.Fatalf("create self-symlink: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() accepted self-symlink ca cert, want error")
	}
	if errors.Is(err, ErrCANotFound) {
		t.Errorf("Load() returned ErrCANotFound for ELOOP; want distinct stat error")
	}
	if !strings.Contains(err.Error(), "stat ca cert") {
		t.Errorf("Load() error = %q, want 'stat ca cert' prefix", err)
	}
}

func TestLoad_CertPubkeyNotEd25519(t *testing.T) {
	dir := t.TempDir()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "rsa-not-ed25519"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &rsaKey.PublicKey, rsaKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write ca private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certFile), der, certPerm); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}
	_, err = Load(dir)
	if err == nil {
		t.Fatal("Load() accepted RSA cert, want ed25519 type-assertion error")
	}
	if !strings.Contains(err.Error(), "ed25519.PublicKey") {
		t.Errorf("Load() error = %q, want mention of ed25519.PublicKey", err)
	}
}

func TestHas_StatErrorOnPrivateKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loop behavior not portable to Windows")
	}
	dir := t.TempDir()
	privPath := filepath.Join(dir, privateKeyFile)
	if err := os.Symlink(privPath, privPath); err != nil {
		t.Fatalf("create self-symlink: %v", err)
	}
	_, err := Has(dir)
	if err == nil {
		t.Fatal("Has() accepted self-symlink private key, want error")
	}
	if !strings.Contains(err.Error(), privateKeyFile) {
		t.Errorf("Has() error = %q, want mention of %q", err, privateKeyFile)
	}
}

func TestHas_StatErrorOnCert(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loop behavior not portable to Windows")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write ca private key: %v", err)
	}
	certPath := filepath.Join(dir, certFile)
	if err := os.Symlink(certPath, certPath); err != nil {
		t.Fatalf("create self-symlink: %v", err)
	}
	_, err := Has(dir)
	if err == nil {
		t.Fatal("Has() accepted self-symlink cert, want error")
	}
	if !strings.Contains(err.Error(), certFile) {
		t.Errorf("Has() error = %q, want mention of %q", err, certFile)
	}
}

func TestMarkPinMode_FailsWhenParentIsFile(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	target := filepath.Join(blocker, "node")
	if err := MarkPinMode(target); err == nil {
		t.Error("MarkPinMode() into path with file-parent returned nil error")
	}
}

func TestMarkPinMode_FailsWhenMarkerPathIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, pinModeFile), 0o700); err != nil {
		t.Fatalf("mkdir pin-mode squatter: %v", err)
	}
	if err := MarkPinMode(dir); err == nil {
		t.Error("MarkPinMode() succeeded when marker path is a directory")
	}
}

func TestLoad_PrivateKeyReadFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("chmod barriers do not apply to root")
	}
	dir := t.TempDir()
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := Save(dir, ca); err != nil {
		t.Fatalf("Save: %v", err)
	}
	privPath := filepath.Join(dir, privateKeyFile)
	if err := os.Chmod(privPath, 0o000); err != nil {
		t.Fatalf("chmod ca private key: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(privPath, privateKeyPerm) })
	_, err = Load(dir)
	if err == nil {
		t.Fatal("Load() returned nil when ca.key is unreadable, want read error")
	}
	if errors.Is(err, ErrCANotFound) {
		t.Errorf("Load() returned ErrCANotFound for EACCES; want distinct read error")
	}
	if !strings.Contains(err.Error(), "read ca private key") {
		t.Errorf("Load() error = %q, want 'read ca private key' prefix", err)
	}
}

func TestLoad_CertReadFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("chmod barriers do not apply to root")
	}
	dir := t.TempDir()
	ca, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := Save(dir, ca); err != nil {
		t.Fatalf("Save: %v", err)
	}
	certPath := filepath.Join(dir, certFile)
	if err := os.Chmod(certPath, 0o000); err != nil {
		t.Fatalf("chmod ca cert: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(certPath, certPerm) })
	_, err = Load(dir)
	if err == nil {
		t.Fatal("Load() returned nil when ca.crt is unreadable, want read error")
	}
	if errors.Is(err, ErrCANotFound) {
		t.Errorf("Load() returned ErrCANotFound for EACCES; want distinct read error")
	}
	if !strings.Contains(err.Error(), "read ca cert") {
		t.Errorf("Load() error = %q, want 'read ca cert' prefix", err)
	}
}
