package node

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestGenerate_ReturnsValidKeypair(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if len(id.PrivateKey) != ed25519.PrivateKeySize {
		t.Errorf("PrivateKey size = %d, want %d", len(id.PrivateKey), ed25519.PrivateKeySize)
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("PublicKey size = %d, want %d", len(id.PublicKey), ed25519.PublicKeySize)
	}

	msg := []byte("backupswarm-test-message")
	sig := ed25519.Sign(id.PrivateKey, msg)
	if !ed25519.Verify(id.PublicKey, msg, sig) {
		t.Error("generated keypair failed sign/verify round-trip")
	}
}

func TestGenerate_ReturnsDistinctKeys(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatalf("Generate() a error: %v", err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatalf("Generate() b error: %v", err)
	}
	if a.PublicKey.Equal(b.PublicKey) {
		t.Error("two Generate() calls produced identical public keys")
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
	if !orig.PublicKey.Equal(loaded.PublicKey) {
		t.Error("loaded public key differs from saved")
	}
	if !orig.PrivateKey.Equal(loaded.PrivateKey) {
		t.Error("loaded private key differs from saved")
	}
}

func TestSave_CreatesDirWith0700(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	dir := filepath.Join(t.TempDir(), "fresh-data-dir")
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := Save(dir, id); err != nil {
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
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := Save(dir, id); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, privateKeyFile))
	if err != nil {
		t.Fatalf("stat private key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("private key perm = %o, want 0600", perm)
	}
}

func TestLoad_RejectsPermissiveMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	dir := t.TempDir()
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	if err := Save(dir, id); err != nil {
		t.Fatalf("Save() error: %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, privateKeyFile), 0o644); err != nil {
		t.Fatalf("chmod private key: %v", err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("Load() accepted world-readable private key, want error")
	}
}

func TestLoad_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() on empty dir returned nil error")
	}
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Errorf("Load() missing-identity error = %v, want wraps ErrIdentityNotFound", err)
	}
}

func TestEnsure_GeneratesWhenMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
	id, created, err := Ensure(dir)
	if err != nil {
		t.Fatalf("Ensure() error: %v", err)
	}
	if !created {
		t.Error("Ensure() created=false on fresh dir, want true")
	}
	if len(id.PublicKey) != ed25519.PublicKeySize {
		t.Errorf("PublicKey size = %d, want %d", len(id.PublicKey), ed25519.PublicKeySize)
	}
}

func TestEnsure_LoadsWhenPresent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
	first, _, err := Ensure(dir)
	if err != nil {
		t.Fatalf("Ensure() first error: %v", err)
	}
	second, created, err := Ensure(dir)
	if err != nil {
		t.Fatalf("Ensure() second error: %v", err)
	}
	if created {
		t.Error("Ensure() created=true on second call, want false")
	}
	if !first.PublicKey.Equal(second.PublicKey) {
		t.Error("Ensure() produced different public keys across runs")
	}
}

func TestLoad_CorruptPrivateKeySize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), []byte("too-short"), privateKeyPerm); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, publicKeyFile), make([]byte, ed25519.PublicKeySize), publicKeyPerm); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() accepted corrupt private key, want error")
	}
	if !strings.Contains(err.Error(), "invalid size") {
		t.Errorf("Load() error = %v, want 'invalid size'", err)
	}
}

func TestLoad_CorruptPublicKeySize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, publicKeyFile), []byte("nope"), publicKeyPerm); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() accepted corrupt public key, want error")
	}
	if !strings.Contains(err.Error(), "invalid size") {
		t.Errorf("Load() error = %v, want 'invalid size'", err)
	}
}

func TestSave_FailsWhenParentIsFile(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	target := filepath.Join(blocker, "node")
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate(): %v", err)
	}
	if err := Save(target, id); err == nil {
		t.Error("Save() into path with file-parent returned nil error")
	}
}

func TestEnsure_PropagatesSaveError(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	target := filepath.Join(blocker, "node")
	if _, _, err := Ensure(target); err == nil {
		t.Error("Ensure() into un-creatable path returned nil error")
	}
}

func TestSave_FailsWhenPrivateKeyPathIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, privateKeyFile), 0o700); err != nil {
		t.Fatalf("mkdir private key squatter: %v", err)
	}
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := Save(dir, id); err == nil {
		t.Error("Save() succeeded when private-key path is a directory")
	}
}

func TestSave_FailsWhenPublicKeyPathIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, publicKeyFile), 0o700); err != nil {
		t.Fatalf("mkdir public key squatter: %v", err)
	}
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := Save(dir, id); err == nil {
		t.Error("Save() succeeded when public-key path is a directory")
	}
}

func TestLoad_ReadErrorWhenPrivateKeyIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, privateKeyFile), 0o700); err != nil {
		t.Fatalf("mkdir private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, publicKeyFile), make([]byte, ed25519.PublicKeySize), publicKeyPerm); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() accepted a directory as private key")
	}
	if errors.Is(err, ErrIdentityNotFound) {
		t.Errorf("Load() returned ErrIdentityNotFound for read error; want distinct error")
	}
}

func TestLoad_ReadErrorWhenPublicKeyIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, publicKeyFile), 0o700); err != nil {
		t.Fatalf("mkdir public key: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() accepted a directory as public key")
	}
}

func TestEnsure_PropagatesNonNotFoundLoadError(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, privateKeyFile), 0o700); err != nil {
		t.Fatalf("mkdir private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, publicKeyFile), make([]byte, ed25519.PublicKeySize), publicKeyPerm); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	if _, _, err := Ensure(dir); err == nil {
		t.Error("Ensure() masked a non-notfound Load error")
	}
}

func TestLoad_PublicKeyMissingReturnsIdentityNotFound(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() with missing public key returned nil error")
	}
	if !errors.Is(err, ErrIdentityNotFound) {
		t.Errorf("Load() missing-pub error = %v, want wraps ErrIdentityNotFound", err)
	}
	if !strings.Contains(err.Error(), publicKeyFile) {
		t.Errorf("Load() missing-pub error = %q, want mention of %q", err, publicKeyFile)
	}
}

func TestLoad_PublicKeyStatNonNotFoundError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loop behavior not portable to Windows")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, privateKeyFile), make([]byte, ed25519.PrivateKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	pubPath := filepath.Join(dir, publicKeyFile)
	if err := os.Symlink(pubPath, pubPath); err != nil {
		t.Fatalf("create self-symlink: %v", err)
	}
	_, err := Load(dir)
	if err == nil {
		t.Fatal("Load() accepted self-symlink public key, want error")
	}
	if errors.Is(err, ErrIdentityNotFound) {
		t.Errorf("Load() returned ErrIdentityNotFound for ELOOP; want distinct stat error")
	}
	if !strings.Contains(err.Error(), "stat public key") {
		t.Errorf("Load() error = %q, want 'stat public key' prefix", err)
	}
}

// TestEnsure_PropagatesSaveErrorAfterLoadNotFound asserts a Save failure surfaces from Ensure when Load returned ErrIdentityNotFound.
func TestEnsure_PropagatesSaveErrorAfterLoadNotFound(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, publicKeyFile), 0o700); err != nil {
		t.Fatalf("mkdir public key squatter: %v", err)
	}
	_, created, err := Ensure(dir)
	if err == nil {
		t.Fatal("Ensure() masked Save error")
	}
	if created {
		t.Error("Ensure() reported created=true on failure")
	}
	if errors.Is(err, ErrIdentityNotFound) {
		t.Errorf("Ensure() leaked ErrIdentityNotFound on Save failure; want distinct write error")
	}
}

func TestIdentity_IDHexFormat(t *testing.T) {
	id, err := Generate()
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	full := id.IDHex()
	if len(full) != ed25519.PublicKeySize*2 {
		t.Errorf("IDHex length = %d, want %d", len(full), ed25519.PublicKeySize*2)
	}
	short := id.ShortID()
	if len(short) != 16 {
		t.Errorf("ShortID length = %d, want 16", len(short))
	}
	if !strings.HasPrefix(full, short) {
		t.Errorf("ShortID %q is not a prefix of IDHex %q", short, full)
	}
}
