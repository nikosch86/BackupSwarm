package node

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateRecipient_ReturnsDistinctPairs(t *testing.T) {
	a, err := GenerateRecipient()
	if err != nil {
		t.Fatalf("GenerateRecipient() a error: %v", err)
	}
	b, err := GenerateRecipient()
	if err != nil {
		t.Fatalf("GenerateRecipient() b error: %v", err)
	}
	if bytes.Equal(a.PublicKey[:], b.PublicKey[:]) {
		t.Error("two GenerateRecipient() calls produced identical public keys")
	}
	if bytes.Equal(a.PrivateKey[:], b.PrivateKey[:]) {
		t.Error("two GenerateRecipient() calls produced identical private keys")
	}
}

func TestSaveLoadRecipient_RoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
	orig, err := GenerateRecipient()
	if err != nil {
		t.Fatalf("GenerateRecipient() error: %v", err)
	}
	if err := SaveRecipient(dir, orig); err != nil {
		t.Fatalf("SaveRecipient() error: %v", err)
	}
	loaded, err := LoadRecipient(dir)
	if err != nil {
		t.Fatalf("LoadRecipient() error: %v", err)
	}
	if !bytes.Equal(orig.PublicKey[:], loaded.PublicKey[:]) {
		t.Error("loaded public key differs from saved")
	}
	if !bytes.Equal(orig.PrivateKey[:], loaded.PrivateKey[:]) {
		t.Error("loaded private key differs from saved")
	}
}

func TestSaveRecipient_PrivateKeyIs0600(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	dir := t.TempDir()
	keys, err := GenerateRecipient()
	if err != nil {
		t.Fatalf("GenerateRecipient(): %v", err)
	}
	if err := SaveRecipient(dir, keys); err != nil {
		t.Fatalf("SaveRecipient(): %v", err)
	}
	info, err := os.Stat(filepath.Join(dir, recipientPrivateKeyFile))
	if err != nil {
		t.Fatalf("stat private recipient key: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("recipient private key perm = %o, want 0600", perm)
	}
}

func TestLoadRecipient_RejectsPermissiveMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions not meaningful on Windows")
	}
	dir := t.TempDir()
	keys, err := GenerateRecipient()
	if err != nil {
		t.Fatalf("GenerateRecipient(): %v", err)
	}
	if err := SaveRecipient(dir, keys); err != nil {
		t.Fatalf("SaveRecipient(): %v", err)
	}
	if err := os.Chmod(filepath.Join(dir, recipientPrivateKeyFile), 0o644); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	if _, err := LoadRecipient(dir); err == nil {
		t.Error("LoadRecipient() accepted world-readable private key, want error")
	}
}

func TestLoadRecipient_MissingFiles(t *testing.T) {
	dir := t.TempDir()
	_, err := LoadRecipient(dir)
	if err == nil {
		t.Fatal("LoadRecipient() on empty dir returned nil error")
	}
	if !errors.Is(err, ErrRecipientNotFound) {
		t.Errorf("LoadRecipient() missing-keys error = %v, want wraps ErrRecipientNotFound", err)
	}
}

func TestLoadRecipient_PublicKeyMissing(t *testing.T) {
	dir := t.TempDir()
	// Valid-size private recipient key, no public: second stat should trigger
	// ErrRecipientNotFound (separate branch from the private-missing case).
	if err := os.WriteFile(filepath.Join(dir, recipientPrivateKeyFile), make([]byte, RecipientKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	_, err := LoadRecipient(dir)
	if err == nil {
		t.Fatal("LoadRecipient() with missing public key returned nil error")
	}
	if !errors.Is(err, ErrRecipientNotFound) {
		t.Errorf("LoadRecipient() missing-pub error = %v, want wraps ErrRecipientNotFound", err)
	}
}

func TestLoadRecipient_CorruptPrivateKeySize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, recipientPrivateKeyFile), []byte("too-short"), privateKeyPerm); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, recipientPublicKeyFile), make([]byte, RecipientKeySize), publicKeyPerm); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	if _, err := LoadRecipient(dir); err == nil {
		t.Fatal("LoadRecipient() accepted corrupt private key, want error")
	}
}

func TestLoadRecipient_CorruptPublicKeySize(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, recipientPrivateKeyFile), make([]byte, RecipientKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, recipientPublicKeyFile), []byte("no"), publicKeyPerm); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	if _, err := LoadRecipient(dir); err == nil {
		t.Fatal("LoadRecipient() accepted corrupt public key, want error")
	}
}

func TestEnsureRecipient_GeneratesWhenMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
	keys, created, err := EnsureRecipient(dir)
	if err != nil {
		t.Fatalf("EnsureRecipient() error: %v", err)
	}
	if !created {
		t.Error("EnsureRecipient() created=false on fresh dir, want true")
	}
	if keys == nil {
		t.Fatal("EnsureRecipient() returned nil keys")
	}
	if keys.PublicKey == nil || keys.PrivateKey == nil {
		t.Fatal("EnsureRecipient() returned nil key fields")
	}
}

func TestEnsureRecipient_LoadsWhenPresent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "node")
	first, _, err := EnsureRecipient(dir)
	if err != nil {
		t.Fatalf("EnsureRecipient() first error: %v", err)
	}
	second, created, err := EnsureRecipient(dir)
	if err != nil {
		t.Fatalf("EnsureRecipient() second error: %v", err)
	}
	if created {
		t.Error("EnsureRecipient() created=true on second call, want false")
	}
	if !bytes.Equal(first.PublicKey[:], second.PublicKey[:]) {
		t.Error("EnsureRecipient() produced different public keys across runs")
	}
}

func TestEnsureRecipient_PropagatesNonNotFoundLoadError(t *testing.T) {
	dir := t.TempDir()
	// Private recipient key as a directory: Load returns a read error
	// (not ErrRecipientNotFound), so Ensure must propagate.
	if err := os.Mkdir(filepath.Join(dir, recipientPrivateKeyFile), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, recipientPublicKeyFile), make([]byte, RecipientKeySize), publicKeyPerm); err != nil {
		t.Fatalf("write public key: %v", err)
	}
	if _, _, err := EnsureRecipient(dir); err == nil {
		t.Error("EnsureRecipient() masked a non-notfound Load error")
	}
}

func TestSaveRecipient_FailsWhenPrivateKeyPathIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, recipientPrivateKeyFile), 0o700); err != nil {
		t.Fatalf("mkdir squatter: %v", err)
	}
	keys, err := GenerateRecipient()
	if err != nil {
		t.Fatalf("GenerateRecipient(): %v", err)
	}
	if err := SaveRecipient(dir, keys); err == nil {
		t.Error("SaveRecipient() succeeded when private-key path is a directory")
	}
}

func TestSaveRecipient_FailsWhenPublicKeyPathIsDir(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, recipientPublicKeyFile), 0o700); err != nil {
		t.Fatalf("mkdir squatter: %v", err)
	}
	keys, err := GenerateRecipient()
	if err != nil {
		t.Fatalf("GenerateRecipient(): %v", err)
	}
	if err := SaveRecipient(dir, keys); err == nil {
		t.Error("SaveRecipient() succeeded when public-key path is a directory")
	}
}

func TestLoadRecipient_PublicKeyStatNonNotFoundError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loop behavior not portable to Windows")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, recipientPrivateKeyFile), make([]byte, RecipientKeySize), privateKeyPerm); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	pubPath := filepath.Join(dir, recipientPublicKeyFile)
	if err := os.Symlink(pubPath, pubPath); err != nil {
		t.Fatalf("create self-symlink: %v", err)
	}
	_, err := LoadRecipient(dir)
	if err == nil {
		t.Fatal("LoadRecipient() accepted self-symlink public key")
	}
	if errors.Is(err, ErrRecipientNotFound) {
		t.Errorf("LoadRecipient() returned ErrRecipientNotFound for ELOOP; want distinct stat error")
	}
}

func TestSaveRecipient_FailsWhenParentIsFile(t *testing.T) {
	root := t.TempDir()
	blocker := filepath.Join(root, "blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatalf("write blocker: %v", err)
	}
	target := filepath.Join(blocker, "node")
	keys, err := GenerateRecipient()
	if err != nil {
		t.Fatalf("GenerateRecipient(): %v", err)
	}
	if err := SaveRecipient(target, keys); err == nil {
		t.Error("SaveRecipient() into path with file-parent returned nil error")
	}
}

// TestLoadRecipient_PrivateKeyStatNonNotFoundError covers the non-ENOENT
// stat-error branch for the private key path (recipient.go line 79:
// `return nil, fmt.Errorf("stat recipient private key: %w", err)`). Mirror
// of TestLoad_PublicKeyStatNonNotFoundError for the Ed25519 identity.
func TestLoadRecipient_PrivateKeyStatNonNotFoundError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink loop behavior not portable to Windows")
	}
	dir := t.TempDir()
	privPath := filepath.Join(dir, recipientPrivateKeyFile)
	// Self-referential symlink: os.Stat follows links, fails with ELOOP,
	// which does not wrap os.ErrNotExist.
	if err := os.Symlink(privPath, privPath); err != nil {
		t.Fatalf("create self-symlink: %v", err)
	}
	_, err := LoadRecipient(dir)
	if err == nil {
		t.Fatal("LoadRecipient() accepted self-symlink private key")
	}
	if errors.Is(err, ErrRecipientNotFound) {
		t.Errorf("LoadRecipient() returned ErrRecipientNotFound for ELOOP; want distinct stat error")
	}
}

// TestEnsureRecipient_PropagatesSaveErrorAfterLoadNotFound exercises the
// Save-error branch of EnsureRecipient (recipient.go lines 131-133).
// LoadRecipient cleanly returns ErrRecipientNotFound; SaveRecipient then
// fails because node.xpub is pre-squatted by a directory, forcing the
// inner WriteFile to error.
func TestEnsureRecipient_PropagatesSaveErrorAfterLoadNotFound(t *testing.T) {
	dir := t.TempDir()
	// Block node.xpub by pre-creating it as a directory so WriteFile fails.
	if err := os.Mkdir(filepath.Join(dir, recipientPublicKeyFile), dirPerm); err != nil {
		t.Fatalf("mkdir blocker: %v", err)
	}
	_, _, err := EnsureRecipient(dir)
	if err == nil {
		t.Fatal("EnsureRecipient() returned nil despite squatted public-key path")
	}
}
