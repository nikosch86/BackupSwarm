package node

import (
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/nacl/box"
)

const (
	recipientPrivateKeyFile = "node.xkey"
	recipientPublicKeyFile  = "node.xpub"

	// RecipientKeySize is the byte length of an X25519 public/private key.
	RecipientKeySize = 32
)

// ErrRecipientNotFound is returned when no X25519 key pair exists in dir.
var ErrRecipientNotFound = errors.New("recipient keys not found")

// RecipientKeys is the per-node X25519 key pair for wrapping chunk keys.
type RecipientKeys struct {
	PublicKey  *[RecipientKeySize]byte
	PrivateKey *[RecipientKeySize]byte
}

// GenerateRecipient returns a fresh X25519 key pair from the system CSPRNG.
func GenerateRecipient() (*RecipientKeys, error) {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate x25519 key: %w", err)
	}
	return &RecipientKeys{PublicKey: pub, PrivateKey: priv}, nil
}

// SaveRecipient writes the X25519 key pair to dir.
func SaveRecipient(dir string, keys *RecipientKeys) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create data dir %q: %w", dir, err)
	}
	if err := os.Chmod(dir, dirPerm); err != nil {
		return fmt.Errorf("chmod data dir %q: %w", dir, err)
	}
	privPath := filepath.Join(dir, recipientPrivateKeyFile)
	if err := os.WriteFile(privPath, keys.PrivateKey[:], privateKeyPerm); err != nil {
		return fmt.Errorf("write recipient private key: %w", err)
	}
	if err := os.Chmod(privPath, privateKeyPerm); err != nil {
		return fmt.Errorf("chmod recipient private key: %w", err)
	}
	pubPath := filepath.Join(dir, recipientPublicKeyFile)
	if err := os.WriteFile(pubPath, keys.PublicKey[:], publicKeyPerm); err != nil {
		return fmt.Errorf("write recipient public key: %w", err)
	}
	return nil
}

// LoadRecipient reads the X25519 key pair from dir or returns ErrRecipientNotFound.
func LoadRecipient(dir string) (*RecipientKeys, error) {
	privPath := filepath.Join(dir, recipientPrivateKeyFile)
	pubPath := filepath.Join(dir, recipientPublicKeyFile)

	privInfo, err := os.Stat(privPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrRecipientNotFound, privPath)
		}
		return nil, fmt.Errorf("stat recipient private key: %w", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrRecipientNotFound, pubPath)
		}
		return nil, fmt.Errorf("stat recipient public key: %w", err)
	}
	if runtime.GOOS != "windows" {
		if perm := privInfo.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("recipient private key %s has insecure permissions %o (want 0600)", privPath, perm)
		}
	}

	priv, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("read recipient private key: %w", err)
	}
	if len(priv) != RecipientKeySize {
		return nil, fmt.Errorf("recipient private key %s: invalid size %d, want %d", privPath, len(priv), RecipientKeySize)
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("read recipient public key: %w", err)
	}
	if len(pub) != RecipientKeySize {
		return nil, fmt.Errorf("recipient public key %s: invalid size %d, want %d", pubPath, len(pub), RecipientKeySize)
	}

	var out RecipientKeys
	out.PrivateKey = new([RecipientKeySize]byte)
	out.PublicKey = new([RecipientKeySize]byte)
	copy(out.PrivateKey[:], priv)
	copy(out.PublicKey[:], pub)
	return &out, nil
}

// EnsureRecipient loads the X25519 key pair from dir or generates and saves one.
func EnsureRecipient(dir string) (keys *RecipientKeys, created bool, err error) {
	keys, err = LoadRecipient(dir)
	if err == nil {
		return keys, false, nil
	}
	if !errors.Is(err, ErrRecipientNotFound) {
		return nil, false, err
	}
	keys, err = GenerateRecipient()
	if err != nil {
		return nil, false, err
	}
	if err := SaveRecipient(dir, keys); err != nil {
		return nil, false, err
	}
	return keys, true, nil
}
