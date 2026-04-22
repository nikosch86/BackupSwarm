// Package node manages the per-node identity (Ed25519 key pair).
//
// The public key is the node ID used throughout the swarm; the private key
// is persisted locally at 0600 and never leaves the node.
package node

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

const (
	privateKeyFile = "node.key"
	publicKeyFile  = "node.pub"

	dirPerm        os.FileMode = 0o700
	privateKeyPerm os.FileMode = 0o600
	publicKeyPerm  os.FileMode = 0o644
)

// ErrIdentityNotFound is returned by Load when no identity exists in the
// given directory. Callers use errors.Is to distinguish "not yet created"
// from corruption or permission errors.
var ErrIdentityNotFound = errors.New("node identity not found")

// Identity is an Ed25519 key pair. The public key is the node's swarm-wide ID.
type Identity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// Generate creates a fresh Ed25519 key pair from the system CSPRNG.
func Generate() (*Identity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519 key: %w", err)
	}
	return &Identity{PrivateKey: priv, PublicKey: pub}, nil
}

// Save writes the identity to dir, creating the directory at 0700 if needed.
// The private key is written at 0600, the public key at 0644.
func Save(dir string, id *Identity) error {
	if err := os.MkdirAll(dir, dirPerm); err != nil {
		return fmt.Errorf("create data dir %q: %w", dir, err)
	}
	// MkdirAll is a no-op on an existing dir with looser perms; force-tighten.
	if err := os.Chmod(dir, dirPerm); err != nil {
		return fmt.Errorf("chmod data dir %q: %w", dir, err)
	}
	privPath := filepath.Join(dir, privateKeyFile)
	if err := os.WriteFile(privPath, id.PrivateKey, privateKeyPerm); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	// WriteFile respects the process umask; force the required mode explicitly
	// so a lax umask can't leave key material world-readable.
	if err := os.Chmod(privPath, privateKeyPerm); err != nil {
		return fmt.Errorf("chmod private key: %w", err)
	}
	pubPath := filepath.Join(dir, publicKeyFile)
	if err := os.WriteFile(pubPath, id.PublicKey, publicKeyPerm); err != nil {
		return fmt.Errorf("write public key: %w", err)
	}
	return nil
}

// Load reads the identity from dir. Returns ErrIdentityNotFound if either
// file is missing; returns an error if the private key has insecure
// permissions (more permissive than 0600 on POSIX systems).
func Load(dir string) (*Identity, error) {
	privPath := filepath.Join(dir, privateKeyFile)
	pubPath := filepath.Join(dir, publicKeyFile)

	privInfo, err := os.Stat(privPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrIdentityNotFound, privPath)
		}
		return nil, fmt.Errorf("stat private key: %w", err)
	}
	if _, err := os.Stat(pubPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrIdentityNotFound, pubPath)
		}
		return nil, fmt.Errorf("stat public key: %w", err)
	}

	if runtime.GOOS != "windows" {
		if perm := privInfo.Mode().Perm(); perm&0o077 != 0 {
			return nil, fmt.Errorf("private key %s has insecure permissions %o (want 0600)", privPath, perm)
		}
	}

	priv, err := os.ReadFile(privPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("private key %s: invalid size %d, want %d", privPath, len(priv), ed25519.PrivateKeySize)
	}
	pub, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, fmt.Errorf("read public key: %w", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("public key %s: invalid size %d, want %d", pubPath, len(pub), ed25519.PublicKeySize)
	}
	return &Identity{PrivateKey: ed25519.PrivateKey(priv), PublicKey: ed25519.PublicKey(pub)}, nil
}

// Ensure loads the identity from dir if present, otherwise generates and
// saves a new one. The created return value reports whether a new identity
// was generated during this call.
func Ensure(dir string) (id *Identity, created bool, err error) {
	id, err = Load(dir)
	if err == nil {
		return id, false, nil
	}
	if !errors.Is(err, ErrIdentityNotFound) {
		return nil, false, err
	}
	id, err = Generate()
	if err != nil {
		return nil, false, err
	}
	if err := Save(dir, id); err != nil {
		return nil, false, err
	}
	return id, true, nil
}

// IDHex returns the node ID (public key) as a lowercase hex string.
func (i *Identity) IDHex() string {
	return hex.EncodeToString(i.PublicKey)
}

// ShortID returns the first 8 bytes of the node ID in hex — suitable for
// human-facing log lines where the full 64-char ID is noisy.
func (i *Identity) ShortID() string {
	const shortBytes = 8
	return hex.EncodeToString(i.PublicKey[:shortBytes])
}
