package daemon

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	"backupswarm/internal/ca"
	"backupswarm/internal/invites"
	"backupswarm/pkg/token"
)

// randReadFunc is the test seam for swarmID/secret randomness.
var randReadFunc = func(p []byte) (int, error) { return io.ReadFull(rand.Reader, p) }

// atomicTempFile is the surface writeAtomicFile uses.
type atomicTempFile interface {
	WriteString(string) (int, error)
	Close() error
	Name() string
}

// createAtomicTempFunc is the test seam for atomic temp-file creation.
var createAtomicTempFunc = func(dir, pattern string) (atomicTempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// writeAtomicFile writes data to path via temp+rename in the same directory.
func writeAtomicFile(path, data string) error {
	dir := filepath.Dir(path)
	tmp, err := createAtomicTempFunc(dir, ".token-")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.WriteString(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	committed = true
	return nil
}

// IssueInvite persists a fresh (swarmID, secret) pair as pending and
// returns the encoded token. An empty caCertDER produces a pin-mode token.
func IssueInvite(dataDir, listenAddr string, introPub ed25519.PublicKey, caCertDER []byte) (string, error) {
	store, err := invites.Open(filepath.Join(dataDir, invites.DefaultFilename))
	if err != nil {
		return "", fmt.Errorf("open invites.db: %w", err)
	}
	defer func() { _ = store.Close() }()

	var swarmID, secret [32]byte
	if _, err := randReadFunc(swarmID[:]); err != nil {
		return "", fmt.Errorf("rand swarm id: %w", err)
	}
	if _, err := randReadFunc(secret[:]); err != nil {
		return "", fmt.Errorf("rand secret: %w", err)
	}
	if err := store.Issue(secret, swarmID); err != nil {
		return "", fmt.Errorf("issue: %w", err)
	}
	tokStr, err := token.Encode(token.Token{
		Addr:    listenAddr,
		Pub:     introPub,
		SwarmID: swarmID,
		Secret:  secret,
		CACert:  caCertDER,
	})
	if err != nil {
		return "", fmt.Errorf("encode token: %w", err)
	}
	return tokStr, nil
}

// ResolveSwarmCA returns the per-swarm CA, generating one on first call
// or writing a pin-mode marker when noCA is true.
func ResolveSwarmCA(ctx context.Context, dir string, noCA bool) (*ca.CA, error) {
	hasCA, err := ca.Has(dir)
	if err != nil {
		return nil, fmt.Errorf("check ca: %w", err)
	}
	pinMode, err := ca.IsPinMode(dir)
	if err != nil {
		return nil, fmt.Errorf("check pin mode: %w", err)
	}
	if noCA {
		if hasCA {
			return nil, fmt.Errorf("swarm at %s is in CA mode; --no-ca is incompatible", dir)
		}
		if !pinMode {
			if err := ca.MarkPinMode(dir); err != nil {
				return nil, fmt.Errorf("mark pin mode: %w", err)
			}
		}
		return nil, nil
	}
	if hasCA {
		swarmCA, err := ca.Load(dir)
		if err != nil {
			return nil, fmt.Errorf("load ca: %w", err)
		}
		return swarmCA, nil
	}
	if pinMode {
		return nil, nil
	}
	swarmCA, err := ca.Generate()
	if err != nil {
		return nil, fmt.Errorf("generate ca: %w", err)
	}
	if err := ca.Save(dir, swarmCA); err != nil {
		return nil, fmt.Errorf("save ca: %w", err)
	}
	slog.InfoContext(ctx, "generated swarm ca", "data_dir", dir)
	return swarmCA, nil
}
