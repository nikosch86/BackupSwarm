// Package peers is the local persistent registry of known storage peers,
// keyed by Ed25519 pubkey with the last-known listen address. Upserts
// overwrite by pubkey; bbolt-backed, matching internal/index.
package peers

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

const (
	bucketName = "peers"

	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600

	// openLockTimeout bounds how long Open will wait for bbolt's file
	// lock. A second Open on the same file is a caller bug; fail fast.
	openLockTimeout = 2 * time.Second

	// DefaultFilename is the conventional basename for the peer-store
	// bbolt file inside a node's data directory.
	DefaultFilename = "peers.db"
)

// ErrPeerNotFound is returned by Get and Remove when no peer is stored
// under the given public key.
var ErrPeerNotFound = errors.New("peer not found")

// Test-only seams; production never reassigns these.
var (
	chmodFunc    = os.Chmod
	dbUpdateFunc = func(db *bbolt.DB, fn func(*bbolt.Tx) error) error {
		return db.Update(fn)
	}
)

// Peer is one known storage peer: its last-reported listen address and
// Ed25519 identity public key.
type Peer struct {
	Addr   string
	PubKey ed25519.PublicKey
}

// Store is a bbolt-backed peer registry.
type Store struct {
	db *bbolt.DB
}

// Open opens (or initializes) the peer store at path. The parent directory
// is created at 0700 if missing; the bbolt file is chmod'd to 0600 after
// Open to make the permissions deterministic across umasks.
func Open(path string) (*Store, error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, dirPerm); err != nil {
		return nil, fmt.Errorf("create peer dir %q: %w", parent, err)
	}
	db, err := bbolt.Open(path, filePerm, &bbolt.Options{Timeout: openLockTimeout})
	if err != nil {
		return nil, fmt.Errorf("open peer store %q: %w", path, err)
	}
	if err := chmodFunc(path, filePerm); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("chmod peer store %q: %w", path, err)
	}
	if err := dbUpdateFunc(db, func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create bucket: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying bbolt database. Operations on a closed
// Store return errors.
func (s *Store) Close() error { return s.db.Close() }

// Add upserts a peer. If a peer with the same pubkey already exists, the
// record is overwritten (addresses change over time). An empty Addr is
// permitted — it records "we know this pubkey but have no dialable
// address yet" (e.g., a joiner that persists its introducer before the
// joiner's own daemon has bound a port). Such records become dialable
// once an address announcement updates them in place.
func (s *Store) Add(p Peer) error {
	if err := validatePubKey(p.PubKey); err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.Put(p.PubKey, []byte(p.Addr))
	})
}

// Get returns the peer stored under pub, or ErrPeerNotFound.
func (s *Store) Get(pub ed25519.PublicKey) (Peer, error) {
	if err := validatePubKey(pub); err != nil {
		return Peer{}, err
	}
	var got Peer
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		raw := b.Get(pub)
		if raw == nil {
			return fmt.Errorf("%w: %x", ErrPeerNotFound, pub[:8])
		}
		got = Peer{
			Addr:   string(raw),
			PubKey: bytes.Clone(pub),
		}
		return nil
	})
	if err != nil {
		return Peer{}, err
	}
	return got, nil
}

// Remove deletes the peer with the given pubkey. Returns ErrPeerNotFound
// if no such peer exists.
func (s *Store) Remove(pub ed25519.PublicKey) error {
	if err := validatePubKey(pub); err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b.Get(pub) == nil {
			return fmt.Errorf("%w: %x", ErrPeerNotFound, pub[:8])
		}
		return b.Delete(pub)
	})
}

// List returns all stored peers in byte-lex order of pubkey (bbolt's
// native iteration order). Empty, not nil, on an empty store.
func (s *Store) List() ([]Peer, error) {
	out := make([]Peer, 0)
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.ForEach(func(k, v []byte) error {
			out = append(out, Peer{
				Addr:   string(v),
				PubKey: bytes.Clone(k),
			})
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func validatePubKey(pub ed25519.PublicKey) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("peers: pubkey must be %d bytes, got %d", ed25519.PublicKeySize, len(pub))
	}
	return nil
}
