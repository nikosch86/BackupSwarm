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

	// valueFormatVersion is the leading byte of every encoded peer record.
	valueFormatVersion byte = 1
)

// ErrPeerNotFound is returned by Get and Remove when no peer is stored
// under the given public key.
var ErrPeerNotFound = errors.New("peer not found")

// ErrUnknownVersion is returned by decodeValue when the leading version
// byte is not recognized.
var ErrUnknownVersion = errors.New("unknown peer record version")

// Role classifies how this node knows about a peer.
type Role uint8

const (
	// RoleUnspecified is the zero value; rejected by Add.
	RoleUnspecified Role = 0
	// RolePeer is a known peer that is not a chosen backup partner.
	RolePeer Role = 1
	// RoleIntroducer is a peer recorded by DoJoin.
	RoleIntroducer Role = 2
	// RoleStorage is an explicit storage target.
	RoleStorage Role = 3
)

// String returns a short human label for the role.
func (r Role) String() string {
	switch r {
	case RoleUnspecified:
		return "unspecified"
	case RolePeer:
		return "peer"
	case RoleIntroducer:
		return "introducer"
	case RoleStorage:
		return "storage"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(r))
	}
}

// IsStorageCandidate reports whether peers with this role admit as
// backup destinations.
func (r Role) IsStorageCandidate() bool {
	return r == RoleIntroducer || r == RoleStorage
}

func validateRole(r Role) error {
	switch r {
	case RolePeer, RoleIntroducer, RoleStorage:
		return nil
	default:
		return fmt.Errorf("peers: invalid role %v", r)
	}
}

// encodeValue serializes a peer record as [version | role | addr...].
func encodeValue(role Role, addr string) []byte {
	out := make([]byte, 2+len(addr))
	out[0] = valueFormatVersion
	out[1] = byte(role)
	copy(out[2:], addr)
	return out
}

// decodeValue parses an encoded peer record, returning ErrUnknownVersion
// when the leading byte is not valueFormatVersion.
func decodeValue(raw []byte) (Role, string, error) {
	if len(raw) < 2 {
		return RoleUnspecified, "", fmt.Errorf("peers: record too short (%d bytes)", len(raw))
	}
	if raw[0] != valueFormatVersion {
		return RoleUnspecified, "", fmt.Errorf("%w: %d", ErrUnknownVersion, raw[0])
	}
	return Role(raw[1]), string(raw[2:]), nil
}

// Test-only seams; production never reassigns these.
var (
	chmodFunc    = os.Chmod
	dbUpdateFunc = func(db *bbolt.DB, fn func(*bbolt.Tx) error) error {
		return db.Update(fn)
	}
)

// Peer is one known storage peer: its last-reported listen address,
// Ed25519 identity public key, and Role.
type Peer struct {
	Addr   string
	PubKey ed25519.PublicKey
	Role   Role
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
	if err := validateRole(p.Role); err != nil {
		return err
	}
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.Put(p.PubKey, encodeValue(p.Role, p.Addr))
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
		role, addr, decErr := decodeValue(raw)
		if decErr != nil {
			return fmt.Errorf("decode peer record: %w", decErr)
		}
		got = Peer{
			Addr:   addr,
			PubKey: bytes.Clone(pub),
			Role:   role,
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
			role, addr, decErr := decodeValue(v)
			if decErr != nil {
				return fmt.Errorf("decode peer record: %w", decErr)
			}
			out = append(out, Peer{
				Addr:   addr,
				PubKey: bytes.Clone(k),
				Role:   role,
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
