// Package invites is the introducer-side persistent log of issued
// single-use join tokens, bbolt-backed with same-tx read-and-mark-
// consumed semantics so replays surface ErrAlreadyUsed.
package invites

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"go.etcd.io/bbolt"
)

const (
	bucketName = "invites"

	dirPerm  os.FileMode = 0o700
	filePerm os.FileMode = 0o600

	openLockTimeout = 2 * time.Second

	// DefaultFilename is the conventional basename for the invites bbolt
	// file inside a node's data directory.
	DefaultFilename = "invites.db"

	valueFormatVersion byte = 1

	statusPending  byte = 0
	statusConsumed byte = 1
)

// ErrUnknown is returned by Consume when no record exists for the secret.
var ErrUnknown = errors.New("invites: unknown secret")

// ErrAlreadyUsed is returned by Consume when the record exists but was
// already consumed by an earlier Consume call.
var ErrAlreadyUsed = errors.New("invites: secret already consumed")

// ErrSecretExists is returned by Issue when a record already exists for
// the given secret.
var ErrSecretExists = errors.New("invites: secret already issued")

// ErrUnknownVersion is returned when a record's leading version byte is
// not recognized.
var ErrUnknownVersion = errors.New("invites: unknown record version")

// Test-only seams; production never reassigns these.
var (
	chmodFunc = os.Chmod
)

// Store is a bbolt-backed log of issued invite secrets.
type Store struct {
	db *bbolt.DB
}

// Open opens (or initializes) the invites store at path. The parent
// directory is created at 0700 if missing; the bbolt file is chmod'd to
// 0600 after Open.
func Open(path string) (*Store, error) {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, dirPerm); err != nil {
		return nil, fmt.Errorf("create invites dir %q: %w", parent, err)
	}
	db, err := bbolt.Open(path, filePerm, &bbolt.Options{Timeout: openLockTimeout})
	if err != nil {
		return nil, fmt.Errorf("open invites store %q: %w", path, err)
	}
	if err := chmodFunc(path, filePerm); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("chmod invites store %q: %w", path, err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	}); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("create bucket: %w", err)
	}
	return &Store{db: db}, nil
}

// Close closes the underlying bbolt database.
func (s *Store) Close() error { return s.db.Close() }

// Issue records secret as pending with the given swarmID. Returns
// ErrSecretExists if the secret was previously issued.
func (s *Store) Issue(secret [32]byte, swarmID [32]byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b.Get(secret[:]) != nil {
			return fmt.Errorf("%w: %x", ErrSecretExists, secret[:8])
		}
		return b.Put(secret[:], encodeValue(statusPending, swarmID))
	})
}

// Consume atomically flips the record from pending to consumed and
// returns the issued swarmID. Errors: ErrUnknown if no record exists,
// ErrAlreadyUsed if the record was previously consumed.
func (s *Store) Consume(secret [32]byte) ([32]byte, error) {
	var swarmID [32]byte
	err := s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		raw := b.Get(secret[:])
		if raw == nil {
			return fmt.Errorf("%w: %x", ErrUnknown, secret[:8])
		}
		status, sid, decErr := decodeValue(raw)
		if decErr != nil {
			return fmt.Errorf("decode invites record: %w", decErr)
		}
		if status == statusConsumed {
			return fmt.Errorf("%w: %x", ErrAlreadyUsed, secret[:8])
		}
		swarmID = sid
		return b.Put(secret[:], encodeValue(statusConsumed, sid))
	})
	if err != nil {
		return [32]byte{}, err
	}
	return swarmID, nil
}

// PutRawForTest seeds an arbitrary value under secret. Test-only.
func (s *Store) PutRawForTest(secret [32]byte, raw []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.Put(secret[:], bytes.Clone(raw))
	})
}

// encodeValue serializes a record as [version | status | swarmID...].
func encodeValue(status byte, swarmID [32]byte) []byte {
	out := make([]byte, 2+len(swarmID))
	out[0] = valueFormatVersion
	out[1] = status
	copy(out[2:], swarmID[:])
	return out
}

// decodeValue parses an encoded record, returning ErrUnknownVersion when
// the leading byte is not valueFormatVersion.
func decodeValue(raw []byte) (byte, [32]byte, error) {
	var swarmID [32]byte
	if len(raw) < 2 {
		return 0, swarmID, fmt.Errorf("invites: record too short (%d bytes)", len(raw))
	}
	if raw[0] != valueFormatVersion {
		return 0, swarmID, fmt.Errorf("%w: %d", ErrUnknownVersion, raw[0])
	}
	if len(raw) != 2+len(swarmID) {
		return 0, swarmID, fmt.Errorf("invites: record body has %d bytes, want %d", len(raw)-2, len(swarmID))
	}
	copy(swarmID[:], raw[2:])
	return raw[1], swarmID, nil
}
