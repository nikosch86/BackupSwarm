// Package invites is the bbolt-backed log of issued single-use join secrets.
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

	// DefaultFilename is the conventional basename for the invites bbolt file.
	DefaultFilename = "invites.db"

	valueFormatVersion byte = 1

	statusPending  byte = 0
	statusConsumed byte = 1
)

// ErrUnknown is returned when no record exists for the secret.
var ErrUnknown = errors.New("invites: unknown secret")

// ErrAlreadyUsed is returned when the secret was already consumed.
var ErrAlreadyUsed = errors.New("invites: secret already consumed")

// ErrSecretExists is returned when a record already exists for the secret.
var ErrSecretExists = errors.New("invites: secret already issued")

// ErrUnknownVersion is returned when the leading version byte is unknown.
var ErrUnknownVersion = errors.New("invites: unknown record version")

// Test seams.
var (
	chmodFunc = os.Chmod
)

// Store is a bbolt-backed log of issued invite secrets.
type Store struct {
	db *bbolt.DB
}

// Open opens (or initializes) the invites store at path.
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

// Issue records secret as pending with swarmID, or returns ErrSecretExists.
func (s *Store) Issue(secret [32]byte, swarmID [32]byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		if b.Get(secret[:]) != nil {
			return fmt.Errorf("%w: %x", ErrSecretExists, secret[:8])
		}
		return b.Put(secret[:], encodeValue(statusPending, swarmID))
	})
}

// Consume atomically flips pending to consumed and returns the swarmID.
// Returns ErrUnknown or ErrAlreadyUsed on failure.
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

// PendingCount returns the number of records still in the pending state.
func (s *Store) PendingCount() (int, error) {
	count := 0
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(bucketName))
		return b.ForEach(func(_, raw []byte) error {
			status, _, decErr := decodeValue(raw)
			if decErr != nil {
				return fmt.Errorf("decode invites record: %w", decErr)
			}
			if status == statusPending {
				count++
			}
			return nil
		})
	})
	if err != nil {
		return 0, err
	}
	return count, nil
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

// decodeValue parses an encoded record.
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
