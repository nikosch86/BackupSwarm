package index

import (
	"bytes"
	"encoding/gob"
	"errors"
	"fmt"
)

// ErrUnknownSnapshotVersion is returned by UnmarshalSnapshot when the
// leading version byte does not match a known wire format.
var ErrUnknownSnapshotVersion = errors.New("unknown index snapshot wire version")

// snapshotVersion is the leading byte of MarshalSnapshot output. Bumped
// on layout changes so older receivers fail closed instead of mis-parsing.
const snapshotVersion byte = 1

// MarshalSnapshot encodes entries as [1B version][gob(slice)].
func MarshalSnapshot(entries []FileEntry) ([]byte, error) {
	if entries == nil {
		entries = []FileEntry{}
	}
	var buf bytes.Buffer
	buf.WriteByte(snapshotVersion)
	if err := gob.NewEncoder(&buf).Encode(entries); err != nil {
		return nil, fmt.Errorf("encode snapshot: %w", err)
	}
	return buf.Bytes(), nil
}

// UnmarshalSnapshot decodes the canonical wire form produced by
// MarshalSnapshot. Fails ErrUnknownSnapshotVersion on a version mismatch
// and a descriptive error on truncated or corrupt input.
func UnmarshalSnapshot(b []byte) ([]FileEntry, error) {
	if len(b) == 0 {
		return nil, errors.New("snapshot: empty input")
	}
	if b[0] != snapshotVersion {
		return nil, fmt.Errorf("%w: got %d, want %d", ErrUnknownSnapshotVersion, b[0], snapshotVersion)
	}
	var out []FileEntry
	if err := gob.NewDecoder(bytes.NewReader(b[1:])).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode snapshot: %w", err)
	}
	return out, nil
}

// ApplySnapshot upserts each entry into ix, replacing any existing
// record at the same Path.
func ApplySnapshot(ix *Index, entries []FileEntry) error {
	for _, e := range entries {
		if err := ix.Put(e); err != nil {
			return fmt.Errorf("apply snapshot entry %q: %w", e.Path, err)
		}
	}
	return nil
}
