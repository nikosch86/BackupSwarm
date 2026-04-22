// Package chunk splits byte streams into fixed-size, content-addressed
// chunks and reassembles them back into the original stream.
//
// Each chunk carries a monotonically increasing index starting at 0, a
// SHA-256 hash of its plaintext bytes (the content address used by the
// on-disk store in M1.6), and the raw bytes themselves. Split returns
// chunks in order; Join tolerates any ordering of its input and validates
// that the index sequence is dense from 0.
package chunk

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Fixed-size chunks are bounded at 1–4 MiB per the M1 design in plan.md.
// Values outside this range are rejected by Split.
const (
	MinChunkSize = 1 << 20 // 1 MiB
	MaxChunkSize = 4 << 20 // 4 MiB
)

// ErrInvalidChunkSize is returned by Split when the requested chunk size is
// outside [MinChunkSize, MaxChunkSize].
var ErrInvalidChunkSize = errors.New("chunk size out of range")

// ErrIncompleteChunks is returned by Join when the input slice has missing
// or duplicate indices, so a contiguous 0..n-1 sequence cannot be formed.
var ErrIncompleteChunks = errors.New("chunk set is incomplete")

// Chunk is a single fixed-size segment of a file's plaintext bytes.
// Hash is sha256(Data) and is stable across encoding / transport.
type Chunk struct {
	Index int
	Data  []byte
	Hash  [sha256.Size]byte
}

// Split reads r and emits fixed-size chunks of the requested size. The
// final chunk may be shorter than size if the input length is not an exact
// multiple. Returns an empty slice (not nil error) on empty input.
func Split(r io.Reader, size int) ([]Chunk, error) {
	if size < MinChunkSize || size > MaxChunkSize {
		return nil, fmt.Errorf("%w: got %d (want %d..%d)", ErrInvalidChunkSize, size, MinChunkSize, MaxChunkSize)
	}
	var chunks []Chunk
	buf := make([]byte, size)
	for idx := 0; ; idx++ {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
			// Copy so each chunk owns its bytes; buf is reused across iterations.
			data := make([]byte, n)
			copy(data, buf[:n])
			chunks = append(chunks, Chunk{
				Index: idx,
				Data:  data,
				Hash:  sha256.Sum256(data),
			})
		}
		switch {
		case err == nil:
			continue
		case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
			return chunks, nil
		default:
			return nil, fmt.Errorf("read chunk %d: %w", idx, err)
		}
	}
}

// Join writes the chunks' data to w in ascending Index order. Input need
// not be sorted; Join sorts a local copy so the caller's slice is not
// mutated. Returns ErrIncompleteChunks if the indices don't form a dense
// 0..len(chunks)-1 sequence.
func Join(chunks []Chunk, w io.Writer) error {
	sorted := make([]Chunk, len(chunks))
	copy(sorted, chunks)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Index < sorted[j].Index })
	for i, c := range sorted {
		if c.Index != i {
			return fmt.Errorf("%w: position %d has index %d", ErrIncompleteChunks, i, c.Index)
		}
		if _, err := w.Write(c.Data); err != nil {
			return fmt.Errorf("write chunk %d: %w", c.Index, err)
		}
	}
	return nil
}
