// Package chunk splits byte streams into fixed-size content-addressed
// chunks and reassembles them.
package chunk

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
)

// Chunk size bounds.
const (
	MinChunkSize = 1 << 20 // 1 MiB
	MaxChunkSize = 4 << 20 // 4 MiB
)

// ErrInvalidChunkSize is returned when chunk size is outside [Min, Max].
var ErrInvalidChunkSize = errors.New("chunk size out of range")

// ErrIncompleteChunks is returned when chunk indices don't form 0..n-1.
var ErrIncompleteChunks = errors.New("chunk set is incomplete")

// Chunk is a fixed-size segment of plaintext bytes; Hash is sha256(Data).
type Chunk struct {
	Index int
	Data  []byte
	Hash  [sha256.Size]byte
}

// Split reads r and emits fixed-size chunks; the final chunk may be shorter.
func Split(r io.Reader, size int) ([]Chunk, error) {
	if size < MinChunkSize || size > MaxChunkSize {
		return nil, fmt.Errorf("%w: got %d (want %d..%d)", ErrInvalidChunkSize, size, MinChunkSize, MaxChunkSize)
	}
	var chunks []Chunk
	buf := make([]byte, size)
	for idx := 0; ; idx++ {
		n, err := io.ReadFull(r, buf)
		if n > 0 {
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

// Join writes chunks to w in ascending Index order.
// Returns ErrIncompleteChunks when indices don't form 0..n-1.
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
