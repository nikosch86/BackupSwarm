package chunk

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"testing"
)

const testChunkSize = MinChunkSize // 1 MiB — smallest valid size

func TestSplit_EmptyInput(t *testing.T) {
	chunks, err := Split(bytes.NewReader(nil), testChunkSize)
	if err != nil {
		t.Fatalf("Split empty: %v", err)
	}
	if len(chunks) != 0 {
		t.Errorf("Split empty: got %d chunks, want 0", len(chunks))
	}
}

func TestSplit_ExactMultiple(t *testing.T) {
	data := makeRandomBytes(t, testChunkSize*3)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(chunks) != 3 {
		t.Fatalf("got %d chunks, want 3", len(chunks))
	}
	for i, c := range chunks {
		if c.Index != i {
			t.Errorf("chunk[%d].Index = %d, want %d", i, c.Index, i)
		}
		if len(c.Data) != testChunkSize {
			t.Errorf("chunk[%d] size = %d, want %d", i, len(c.Data), testChunkSize)
		}
	}
}

func TestSplit_PartialLastChunk(t *testing.T) {
	const trailer = 123
	data := makeRandomBytes(t, testChunkSize+trailer)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(chunks) != 2 {
		t.Fatalf("got %d chunks, want 2", len(chunks))
	}
	if len(chunks[0].Data) != testChunkSize {
		t.Errorf("chunk[0] size = %d, want %d", len(chunks[0].Data), testChunkSize)
	}
	if len(chunks[1].Data) != trailer {
		t.Errorf("chunk[1] size = %d, want %d", len(chunks[1].Data), trailer)
	}
}

func TestSplit_SmallerThanChunkSize(t *testing.T) {
	data := makeRandomBytes(t, 42)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(chunks) != 1 {
		t.Fatalf("got %d chunks, want 1", len(chunks))
	}
	if !bytes.Equal(chunks[0].Data, data) {
		t.Error("single chunk data differs from input")
	}
}

func TestSplit_HashMatchesContent(t *testing.T) {
	data := makeRandomBytes(t, testChunkSize*2+17)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	for i, c := range chunks {
		want := sha256.Sum256(c.Data)
		if c.Hash != want {
			t.Errorf("chunk[%d] hash mismatch", i)
		}
	}
}

func TestSplit_RejectsInvalidSize(t *testing.T) {
	cases := []int{0, -1, MinChunkSize - 1, MaxChunkSize + 1, 1024}
	for _, size := range cases {
		_, err := Split(bytes.NewReader([]byte("x")), size)
		if err == nil {
			t.Errorf("Split(size=%d) returned nil error", size)
			continue
		}
		if !errors.Is(err, ErrInvalidChunkSize) {
			t.Errorf("Split(size=%d) err = %v, want wraps ErrInvalidChunkSize", size, err)
		}
	}
}

func TestSplit_AcceptsBoundarySizes(t *testing.T) {
	for _, size := range []int{MinChunkSize, MaxChunkSize} {
		if _, err := Split(bytes.NewReader(nil), size); err != nil {
			t.Errorf("Split(size=%d) on empty data: %v", size, err)
		}
	}
}

func TestSplit_PropagatesReaderError(t *testing.T) {
	wantErr := errors.New("boom")
	r := &errReader{err: wantErr}
	_, err := Split(r, testChunkSize)
	if err == nil {
		t.Fatal("Split accepted broken reader")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Split err = %v, want wraps %v", err, wantErr)
	}
}

func TestSplit_DoesNotAliasBuffer(t *testing.T) {
	// If Split returned slices into a shared internal buffer, mutating one
	// chunk's Data would corrupt another — verify each chunk owns its bytes.
	data := makeRandomBytes(t, testChunkSize*2)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(chunks) < 2 {
		t.Fatalf("want >= 2 chunks, got %d", len(chunks))
	}
	orig1 := make([]byte, len(chunks[1].Data))
	copy(orig1, chunks[1].Data)
	for i := range chunks[0].Data {
		chunks[0].Data[i] = 0xff
	}
	if !bytes.Equal(chunks[1].Data, orig1) {
		t.Error("mutating chunk[0] altered chunk[1] — buffers are aliased")
	}
}

func TestJoin_RoundTrip(t *testing.T) {
	data := makeRandomBytes(t, testChunkSize*2+55)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	var buf bytes.Buffer
	if err := Join(chunks, &buf); err != nil {
		t.Fatalf("Join: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Error("Join output differs from original")
	}
}

func TestJoin_Empty(t *testing.T) {
	var buf bytes.Buffer
	if err := Join(nil, &buf); err != nil {
		t.Fatalf("Join nil: %v", err)
	}
	if buf.Len() != 0 {
		t.Errorf("Join nil wrote %d bytes, want 0", buf.Len())
	}
}

func TestJoin_OutOfOrderIsReassembled(t *testing.T) {
	data := makeRandomBytes(t, testChunkSize*3)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	chunks[0], chunks[2] = chunks[2], chunks[0]
	var buf bytes.Buffer
	if err := Join(chunks, &buf); err != nil {
		t.Fatalf("Join: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Error("Join did not restore original after shuffle")
	}
}

func TestJoin_MissingIndexFails(t *testing.T) {
	data := makeRandomBytes(t, testChunkSize*3)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	gapped := []Chunk{chunks[0], chunks[2]} // drop middle
	var buf bytes.Buffer
	err = Join(gapped, &buf)
	if err == nil {
		t.Fatal("Join accepted chunks with missing index")
	}
	if !errors.Is(err, ErrIncompleteChunks) {
		t.Errorf("Join err = %v, want wraps ErrIncompleteChunks", err)
	}
}

func TestJoin_DuplicateIndexFails(t *testing.T) {
	data := makeRandomBytes(t, testChunkSize*2)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	chunks[1].Index = 0
	var buf bytes.Buffer
	if err := Join(chunks, &buf); err == nil {
		t.Fatal("Join accepted duplicate index")
	}
}

func TestJoin_FirstIndexNonZeroFails(t *testing.T) {
	data := makeRandomBytes(t, testChunkSize*2)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	for i := range chunks {
		chunks[i].Index++ // shift to 1..n, no index 0
	}
	var buf bytes.Buffer
	if err := Join(chunks, &buf); err == nil {
		t.Fatal("Join accepted chunks with no index-0 entry")
	}
}

func TestJoin_PropagatesWriterError(t *testing.T) {
	data := makeRandomBytes(t, testChunkSize)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	wantErr := errors.New("boom")
	err = Join(chunks, &errWriter{err: wantErr})
	if err == nil {
		t.Fatal("Join accepted broken writer")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("Join err = %v, want wraps %v", err, wantErr)
	}
}

func TestJoin_DoesNotMutateInput(t *testing.T) {
	data := makeRandomBytes(t, testChunkSize*3)
	chunks, err := Split(bytes.NewReader(data), testChunkSize)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	chunks[0], chunks[2] = chunks[2], chunks[0]
	indicesBefore := []int{chunks[0].Index, chunks[1].Index, chunks[2].Index}
	var buf bytes.Buffer
	if err := Join(chunks, &buf); err != nil {
		t.Fatalf("Join: %v", err)
	}
	indicesAfter := []int{chunks[0].Index, chunks[1].Index, chunks[2].Index}
	for i := range indicesBefore {
		if indicesBefore[i] != indicesAfter[i] {
			t.Errorf("Join mutated caller slice order at position %d: %d -> %d",
				i, indicesBefore[i], indicesAfter[i])
		}
	}
}

type errReader struct{ err error }

func (e *errReader) Read(_ []byte) (int, error) { return 0, e.err }

type errWriter struct{ err error }

func (e *errWriter) Write(_ []byte) (int, error) { return 0, e.err }

func makeRandomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return b
}
