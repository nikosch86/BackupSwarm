package backup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"testing"

	"backupswarm/internal/protocol"
)

// fakeStream is a minimal io.ReadWriteCloser used to drive sendChunk
// without a real QUIC transport. It reads from rd (what the "peer"
// would send back) and writes are captured into wbuf.
type fakeStream struct {
	rd         io.Reader
	wbuf       bytes.Buffer
	closed     bool
	closeErr   error
	writeErrAt int // fail the Nth write (-1 = never); counts calls
	writeCalls int
	writeErr   error
}

func (f *fakeStream) Read(p []byte) (int, error) {
	if f.rd == nil {
		return 0, io.EOF
	}
	return f.rd.Read(p)
}

func (f *fakeStream) Write(p []byte) (int, error) {
	defer func() { f.writeCalls++ }()
	if f.writeErrAt >= 0 && f.writeCalls == f.writeErrAt {
		return 0, f.writeErr
	}
	return f.wbuf.Write(p)
}

func (f *fakeStream) Close() error {
	f.closed = true
	return f.closeErr
}

// fakeOpener satisfies the sendChunk streamOpener interface. It returns
// openErr if set, otherwise the canned stream.
type fakeOpener struct {
	stream  *fakeStream
	openErr error
}

func (f *fakeOpener) OpenStream(ctx context.Context) (io.ReadWriteCloser, error) {
	if f.openErr != nil {
		return nil, f.openErr
	}
	return f.stream, nil
}

// okResponseFrame returns a byte slice containing a protocol
// PutChunkResponse success frame for the given hash.
func okResponseFrame(t *testing.T, hash [32]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := protocol.WritePutChunkResponse(&buf, hash, ""); err != nil {
		t.Fatalf("build response frame: %v", err)
	}
	return buf.Bytes()
}

// errResponseFrame returns a byte slice containing a PutChunkResponse
// application-error frame with the given message.
func errResponseFrame(t *testing.T, msg string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := protocol.WritePutChunkResponse(&buf, [32]byte{}, msg); err != nil {
		t.Fatalf("build err response frame: %v", err)
	}
	return buf.Bytes()
}

// TestSendChunk_OpenStreamError exercises the OpenStream error wrap
// (backup.go line 150-152). The opener returns an error before any
// bytes are written, which must be surfaced as "open stream: ...".
func TestSendChunk_OpenStreamError(t *testing.T) {
	sentinel := errors.New("open stream boom")
	opener := &fakeOpener{openErr: sentinel}
	_, err := sendChunk(context.Background(), opener, []byte("blob"))
	if err == nil {
		t.Fatal("sendChunk returned nil on OpenStream error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("sendChunk err = %v, want wraps sentinel", err)
	}
}

// TestSendChunk_WritePutChunkRequestError exercises the
// WritePutChunkRequest error wrap (backup.go line 154-157). The fake
// stream fails its first write call, so WritePutChunkRequest returns
// an error that sendChunk must surface without further stream traffic.
// Also asserts the stream was closed on the error path.
func TestSendChunk_WritePutChunkRequestError(t *testing.T) {
	sentinel := errors.New("write request boom")
	stream := &fakeStream{writeErrAt: 0, writeErr: sentinel}
	opener := &fakeOpener{stream: stream}

	_, err := sendChunk(context.Background(), opener, []byte("blob"))
	if err == nil {
		t.Fatal("sendChunk returned nil on WritePutChunkRequest error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("sendChunk err = %v, want wraps sentinel", err)
	}
	if !stream.closed {
		t.Error("sendChunk did not close stream after WritePutChunkRequest error")
	}
}

// TestSendChunk_CloseSendSideError exercises the half-close error wrap
// (backup.go line 159-161). The request write succeeds; the subsequent
// stream.Close() returns an error that must be wrapped as
// "close send side: ...".
func TestSendChunk_CloseSendSideError(t *testing.T) {
	sentinel := errors.New("half-close boom")
	stream := &fakeStream{writeErrAt: -1, closeErr: sentinel}
	opener := &fakeOpener{stream: stream}

	_, err := sendChunk(context.Background(), opener, []byte("blob"))
	if err == nil {
		t.Fatal("sendChunk returned nil on stream close error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("sendChunk err = %v, want wraps sentinel", err)
	}
}

// TestSendChunk_ReadResponseError exercises the ReadPutChunkResponse
// error wrap (backup.go line 164-166). Request write and close succeed,
// but the response read fails immediately (empty reader — EOF).
func TestSendChunk_ReadResponseError(t *testing.T) {
	stream := &fakeStream{
		writeErrAt: -1,
		rd:         bytes.NewReader(nil),
	}
	opener := &fakeOpener{stream: stream}

	_, err := sendChunk(context.Background(), opener, []byte("blob"))
	if err == nil {
		t.Fatal("sendChunk returned nil on empty response stream")
	}
	// Must be surfaced via the "read response" wrap, not the close wrap.
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("read response")) {
		t.Errorf("sendChunk err = %q, want 'read response' prefix", got)
	}
}

// TestSendChunk_AppErrorPropagation exercises the appErr != "" branch
// (backup.go line 167-169). The peer returns a well-formed error frame
// with a non-empty message; sendChunk must wrap it as "peer rejected
// chunk: <msg>".
func TestSendChunk_AppErrorPropagation(t *testing.T) {
	frame := errResponseFrame(t, "store is full")
	stream := &fakeStream{
		writeErrAt: -1,
		rd:         bytes.NewReader(frame),
	}
	opener := &fakeOpener{stream: stream}

	_, err := sendChunk(context.Background(), opener, []byte("blob"))
	if err == nil {
		t.Fatal("sendChunk returned nil despite app-error frame")
	}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("peer rejected chunk")) {
		t.Errorf("sendChunk err = %q, want 'peer rejected chunk' prefix", got)
	}
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("store is full")) {
		t.Errorf("sendChunk err = %q, want peer message included", got)
	}
}

// TestHandlePutChunkStream_ReadRequestError exercises the
// ReadPutChunkRequest error wrap in handlePutChunkStream. The fake
// stream returns EOF immediately so the header read fails; the
// returned error wraps "read request".
func TestHandlePutChunkStream_ReadRequestError(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	err := handlePutChunkStream(rw, nil) // st unused on early-error path
	if err == nil {
		t.Fatal("handlePutChunkStream returned nil on empty request")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read request")) {
		t.Errorf("err = %q, want 'read request' prefix", err)
	}
}

// TestSendChunk_SuccessPath exercises the happy path through the fake
// stream — sanity check that the fake plumbs writes and reads the way
// a real QUIC stream would. Helps the write/read/close coverage
// interaction line up with what the real integration tests expect.
func TestSendChunk_SuccessPath(t *testing.T) {
	want := sha256.Sum256([]byte("peer would hash this"))
	frame := okResponseFrame(t, want)
	stream := &fakeStream{
		writeErrAt: -1,
		rd:         bytes.NewReader(frame),
	}
	opener := &fakeOpener{stream: stream}

	got, err := sendChunk(context.Background(), opener, []byte("blob"))
	if err != nil {
		t.Fatalf("sendChunk: %v", err)
	}
	if got != want {
		t.Errorf("hash mismatch: got %x, want %x", got, want)
	}
}
