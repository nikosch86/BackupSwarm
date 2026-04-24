package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
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
	err := handlePutChunkStream(rw, nil, []byte{0x01}) // st unused on early-error path
	if err == nil {
		t.Fatal("handlePutChunkStream returned nil on empty request")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read request")) {
		t.Errorf("err = %q, want 'read request' prefix", err)
	}
}

// TestHandleDeleteChunkStream_AuthorizedDelete exercises the happy path
// on the delete handler: a blob previously stored via PutOwned by owner
// can be removed by a DeleteChunk request with that same owner key, and
// the response is a success frame.
func TestHandleDeleteChunkStream_AuthorizedDelete(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	owner := []byte("alice")
	blob := []byte("file-bytes")
	hash, err := st.PutOwned(blob, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	var reqBuf bytes.Buffer
	if err := protocol.WriteDeleteChunkRequest(&reqBuf, hash); err != nil {
		t.Fatalf("WriteDeleteChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleDeleteChunkStream(rw, st, owner); err != nil {
		t.Fatalf("handleDeleteChunkStream: %v", err)
	}
	appErr, err := protocol.ReadDeleteChunkResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadDeleteChunkResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
	if ok, err := st.Has(hash); err != nil || ok {
		t.Errorf("blob still present after authorized delete (has=%v, err=%v)", ok, err)
	}
}

// TestHandleDeleteChunkStream_OwnerMismatch asserts that the handler
// returns an application-level error (owner mismatch) rather than
// silently succeeding when the requesting pubkey does not match the
// stored owner. The blob must remain on disk.
func TestHandleDeleteChunkStream_OwnerMismatch(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	alice := []byte("alice")
	bob := []byte("bob")
	blob := []byte("alice's file")
	hash, err := st.PutOwned(blob, alice)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	var reqBuf bytes.Buffer
	if err := protocol.WriteDeleteChunkRequest(&reqBuf, hash); err != nil {
		t.Fatalf("WriteDeleteChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleDeleteChunkStream(rw, st, bob); err != nil {
		t.Fatalf("handleDeleteChunkStream: %v", err)
	}
	appErr, err := protocol.ReadDeleteChunkResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadDeleteChunkResponse: %v", err)
	}
	if appErr == "" {
		t.Error("expected owner-mismatch app error, got empty")
	}
	if ok, err := st.Has(hash); err != nil || !ok {
		t.Errorf("blob missing after unauthorized delete (has=%v, err=%v)", ok, err)
	}
}

// TestHandleDeleteChunkStream_UnknownHash asserts ErrChunkNotFound is
// surfaced as an application error, not a transport error.
func TestHandleDeleteChunkStream_UnknownHash(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var unknown [32]byte
	var reqBuf bytes.Buffer
	if err := protocol.WriteDeleteChunkRequest(&reqBuf, unknown); err != nil {
		t.Fatalf("WriteDeleteChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleDeleteChunkStream(rw, st, []byte("anyone")); err != nil {
		t.Fatalf("handleDeleteChunkStream: %v", err)
	}
	appErr, err := protocol.ReadDeleteChunkResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadDeleteChunkResponse: %v", err)
	}
	if appErr == "" {
		t.Error("expected chunk-not-found app error, got empty")
	}
}

func TestHandleDeleteChunkStream_ReadRequestError(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	err := handleDeleteChunkStream(rw, nil, []byte{0x01})
	if err == nil {
		t.Fatal("handleDeleteChunkStream returned nil on empty request")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read request")) {
		t.Errorf("err = %q, want 'read request' prefix", err)
	}
}

// TestDispatchStream_UnknownMessageType asserts the dispatcher rejects
// an unrecognized leading byte rather than silently parsing one of the
// known body shapes against mismatched bytes.
func TestDispatchStream_UnknownMessageType(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader([]byte{0xff})}
	err := dispatchStream(context.Background(), rw, nil, []byte{0x01})
	if err == nil {
		t.Fatal("dispatchStream accepted unknown message type")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("unknown message type")) {
		t.Errorf("err = %q, want 'unknown message type' prefix", err)
	}
}

func TestDispatchStream_ReadTypeError(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	err := dispatchStream(context.Background(), rw, nil, []byte{0x01})
	if err == nil {
		t.Fatal("dispatchStream returned nil on empty stream")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read message type")) {
		t.Errorf("err = %q, want 'read message type' prefix", err)
	}
}

// TestDispatchStream_RoutesPutChunk asserts the put-chunk path still
// reaches handlePutChunkStream through the dispatcher.
func TestDispatchStream_RoutesPutChunk(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var reqBuf bytes.Buffer
	if err := protocol.WriteMessageType(&reqBuf, protocol.MsgPutChunk); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	if err := protocol.WritePutChunkRequest(&reqBuf, []byte("blob")); err != nil {
		t.Fatalf("WritePutChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := dispatchStream(context.Background(), rw, st, []byte("alice")); err != nil {
		t.Fatalf("dispatchStream: %v", err)
	}
	// Response on wbuf must be a put-chunk response (1B status + 32B hash on OK).
	hash, appErr, err := protocol.ReadPutChunkResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadPutChunkResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
	want := sha256.Sum256([]byte("blob"))
	if hash != want {
		t.Errorf("hash = %x, want %x", hash, want)
	}
}

// TestSendDeleteChunk_SuccessPath exercises the happy path through the
// fake stream.
func TestSendDeleteChunk_SuccessPath(t *testing.T) {
	var resp bytes.Buffer
	if err := protocol.WriteDeleteChunkResponse(&resp, ""); err != nil {
		t.Fatalf("build response: %v", err)
	}
	stream := &fakeStream{writeErrAt: -1, rd: &resp}
	opener := &fakeOpener{stream: stream}

	if err := sendDeleteChunk(context.Background(), opener, [32]byte{0xaa}); err != nil {
		t.Fatalf("sendDeleteChunk: %v", err)
	}
	if !stream.closed {
		t.Error("sendDeleteChunk did not half-close stream")
	}
}

func TestSendDeleteChunk_AppErrorPropagation(t *testing.T) {
	var resp bytes.Buffer
	if err := protocol.WriteDeleteChunkResponse(&resp, "owner mismatch"); err != nil {
		t.Fatalf("build err response: %v", err)
	}
	stream := &fakeStream{writeErrAt: -1, rd: &resp}
	opener := &fakeOpener{stream: stream}

	err := sendDeleteChunk(context.Background(), opener, [32]byte{0xaa})
	if err == nil {
		t.Fatal("sendDeleteChunk returned nil despite app-error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("peer rejected delete")) {
		t.Errorf("err = %q, want 'peer rejected delete' prefix", err)
	}
}

func TestSendDeleteChunk_OpenStreamError(t *testing.T) {
	sentinel := errors.New("open boom")
	opener := &fakeOpener{openErr: sentinel}
	err := sendDeleteChunk(context.Background(), opener, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestSendDeleteChunk_WriteError(t *testing.T) {
	sentinel := errors.New("write boom")
	stream := &fakeStream{writeErrAt: 0, writeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	err := sendDeleteChunk(context.Background(), opener, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !stream.closed {
		t.Error("sendDeleteChunk did not close stream after write error")
	}
}

func TestSendDeleteChunk_CloseError(t *testing.T) {
	sentinel := errors.New("close boom")
	stream := &fakeStream{writeErrAt: -1, closeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	err := sendDeleteChunk(context.Background(), opener, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestSendDeleteChunk_ReadResponseError(t *testing.T) {
	stream := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	opener := &fakeOpener{stream: stream}
	err := sendDeleteChunk(context.Background(), opener, [32]byte{})
	if err == nil {
		t.Fatal("sendDeleteChunk returned nil on empty response")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read response")) {
		t.Errorf("err = %q, want 'read response' prefix", err)
	}
}

// withIndexDeleteFunc swaps indexDeleteFunc for the duration of a test.
// White-box only — production never reassigns it.
func withIndexDeleteFunc(t *testing.T, fn func(idx *index.Index, path string) error) {
	t.Helper()
	prev := indexDeleteFunc
	indexDeleteFunc = fn
	t.Cleanup(func() { indexDeleteFunc = prev })
}

// TestPrune_IndexDeleteError exercises the `opts.Index.Delete` error
// wrap at the end of Prune's per-entry body (backup.go lines 235-237).
// A real bbolt Delete cannot fail on a healthy, open db with an
// existing key — the error branch is reachable only via fault
// injection. Same pattern as the `gobEncodeFunc` seam in internal/index
// and `createTempFunc` in internal/store.
func TestPrune_IndexDeleteError(t *testing.T) {
	// Set up a real peer + conn so sendDeleteChunk succeeds against a
	// live QUIC transport. Only after all chunks are delivered does
	// Prune reach the Index.Delete call the seam fails.
	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	_, ownerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("owner key: %v", err)
	}
	peerStore, err := store.New(filepath.Join(t.TempDir(), "peer-chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = peerStore.Close() })

	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serveCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Serve(serveCtx, listener, peerStore) }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), ownerPriv, peerPub)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	idx, err := index.Open(filepath.Join(t.TempDir(), "prune-del-fail.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

	// First, ship a real chunk to the peer with recipient encryption so
	// the delete call at the peer side succeeds for our seeded hash.
	recipientPub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	root := t.TempDir()
	path := filepath.Join(root, "f.bin")
	if err := os.WriteFile(path, []byte("doomed"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := Run(context.Background(), RunOptions{
		Path:         path,
		Conn:         conn,
		RecipientPub: recipientPub,
		Index:        idx,
		ChunkSize:    1 << 20,
		Progress:     io.Discard,
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatalf("rm: %v", err)
	}

	sentinel := errors.New("forced index.Delete failure")
	withIndexDeleteFunc(t, func(_ *index.Index, _ string) error {
		return sentinel
	})

	err = Prune(context.Background(), PruneOptions{
		Root:     root,
		Conn:     conn,
		Index:    idx,
		Progress: io.Discard,
	})
	if err == nil {
		t.Fatal("Prune returned nil despite injected index.Delete failure")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("index delete")) {
		t.Errorf("err = %q, want 'index delete' prefix", err)
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
