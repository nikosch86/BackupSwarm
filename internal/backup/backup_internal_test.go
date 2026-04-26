package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// fakeStream is a minimal io.ReadWriteCloser used to drive sendChunk.
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

// fakeOpener satisfies the sendChunk streamOpener interface.
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

// TestSendChunk_OpenStreamError asserts an OpenStream error is surfaced wrapped.
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

// TestSendChunk_WritePutChunkRequestError asserts a WritePutChunkRequest write error is surfaced and the stream is closed.
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

// TestSendChunk_CloseSendSideError asserts a stream-close error is surfaced wrapped.
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

// TestSendChunk_ReadResponseError asserts a ReadPutChunkResponse error is surfaced wrapped.
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
	if got := err.Error(); !bytes.Contains([]byte(got), []byte("read response")) {
		t.Errorf("sendChunk err = %q, want 'read response' prefix", got)
	}
}

// TestSendChunk_AppErrorPropagation asserts an app-error frame is wrapped as "peer rejected chunk".
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

// TestHandlePutChunkStream_ReadRequestError asserts the ReadPutChunkRequest error is wrapped as "read request".
func TestHandlePutChunkStream_ReadRequestError(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	err := handlePutChunkStream(context.Background(), rw, nil, []byte{0x01})
	if err == nil {
		t.Fatal("handlePutChunkStream returned nil on empty request")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read request")) {
		t.Errorf("err = %q, want 'read request' prefix", err)
	}
}

// TestHandleDeleteChunkStream_AuthorizedDelete asserts a DeleteChunk from the original owner removes the blob.
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
	if err := handleDeleteChunkStream(context.Background(), rw, st, owner); err != nil {
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

// TestHandleDeleteChunkStream_OwnerMismatch asserts a non-owner DeleteChunk returns the "owner_mismatch" short code and leaves the blob.
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
	if err := handleDeleteChunkStream(context.Background(), rw, st, bob); err != nil {
		t.Fatalf("handleDeleteChunkStream: %v", err)
	}
	appErr, err := protocol.ReadDeleteChunkResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadDeleteChunkResponse: %v", err)
	}
	if appErr != "owner_mismatch" {
		t.Errorf("appErr = %q, want %q", appErr, "owner_mismatch")
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte("/")) {
		t.Errorf("response frame contains '/'; suggests path leak: %q", rw.wbuf.String())
	}
	if ok, err := st.Has(hash); err != nil || !ok {
		t.Errorf("blob missing after unauthorized delete (has=%v, err=%v)", ok, err)
	}
}

// TestHandleDeleteChunkStream_UnknownHash asserts ErrChunkNotFound is surfaced as the "not_found" short code.
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
	if err := handleDeleteChunkStream(context.Background(), rw, st, []byte("anyone")); err != nil {
		t.Fatalf("handleDeleteChunkStream: %v", err)
	}
	appErr, err := protocol.ReadDeleteChunkResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadDeleteChunkResponse: %v", err)
	}
	if appErr != "not_found" {
		t.Errorf("appErr = %q, want %q", appErr, "not_found")
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte("/")) {
		t.Errorf("response frame contains '/'; suggests path leak: %q", rw.wbuf.String())
	}
}

func TestHandleDeleteChunkStream_ReadRequestError(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	err := handleDeleteChunkStream(context.Background(), rw, nil, []byte{0x01})
	if err == nil {
		t.Fatal("handleDeleteChunkStream returned nil on empty request")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read request")) {
		t.Errorf("err = %q, want 'read request' prefix", err)
	}
}

// TestDispatchStream_UnknownMessageType asserts the dispatcher rejects an unrecognized message type byte.
func TestDispatchStream_UnknownMessageType(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader([]byte{0xff})}
	err := dispatchStream(context.Background(), rw, nil, []byte{0x01}, nil)
	if err == nil {
		t.Fatal("dispatchStream accepted unknown message type")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("unknown message type")) {
		t.Errorf("err = %q, want 'unknown message type' prefix", err)
	}
}

func TestDispatchStream_ReadTypeError(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	err := dispatchStream(context.Background(), rw, nil, []byte{0x01}, nil)
	if err == nil {
		t.Fatal("dispatchStream returned nil on empty stream")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read message type")) {
		t.Errorf("err = %q, want 'read message type' prefix", err)
	}
}

func TestDispatchStream_RoutesPeerAnnouncement(t *testing.T) {
	body := bytes.NewBuffer(nil)
	body.WriteByte(byte(protocol.MsgPeerAnnouncement))
	body.Write([]byte("ANNOUNCEMENT_PAYLOAD"))
	rw := &fakeStream{writeErrAt: -1, rd: body}

	var got bytes.Buffer
	announceFn := func(_ context.Context, r io.Reader) error {
		_, err := got.ReadFrom(r)
		return err
	}
	if err := dispatchStream(context.Background(), rw, nil, []byte("alice"), announceFn); err != nil {
		t.Fatalf("dispatchStream: %v", err)
	}
	if got.String() != "ANNOUNCEMENT_PAYLOAD" {
		t.Errorf("announceFn body = %q, want 'ANNOUNCEMENT_PAYLOAD'", got.String())
	}
}

func TestDispatchStream_PeerAnnouncement_NoHandler(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader([]byte{byte(protocol.MsgPeerAnnouncement)})}
	err := dispatchStream(context.Background(), rw, nil, []byte("alice"), nil)
	if err == nil {
		t.Fatal("dispatchStream accepted MsgPeerAnnouncement with nil handler")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("announcement")) {
		t.Errorf("err = %q, want 'announcement' substring", err)
	}
}

// TestDispatchStream_RoutesPutChunk asserts the put-chunk path reaches handlePutChunkStream through the dispatcher.
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
	if err := dispatchStream(context.Background(), rw, st, []byte("alice"), nil); err != nil {
		t.Fatalf("dispatchStream: %v", err)
	}
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

// TestSendDeleteChunk_SuccessPath exercises the happy path through the fake stream.
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
func withIndexDeleteFunc(t *testing.T, fn func(idx *index.Index, path string) error) {
	t.Helper()
	prev := indexDeleteFunc
	indexDeleteFunc = fn
	t.Cleanup(func() { indexDeleteFunc = prev })
}

// TestPrune_IndexDeleteError injects an Index.Delete failure and asserts Prune wraps and returns it.
func TestPrune_IndexDeleteError(t *testing.T) {
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

	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serveCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Serve(serveCtx, listener, peerStore, nil) }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer dialCancel()
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), ownerPriv, peerPub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	idx, err := index.Open(filepath.Join(t.TempDir(), "prune-del-fail.db"))
	if err != nil {
		t.Fatalf("index.Open: %v", err)
	}
	t.Cleanup(func() { _ = idx.Close() })

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

// TestSendChunk_SuccessPath exercises the happy path through the fake stream.
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

// getOKFrame returns a GetChunk success frame for the given blob.
func getOKFrame(t *testing.T, blob []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := protocol.WriteGetChunkResponse(&buf, blob, ""); err != nil {
		t.Fatalf("build get-chunk ok frame: %v", err)
	}
	return buf.Bytes()
}

// getErrFrame returns a GetChunk application-error frame.
func getErrFrame(t *testing.T, msg string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := protocol.WriteGetChunkResponse(&buf, nil, msg); err != nil {
		t.Fatalf("build get-chunk err frame: %v", err)
	}
	return buf.Bytes()
}

// TestHandleGetChunkStream_Success asserts the recorded owner can read its blob over a GetChunk stream with an empty appErr.
func TestHandleGetChunkStream_Success(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	blob := []byte("ciphertext blob")
	owner := []byte("alice")
	hash, err := st.PutOwned(blob, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	var reqBuf bytes.Buffer
	if err := protocol.WriteGetChunkRequest(&reqBuf, hash); err != nil {
		t.Fatalf("WriteGetChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleGetChunkStream(context.Background(), rw, st, owner); err != nil {
		t.Fatalf("handleGetChunkStream: %v", err)
	}
	got, appErr, err := protocol.ReadGetChunkResponse(&rw.wbuf, 1<<20)
	if err != nil {
		t.Fatalf("ReadGetChunkResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob mismatch: got %q, want %q", got, blob)
	}
}

// TestHandleGetChunkStream_UnknownHash asserts an unknown hash surfaces as the "not_found" short code.
func TestHandleGetChunkStream_UnknownHash(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	var unknown [32]byte
	var reqBuf bytes.Buffer
	if err := protocol.WriteGetChunkRequest(&reqBuf, unknown); err != nil {
		t.Fatalf("WriteGetChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleGetChunkStream(context.Background(), rw, st, []byte("alice")); err != nil {
		t.Fatalf("handleGetChunkStream: %v", err)
	}
	_, appErr, err := protocol.ReadGetChunkResponse(&rw.wbuf, 1<<20)
	if err != nil {
		t.Fatalf("ReadGetChunkResponse: %v", err)
	}
	if appErr != "not_found" {
		t.Errorf("appErr = %q, want %q", appErr, "not_found")
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte("/")) {
		t.Errorf("response frame contains '/'; suggests path leak: %q", rw.wbuf.String())
	}
}

// TestHandleGetChunkStream_WrongOwner asserts a non-owner request surfaces
// as the "owner_mismatch" short code without leaking a path or hex hash.
func TestHandleGetChunkStream_WrongOwner(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	blob := []byte("alice's ciphertext")
	hash, err := st.PutOwned(blob, []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	var reqBuf bytes.Buffer
	if err := protocol.WriteGetChunkRequest(&reqBuf, hash); err != nil {
		t.Fatalf("WriteGetChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleGetChunkStream(context.Background(), rw, st, []byte("bob")); err != nil {
		t.Fatalf("handleGetChunkStream: %v", err)
	}
	got, appErr, err := protocol.ReadGetChunkResponse(&rw.wbuf, 1<<20)
	if err != nil {
		t.Fatalf("ReadGetChunkResponse: %v", err)
	}
	if appErr != "owner_mismatch" {
		t.Errorf("appErr = %q, want %q", appErr, "owner_mismatch")
	}
	if len(got) != 0 {
		t.Errorf("blob payload non-empty on owner_mismatch: %q", got)
	}
	hexHash := fmt.Sprintf("%x", hash)
	if bytes.Contains(rw.wbuf.Bytes(), []byte(hexHash)) {
		t.Errorf("response frame contains chunk hex; leak: %q", rw.wbuf.String())
	}
}

// TestHandleGetChunkStream_UnownedBlob asserts a blob written via plain
// Put (no owner row) is unreadable to any caller — surfaces as
// "owner_mismatch", not as a successful blob fetch.
func TestHandleGetChunkStream_UnownedBlob(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	blob := []byte("ownerless ciphertext")
	hash, err := st.Put(blob)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}

	var reqBuf bytes.Buffer
	if err := protocol.WriteGetChunkRequest(&reqBuf, hash); err != nil {
		t.Fatalf("WriteGetChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleGetChunkStream(context.Background(), rw, st, []byte("anyone")); err != nil {
		t.Fatalf("handleGetChunkStream: %v", err)
	}
	_, appErr, err := protocol.ReadGetChunkResponse(&rw.wbuf, 1<<20)
	if err != nil {
		t.Fatalf("ReadGetChunkResponse: %v", err)
	}
	if appErr != "owner_mismatch" {
		t.Errorf("appErr = %q, want %q", appErr, "owner_mismatch")
	}
}

func TestHandleGetChunkStream_ReadRequestError(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	err := handleGetChunkStream(context.Background(), rw, nil, nil)
	if err == nil {
		t.Fatal("handleGetChunkStream returned nil on empty request")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read request")) {
		t.Errorf("err = %q, want 'read request' prefix", err)
	}
}

// TestDispatchStream_RoutesGetChunk asserts the get-chunk path reaches handleGetChunkStream through the dispatcher with the connection's owner key threaded through.
func TestDispatchStream_RoutesGetChunk(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	owner := []byte("alice")
	blob := []byte("bytes for get")
	hash, err := st.PutOwned(blob, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	var reqBuf bytes.Buffer
	if err := protocol.WriteMessageType(&reqBuf, protocol.MsgGetChunk); err != nil {
		t.Fatalf("WriteMessageType: %v", err)
	}
	if err := protocol.WriteGetChunkRequest(&reqBuf, hash); err != nil {
		t.Fatalf("WriteGetChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := dispatchStream(context.Background(), rw, st, owner, nil); err != nil {
		t.Fatalf("dispatchStream: %v", err)
	}
	got, appErr, err := protocol.ReadGetChunkResponse(&rw.wbuf, 1<<20)
	if err != nil {
		t.Fatalf("ReadGetChunkResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob mismatch: got %q, want %q", got, blob)
	}
}

func TestSendGetChunk_SuccessPath(t *testing.T) {
	want := []byte("peer-side blob")
	stream := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(getOKFrame(t, want))}
	opener := &fakeOpener{stream: stream}

	got, err := sendGetChunk(context.Background(), opener, [32]byte{0xaa})
	if err != nil {
		t.Fatalf("sendGetChunk: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("blob mismatch: got %q, want %q", got, want)
	}
	if !stream.closed {
		t.Error("sendGetChunk did not half-close stream")
	}
}

func TestSendGetChunk_AppErrorPropagation(t *testing.T) {
	stream := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(getErrFrame(t, "chunk not found"))}
	opener := &fakeOpener{stream: stream}

	_, err := sendGetChunk(context.Background(), opener, [32]byte{0xaa})
	if err == nil {
		t.Fatal("sendGetChunk returned nil despite app-error frame")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("peer rejected get")) {
		t.Errorf("err = %q, want 'peer rejected get' prefix", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("chunk not found")) {
		t.Errorf("err = %q, want peer message", err)
	}
}

func TestSendGetChunk_OpenStreamError(t *testing.T) {
	sentinel := errors.New("open boom")
	opener := &fakeOpener{openErr: sentinel}
	_, err := sendGetChunk(context.Background(), opener, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestSendGetChunk_WriteMessageTypeError(t *testing.T) {
	sentinel := errors.New("type boom")
	stream := &fakeStream{writeErrAt: 0, writeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	_, err := sendGetChunk(context.Background(), opener, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !stream.closed {
		t.Error("sendGetChunk did not close stream after type-write error")
	}
}

func TestSendGetChunk_WriteRequestError(t *testing.T) {
	sentinel := errors.New("hash write boom")
	stream := &fakeStream{writeErrAt: 1, writeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	_, err := sendGetChunk(context.Background(), opener, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !stream.closed {
		t.Error("sendGetChunk did not close stream after request-write error")
	}
}

func TestSendGetChunk_CloseError(t *testing.T) {
	sentinel := errors.New("close boom")
	stream := &fakeStream{writeErrAt: -1, closeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	_, err := sendGetChunk(context.Background(), opener, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestSendGetChunk_ReadResponseError(t *testing.T) {
	stream := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	opener := &fakeOpener{stream: stream}
	_, err := sendGetChunk(context.Background(), opener, [32]byte{})
	if err == nil {
		t.Fatal("sendGetChunk returned nil on empty response stream")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read response")) {
		t.Errorf("err = %q, want 'read response' prefix", err)
	}
}

// withDispatchStreamFunc swaps dispatchStreamFunc for the duration of a test.
func withDispatchStreamFunc(t *testing.T, fn func(context.Context, io.ReadWriter, *store.Store, []byte, AnnouncementHandler) error) {
	t.Helper()
	prev := dispatchStreamFunc
	dispatchStreamFunc = fn
	t.Cleanup(func() { dispatchStreamFunc = prev })
}

// TestServeConnStreamCap_MatchesQUICConfig asserts the handler-side cap
// equals the QUIC listener-side cap.
func TestServeConnStreamCap_MatchesQUICConfig(t *testing.T) {
	if int64(serveConnStreamCap) != bsquic.MaxIncomingStreamsPerConn {
		t.Errorf("serveConnStreamCap = %d, want %d",
			serveConnStreamCap, bsquic.MaxIncomingStreamsPerConn)
	}
}

// TestServeConn_BoundsConcurrentDispatchers asserts a single peer cannot
// induce more than serveConnStreamCap concurrent dispatchStream
// goroutines on one connection.
func TestServeConn_BoundsConcurrentDispatchers(t *testing.T) {
	const testCap = 2
	const totalStreams = 6
	const settleWindow = 200 * time.Millisecond

	prevCap := serveConnStreamCap
	serveConnStreamCap = testCap
	t.Cleanup(func() { serveConnStreamCap = prevCap })

	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)

	started := make(chan struct{}, totalStreams)
	release := make(chan struct{})
	var releaseOnce sync.Once

	withDispatchStreamFunc(t, func(_ context.Context, _ io.ReadWriter, _ *store.Store, _ []byte, _ AnnouncementHandler) error {
		started <- struct{}{}
		<-release
		return nil
	})

	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}

	listener, err := bsquic.Listen("127.0.0.1:0", serverPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serveCtx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		_ = Serve(serveCtx, listener, nil, nil)
		close(serveDone)
	}()
	// Registered after withDispatchStreamFunc so LIFO drains all
	// dispatchers before the dispatchStreamFunc restore.
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		cancel()
		select {
		case <-serveDone:
		case <-time.After(3 * time.Second):
			t.Error("Serve did not return within 3s of cancel")
		}
	})

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(dialCancel)
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), clientPriv, serverPub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	for i := 0; i < totalStreams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := conn.OpenStream(dialCtx)
			if err != nil {
				return
			}
			// A write triggers the STREAM frame so the peer's
			// AcceptStream returns.
			_, _ = s.Write([]byte{0xff})
			_ = s.Close()
			_, _ = io.Copy(io.Discard, s)
		}()
	}

	// Wait until `cap` handlers have entered the stub.
	for i := 0; i < testCap; i++ {
		select {
		case <-started:
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d/%d handlers started within 3s", i, testCap)
		}
	}

	// Settle window: any additional starts here mean the cap leaked.
	settle := time.NewTimer(settleWindow)
	defer settle.Stop()
	extra := 0
loop:
	for {
		select {
		case <-started:
			extra++
		case <-settle.C:
			break loop
		}
	}
	if extra > 0 {
		t.Errorf("%d extra handlers started past cap=%d", extra, testCap)
	}

	// Release the held handlers so the remaining streams can drain.
	releaseOnce.Do(func() { close(release) })
}

// TestServeConn_LogsDispatchError asserts serveConn surfaces a dispatcher
// error through the warn-log branch without crashing.
func TestServeConn_LogsDispatchError(t *testing.T) {
	dispatchDone := make(chan struct{}, 1)
	withDispatchStreamFunc(t, func(_ context.Context, _ io.ReadWriter, _ *store.Store, _ []byte, _ AnnouncementHandler) error {
		dispatchDone <- struct{}{}
		return errors.New("dispatch boom")
	})

	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}

	listener, err := bsquic.Listen("127.0.0.1:0", serverPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serveCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = Serve(serveCtx, listener, nil, nil) }()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(dialCancel)
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), clientPriv, serverPub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	s, err := conn.OpenStream(dialCtx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := s.Write([]byte{0xff}); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = s.Close()

	select {
	case <-dispatchDone:
	case <-time.After(3 * time.Second):
		t.Fatal("dispatcher stub never invoked")
	}
}

// TestServeConn_SemaphoreAcquireCancelled asserts serveConn returns when
// the serve context is cancelled while a stream is parked waiting for a
// semaphore slot.
func TestServeConn_SemaphoreAcquireCancelled(t *testing.T) {
	prev := serveConnStreamCap
	serveConnStreamCap = 1
	t.Cleanup(func() { serveConnStreamCap = prev })

	var wg sync.WaitGroup
	t.Cleanup(wg.Wait)

	stubEntered := make(chan struct{}, 1)
	blockForever := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(blockForever) }) })

	withDispatchStreamFunc(t, func(_ context.Context, _ io.ReadWriter, _ *store.Store, _ []byte, _ AnnouncementHandler) error {
		stubEntered <- struct{}{}
		<-blockForever
		return nil
	})

	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("server key: %v", err)
	}
	_, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("client key: %v", err)
	}

	listener, err := bsquic.Listen("127.0.0.1:0", serverPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	serveCtx, cancel := context.WithCancel(context.Background())
	serveDone := make(chan struct{})
	go func() {
		_ = Serve(serveCtx, listener, nil, nil)
		close(serveDone)
	}()

	dialCtx, dialCancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(dialCancel)
	conn, err := bsquic.Dial(dialCtx, listener.Addr().String(), clientPriv, serverPub, nil)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	// Occupies the only semaphore slot.
	s1, err := conn.OpenStream(dialCtx)
	if err != nil {
		t.Fatalf("OpenStream s1: %v", err)
	}
	if _, err := s1.Write([]byte{0xff}); err != nil {
		t.Fatalf("Write s1: %v", err)
	}
	select {
	case <-stubEntered:
	case <-time.After(3 * time.Second):
		t.Fatal("stub never entered for stream 1")
	}

	// Parks at the semaphore acquire because the cap is exhausted.
	s2, err := conn.OpenStream(dialCtx)
	if err != nil {
		t.Fatalf("OpenStream s2: %v", err)
	}
	if _, err := s2.Write([]byte{0xff}); err != nil {
		t.Fatalf("Write s2: %v", err)
	}

	// Let the serve loop accept s2 and park at the semaphore acquire.
	time.Sleep(150 * time.Millisecond)

	cancel()

	// The cancel-aware sem-acquire branch closes s2 server-side. From the
	// client, that surfaces as Read returning before the deadline. If
	// sem-acquire is not cancellation-aware, s2 stays open server-side and
	// Read blocks until the deadline.
	if err := s2.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("s2 SetReadDeadline: %v", err)
	}
	if _, err := s2.Read(make([]byte, 1)); err == nil {
		t.Fatal("s2 Read returned nil err after cancel; sem-acquire not cancellation-aware")
	} else if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("s2 Read hit deadline; sem-acquire not cancellation-aware")
	}

	// Release the held dispatcher so serveConn's deferred wg.Wait can
	// drain and Serve can return.
	releaseOnce.Do(func() { close(blockForever) })
	select {
	case <-serveDone:
	case <-time.After(3 * time.Second):
		t.Fatal("Serve did not return after dispatcher released")
	}
}

// TestErrCode_MapsSentinels asserts every store sentinel maps to a stable
// short code, wrapped sentinels match through errors.Is, and unmapped
// errors fall through to "internal".
func TestErrCode_MapsSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"chunk-not-found bare", store.ErrChunkNotFound, "not_found"},
		{"chunk-not-found wrapped", fmt.Errorf("wrap: %w", store.ErrChunkNotFound), "not_found"},
		{"owner-mismatch bare", store.ErrOwnerMismatch, "owner_mismatch"},
		{"owner-mismatch wrapped", fmt.Errorf("wrap: %w", store.ErrOwnerMismatch), "owner_mismatch"},
		{"unmapped", errors.New("permission denied: /data/secret"), "internal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := errCode(tc.err); got != tc.want {
				t.Errorf("errCode(%v) = %q, want %q", tc.err, got, tc.want)
			}
		})
	}
}

// TestHandlePutChunkStream_OwnerMismatchReturnsCode pre-creates an orphan
// blob (Put with no owner row), then a different caller's PutOwned must
// be refused with the "owner_mismatch" short code and no path leak.
func TestHandlePutChunkStream_OwnerMismatchReturnsCode(t *testing.T) {
	st, err := store.New(filepath.Join(t.TempDir(), "chunks"))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	blob := []byte("orphan blob")
	if _, err := st.Put(blob); err != nil {
		t.Fatalf("Put: %v", err)
	}

	var reqBuf bytes.Buffer
	if err := protocol.WritePutChunkRequest(&reqBuf, blob); err != nil {
		t.Fatalf("WritePutChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handlePutChunkStream(context.Background(), rw, st, []byte("claimant")); err != nil {
		t.Fatalf("handlePutChunkStream: %v", err)
	}
	_, appErr, err := protocol.ReadPutChunkResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadPutChunkResponse: %v", err)
	}
	if appErr != "owner_mismatch" {
		t.Errorf("appErr = %q, want %q", appErr, "owner_mismatch")
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte("/")) {
		t.Errorf("response frame contains '/'; suggests path leak: %q", rw.wbuf.String())
	}
}

// TestHandlePutChunkStream_InternalErrorReturnsCode forces a path-laden
// EACCES from the store (chmod chunks dir read-only) and asserts the wire
// response is the "internal" short code without the path.
func TestHandlePutChunkStream_InternalErrorReturnsCode(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	chunksDir := filepath.Join(t.TempDir(), "chunks")
	st, err := store.New(chunksDir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := os.Chmod(chunksDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(chunksDir, 0o700) })

	var reqBuf bytes.Buffer
	if err := protocol.WritePutChunkRequest(&reqBuf, []byte("blob")); err != nil {
		t.Fatalf("WritePutChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handlePutChunkStream(context.Background(), rw, st, []byte("alice")); err != nil {
		t.Fatalf("handlePutChunkStream: %v", err)
	}
	_, appErr, err := protocol.ReadPutChunkResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadPutChunkResponse: %v", err)
	}
	if appErr != "internal" {
		t.Errorf("appErr = %q, want %q", appErr, "internal")
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte(chunksDir)) {
		t.Errorf("response frame contains chunks dir path; leak: %q", rw.wbuf.String())
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte("/")) {
		t.Errorf("response frame contains '/'; suggests path leak: %q", rw.wbuf.String())
	}
}

// TestHandleDeleteChunkStream_InternalErrorReturnsCode chmods the shard
// dir read-only after PutOwned so os.Remove fails with EACCES + a
// path-laden wrap. Wire must be "internal" without the path.
func TestHandleDeleteChunkStream_InternalErrorReturnsCode(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	chunksDir := filepath.Join(t.TempDir(), "chunks")
	st, err := store.New(chunksDir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	owner := []byte("alice")
	blob := []byte("doomed-by-perm")
	hash, err := st.PutOwned(blob, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	hexHash := fmt.Sprintf("%x", hash)
	shardDir := filepath.Join(chunksDir, hexHash[:2])
	if err := os.Chmod(shardDir, 0o500); err != nil {
		t.Fatalf("chmod shard: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	var reqBuf bytes.Buffer
	if err := protocol.WriteDeleteChunkRequest(&reqBuf, hash); err != nil {
		t.Fatalf("WriteDeleteChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleDeleteChunkStream(context.Background(), rw, st, owner); err != nil {
		t.Fatalf("handleDeleteChunkStream: %v", err)
	}
	appErr, err := protocol.ReadDeleteChunkResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadDeleteChunkResponse: %v", err)
	}
	if appErr != "internal" {
		t.Errorf("appErr = %q, want %q", appErr, "internal")
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte(chunksDir)) {
		t.Errorf("response frame contains chunks dir path; leak: %q", rw.wbuf.String())
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte(hexHash)) {
		t.Errorf("response frame contains chunk hex; leak: %q", rw.wbuf.String())
	}
}

// TestHandleGetChunkStream_InternalErrorReturnsCode chmods the shard dir
// 0o000 after PutOwned so os.Open fails with EACCES (not ErrNotExist). Wire
// must be "internal" without the path or hex hash.
func TestHandleGetChunkStream_InternalErrorReturnsCode(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	chunksDir := filepath.Join(t.TempDir(), "chunks")
	st, err := store.New(chunksDir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	owner := []byte("alice")
	blob := []byte("ciphertext")
	hash, err := st.PutOwned(blob, owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}
	hexHash := fmt.Sprintf("%x", hash)
	shardDir := filepath.Join(chunksDir, hexHash[:2])
	if err := os.Chmod(shardDir, 0o000); err != nil {
		t.Fatalf("chmod shard: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(shardDir, 0o700) })

	var reqBuf bytes.Buffer
	if err := protocol.WriteGetChunkRequest(&reqBuf, hash); err != nil {
		t.Fatalf("WriteGetChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleGetChunkStream(context.Background(), rw, st, owner); err != nil {
		t.Fatalf("handleGetChunkStream: %v", err)
	}
	_, appErr, err := protocol.ReadGetChunkResponse(&rw.wbuf, 1<<20)
	if err != nil {
		t.Fatalf("ReadGetChunkResponse: %v", err)
	}
	if appErr != "internal" {
		t.Errorf("appErr = %q, want %q", appErr, "internal")
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte(chunksDir)) {
		t.Errorf("response frame contains chunks dir path; leak: %q", rw.wbuf.String())
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte(hexHash)) {
		t.Errorf("response frame contains chunk hex; leak: %q", rw.wbuf.String())
	}
}

// TestHandlePutChunkStream_LogsRichError asserts the path-laden internal
// error reaches slog.WarnContext on the server side even though only the
// short "internal" code is sent on the wire.
func TestHandlePutChunkStream_LogsRichError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	var captured bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&captured, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	chunksDir := filepath.Join(t.TempDir(), "chunks")
	st, err := store.New(chunksDir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := os.Chmod(chunksDir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(chunksDir, 0o700) })

	var reqBuf bytes.Buffer
	if err := protocol.WritePutChunkRequest(&reqBuf, []byte("blob")); err != nil {
		t.Fatalf("WritePutChunkRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handlePutChunkStream(context.Background(), rw, st, []byte("alice")); err != nil {
		t.Fatalf("handlePutChunkStream: %v", err)
	}

	logged := captured.String()
	if !strings.Contains(logged, chunksDir) {
		t.Errorf("slog capture missing path %q; got: %s", chunksDir, logged)
	}
	if !strings.Contains(logged, "level=WARN") {
		t.Errorf("slog capture missing WARN level; got: %s", logged)
	}
}
