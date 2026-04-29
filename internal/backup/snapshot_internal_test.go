package backup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"backupswarm/internal/protocol"
	"backupswarm/internal/store"
)

// putIndexSnapshotResponseFrame returns a wire-encoded put-index-snapshot
// response with the supplied appErr (empty = success).
func putIndexSnapshotResponseFrame(t *testing.T, appErr string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := protocol.WritePutIndexSnapshotResponse(&buf, appErr); err != nil {
		t.Fatalf("WritePutIndexSnapshotResponse: %v", err)
	}
	return buf.Bytes()
}

// getIndexSnapshotResponseFrame returns a wire-encoded get-index-snapshot
// response with blob+appErr (caller picks one).
func getIndexSnapshotResponseFrame(t *testing.T, blob []byte, appErr string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := protocol.WriteGetIndexSnapshotResponse(&buf, blob, appErr); err != nil {
		t.Fatalf("WriteGetIndexSnapshotResponse: %v", err)
	}
	return buf.Bytes()
}

// TestSendPutIndexSnapshot_OpenStreamError asserts an OpenStream failure
// surfaces wrapped.
func TestSendPutIndexSnapshot_OpenStreamError(t *testing.T) {
	sentinel := errors.New("open boom")
	opener := &fakeOpener{openErr: sentinel}
	err := sendPutIndexSnapshot(context.Background(), opener, []byte("blob"))
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

// TestSendPutIndexSnapshot_WriteMessageTypeError fails the type-byte write.
func TestSendPutIndexSnapshot_WriteMessageTypeError(t *testing.T) {
	sentinel := errors.New("type write boom")
	stream := &fakeStream{writeErrAt: 0, writeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	err := sendPutIndexSnapshot(context.Background(), opener, []byte("blob"))
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !stream.closed {
		t.Error("stream not closed after type-write error")
	}
}

// TestSendPutIndexSnapshot_WriteRequestError fails the request-frame write.
func TestSendPutIndexSnapshot_WriteRequestError(t *testing.T) {
	sentinel := errors.New("req write boom")
	stream := &fakeStream{writeErrAt: 1, writeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	err := sendPutIndexSnapshot(context.Background(), opener, []byte("blob"))
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !stream.closed {
		t.Error("stream not closed after request-write error")
	}
}

// TestSendPutIndexSnapshot_CloseSendSideError surfaces a half-close failure.
func TestSendPutIndexSnapshot_CloseSendSideError(t *testing.T) {
	sentinel := errors.New("close boom")
	stream := &fakeStream{writeErrAt: -1, closeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	err := sendPutIndexSnapshot(context.Background(), opener, []byte("blob"))
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

// TestSendPutIndexSnapshot_ReadResponseError surfaces an empty-response read.
func TestSendPutIndexSnapshot_ReadResponseError(t *testing.T) {
	stream := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	opener := &fakeOpener{stream: stream}
	err := sendPutIndexSnapshot(context.Background(), opener, []byte("blob"))
	if err == nil {
		t.Fatal("sendPutIndexSnapshot returned nil on empty response")
	}
	if !strings.Contains(err.Error(), "read response") {
		t.Errorf("err = %v, want 'read response' wrap", err)
	}
}

// TestSendPutIndexSnapshot_AppErrorPropagation wraps a peer-supplied appErr.
func TestSendPutIndexSnapshot_AppErrorPropagation(t *testing.T) {
	frame := putIndexSnapshotResponseFrame(t, "no_space")
	stream := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(frame)}
	opener := &fakeOpener{stream: stream}
	err := sendPutIndexSnapshot(context.Background(), opener, []byte("blob"))
	if err == nil {
		t.Fatal("expected appErr wrap, got nil")
	}
	if !strings.Contains(err.Error(), "peer rejected put index snapshot") {
		t.Errorf("err = %v, want 'peer rejected' wrap", err)
	}
	if !strings.Contains(err.Error(), "no_space") {
		t.Errorf("err = %v, want peer message included", err)
	}
}

// TestSendGetIndexSnapshot_OpenStreamError surfaces an OpenStream failure.
func TestSendGetIndexSnapshot_OpenStreamError(t *testing.T) {
	sentinel := errors.New("open boom")
	opener := &fakeOpener{openErr: sentinel}
	_, err := sendGetIndexSnapshot(context.Background(), opener)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

// TestSendGetIndexSnapshot_WriteMessageTypeError surfaces a type-write failure.
func TestSendGetIndexSnapshot_WriteMessageTypeError(t *testing.T) {
	sentinel := errors.New("type write boom")
	stream := &fakeStream{writeErrAt: 0, writeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	_, err := sendGetIndexSnapshot(context.Background(), opener)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !stream.closed {
		t.Error("stream not closed after type-write error")
	}
}

// TestSendGetIndexSnapshot_CloseSendSideError surfaces a half-close failure.
func TestSendGetIndexSnapshot_CloseSendSideError(t *testing.T) {
	sentinel := errors.New("close boom")
	stream := &fakeStream{writeErrAt: -1, closeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	_, err := sendGetIndexSnapshot(context.Background(), opener)
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

// TestSendGetIndexSnapshot_ReadResponseError surfaces an empty-response read.
func TestSendGetIndexSnapshot_ReadResponseError(t *testing.T) {
	stream := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	opener := &fakeOpener{stream: stream}
	_, err := sendGetIndexSnapshot(context.Background(), opener)
	if err == nil {
		t.Fatal("expected nil-response read error, got nil")
	}
	if !strings.Contains(err.Error(), "read response") {
		t.Errorf("err = %v, want 'read response' wrap", err)
	}
}

// TestSendGetIndexSnapshot_AppErrorPropagation wraps a peer-supplied appErr.
func TestSendGetIndexSnapshot_AppErrorPropagation(t *testing.T) {
	frame := getIndexSnapshotResponseFrame(t, nil, "not_found")
	stream := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(frame)}
	opener := &fakeOpener{stream: stream}
	_, err := sendGetIndexSnapshot(context.Background(), opener)
	if err == nil {
		t.Fatal("expected appErr wrap, got nil")
	}
	if !strings.Contains(err.Error(), "peer rejected get index snapshot") {
		t.Errorf("err = %v, want 'peer rejected' wrap", err)
	}
}

// TestHandlePutIndexSnapshotStream_ReadRequestError asserts a truncated
// request body surfaces the read error.
func TestHandlePutIndexSnapshotStream_ReadRequestError(t *testing.T) {
	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	owner := bytes.Repeat([]byte{0x01}, ed25519.PublicKeySize)
	err := handlePutIndexSnapshotStream(context.Background(), rw, nil, owner)
	if err == nil {
		t.Fatal("handler accepted empty request")
	}
	if !strings.Contains(err.Error(), "read request") {
		t.Errorf("err = %v, want 'read request' wrap", err)
	}
}

// TestHandlePutIndexSnapshotStream_StoreErrorWritesAppErr asserts a
// store-side failure encodes an "internal" appErr in the response frame.
func TestHandlePutIndexSnapshotStream_StoreErrorWritesAppErr(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses POSIX file-permission checks")
	}
	storeRoot := filepath.Join(t.TempDir(), "chunks")
	st, err := store.New(storeRoot)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	if err := os.Chmod(storeRoot, 0o500); err != nil {
		t.Fatalf("chmod root: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(storeRoot, 0o700) })

	owner := bytes.Repeat([]byte{0x02}, ed25519.PublicKeySize)
	var reqBuf bytes.Buffer
	if err := protocol.WritePutIndexSnapshotRequest(&reqBuf, []byte("snapshot")); err != nil {
		t.Fatalf("WritePutIndexSnapshotRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handlePutIndexSnapshotStream(context.Background(), rw, st, owner); err != nil {
		t.Fatalf("handler returned %v, want nil (appErr written to frame)", err)
	}
	appErr, err := protocol.ReadPutIndexSnapshotResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadPutIndexSnapshotResponse: %v", err)
	}
	if appErr != "internal" {
		t.Errorf("appErr = %q, want %q", appErr, "internal")
	}
}

// TestSnapshotErrCode_NotFoundMapsToShortCode asserts ErrSnapshotNotFound
// wraps map to "not_found" while other errors map to "internal".
func TestSnapshotErrCode_NotFoundMapsToShortCode(t *testing.T) {
	wrapped := errors.New("wrap: " + store.ErrSnapshotNotFound.Error())
	if got := snapshotErrCode(wrapped); got != "internal" {
		t.Errorf("plain string-wrap mapped to %q; expected 'internal' (no errors.Is link)", got)
	}
	chained := errors.Join(store.ErrSnapshotNotFound, errors.New("extra context"))
	if got := snapshotErrCode(chained); got != "not_found" {
		t.Errorf("ErrSnapshotNotFound chain mapped to %q; want 'not_found'", got)
	}
	if got := snapshotErrCode(errors.New("disk on fire")); got != "internal" {
		t.Errorf("non-NotFound err mapped to %q; want 'internal'", got)
	}
}
