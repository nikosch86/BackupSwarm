package backup

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"backupswarm/internal/protocol"
	"backupswarm/internal/store"
)

func newTTLStore(t *testing.T, ttl time.Duration, now func() time.Time) *store.Store {
	t.Helper()
	st, err := store.NewWithOptions(filepath.Join(t.TempDir(), "chunks"), store.Options{
		ChunkTTL: ttl,
		Now:      now,
	})
	if err != nil {
		t.Fatalf("NewWithOptions: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st
}

func TestHandleRenewTTLStream_AuthorizedRenew(t *testing.T) {
	wallStart := time.Unix(1_700_000_000, 0).UTC()
	clock := wallStart
	st := newTTLStore(t, 30*24*time.Hour, func() time.Time { return clock })

	owner := []byte("alice")
	hash, err := st.PutOwned([]byte("renewable"), owner)
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	clock = wallStart.Add(10 * 24 * time.Hour)

	var reqBuf bytes.Buffer
	if err := protocol.WriteRenewTTLRequest(&reqBuf, hash); err != nil {
		t.Fatalf("WriteRenewTTLRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleRenewTTLStream(context.Background(), rw, st, owner); err != nil {
		t.Fatalf("handleRenewTTLStream: %v", err)
	}
	appErr, err := protocol.ReadRenewTTLResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadRenewTTLResponse: %v", err)
	}
	if appErr != "" {
		t.Errorf("appErr = %q, want empty", appErr)
	}
	got, err := st.ExpiresAt(hash)
	if err != nil {
		t.Fatalf("ExpiresAt: %v", err)
	}
	want := clock.Add(30 * 24 * time.Hour)
	if !got.Equal(want) {
		t.Errorf("ExpiresAt = %v, want %v after RenewTTL", got, want)
	}
}

func TestHandleRenewTTLStream_OwnerMismatch(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	st := newTTLStore(t, 30*24*time.Hour, now)

	hash, err := st.PutOwned([]byte("alice's"), []byte("alice"))
	if err != nil {
		t.Fatalf("PutOwned: %v", err)
	}

	var reqBuf bytes.Buffer
	if err := protocol.WriteRenewTTLRequest(&reqBuf, hash); err != nil {
		t.Fatalf("WriteRenewTTLRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleRenewTTLStream(context.Background(), rw, st, []byte("mallory")); err != nil {
		t.Fatalf("handleRenewTTLStream: %v", err)
	}
	appErr, err := protocol.ReadRenewTTLResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadRenewTTLResponse: %v", err)
	}
	if appErr != "owner_mismatch" {
		t.Errorf("appErr = %q, want owner_mismatch", appErr)
	}
	if bytes.Contains(rw.wbuf.Bytes(), []byte("/")) {
		t.Errorf("response frame leaks slash; suggests path leak: %q", rw.wbuf.String())
	}
}

func TestHandleRenewTTLStream_UnknownHash(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	st := newTTLStore(t, 30*24*time.Hour, now)

	var unknown [32]byte
	var reqBuf bytes.Buffer
	if err := protocol.WriteRenewTTLRequest(&reqBuf, unknown); err != nil {
		t.Fatalf("WriteRenewTTLRequest: %v", err)
	}
	rw := &fakeStream{writeErrAt: -1, rd: &reqBuf}
	if err := handleRenewTTLStream(context.Background(), rw, st, []byte("anyone")); err != nil {
		t.Fatalf("handleRenewTTLStream: %v", err)
	}
	appErr, err := protocol.ReadRenewTTLResponse(&rw.wbuf)
	if err != nil {
		t.Fatalf("ReadRenewTTLResponse: %v", err)
	}
	if appErr != "not_found" {
		t.Errorf("appErr = %q, want not_found", appErr)
	}
}

func TestSendRenewTTL_SuccessPath(t *testing.T) {
	var resp bytes.Buffer
	if err := protocol.WriteRenewTTLResponse(&resp, ""); err != nil {
		t.Fatalf("build response: %v", err)
	}
	stream := &fakeStream{writeErrAt: -1, rd: &resp}
	opener := &fakeOpener{stream: stream}

	if err := sendRenewTTL(context.Background(), opener, [32]byte{0xaa}); err != nil {
		t.Fatalf("sendRenewTTL: %v", err)
	}
	if !stream.closed {
		t.Error("sendRenewTTL did not half-close stream")
	}
}

func TestSendRenewTTL_AppErrorPropagation(t *testing.T) {
	var resp bytes.Buffer
	if err := protocol.WriteRenewTTLResponse(&resp, "owner_mismatch"); err != nil {
		t.Fatalf("build err response: %v", err)
	}
	stream := &fakeStream{writeErrAt: -1, rd: &resp}
	opener := &fakeOpener{stream: stream}

	err := sendRenewTTL(context.Background(), opener, [32]byte{0xaa})
	if err == nil {
		t.Fatal("sendRenewTTL returned nil despite app-error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("peer rejected renew")) {
		t.Errorf("err = %q, want 'peer rejected renew' prefix", err)
	}
}

func TestSendRenewTTL_OpenStreamError(t *testing.T) {
	sentinel := errors.New("open boom")
	opener := &fakeOpener{openErr: sentinel}
	err := sendRenewTTL(context.Background(), opener, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
}

func TestSendRenewTTL_WriteMessageTypeError(t *testing.T) {
	sentinel := errors.New("type write boom")
	stream := &fakeStream{writeErrAt: 0, writeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	err := sendRenewTTL(context.Background(), opener, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !stream.closed {
		t.Error("sendRenewTTL did not close stream after type-write error")
	}
}

func TestSendRenewTTL_WriteHashError(t *testing.T) {
	sentinel := errors.New("hash write boom")
	stream := &fakeStream{writeErrAt: 1, writeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	err := sendRenewTTL(context.Background(), opener, [32]byte{})
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !stream.closed {
		t.Error("sendRenewTTL did not close stream after hash-write error")
	}
}

func TestSendRenewTTL_ReadResponseError(t *testing.T) {
	stream := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	opener := &fakeOpener{stream: stream}
	err := sendRenewTTL(context.Background(), opener, [32]byte{})
	if err == nil {
		t.Fatal("sendRenewTTL returned nil despite empty response stream")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read response")) {
		t.Errorf("err = %q, want 'read response' prefix", err)
	}
}

func TestSendRenewTTL_CloseSendSideError(t *testing.T) {
	sentinel := errors.New("half-close boom")
	stream := &fakeStream{writeErrAt: -1, closeErr: sentinel}
	opener := &fakeOpener{stream: stream}
	err := sendRenewTTL(context.Background(), opener, [32]byte{})
	if err == nil {
		t.Fatal("sendRenewTTL returned nil despite close error")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("err = %v, want wraps sentinel", err)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("close send side")) {
		t.Errorf("err = %q, want 'close send side' prefix", err)
	}
}

func TestHandleRenewTTLStream_ReadRequestError(t *testing.T) {
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }
	st := newTTLStore(t, 30*24*time.Hour, now)

	rw := &fakeStream{writeErrAt: -1, rd: bytes.NewReader(nil)}
	err := handleRenewTTLStream(context.Background(), rw, st, []byte("alice"))
	if err == nil {
		t.Fatal("handleRenewTTLStream returned nil for empty request")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("read request")) {
		t.Errorf("err = %q, want 'read request' prefix", err)
	}
}
