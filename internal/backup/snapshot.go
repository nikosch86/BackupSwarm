package backup

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"backupswarm/internal/protocol"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// MaxIndexSnapshotSize caps a single PutIndexSnapshot / GetIndexSnapshot
// blob at 64 MiB. Larger snapshots must be chunked via the chunk pipeline.
const MaxIndexSnapshotSize = 64 << 20

// SendPutIndexSnapshot uploads blob as the latest encrypted index
// snapshot for the conn's TLS-authenticated owner pubkey. Wraps any
// peer-reported application error.
func SendPutIndexSnapshot(ctx context.Context, conn *bsquic.Conn, blob []byte) error {
	return sendPutIndexSnapshot(ctx, bsquicConnAdapter{c: conn}, blob)
}

// SendGetIndexSnapshot fetches the latest snapshot for the conn's
// TLS-authenticated owner pubkey. Wraps any peer-reported application
// error (e.g. not_found).
func SendGetIndexSnapshot(ctx context.Context, conn *bsquic.Conn) ([]byte, error) {
	return sendGetIndexSnapshot(ctx, bsquicConnAdapter{c: conn})
}

func sendPutIndexSnapshot(ctx context.Context, conn streamOpener, blob []byte) error {
	if len(blob) == 0 {
		return errors.New("put index snapshot blob must be non-empty")
	}
	s, err := conn.OpenStream(ctx)
	if err != nil {
		return fmt.Errorf("open stream: %w", err)
	}
	if err := protocol.WriteMessageType(s, protocol.MsgPutIndexSnapshot); err != nil {
		_ = s.Close()
		return err
	}
	if err := protocol.WritePutIndexSnapshotRequest(s, blob); err != nil {
		_ = s.Close()
		return err
	}
	if err := s.Close(); err != nil {
		return fmt.Errorf("close send side: %w", err)
	}
	appErr, err := protocol.ReadPutIndexSnapshotResponse(s)
	if err != nil {
		return fmt.Errorf("read response: %w", err)
	}
	if appErr != "" {
		return fmt.Errorf("peer rejected put index snapshot: %s", appErr)
	}
	return nil
}

func sendGetIndexSnapshot(ctx context.Context, conn streamOpener) ([]byte, error) {
	s, err := conn.OpenStream(ctx)
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	if err := protocol.WriteMessageType(s, protocol.MsgGetIndexSnapshot); err != nil {
		_ = s.Close()
		return nil, err
	}
	if err := s.Close(); err != nil {
		return nil, fmt.Errorf("close send side: %w", err)
	}
	blob, appErr, err := protocol.ReadGetIndexSnapshotResponse(s, MaxIndexSnapshotSize)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	if appErr != "" {
		return nil, fmt.Errorf("peer rejected get index snapshot: %s", appErr)
	}
	return blob, nil
}

// handlePutIndexSnapshotStream stores the request blob under the conn's
// owner pubkey. Store errors map to the same wire vocabulary as chunk
// errors; the rich error stays in slog.WarnContext.
func handlePutIndexSnapshotStream(ctx context.Context, rw io.ReadWriter, st *store.Store, owner []byte) error {
	blob, err := protocol.ReadPutIndexSnapshotRequest(rw, MaxIndexSnapshotSize)
	if err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	if putErr := st.PutIndexSnapshot(owner, blob); putErr != nil {
		code := snapshotErrCode(putErr)
		slog.WarnContext(ctx, "put index snapshot failed", "code", code, "err", putErr)
		return protocol.WritePutIndexSnapshotResponse(rw, code)
	}
	return protocol.WritePutIndexSnapshotResponse(rw, "")
}

// handleGetIndexSnapshotStream serves the snapshot stored under the
// conn's owner pubkey. ErrSnapshotNotFound maps to "not_found".
func handleGetIndexSnapshotStream(ctx context.Context, rw io.ReadWriter, st *store.Store, owner []byte) error {
	blob, getErr := st.GetIndexSnapshot(owner)
	if getErr != nil {
		code := snapshotErrCode(getErr)
		slog.WarnContext(ctx, "get index snapshot failed", "code", code, "err", getErr)
		return protocol.WriteGetIndexSnapshotResponse(rw, nil, code)
	}
	return protocol.WriteGetIndexSnapshotResponse(rw, blob, "")
}

// snapshotErrCode maps a snapshot-side store error to a stable wire
// short code. ErrSnapshotNotFound surfaces as "not_found"; all other
// errors fall through to "internal".
func snapshotErrCode(err error) string {
	if errors.Is(err, store.ErrSnapshotNotFound) {
		return "not_found"
	}
	return "internal"
}
