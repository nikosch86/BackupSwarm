package quic

import (
	"context"
	"io"

	qgo "github.com/quic-go/quic-go"
	"golang.org/x/time/rate"
)

// Stream wraps a QUIC bidirectional stream with optional upload/download
// rate limiters. nil limiter on either side = pass-through. Embedded
// *qgo.Stream promotes transport-level methods; Read/Write are overridden.
type Stream struct {
	*qgo.Stream
	rwc  io.ReadWriteCloser
	up   *rate.Limiter
	down *rate.Limiter
	ctx  context.Context
}

// Read reads from the underlying stream, then waits for download tokens
// for the bytes returned. A token-wait failure (ctx cancel) returns the
// canceled error in place of any read-side success.
func (s *Stream) Read(p []byte) (int, error) {
	n, err := s.readInner(p)
	if n > 0 && s.down != nil {
		if werr := waitTokens(s.streamCtx(), s.down, n); werr != nil {
			return n, werr
		}
	}
	return n, err
}

// Write reserves up tokens then writes; chunks p by burst so a single
// WaitN never asks for more than the limiter permits.
func (s *Stream) Write(p []byte) (int, error) {
	if s.up == nil {
		return s.writeInner(p)
	}
	burst := s.up.Burst()
	if burst <= 0 {
		return s.writeInner(p)
	}
	ctx := s.streamCtx()
	off := 0
	for off < len(p) {
		chunk := len(p) - off
		if chunk > burst {
			chunk = burst
		}
		if err := s.up.WaitN(ctx, chunk); err != nil {
			return off, err
		}
		n, err := s.writeInner(p[off : off+chunk])
		off += n
		if err != nil {
			return off, err
		}
	}
	return off, nil
}

// Close closes the inner stream.
func (s *Stream) Close() error {
	if s.rwc != nil {
		return s.rwc.Close()
	}
	return s.Stream.Close()
}

func (s *Stream) readInner(p []byte) (int, error) {
	if s.rwc != nil {
		return s.rwc.Read(p)
	}
	return s.Stream.Read(p)
}

func (s *Stream) writeInner(p []byte) (int, error) {
	if s.rwc != nil {
		return s.rwc.Write(p)
	}
	return s.Stream.Write(p)
}

func (s *Stream) streamCtx() context.Context {
	if s.ctx == nil {
		return context.Background()
	}
	return s.ctx
}

// waitTokens consumes n tokens from lim, chunking by burst so WaitN is
// never asked for more than the limiter permits.
func waitTokens(ctx context.Context, lim *rate.Limiter, n int) error {
	burst := lim.Burst()
	if burst <= 0 {
		return nil
	}
	for n > 0 {
		chunk := n
		if chunk > burst {
			chunk = burst
		}
		if err := lim.WaitN(ctx, chunk); err != nil {
			return err
		}
		n -= chunk
	}
	return nil
}
