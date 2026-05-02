package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// PacketWriter is the punch's "send a UDP datagram to addr" seam.
// *net.UDPConn satisfies it implicitly via net.PacketConn.
type PacketWriter interface {
	WriteTo(b []byte, addr net.Addr) (int, error)
}

// punchPayload is the byte body each punch attempt carries. The remote
// QUIC stack will discard it as malformed; the only purpose is the side
// effect on the local NAT mapping.
var punchPayload = []byte("BACKUPSWARM-PUNCH")

// Punch fires `attempts` short UDP datagrams from pc at target, spaced
// by interval. The remote ignores the bytes — what matters is that each
// outbound packet opens a NAT pinhole on the local side so a peer's
// returning QUIC handshake can traverse the same mapping. Aborts on the
// first send error or on ctx cancellation.
func Punch(ctx context.Context, pc PacketWriter, target *net.UDPAddr, attempts int, interval time.Duration) error {
	if pc == nil {
		return errors.New("nat: PacketWriter is required")
	}
	if target == nil {
		return errors.New("nat: target is required")
	}
	if attempts <= 0 {
		return fmt.Errorf("nat: attempts must be > 0, got %d", attempts)
	}
	for i := 0; i < attempts; i++ {
		if _, err := pc.WriteTo(punchPayload, target); err != nil {
			return fmt.Errorf("nat: punch send %d: %w", i+1, err)
		}
		if i == attempts-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
	return nil
}
