package quic

import "crypto/ed25519"

// NewConnForTest constructs a *Conn carrying only remotePub. The inner
// *qgo.Conn is nil; OpenStream / AcceptStream / Close panic.
// Test-only sentinel for ConnSet membership logic.
func NewConnForTest(pub ed25519.PublicKey) *Conn {
	return &Conn{remotePub: pub}
}
