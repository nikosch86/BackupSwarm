// Package quic implements the peer transport over QUIC with mutual TLS
// keyed by per-node Ed25519 identities, in either pin-mode (self-signed
// leaves, pubkey-pinned) or CA-mode (chain-verified against a TrustConfig).
package quic

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync/atomic"
	"time"

	qgo "github.com/quic-go/quic-go"
	"golang.org/x/time/rate"
)

// Limiters carries the upload/download token-bucket limiters propagated
// to every Stream a Conn opens or accepts. nil on either side = no
// throttle.
type Limiters struct {
	Up   *rate.Limiter
	Down *rate.Limiter
}

// randReader is the package-level random source; tests swap it via white-box.
var randReader io.Reader = rand.Reader

// NextProtocol is the ALPN identifier negotiated for BackupSwarm peer connections.
const NextProtocol = "bsw/1"

// defaultKeepAlivePeriod is the PING interval on idle connections; ~1/3 of
// quic-go's 30s MaxIdleTimeout.
const defaultKeepAlivePeriod = 10 * time.Second

// MaxIncomingStreamsPerConn caps concurrent inbound bidirectional streams
// per peer connection.
const MaxIncomingStreamsPerConn int64 = 32

// disallowUniStreams disables unidirectional streams for quic-go (0 means
// default 100; negative disables).
const disallowUniStreams int64 = -1

// newQUICConfig returns the quic-go Config shared by Listen and Dial.
func newQUICConfig() *qgo.Config {
	return &qgo.Config{
		KeepAlivePeriod:       defaultKeepAlivePeriod,
		MaxIncomingStreams:    MaxIncomingStreamsPerConn,
		MaxIncomingUniStreams: disallowUniStreams,
	}
}

// ErrPeerPubkeyMismatch is returned when a dial pins an expected peer public
// key and the peer presents a certificate with a different one.
var ErrPeerPubkeyMismatch = errors.New("peer Ed25519 public key mismatch")

// ErrInvalidPeerCert is returned when the peer's TLS certificate is missing
// or its public key is not an Ed25519 key.
var ErrInvalidPeerCert = errors.New("peer TLS certificate not Ed25519")

// VerifyPeerFunc is called during the TLS handshake with the peer's verified
// Ed25519 pubkey. Non-nil error aborts the handshake. nil = accept any Ed25519
// peer.
type VerifyPeerFunc func(pub ed25519.PublicKey) error

// TrustConfig opts a Listener or Dialer into CA-mode mTLS: Cert is the
// wire leaf (CA-signed); Pool is the trust-root set the peer's leaf must
// chain to. Both fields must be set together; nil = pin-mode.
type TrustConfig struct {
	Cert *tls.Certificate
	Pool *x509.CertPool
}

// ErrInvalidTrustConfig is returned by Listen/Dial when a non-nil
// TrustConfig is missing Cert or Pool.
var ErrInvalidTrustConfig = errors.New("TrustConfig requires both Cert and Pool")

// Listener accepts inbound peer connections. The membership predicate is
// held behind an atomic so SetVerifyPeer can swap it race-free after bind.
type Listener struct {
	inner      *qgo.Listener
	tr         *qgo.Transport
	conn       net.PacketConn
	verifyPeer atomic.Pointer[VerifyPeerFunc]
	limiters   Limiters
}

// SetLimiters installs the rate limiters every Conn returned from a
// subsequent Accept inherits. nil fields = no throttle on that side.
func (l *Listener) SetLimiters(lim Limiters) { l.limiters = lim }

// Listen binds a QUIC listener on addr. nil trust = pin-mode (self-signed
// from priv); non-nil = CA-mode (trust.Cert as leaf, peer chain-verified
// against trust.Pool). verifyPeer gates by Ed25519 pubkey; nil = accept any.
func Listen(addr string, priv ed25519.PrivateKey, verifyPeer VerifyPeerFunc, trust *TrustConfig) (*Listener, error) {
	if err := validateTrust(trust); err != nil {
		return nil, err
	}
	cert, err := leafCert(priv, trust)
	if err != nil {
		return nil, fmt.Errorf("build server cert: %w", err)
	}
	l := &Listener{}
	l.SetVerifyPeer(verifyPeer)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if trust != nil {
				if err := verifyChain(rawCerts, trust.Pool); err != nil {
					return err
				}
			}
			pub, err := peerEd25519Pub(rawCerts)
			if err != nil {
				return err
			}
			if fn := l.verifyPeer.Load(); fn != nil && *fn != nil {
				return (*fn)(pub)
			}
			return nil
		},
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{NextProtocol},
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve udp %q: %w", addr, err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return nil, fmt.Errorf("listen udp %q: %w", addr, err)
	}
	tr := &qgo.Transport{Conn: udpConn}
	inner, err := tr.Listen(tlsConf, newQUICConfig())
	if err != nil {
		_ = udpConn.Close()
		return nil, fmt.Errorf("quic listen %q: %w", addr, err)
	}
	l.inner = inner
	l.tr = tr
	l.conn = udpConn
	return l, nil
}

// SetVerifyPeer swaps the membership predicate atomically. Subsequent
// handshakes use the new predicate; already-handshaked connections are
// unaffected.
func (l *Listener) SetVerifyPeer(fn VerifyPeerFunc) {
	l.verifyPeer.Store(&fn)
}

// Addr returns the local address the listener is bound to.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// PacketConn returns the underlying UDP socket. NAT-traversal callers
// reuse it to send raw datagrams from the same (ip,port) tuple the QUIC
// stack listens on, so a punch packet opens the same NAT mapping a
// subsequent QUIC Dial will traverse. Writes to the returned conn do not
// disturb the QUIC accept loop.
func (l *Listener) PacketConn() net.PacketConn { return l.conn }

// Accept blocks until a new peer connection is established or ctx is cancelled.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	qc, err := l.inner.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &Conn{inner: qc, remotePub: connRemotePub(qc), limiters: l.limiters}, nil
}

// Close shuts down the listener, tears down all accepted connections, and
// releases the UDP port.
func (l *Listener) Close() error {
	_ = l.tr.Close()
	return l.conn.Close()
}

// Dial opens an outbound QUIC connection to addr, pinning the peer's pubkey
// to expectedPeerPub. Non-nil trust = CA-mode (peer chain-verified against
// trust.Pool). Wraps ErrPeerPubkeyMismatch on identity mismatch.
func Dial(ctx context.Context, addr string, priv ed25519.PrivateKey, expectedPeerPub ed25519.PublicKey, trust *TrustConfig) (*Conn, error) {
	return DialOver(ctx, nil, addr, priv, expectedPeerPub, trust)
}

// DialOver opens an outbound QUIC connection through pc to addr. nil pc
// uses a fresh UDP socket; non-nil carries QUIC over the supplied
// transport (e.g. a TURN-allocated relay).
func DialOver(ctx context.Context, pc net.PacketConn, addr string, priv ed25519.PrivateKey, expectedPeerPub ed25519.PublicKey, trust *TrustConfig) (*Conn, error) {
	if err := validateTrust(trust); err != nil {
		return nil, err
	}
	cert, err := leafCert(priv, trust)
	if err != nil {
		return nil, fmt.Errorf("build client cert: %w", err)
	}
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if trust != nil {
				if err := verifyChain(rawCerts, trust.Pool); err != nil {
					return err
				}
			}
			pub, err := peerEd25519Pub(rawCerts)
			if err != nil {
				return err
			}
			if !pub.Equal(expectedPeerPub) {
				return fmt.Errorf("%w: got %s, want %s",
					ErrPeerPubkeyMismatch,
					hex.EncodeToString(pub),
					hex.EncodeToString(expectedPeerPub))
			}
			return nil
		},
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{NextProtocol},
	}
	var qc *qgo.Conn
	if pc == nil {
		qc, err = qgo.DialAddr(ctx, addr, tlsConf, newQUICConfig())
	} else {
		udpAddr, rerr := net.ResolveUDPAddr("udp", addr)
		if rerr != nil {
			return nil, fmt.Errorf("resolve udp %q: %w", addr, rerr)
		}
		tr := &qgo.Transport{Conn: pc}
		qc, err = tr.Dial(ctx, udpAddr, tlsConf, newQUICConfig())
	}
	if err != nil {
		return nil, fmt.Errorf("quic dial %q: %w", addr, err)
	}
	return &Conn{inner: qc, remotePub: connRemotePub(qc)}, nil
}

// ListenOver wraps an existing net.PacketConn (e.g. a TURN-allocated
// relay) as a QUIC Listener. Same TLS configuration as Listen; the
// returned Listener's Close also closes pc.
func ListenOver(pc net.PacketConn, priv ed25519.PrivateKey, verifyPeer VerifyPeerFunc, trust *TrustConfig) (*Listener, error) {
	if err := validateTrust(trust); err != nil {
		return nil, err
	}
	cert, err := leafCert(priv, trust)
	if err != nil {
		return nil, fmt.Errorf("build server cert: %w", err)
	}
	l := &Listener{}
	l.SetVerifyPeer(verifyPeer)
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if trust != nil {
				if err := verifyChain(rawCerts, trust.Pool); err != nil {
					return err
				}
			}
			pub, err := peerEd25519Pub(rawCerts)
			if err != nil {
				return err
			}
			if fn := l.verifyPeer.Load(); fn != nil && *fn != nil {
				return (*fn)(pub)
			}
			return nil
		},
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{NextProtocol},
	}
	tr := &qgo.Transport{Conn: pc}
	inner, err := tr.Listen(tlsConf, newQUICConfig())
	if err != nil {
		return nil, fmt.Errorf("quic listen over packet conn: %w", err)
	}
	l.inner = inner
	l.tr = tr
	l.conn = pc
	return l, nil
}

// Conn is a QUIC connection to a single peer with a verified Ed25519 identity.
type Conn struct {
	inner     *qgo.Conn
	remotePub ed25519.PublicKey
	limiters  Limiters
}

// RemotePub returns the verified Ed25519 public key of the remote peer.
func (c *Conn) RemotePub() ed25519.PublicKey { return c.remotePub }

// SetLimiters swaps the rate limiters this Conn applies to subsequently
// opened or accepted Streams. Already-returned Streams keep their original
// limiters.
func (c *Conn) SetLimiters(lim Limiters) { c.limiters = lim }

// OpenStream opens a new bidirectional stream initiated by this side.
// The returned Stream inherits the Conn's limiters.
func (c *Conn) OpenStream(ctx context.Context) (*Stream, error) {
	qs, err := c.inner.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return c.wrapStream(qs), nil
}

// AcceptStream blocks until the peer opens a new bidirectional stream.
// The returned Stream inherits the Conn's limiters.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	qs, err := c.inner.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return c.wrapStream(qs), nil
}

func (c *Conn) wrapStream(qs *qgo.Stream) *Stream {
	return &Stream{
		Stream: qs,
		up:     c.limiters.Up,
		down:   c.limiters.Down,
		ctx:    qs.Context(),
	}
}

// Close terminates the connection.
func (c *Conn) Close() error {
	return c.inner.CloseWithError(0, "")
}

// connRemotePub extracts the peer's Ed25519 pubkey from the negotiated TLS
// state. Caller must ensure the handshake has completed.
func connRemotePub(qc *qgo.Conn) ed25519.PublicKey {
	return qc.ConnectionState().TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
}

// peerEd25519Pub parses the leaf cert from a raw TLS chain and returns its
// Ed25519 public key.
func peerEd25519Pub(rawCerts [][]byte) (ed25519.PublicKey, error) {
	if len(rawCerts) == 0 {
		return nil, ErrInvalidPeerCert
	}
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return nil, fmt.Errorf("parse peer cert: %w", err)
	}
	return ed25519FromCerts([]*x509.Certificate{cert})
}

// ed25519FromCerts returns the Ed25519 public key from the leaf cert in
// chain or ErrInvalidPeerCert if the chain is empty or the leaf key is not
// Ed25519.
func ed25519FromCerts(chain []*x509.Certificate) (ed25519.PublicKey, error) {
	if len(chain) == 0 {
		return nil, ErrInvalidPeerCert
	}
	pub, ok := chain[0].PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, ErrInvalidPeerCert
	}
	return pub, nil
}

// validateTrust requires both Cert and Pool when trust is non-nil.
func validateTrust(t *TrustConfig) error {
	if t == nil {
		return nil
	}
	if t.Cert == nil || t.Pool == nil {
		return ErrInvalidTrustConfig
	}
	return nil
}

// leafCert returns the TLS leaf to present on the wire (CA-mode → caller
// cert, pin-mode → self-signed from priv).
func leafCert(priv ed25519.PrivateKey, trust *TrustConfig) (tls.Certificate, error) {
	if trust != nil {
		return *trust.Cert, nil
	}
	return newSelfSignedCert(priv)
}

// verifyChain checks the leaf in rawCerts chains to pool, without the
// hostname check the stdlib path entails.
func verifyChain(rawCerts [][]byte, pool *x509.CertPool) error {
	if len(rawCerts) == 0 {
		return ErrInvalidPeerCert
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("parse peer leaf: %w", err)
	}
	intermediates := x509.NewCertPool()
	for _, der := range rawCerts[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return fmt.Errorf("parse peer intermediate: %w", err)
		}
		intermediates.AddCert(cert)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         pool,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}); err != nil {
		return fmt.Errorf("chain verify: %w", err)
	}
	return nil
}

// newSelfSignedCert builds a self-signed X.509 cert whose key is priv's
// Ed25519 identity.
func newSelfSignedCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	pub := priv.Public().(ed25519.PublicKey)
	serial, err := rand.Int(randReader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "backupswarm-" + hex.EncodeToString(pub[:8]),
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(100 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(randReader, template, template, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}
