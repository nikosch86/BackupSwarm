// Package quic implements the peer transport over QUIC with mutual TLS
// keyed by per-node Ed25519 identities. Each node presents a self-signed
// cert whose public key is its identity; outbound dials pin the expected
// pubkey. No CA — the pubkey is the identity.
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
	"time"

	qgo "github.com/quic-go/quic-go"
)

// randReader is the source of randomness used by this package. It is a
// package-level seam so white-box tests can substitute a failing reader to
// exercise rng-error branches; production code never reassigns it.
var randReader io.Reader = rand.Reader

// NextProtocol is the ALPN identifier negotiated for BackupSwarm peer connections.
const NextProtocol = "bsw/1"

// defaultKeepAlivePeriod is the interval at which idle connections send
// PING frames to keep NAT/firewall state and avoid quic-go's default
// 30s MaxIdleTimeout tearing down a connection between scan passes.
// 10s is well under 1/3 of the idle timeout — the common rule of thumb
// so a single lost PING doesn't cascade into a close.
const defaultKeepAlivePeriod = 10 * time.Second

// newQUICConfig returns the quic-go Config used by both Listen and
// Dial. Factored out so white-box tests can assert the invariants
// (keep-alive enabled, etc.) on a single source of truth.
func newQUICConfig() *qgo.Config {
	return &qgo.Config{
		KeepAlivePeriod: defaultKeepAlivePeriod,
	}
}

// ErrPeerPubkeyMismatch is returned when a dial pins an expected peer public
// key and the peer presents a certificate with a different one.
var ErrPeerPubkeyMismatch = errors.New("peer Ed25519 public key mismatch")

// ErrInvalidPeerCert is returned when the peer's TLS certificate is missing
// or its public key is not an Ed25519 key.
var ErrInvalidPeerCert = errors.New("peer TLS certificate not Ed25519")

// Listener accepts inbound peer connections.
type Listener struct {
	inner *qgo.Listener
	tr    *qgo.Transport
	conn  *net.UDPConn
}

// Listen starts a QUIC listener on addr (e.g. "127.0.0.1:0", ":7777"),
// presenting a TLS certificate signed by priv.
func Listen(addr string, priv ed25519.PrivateKey) (*Listener, error) {
	cert, err := newSelfSignedCert(priv)
	if err != nil {
		return nil, fmt.Errorf("build server cert: %w", err)
	}
	tlsConf := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAnyClientCert,
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			_, err := peerEd25519Pub(rawCerts)
			return err
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
	return &Listener{inner: inner, tr: tr, conn: udpConn}, nil
}

// Addr returns the local address the listener is bound to.
func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

// Accept blocks until a new peer connection is established or ctx is cancelled.
//
// VerifyPeerCertificate has already validated the leaf is an Ed25519 cert by
// the time the handshake completes, so the Conn's RemotePub is safe to read
// without re-checking.
func (l *Listener) Accept(ctx context.Context) (*Conn, error) {
	qc, err := l.inner.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &Conn{inner: qc, remotePub: connRemotePub(qc)}, nil
}

// Close shuts down the listener, tears down all accepted connections, and
// releases the UDP port.
func (l *Listener) Close() error {
	_ = l.tr.Close()
	return l.conn.Close()
}

// Dial opens an outbound QUIC connection to addr authenticated as priv,
// pinning the peer's Ed25519 public key to expectedPeerPub. The dial fails
// with an error wrapping ErrPeerPubkeyMismatch if the peer presents any
// other identity.
func Dial(ctx context.Context, addr string, priv ed25519.PrivateKey, expectedPeerPub ed25519.PublicKey) (*Conn, error) {
	cert, err := newSelfSignedCert(priv)
	if err != nil {
		return nil, fmt.Errorf("build client cert: %w", err)
	}
	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // chain verification disabled; we pin the Ed25519 pubkey ourselves
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
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
	qc, err := qgo.DialAddr(ctx, addr, tlsConf, newQUICConfig())
	if err != nil {
		return nil, fmt.Errorf("quic dial %q: %w", addr, err)
	}
	// VerifyPeerCertificate has already validated both the Ed25519 key
	// type and the pin, so we can safely extract the pubkey from the
	// negotiated state without re-checking.
	return &Conn{inner: qc, remotePub: connRemotePub(qc)}, nil
}

// Conn is a QUIC connection to a single peer with a verified Ed25519 identity.
type Conn struct {
	inner     *qgo.Conn
	remotePub ed25519.PublicKey
}

// RemotePub returns the verified Ed25519 public key of the remote peer.
func (c *Conn) RemotePub() ed25519.PublicKey { return c.remotePub }

// OpenStream opens a new bidirectional stream initiated by this side.
func (c *Conn) OpenStream(ctx context.Context) (*qgo.Stream, error) {
	return c.inner.OpenStreamSync(ctx)
}

// AcceptStream blocks until the peer opens a new bidirectional stream.
func (c *Conn) AcceptStream(ctx context.Context) (*qgo.Stream, error) {
	return c.inner.AcceptStream(ctx)
}

// Close terminates the connection.
func (c *Conn) Close() error {
	return c.inner.CloseWithError(0, "")
}

// connRemotePub extracts the peer's Ed25519 pubkey from the negotiated TLS
// state. Only safe to call after a successful handshake — VerifyPeerCertificate
// guarantees the leaf is a valid Ed25519 cert by the time we reach here.
func connRemotePub(qc *qgo.Conn) ed25519.PublicKey {
	return qc.ConnectionState().TLS.PeerCertificates[0].PublicKey.(ed25519.PublicKey)
}

// peerEd25519Pub parses the leaf cert from a raw TLS chain and returns its
// Ed25519 public key. Used inside VerifyPeerCertificate where the parsed
// chain isn't yet available.
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

// newSelfSignedCert builds a self-signed X.509 cert whose key is priv's
// Ed25519 identity. The cert's subject CN is informational only — peer
// authentication is by Ed25519 public key, not by name.
func newSelfSignedCert(priv ed25519.PrivateKey) (tls.Certificate, error) {
	pub := priv.Public().(ed25519.PublicKey)
	// rand.Int draws bytes from randReader; the swappable seam lets tests
	// exercise the error path without faking the stdlib.
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
	// x509.CreateCertificate's rand parameter is unused with Ed25519
	// signing (deterministic) and a pre-supplied SerialNumber, so passing
	// randReader vs rand.Reader has no observable effect — but we pass the
	// seam for consistency.
	der, err := x509.CreateCertificate(randReader, template, template, pub, priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create cert: %w", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}, nil
}
