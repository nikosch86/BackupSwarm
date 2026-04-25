package quic

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

// withRandReader swaps the package-level randReader for the duration of a test.
func withRandReader(t *testing.T, r io.Reader) {
	t.Helper()
	prev := randReader
	randReader = r
	t.Cleanup(func() { randReader = prev })
}

// TestDefaultQUICConfig_EnablesKeepAlive asserts the shared quic-go Config has a non-zero KeepAlivePeriod under 20s.
func TestDefaultQUICConfig_EnablesKeepAlive(t *testing.T) {
	cfg := newQUICConfig()
	if cfg.KeepAlivePeriod == 0 {
		t.Error("quic Config KeepAlivePeriod = 0; connections will time out on idle scan intervals")
	}
	if cfg.KeepAlivePeriod > 20*1_000_000_000 {
		t.Errorf("KeepAlivePeriod = %v is too close to MaxIdleTimeout; need 1/3 or less", cfg.KeepAlivePeriod)
	}
}

func newTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	return priv
}

func TestEd25519FromCerts_EmptyChain(t *testing.T) {
	t.Parallel()
	if _, err := ed25519FromCerts(nil); !errors.Is(err, ErrInvalidPeerCert) {
		t.Fatalf("want ErrInvalidPeerCert for empty chain, got %v", err)
	}
}

func TestEd25519FromCerts_NonEd25519Key(t *testing.T) {
	t.Parallel()
	cert := &x509.Certificate{PublicKey: "not-a-key"}
	if _, err := ed25519FromCerts([]*x509.Certificate{cert}); !errors.Is(err, ErrInvalidPeerCert) {
		t.Fatalf("want ErrInvalidPeerCert for non-Ed25519 leaf, got %v", err)
	}
}

func TestPeerEd25519Pub_EmptyRawCerts(t *testing.T) {
	t.Parallel()
	if _, err := peerEd25519Pub(nil); !errors.Is(err, ErrInvalidPeerCert) {
		t.Fatalf("want ErrInvalidPeerCert, got %v", err)
	}
}

func TestPeerEd25519Pub_BadDER(t *testing.T) {
	t.Parallel()
	_, err := peerEd25519Pub([][]byte{{0x00, 0x01, 0x02, 0x03}})
	if err == nil {
		t.Fatalf("want parse error, got nil")
	}
	if errors.Is(err, ErrInvalidPeerCert) {
		t.Fatalf("did not expect ErrInvalidPeerCert for bad DER, got %v", err)
	}
}

// TestNewSelfSignedCert_SerialRandFailure asserts newSelfSignedCert wraps a rand.Int failure as a "serial" error.
func TestNewSelfSignedCert_SerialRandFailure(t *testing.T) {
	priv := newTestKey(t)
	withRandReader(t, iotest.ErrReader(errors.New("forced rng failure")))

	if _, err := newSelfSignedCert(priv); err == nil {
		t.Fatal("expected error when rand source fails for serial generation")
	}
}

// TestListen_CertBuildFailure asserts Listen returns an error when cert generation fails.
func TestListen_CertBuildFailure(t *testing.T) {
	priv := newTestKey(t)
	withRandReader(t, iotest.ErrReader(errors.New("forced rng failure")))

	if _, err := Listen("127.0.0.1:0", priv); err == nil {
		t.Fatal("expected Listen to fail when cert build fails")
	}
}

// TestDial_CertBuildFailure asserts Dial returns an error when cert generation fails.
func TestDial_CertBuildFailure(t *testing.T) {
	priv := newTestKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	withRandReader(t, iotest.ErrReader(errors.New("forced rng failure")))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Dial(ctx, "127.0.0.1:1", priv, pub); err == nil {
		t.Fatal("expected Dial to fail when cert build fails")
	}
}
