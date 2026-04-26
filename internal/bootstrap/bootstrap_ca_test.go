package bootstrap_test

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/bootstrap"
	"backupswarm/internal/ca"
	"backupswarm/pkg/token"
)

// caRig is a twoSides rig augmented with a swarm CA. tokenStrCA encodes
// the rig's CA cert into the invite token so DoJoin enters CA-mode.
type caRig struct {
	*twoSides
	swarmCA *ca.CA
}

func setupCARig(t *testing.T) *caRig {
	t.Helper()
	rig := setupTwoSides(t)
	swarmCA, err := ca.Generate()
	if err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	return &caRig{twoSides: rig, swarmCA: swarmCA}
}

func (r *caRig) tokenStrCA(t *testing.T) string {
	t.Helper()
	tok, err := token.Encode(token.Token{
		Addr:    r.listener.Addr().String(),
		Pub:     r.introducerPub,
		SwarmID: r.swarmID,
		Secret:  r.secret,
		CACert:  r.swarmCA.CertDER,
	})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}
	return tok
}

// TestBootstrap_CAMode_SignsAndReturnsLeaf is the happy-path E2E for
// CA-mode: joiner sends CSR, introducer signs it, joiner receives a leaf
// that chains to the swarm CA and binds to the joiner's pubkey.
func TestBootstrap_CAMode_SignsAndReturnsLeaf(t *testing.T) {
	rig := setupCARig(t)
	tok := rig.tokenStrCA(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), rig.swarmCA)
	}()

	result, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	if err != nil {
		t.Fatalf("DoJoin: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptJoin: %v", acceptErr)
	}

	if len(result.SignedCert) == 0 {
		t.Fatal("DoJoin returned empty SignedCert in CA-mode")
	}
	leaf, err := x509.ParseCertificate(result.SignedCert)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(rig.swarmCA.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("leaf does not chain to CA: %v", err)
	}
	leafPub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("leaf public key type %T", leaf.PublicKey)
	}
	if !leafPub.Equal(rig.joinerPub) {
		t.Error("leaf public key does not match joiner pubkey")
	}
}

// TestBootstrap_PinMode_NoCertReturned asserts a token without a CA cert
// produces no signed leaf, regardless of whether AcceptJoin has a CA.
func TestBootstrap_PinMode_NoCertReturned(t *testing.T) {
	rig := setupTwoSides(t)
	tok := rig.tokenStr(t, rig.listener.Addr().String(), rig.introducerPub)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), nil)
	}()

	result, err := bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	if err != nil {
		t.Fatalf("DoJoin: %v", err)
	}
	wg.Wait()
	if acceptErr != nil {
		t.Fatalf("AcceptJoin: %v", acceptErr)
	}
	if len(result.SignedCert) != 0 {
		t.Errorf("pin-mode SignedCert = %d bytes, want 0", len(result.SignedCert))
	}
}

// TestBootstrap_CAMode_RejectsTokenWithoutCSR feeds a CA-equipped accept
// loop a CA-mode token but a joiner that swaps in a pin-mode wire flow
// (no CSR in request). The joiner-side bug must be caught and reported.
func TestBootstrap_CAMode_RejectsTokenWithoutCSR(t *testing.T) {
	rig := setupCARig(t)
	// Strip the CACert from the token so DoJoin skips CSR generation,
	// but AcceptJoin still has the CA: server expects a CSR, gets none.
	tok, err := token.Encode(token.Token{
		Addr:    rig.listener.Addr().String(),
		Pub:     rig.introducerPub,
		SwarmID: rig.swarmID,
		Secret:  rig.secret,
		// CACert omitted → joiner sends no CSR
	})
	if err != nil {
		t.Fatalf("token.Encode: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	var acceptErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, acceptErr = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), rig.swarmCA)
	}()

	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	wg.Wait()
	if acceptErr == nil {
		t.Fatal("AcceptJoin returned nil despite CA-mode swarm with no CSR")
	}
	if err == nil {
		t.Fatal("DoJoin returned nil despite introducer rejection")
	}
	if !errors.Is(err, bootstrap.ErrIntroducerInternal) {
		t.Errorf("DoJoin err = %v, want ErrIntroducerInternal", err)
	}
}

// TestBootstrap_CAMode_RejectsForgedLeaf asserts the joiner discards a
// signed cert that does not chain to the CA cert in its token. Crafted
// by spinning up a second CA and having the introducer sign with that
// instead.
func TestBootstrap_CAMode_RejectsForgedLeaf(t *testing.T) {
	rig := setupCARig(t)
	// The token claims rig.swarmCA, but AcceptJoin signs with otherCA.
	otherCA, err := ca.Generate()
	if err != nil {
		t.Fatalf("other ca: %v", err)
	}
	tok := rig.tokenStrCA(t)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = bootstrap.AcceptJoin(ctx, rig.listener, rig.introducerPeerList, rig.validator(), otherCA)
	}()

	_, err = bootstrap.DoJoin(ctx, tok, rig.joinerPriv, "192.0.2.1:9000", rig.joinerPeerList)
	wg.Wait()
	if err == nil {
		t.Fatal("DoJoin accepted a leaf that does not chain to the token's CA")
	}
	list, _ := rig.joinerPeerList.List()
	if len(list) != 0 {
		t.Errorf("joiner peer list mutated after forged-leaf rejection: %d entries", len(list))
	}
}
