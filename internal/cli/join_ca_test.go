package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"io"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"backupswarm/internal/ca"
	"backupswarm/internal/node"
)

// TestJoinCmd_CAModePersistsSignedLeafCert runs a default invite+join
// and asserts the joiner's node.crt chains to the inviter's swarm CA
// and binds to the joiner's identity pubkey.
func TestJoinCmd_CAModePersistsSignedLeafCert(t *testing.T) {
	dataInviter := filepath.Join(t.TempDir(), "inviter")
	dataJoiner := filepath.Join(t.TempDir(), "joiner")

	overallCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inviteOut := &syncBuffer{}
	inviterCmd := NewRootCmd()
	inviterCmd.SetOut(inviteOut)
	inviterCmd.SetErr(io.Discard)
	inviterCmd.SetArgs([]string{
		"--data-dir", dataInviter,
		"run",
		"--listen", "127.0.0.1:0",
		"--invite",
	})

	inviterCtx, inviterCancel := context.WithCancel(overallCtx)
	defer inviterCancel()
	var wg sync.WaitGroup
	var inviteErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		inviteErr = inviterCmd.ExecuteContext(inviterCtx)
	}()
	tokStr := waitForToken(t, inviteOut, 5*time.Second)

	joinCmd := NewRootCmd()
	joinCmd.SetOut(io.Discard)
	joinCmd.SetErr(io.Discard)
	joinCmd.SetArgs([]string{"--data-dir", dataJoiner, "join", tokStr})
	if err := joinCmd.ExecuteContext(overallCtx); err != nil {
		t.Fatalf("join: %v", err)
	}
	inviterCancel()
	wg.Wait()
	if inviteErr != nil && inviteErr != context.Canceled {
		t.Fatalf("inviter returned error: %v", inviteErr)
	}

	leafDER, err := ca.LoadNodeCert(dataJoiner)
	if err != nil {
		t.Fatalf("LoadNodeCert: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	swarmCA, err := ca.Load(dataInviter)
	if err != nil {
		t.Fatalf("load inviter CA: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(swarmCA.Cert)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("persisted leaf does not chain to swarm CA: %v", err)
	}
	joinerID, err := node.Load(dataJoiner)
	if err != nil {
		t.Fatalf("node.Load joiner: %v", err)
	}
	leafPub, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("leaf public key type %T", leaf.PublicKey)
	}
	if !leafPub.Equal(joinerID.PublicKey) {
		t.Error("persisted leaf does not bind to joiner identity pubkey")
	}
}

// TestJoinCmd_PinModeDoesNotPersistCert asserts a --no-ca invite + join
// writes no node.crt on the joiner.
func TestJoinCmd_PinModeDoesNotPersistCert(t *testing.T) {
	dataInviter := filepath.Join(t.TempDir(), "inviter")
	dataJoiner := filepath.Join(t.TempDir(), "joiner")

	overallCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	inviteOut := &syncBuffer{}
	inviterCmd := NewRootCmd()
	inviterCmd.SetOut(inviteOut)
	inviterCmd.SetErr(io.Discard)
	inviterCmd.SetArgs([]string{
		"--data-dir", dataInviter,
		"run",
		"--listen", "127.0.0.1:0",
		"--invite",
		"--no-ca",
	})

	inviterCtx, inviterCancel := context.WithCancel(overallCtx)
	defer inviterCancel()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = inviterCmd.ExecuteContext(inviterCtx)
	}()
	tokStr := waitForToken(t, inviteOut, 5*time.Second)

	joinCmd := NewRootCmd()
	joinCmd.SetOut(io.Discard)
	joinCmd.SetErr(io.Discard)
	joinCmd.SetArgs([]string{"--data-dir", dataJoiner, "join", tokStr})
	if err := joinCmd.ExecuteContext(overallCtx); err != nil {
		t.Fatalf("join: %v", err)
	}
	inviterCancel()
	wg.Wait()

	if _, err := ca.LoadNodeCert(dataJoiner); err == nil {
		t.Error("pin-mode join wrote node.crt; want none")
	}
}
