package backup_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"backupswarm/internal/backup"
	bsquic "backupswarm/internal/quic"
)

// TestSendPutGetIndexSnapshot_RoundTrip exercises the index-snapshot
// upload/download wrappers end-to-end against a real QUIC peer.
func TestSendPutGetIndexSnapshot_RoundTrip(t *testing.T) {
	rig := newTestRig(t)
	blob := []byte("encrypted index snapshot blob")

	if err := backup.SendPutIndexSnapshot(context.Background(), rig.ownerConn, blob); err != nil {
		t.Fatalf("SendPutIndexSnapshot: %v", err)
	}
	got, err := backup.SendGetIndexSnapshot(context.Background(), rig.ownerConn)
	if err != nil {
		t.Fatalf("SendGetIndexSnapshot: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Errorf("blob mismatch: got %q, want %q", got, blob)
	}

	// Verify the peer-side store has the snapshot recorded under owner.
	got2, err := rig.peerStore.GetIndexSnapshot(rig.ownerPubKey)
	if err != nil {
		t.Fatalf("peerStore.GetIndexSnapshot: %v", err)
	}
	if !bytes.Equal(got2, blob) {
		t.Errorf("peer-side snapshot mismatch")
	}
}

// TestSendGetIndexSnapshot_NotFound asserts Get returns the "not_found"
// peer error when no snapshot is stored for the conn's owner pubkey.
func TestSendGetIndexSnapshot_NotFound(t *testing.T) {
	rig := newTestRig(t)
	_, err := backup.SendGetIndexSnapshot(context.Background(), rig.ownerConn)
	if err == nil {
		t.Fatal("SendGetIndexSnapshot returned nil for missing snapshot")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("not_found")) {
		t.Errorf("err = %q, want 'not_found' mention", err)
	}
}

// TestSendPutIndexSnapshot_ReplacesPrevious asserts a second put for
// the same owner replaces the first.
func TestSendPutIndexSnapshot_ReplacesPrevious(t *testing.T) {
	rig := newTestRig(t)
	if err := backup.SendPutIndexSnapshot(context.Background(), rig.ownerConn, []byte("first")); err != nil {
		t.Fatalf("PutIndexSnapshot first: %v", err)
	}
	if err := backup.SendPutIndexSnapshot(context.Background(), rig.ownerConn, []byte("second")); err != nil {
		t.Fatalf("PutIndexSnapshot second: %v", err)
	}
	got, err := backup.SendGetIndexSnapshot(context.Background(), rig.ownerConn)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if string(got) != "second" {
		t.Errorf("Get = %q, want %q", got, "second")
	}
}

// TestSendGetIndexSnapshot_OwnerIsolation asserts that one owner's
// snapshot is not readable by a different owner connecting to the same
// peer — the dispatch keys on TLS-authenticated pubkey, not request body.
func TestSendGetIndexSnapshot_OwnerIsolation(t *testing.T) {
	rig := newTestRig(t)
	// Owner A puts its snapshot.
	if err := backup.SendPutIndexSnapshot(context.Background(), rig.ownerConn, []byte("alice")); err != nil {
		t.Fatalf("PutIndexSnapshot owner A: %v", err)
	}

	// Owner B (a separate keypair) opens its own conn and asks for ITS
	// snapshot — should be not_found, not Alice's.
	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("gen other key: %v", err)
	}
	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	otherConn, err := bsquic.Dial(dialCtx, rig.listenerAddr, otherPriv, rig.peerPubKey, nil)
	if err != nil {
		t.Fatalf("Dial other: %v", err)
	}
	t.Cleanup(func() { _ = otherConn.Close() })

	_, err = backup.SendGetIndexSnapshot(context.Background(), otherConn)
	if err == nil {
		t.Fatal("SendGetIndexSnapshot for other owner returned no error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("not_found")) {
		t.Errorf("err = %q, want 'not_found' mention", err)
	}
}

// TestSendPutIndexSnapshot_RejectsEmpty asserts the owner-side wrapper
// refuses an empty blob without opening a stream.
func TestSendPutIndexSnapshot_RejectsEmpty(t *testing.T) {
	rig := newTestRig(t)
	if err := backup.SendPutIndexSnapshot(context.Background(), rig.ownerConn, nil); err == nil {
		t.Error("nil blob accepted")
	}
	if err := backup.SendPutIndexSnapshot(context.Background(), rig.ownerConn, []byte{}); err == nil {
		t.Error("empty blob accepted")
	}
}
