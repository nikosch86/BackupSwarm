package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"backupswarm/internal/backup"
	"backupswarm/internal/crypto"
	"backupswarm/internal/index"
	"backupswarm/internal/node"
	"backupswarm/internal/peers"
	bsquic "backupswarm/internal/quic"
	"backupswarm/internal/store"
)

// withFetchSnapshotFunc swaps fetchSnapshotFunc for the duration of a test.
func withFetchSnapshotFunc(t *testing.T, fn func(context.Context, *bsquic.Conn) ([]byte, error)) {
	t.Helper()
	prev := fetchSnapshotFunc
	fetchSnapshotFunc = fn
	t.Cleanup(func() { fetchSnapshotFunc = prev })
}

// TestFetchAnyIndexSnapshot_NoConns asserts an empty conn list yields the
// errNoSnapshotAvailable sentinel.
func TestFetchAnyIndexSnapshot_NoConns(t *testing.T) {
	_, err := fetchAnyIndexSnapshot(context.Background(), nil)
	if !errors.Is(err, errNoSnapshotAvailable) {
		t.Errorf("err = %v, want errNoSnapshotAvailable", err)
	}
}

// TestFetchAnyIndexSnapshot_AllConnsFail asserts every-conn-fails surfaces
// errNoSnapshotAvailable wrapping the last per-peer error.
func TestFetchAnyIndexSnapshot_AllConnsFail(t *testing.T) {
	withFetchSnapshotFunc(t, func(context.Context, *bsquic.Conn) ([]byte, error) {
		return nil, errors.New("simulated peer fail")
	})
	_, err := fetchAnyIndexSnapshot(context.Background(), []*bsquic.Conn{nil, nil})
	if !errors.Is(err, errNoSnapshotAvailable) {
		t.Errorf("err = %v, want errNoSnapshotAvailable", err)
	}
	if !strings.Contains(err.Error(), "simulated peer fail") {
		t.Errorf("err = %v, want last per-peer error included", err)
	}
}

// TestFetchAnyIndexSnapshot_EmptyBlobThenSuccess asserts an empty-blob
// response is treated as a per-peer failure and a later success wins.
func TestFetchAnyIndexSnapshot_EmptyBlobThenSuccess(t *testing.T) {
	var calls atomic.Int32
	withFetchSnapshotFunc(t, func(context.Context, *bsquic.Conn) ([]byte, error) {
		n := calls.Add(1)
		if n == 1 {
			return nil, nil
		}
		return []byte("payload"), nil
	})
	got, err := fetchAnyIndexSnapshot(context.Background(), []*bsquic.Conn{nil, nil})
	if err != nil {
		t.Fatalf("fetchAnyIndexSnapshot: %v", err)
	}
	if !bytes.Equal(got, []byte("payload")) {
		t.Errorf("blob = %q, want 'payload'", got)
	}
}

// TestFetchAnyIndexSnapshot_AllEmptyBlobs asserts an all-empty-blob run
// surfaces errNoSnapshotAvailable wrapping the empty-blob note.
func TestFetchAnyIndexSnapshot_AllEmptyBlobs(t *testing.T) {
	withFetchSnapshotFunc(t, func(context.Context, *bsquic.Conn) ([]byte, error) {
		return nil, nil
	})
	_, err := fetchAnyIndexSnapshot(context.Background(), []*bsquic.Conn{nil})
	if !errors.Is(err, errNoSnapshotAvailable) {
		t.Errorf("err = %v, want errNoSnapshotAvailable", err)
	}
	if !strings.Contains(err.Error(), "empty snapshot blob") {
		t.Errorf("err = %v, want 'empty snapshot blob' wrap", err)
	}
}

// TestDecodeSnapshotBlob_GarbageInput asserts a non-EncryptedChunk blob
// surfaces an unmarshal error.
func TestDecodeSnapshotBlob_GarbageInput(t *testing.T) {
	pub, priv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	_, err = decodeSnapshotBlob([]byte("not an encrypted chunk"), pub, priv)
	if err == nil {
		t.Fatal("decodeSnapshotBlob accepted garbage input")
	}
	if !strings.Contains(err.Error(), "unmarshal encrypted chunk") {
		t.Errorf("err = %v, want 'unmarshal encrypted chunk' wrap", err)
	}
}

// TestDecodeSnapshotBlob_WrongRecipientKey asserts a chunk encrypted to a
// different recipient key fails the Decrypt step.
func TestDecodeSnapshotBlob_WrongRecipientKey(t *testing.T) {
	encryptPub, _, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	otherPub, otherPriv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	plain, err := index.MarshalSnapshot([]index.FileEntry{{Path: "a.bin", Size: 1}})
	if err != nil {
		t.Fatalf("MarshalSnapshot: %v", err)
	}
	ec, err := crypto.Encrypt(plain, encryptPub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	blob, err := ec.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	_, err = decodeSnapshotBlob(blob, otherPub, otherPriv)
	if err == nil {
		t.Fatal("decodeSnapshotBlob accepted wrong-key blob")
	}
	if !strings.Contains(err.Error(), "decrypt") {
		t.Errorf("err = %v, want 'decrypt' wrap", err)
	}
}

// TestDecodeSnapshotBlob_GarbagePlaintext asserts a chunk whose plaintext
// is not a snapshot wire frame fails the unmarshal-snapshot step.
func TestDecodeSnapshotBlob_GarbagePlaintext(t *testing.T) {
	pub, priv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	ec, err := crypto.Encrypt([]byte{0xff, 0x00, 0x01}, pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	blob, err := ec.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	_, err = decodeSnapshotBlob(blob, pub, priv)
	if err == nil {
		t.Fatal("decodeSnapshotBlob accepted garbage plaintext")
	}
	if !strings.Contains(err.Error(), "unmarshal snapshot") {
		t.Errorf("err = %v, want 'unmarshal snapshot' wrap", err)
	}
}

// restoreIndexCmdRig brings up a listener and seeds a peers.db plus
// node identity files, returning the data-dir ready for restore-index.
type restoreIndexCmdRig struct {
	dataDir string
	cancel  context.CancelFunc
}

func newRestoreIndexCmdRig(t *testing.T) *restoreIndexCmdRig {
	t.Helper()
	dataDir := t.TempDir()

	peerStoreDir := filepath.Join(t.TempDir(), "chunks")
	peerStore, err := store.New(peerStoreDir)
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(func() { _ = peerStore.Close() })

	peerPub, peerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("peer key: %v", err)
	}
	listener, err := bsquic.Listen("127.0.0.1:0", peerPriv, nil, nil)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
	})
	go func() { _ = backup.Serve(ctx, listener, peerStore, nil, nil, nil) }()

	if _, _, err := node.Ensure(dataDir); err != nil {
		t.Fatalf("node.Ensure: %v", err)
	}
	if _, _, err := node.EnsureRecipient(dataDir); err != nil {
		t.Fatalf("EnsureRecipient: %v", err)
	}
	ps, err := peers.Open(filepath.Join(dataDir, "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: listener.Addr().String(), PubKey: peerPub, Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("peers.Add: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("peers.Close: %v", err)
	}
	return &restoreIndexCmdRig{dataDir: dataDir, cancel: cancel}
}

// TestRestoreIndexCmd_FetchError asserts a fetchSnapshotFunc failure
// surfaces as the restore-index command's exit error.
func TestRestoreIndexCmd_FetchError(t *testing.T) {
	rig := newRestoreIndexCmdRig(t)
	withFetchSnapshotFunc(t, func(context.Context, *bsquic.Conn) ([]byte, error) {
		return nil, errors.New("simulated fetch fail")
	})

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", rig.dataDir, "restore-index"})
	if err := root.Execute(); err == nil {
		t.Error("restore-index returned nil despite injected fetch error")
	}
}

// TestRestoreIndexCmd_DecodeError asserts a malformed blob from the peer
// surfaces as a "decode snapshot" error from the restore-index command.
func TestRestoreIndexCmd_DecodeError(t *testing.T) {
	rig := newRestoreIndexCmdRig(t)
	withFetchSnapshotFunc(t, func(context.Context, *bsquic.Conn) ([]byte, error) {
		return []byte("garbage that is not an EncryptedChunk"), nil
	})

	root := NewRootCmd()
	out := &bytes.Buffer{}
	root.SetOut(out)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", rig.dataDir, "restore-index"})
	err := root.Execute()
	if err == nil {
		t.Fatal("restore-index returned nil despite garbage blob")
	}
	if !strings.Contains(err.Error(), "decode snapshot") {
		t.Errorf("err = %v, want 'decode snapshot' wrap", err)
	}
}

// TestRestoreIndexCmd_IndexOpenError asserts a blocked index.db path
// surfaces an "open index" error from the restore-index command.
func TestRestoreIndexCmd_IndexOpenError(t *testing.T) {
	rig := newRestoreIndexCmdRig(t)
	if err := os.Mkdir(filepath.Join(rig.dataDir, "index.db"), 0o700); err != nil {
		t.Fatalf("mkdir squatter: %v", err)
	}

	pub, priv, err := crypto.GenerateRecipientKey()
	if err != nil {
		t.Fatalf("GenerateRecipientKey: %v", err)
	}
	plain, err := index.MarshalSnapshot([]index.FileEntry{{Path: "a.bin", Size: 1}})
	if err != nil {
		t.Fatalf("MarshalSnapshot: %v", err)
	}
	ec, err := crypto.Encrypt(plain, pub)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	blob, err := ec.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	overrideRecipientKeys(t, rig.dataDir, pub, priv)
	withFetchSnapshotFunc(t, func(context.Context, *bsquic.Conn) ([]byte, error) {
		return blob, nil
	})

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", rig.dataDir, "restore-index"})
	err = root.Execute()
	if err == nil {
		t.Fatal("restore-index returned nil despite blocked index.db")
	}
	if !strings.Contains(err.Error(), "open index") {
		t.Errorf("err = %v, want 'open index' wrap", err)
	}
}

// overrideRecipientKeys rewrites the recipient keypair under dataDir
// to match the supplied (pub, priv) pair so tests can encrypt blobs the
// command will accept.
func overrideRecipientKeys(t *testing.T, dataDir string, pub, priv *[crypto.RecipientKeySize]byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dataDir, "node.xpub"), pub[:], 0o644); err != nil {
		t.Fatalf("write pub: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "node.xkey"), priv[:], 0o600); err != nil {
		t.Fatalf("write priv: %v", err)
	}
}

// TestRestoreIndexCmd_NoStoragePeer asserts an empty peers.db surfaces
// the "no storage peer" error.
func TestRestoreIndexCmd_NoStoragePeer(t *testing.T) {
	dataDir := t.TempDir()
	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", dataDir, "restore-index"})
	if err := root.Execute(); err == nil {
		t.Error("restore-index accepted empty peers.db")
	}
}

// TestRestoreIndexCmd_DialFailure asserts dialAll surfaces its error
// when the only peer addr is unreachable.
func TestRestoreIndexCmd_DialFailure(t *testing.T) {
	dataDir := t.TempDir()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	ps, err := peers.Open(filepath.Join(dataDir, "peers.db"))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "127.0.0.1:1", PubKey: pub, Role: peers.RoleIntroducer}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	_ = ps.Close()

	root := NewRootCmd()
	root.SetOut(&bytes.Buffer{})
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{
		"--data-dir", dataDir, "restore-index",
		"--dial-timeout", "200ms",
	})
	if err := root.Execute(); err == nil {
		t.Error("restore-index accepted unreachable peer")
	}
}
