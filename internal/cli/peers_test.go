package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"backupswarm/internal/daemon"
	"backupswarm/internal/peers"
)

func TestPeersCmd_RegisteredOnRoot(t *testing.T) {
	root := NewRootCmd()
	found := false
	for _, c := range root.Commands() {
		if c.Name() == "peers" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("root command missing `peers` subcommand")
	}
}

func TestPeersCmd_PrintsHeaderAndPeerFromSnapshot(t *testing.T) {
	dataDir := t.TempDir()
	snap := daemon.RuntimeSnapshot{
		Mode:       "reconcile",
		ListenAddr: "127.0.0.1:7777",
		LastScanAt: time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC),
		Peers: []daemon.RuntimePeerSnapshot{
			{
				PubKeyHex:   "0102030405060708abcdef0011223344",
				Role:        "storage",
				Addr:        "10.0.0.1:7777",
				Reach:       "reachable",
				RemoteUsed:  100,
				RemoteMax:   1000,
				HasCapacity: true,
			},
		},
	}
	if err := daemon.WriteRuntimeSnapshot(dataDir, snap); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}

	out := runPeersCommand(t, dataDir)
	for _, want := range []string{"NODE_ID", "ROLE", "ADDR", "REACH", "CAPACITY", "0102030405060708", "storage", "10.0.0.1:7777", "reachable"} {
		if !strings.Contains(out, want) {
			t.Errorf("peers output missing %q\n--- output ---\n%s", want, out)
		}
	}
}

func TestPeersCmd_NoCapacity_RendersDash(t *testing.T) {
	dataDir := t.TempDir()
	snap := daemon.RuntimeSnapshot{
		Peers: []daemon.RuntimePeerSnapshot{
			{
				PubKeyHex: "0102030405060708",
				Role:      "peer",
				Addr:      "10.0.0.2:7777",
				Reach:     "unreachable",
			},
		},
	}
	if err := daemon.WriteRuntimeSnapshot(dataDir, snap); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}
	out := runPeersCommand(t, dataDir)
	if !strings.Contains(out, "unreachable") {
		t.Errorf("expected reach 'unreachable' in output, got:\n%s", out)
	}
	// The capacity column should render `-` when HasCapacity is false.
	if !strings.Contains(out, "-") {
		t.Errorf("expected '-' for missing capacity, got:\n%s", out)
	}
}

func TestPeersCmd_UnlimitedMaxRendered(t *testing.T) {
	dataDir := t.TempDir()
	snap := daemon.RuntimeSnapshot{
		Peers: []daemon.RuntimePeerSnapshot{
			{
				PubKeyHex:   "01",
				Role:        "storage",
				Addr:        "10.0.0.1:7777",
				Reach:       "reachable",
				RemoteUsed:  1024,
				RemoteMax:   0, // unlimited sentinel
				HasCapacity: true,
			},
		},
	}
	if err := daemon.WriteRuntimeSnapshot(dataDir, snap); err != nil {
		t.Fatalf("WriteRuntimeSnapshot: %v", err)
	}
	out := runPeersCommand(t, dataDir)
	if !strings.Contains(out, "unlimited") {
		t.Errorf("expected 'unlimited' for max=0, got:\n%s", out)
	}
}

func TestPeersCmd_FallsBackToPeersDBWhenNoSnapshot(t *testing.T) {
	dataDir := t.TempDir()
	ps, err := peers.Open(filepath.Join(dataDir, peers.DefaultFilename))
	if err != nil {
		t.Fatalf("peers.Open: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := ps.Add(peers.Peer{Addr: "10.0.0.5:7777", PubKey: pub, Role: peers.RoleStorage}); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := ps.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	out := runPeersCommand(t, dataDir)
	if !strings.Contains(out, "10.0.0.5:7777") {
		t.Errorf("output missing addr: %s", out)
	}
	if !strings.Contains(out, "storage") {
		t.Errorf("output missing role 'storage': %s", out)
	}
	if !strings.Contains(out, "unknown") {
		t.Errorf("expected reach 'unknown' (no daemon) in output: %s", out)
	}
	if !strings.Contains(out, "daemon not running") {
		t.Errorf("expected 'daemon not running' notice, got:\n%s", out)
	}
}

func TestPeersCmd_EmptyDataDir(t *testing.T) {
	out := runPeersCommand(t, t.TempDir())
	if !strings.Contains(out, "NODE_ID") {
		t.Errorf("expected header even with no peers, got:\n%s", out)
	}
}

// runPeersCommand executes `backupswarm --data-dir <dir> peers` and
// returns the captured stdout.
func runPeersCommand(t *testing.T, dataDir string) string {
	t.Helper()
	root := NewRootCmd()
	var stdout bytes.Buffer
	root.SetOut(&stdout)
	root.SetErr(&bytes.Buffer{})
	root.SetArgs([]string{"--data-dir", dataDir, "peers"})
	if err := root.Execute(); err != nil {
		t.Fatalf("execute: %v", err)
	}
	return stdout.String()
}
