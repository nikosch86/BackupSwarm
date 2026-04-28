package daemon_test

import (
	"testing"
	"time"

	"backupswarm/internal/daemon"
	"backupswarm/internal/index"
)

func TestComputeOwnBackup_Empty(t *testing.T) {
	got := daemon.ComputeOwnBackup(nil)
	if got != (daemon.RuntimeOwnBackupSnapshot{}) {
		t.Errorf("ComputeOwnBackup(nil) = %+v, want zero value", got)
	}
}

func TestComputeOwnBackup_TotalsAndReplication(t *testing.T) {
	pubA := []byte{0xa1}
	pubB := []byte{0xb2}
	entries := []index.FileEntry{
		{
			Path: "f1", Size: 100, ModTime: time.Now(),
			Chunks: []index.ChunkRef{{Size: 50, Peers: [][]byte{pubA, pubB}}},
		},
		{
			Path: "f2", Size: 300, ModTime: time.Now(),
			Chunks: []index.ChunkRef{
				{Size: 150, Peers: [][]byte{pubA}},
				{Size: 150, Peers: [][]byte{pubA, pubB}},
			},
		},
	}
	got := daemon.ComputeOwnBackup(entries)
	want := daemon.RuntimeOwnBackupSnapshot{
		Files:   2,
		Bytes:   400,
		Chunks:  3,
		ReplMin: 1,
		ReplMax: 2,
		ReplAvg: float64(2+1+2) / 3.0,
	}
	if got != want {
		t.Errorf("ComputeOwnBackup() = %+v, want %+v", got, want)
	}
}

func TestComputeOwnBackup_FileWithNoChunks(t *testing.T) {
	entries := []index.FileEntry{{Path: "empty", Size: 0}}
	got := daemon.ComputeOwnBackup(entries)
	want := daemon.RuntimeOwnBackupSnapshot{Files: 1}
	if got != want {
		t.Errorf("ComputeOwnBackup(no-chunk file) = %+v, want %+v", got, want)
	}
}

func TestComputeOwnBackup_SingleChunkSetsMinMaxEqual(t *testing.T) {
	entries := []index.FileEntry{{
		Path: "f", Size: 10,
		Chunks: []index.ChunkRef{{Size: 10, Peers: [][]byte{{0x01}, {0x02}, {0x03}}}},
	}}
	got := daemon.ComputeOwnBackup(entries)
	if got.ReplMin != 3 || got.ReplMax != 3 || got.ReplAvg != 3 {
		t.Errorf("single-chunk repl = (min %d, max %d, avg %v), want (3,3,3)", got.ReplMin, got.ReplMax, got.ReplAvg)
	}
}
