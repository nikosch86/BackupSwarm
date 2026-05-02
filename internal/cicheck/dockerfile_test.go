package cicheck

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDockerfileSetsDataDirEnv(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "Dockerfile")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read Dockerfile: %v", err)
	}
	must := []byte("ENV BACKUPSWARM_DATA_DIR=/data")
	if !bytes.Contains(data, must) {
		t.Errorf("Dockerfile missing %q — image must default the data dir to the /data volume so a recreated container preserves identity/peers.db", must)
	}
}
