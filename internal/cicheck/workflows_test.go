// Package cicheck holds structural assertions over the project's GitHub
// Actions workflow files. The package has no production code; the tests
// exist to catch drift in the CI/release configuration.
package cicheck

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod above %s", dir)
		}
		dir = parent
	}
}

func TestPublishGatesOnCIJobs(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, ".github", "workflows", "release.yml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read release.yml: %v", err)
	}
	must := []string{
		"needs: [test, build, docker]",
		"if: github.event_name == 'push'",
		"refs/heads/main",
		"refs/tags/v",
	}
	for _, s := range must {
		if !bytes.Contains(data, []byte(s)) {
			t.Errorf("release.yml missing required marker %q", s)
		}
	}
}

func TestNoStandaloneCIWorkflow(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, ".github", "workflows", "ci.yml")
	if _, err := os.Stat(path); err == nil {
		t.Errorf("%s still exists; the publish gate collapses CI into release.yml", path)
	}
}
