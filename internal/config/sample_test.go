package config_test

import (
	"path/filepath"
	"reflect"
	"testing"

	"backupswarm/internal/config"
)

// TestSampleConfig_ParsesAgainstSchema asserts configs/default.toml loads
// cleanly through Resolve, doesn't trip the unknown-key check, and yields
// the same values Default() does. Drift between code defaults and the
// shipped sample surfaces here.
func TestSampleConfig_ParsesAgainstSchema(t *testing.T) {
	t.Parallel()

	repoRoot := filepath.Join("..", "..")
	sample := filepath.Join(repoRoot, "configs", "default.toml")

	cmd := newTestCmd(t)
	cfg, err := config.Resolve(cmd, sample)
	if err != nil {
		t.Fatalf("Resolve sample: %v", err)
	}
	def := config.Default()
	if !reflect.DeepEqual(cfg, def) {
		t.Fatalf("sample config drifted from Default()\nfile: %+v\ndefault: %+v", cfg, def)
	}
}
