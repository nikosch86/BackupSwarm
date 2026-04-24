package cli

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	dataDirEnvVar    = "BACKUPSWARM_DATA_DIR"
	xdgDataHomeEnv   = "XDG_DATA_HOME"
	defaultAppSubdir = "backupswarm"
)

// resolveDataDir applies the precedence flag > env > XDG_DATA_HOME > $HOME.
// Returns an error only if the fallback chain needs $HOME but it's unset.
func resolveDataDir(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv(dataDirEnvVar); env != "" {
		return env, nil
	}
	if xdg := os.Getenv(xdgDataHomeEnv); xdg != "" {
		return filepath.Join(xdg, defaultAppSubdir), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve data dir: no --data-dir, %s, %s, or $HOME set: %w",
			dataDirEnvVar, xdgDataHomeEnv, err)
	}
	return filepath.Join(home, ".local", "share", defaultAppSubdir), nil
}
