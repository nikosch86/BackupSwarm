package cli

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"backupswarm/internal/node"
)

const (
	dataDirEnvVar    = "BACKUPSWARM_DATA_DIR"
	xdgDataHomeEnv   = "XDG_DATA_HOME"
	defaultAppSubdir = "backupswarm"
)

func newInitCmd(dataDir *string) *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize a new node (generate identity, create data directory)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}
			id, created, err := node.Ensure(dir)
			if err != nil {
				return fmt.Errorf("ensure identity in %s: %w", dir, err)
			}
			msg := "loaded existing node identity"
			if created {
				msg = "created new node identity"
			}
			slog.InfoContext(cmd.Context(), msg,
				"data_dir", dir,
				"node_id", id.IDHex(),
				"short_id", id.ShortID(),
			)
			return nil
		},
	}
}

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
