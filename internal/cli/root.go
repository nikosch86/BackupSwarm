// Package cli wires the backupswarm command-line interface.
package cli

import (
	"github.com/spf13/cobra"
)

// NewRootCmd builds the root cobra command with all subcommands registered.
func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "backupswarm",
		Short:         "P2P encrypted backup tool",
		Long:          "BackupSwarm is a peer-to-peer encrypted backup tool that shares encrypted chunks of data across a swarm of trusted nodes.",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	var dataDir string
	root.PersistentFlags().StringVar(&dataDir, "data-dir", "",
		"Node data directory (default $BACKUPSWARM_DATA_DIR or $XDG_DATA_HOME/backupswarm)")

	root.AddCommand(newInviteCmd(&dataDir))
	root.AddCommand(newJoinCmd(&dataDir))
	root.AddCommand(newRunCmd(&dataDir))
	root.AddCommand(newRestoreCmd(&dataDir))
	root.AddCommand(newRestoreIndexCmd(&dataDir))
	root.AddCommand(newPeersCmd(&dataDir))
	root.AddCommand(newStatusCmd(&dataDir))

	return root
}
