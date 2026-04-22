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

	root.AddCommand(newInitCmd())

	return root
}
