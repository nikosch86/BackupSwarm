package cli

import (
	"log/slog"

	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init",
		Short: "Initialize a new node (generate identity, create data directory)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			// TDD: full init logic lands in M1.2 (identity) and later stories.
			// This stub exists to wire up the CLI skeleton for M1.1.
			slog.InfoContext(cmd.Context(), "init: not yet implemented")
			return nil
		},
	}
}
