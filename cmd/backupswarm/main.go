// Command backupswarm is the BackupSwarm CLI entrypoint.
package main

import (
	"io"
	"log/slog"
	"os"

	"backupswarm/internal/cli"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	slog.SetDefault(slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	root := cli.NewRootCmd()
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)

	if err := root.Execute(); err != nil {
		slog.Error("command failed", "err", err)
		return 1
	}
	return 0
}
