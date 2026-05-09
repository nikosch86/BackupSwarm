// Command backupswarm is the BackupSwarm CLI entrypoint.
package main

import (
	"context"
	"io"
	"log/slog"
	"os"
	"syscall"

	"backupswarm/internal/cli"
	"backupswarm/internal/signalctx"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	slog.SetDefault(slog.New(slog.NewJSONHandler(stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))

	ctx, stop := signalctx.WithSignalCancel(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	root := cli.NewRootCmd()
	root.SetOut(stdout)
	root.SetErr(stderr)
	root.SetArgs(args)

	if err := root.ExecuteContext(ctx); err != nil {
		slog.Error("command failed", "err", err)
		return 1
	}
	return 0
}
