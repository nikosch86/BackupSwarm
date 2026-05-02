package cli

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// LogLevelEnvVar names the env var that sets the default log level.
const LogLevelEnvVar = "BACKUPSWARM_LOG_LEVEL"

// parseLogLevel maps a case-insensitive level string to slog.Level; empty is info.
func parseLogLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q (want debug|info|warn|error)", s)
	}
}

// resolveLogLevel returns the parsed flag value when set, otherwise the env value.
func resolveLogLevel(flagVal, envVal string) (slog.Level, error) {
	if strings.TrimSpace(flagVal) != "" {
		return parseLogLevel(flagVal)
	}
	return parseLogLevel(envVal)
}

// installLogger sets the default slog logger to a JSON handler at level writing to w.
func installLogger(w io.Writer, level slog.Level) {
	slog.SetDefault(slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level})))
}
