package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"backupswarm/internal/ca"
	"backupswarm/internal/daemon"
	"backupswarm/internal/node"
)

func newInviteCmd(dataDir *string) *cobra.Command {
	var (
		tokenOut string
		wait     time.Duration
	)
	cmd := &cobra.Command{
		Use:   "invite",
		Short: "Issue a single-use invite token against a running daemon",
		Long: "Issue a fresh invite token. Reads the daemon's bound listen " +
			"address from <data-dir>/listen.addr, opens invites.db, persists " +
			"a new pending secret, and prints the encoded token. Requires a " +
			"running daemon at <data-dir>; the founder bootstraps a swarm " +
			"with `run --invite` instead. --token-out additionally writes " +
			"the token to a file (atomic). --wait polls for listen.addr " +
			"until present (orchestrators like docker-compose where the " +
			"daemon may still be starting).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			dir, err := resolveDataDir(*dataDir)
			if err != nil {
				return err
			}
			id, _, err := node.Ensure(dir)
			if err != nil {
				return fmt.Errorf("ensure identity: %w", err)
			}

			listenAddr, err := readListenAddrWithWait(cmd.Context(), dir, wait)
			if err != nil {
				if errors.Is(err, daemon.ErrNoRunningDaemon) {
					return fmt.Errorf("invite: %w (start the daemon first via `run`)", err)
				}
				return fmt.Errorf("read listen.addr: %w", err)
			}

			caCertDER, err := readSwarmCACertIfPresent(dir)
			if err != nil {
				return err
			}

			tokStr, err := daemon.IssueInvite(dir, listenAddr, id.PublicKey, caCertDER)
			if err != nil {
				return fmt.Errorf("issue invite: %w", err)
			}
			fmt.Fprintln(cmd.OutOrStdout(), tokStr)
			if tokenOut != "" {
				if err := writeTokenFile(tokenOut, tokStr); err != nil {
					return fmt.Errorf("write token file: %w", err)
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&tokenOut, "token-out", "", "Write the printed token to this file (atomic)")
	cmd.Flags().DurationVar(&wait, "wait", 0, "Poll for the daemon's listen.addr to appear, up to this duration (0 = fail-fast)")
	return cmd
}

// readListenAddrWithWait calls daemon.ReadListenAddr, polling for up
// to wait when the file is absent. wait <= 0 fails fast.
func readListenAddrWithWait(ctx context.Context, dir string, wait time.Duration) (string, error) {
	if wait <= 0 {
		return daemon.ReadListenAddr(dir)
	}
	const pollInterval = 100 * time.Millisecond
	deadline := time.Now().Add(wait)
	for {
		addr, err := daemon.ReadListenAddr(dir)
		if err == nil {
			return addr, nil
		}
		if !errors.Is(err, daemon.ErrNoRunningDaemon) {
			return "", err
		}
		if time.Now().After(deadline) {
			return "", err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(pollInterval):
		}
	}
}

// readSwarmCACertIfPresent loads ca.crt from dir, or returns
// (nil, nil) when no CA is on disk.
func readSwarmCACertIfPresent(dir string) ([]byte, error) {
	has, err := ca.Has(dir)
	if err != nil {
		return nil, fmt.Errorf("check ca: %w", err)
	}
	if !has {
		return nil, nil
	}
	swarmCA, err := ca.Load(dir)
	if err != nil {
		return nil, fmt.Errorf("load ca: %w", err)
	}
	return swarmCA.CertDER, nil
}

// tokenTempFile narrows the surface writeTokenFile needs from a
// temp-file handle so the white-box test can swap in a fake whose
// Write/Close legs fail — same seam pattern internal/store uses for
// its atomic Put.
type tokenTempFile interface {
	WriteString(string) (int, error)
	Close() error
	Name() string
}

// createTokenTempFunc is the seam that lets tests inject a tokenTempFile
// whose methods fail. Production never reassigns it.
var createTokenTempFunc = func(dir, pattern string) (tokenTempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// writeTokenFile writes tok+newline to path via a same-directory temp
// file + rename, so concurrent readers never observe a partially-written
// token. Used by --token-out.
func writeTokenFile(path, tok string) error {
	dir := filepath.Dir(path)
	tmp, err := createTokenTempFunc(dir, ".token-")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.WriteString(tok + "\n"); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	committed = true
	return nil
}
