package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// RelayAddrFilename is the basename of the daemon's TURN-relayed
// listening-address file. Present only when --turn-server is configured;
// absent file means no relay is available for this daemon.
const RelayAddrFilename = "relay.addr"

// WriteRelayAddr atomically writes addr to <dir>/relay.addr via temp+rename.
func WriteRelayAddr(dir, addr string) error {
	path := filepath.Join(dir, RelayAddrFilename)
	tmp, err := createListenAddrTempFunc(dir, ".relay.addr.")
	if err != nil {
		return fmt.Errorf("create temp relay.addr: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.WriteString(addr); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp relay.addr: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp relay.addr: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename relay.addr: %w", err)
	}
	committed = true
	return nil
}

// RemoveRelayAddr removes <dir>/relay.addr; missing file is not an error.
func RemoveRelayAddr(dir string) error {
	err := os.Remove(filepath.Join(dir, RelayAddrFilename))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove relay.addr: %w", err)
	}
	return nil
}

// ReadRelayAddr returns the trimmed contents of <dir>/relay.addr, or the
// empty string when the file is missing — callers treat absent as "no
// relay available" rather than an error.
func ReadRelayAddr(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, RelayAddrFilename))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read relay.addr: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}
