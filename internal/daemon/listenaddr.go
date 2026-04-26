package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ListenAddrFilename is the basename of the file the daemon writes its
// bound listener address into at startup. `invite` reads it to embed in
// the token; an absent file fails fast with ErrNoRunningDaemon.
const ListenAddrFilename = "listen.addr"

// ErrNoRunningDaemon is returned by ReadListenAddr when listen.addr is
// missing from the data dir.
var ErrNoRunningDaemon = errors.New("no running daemon (listen.addr missing in data dir)")

// listenAddrTempFile narrows the temp-file surface WriteListenAddr
// needs so a white-box test can inject Write/Close failures.
type listenAddrTempFile interface {
	WriteString(string) (int, error)
	Close() error
	Name() string
}

// createListenAddrTempFunc is the seam tests swap to inject a
// listenAddrTempFile whose methods fail. Production never reassigns it.
var createListenAddrTempFunc = func(dir, pattern string) (listenAddrTempFile, error) {
	return os.CreateTemp(dir, pattern)
}

// WriteListenAddr atomically writes addr to <dir>/listen.addr via a
// same-directory temp file + rename, so concurrent readers never observe
// a partially-written address.
func WriteListenAddr(dir, addr string) error {
	path := filepath.Join(dir, ListenAddrFilename)
	tmp, err := createListenAddrTempFunc(dir, ".listen.addr.")
	if err != nil {
		return fmt.Errorf("create temp listen.addr: %w", err)
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
		return fmt.Errorf("write temp listen.addr: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp listen.addr: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename listen.addr: %w", err)
	}
	committed = true
	return nil
}

// RemoveListenAddr removes <dir>/listen.addr. A missing file is not an error.
func RemoveListenAddr(dir string) error {
	err := os.Remove(filepath.Join(dir, ListenAddrFilename))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove listen.addr: %w", err)
	}
	return nil
}

// ReadListenAddr returns the trimmed contents of <dir>/listen.addr, or
// ErrNoRunningDaemon when the file is absent.
func ReadListenAddr(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, ListenAddrFilename))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNoRunningDaemon
	}
	if err != nil {
		return "", fmt.Errorf("read listen.addr: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}
