package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// TURNCredsFilename is the basename of the published TURN-credential
// file. Absent file means no credentials are embedded in issued tokens.
const TURNCredsFilename = "turn.creds"

// turnCredsOnDisk is the JSON envelope read/written from disk.
type turnCredsOnDisk struct {
	Server string `json:"server"`
	User   string `json:"user"`
	Pass   string `json:"pass"`
	Realm  string `json:"realm"`
}

// WriteTURNCreds atomically writes creds to <dir>/turn.creds via
// temp+rename, with file mode 0o600.
func WriteTURNCreds(dir string, creds TURNCreds) error {
	path := filepath.Join(dir, TURNCredsFilename)
	body, err := json.Marshal(turnCredsOnDisk{
		Server: creds.Server,
		User:   creds.User,
		Pass:   creds.Pass,
		Realm:  creds.Realm,
	})
	if err != nil {
		return fmt.Errorf("marshal turn.creds: %w", err)
	}
	tmp, err := createListenAddrTempFunc(dir, ".turn.creds.")
	if err != nil {
		return fmt.Errorf("create temp turn.creds: %w", err)
	}
	tmpPath := tmp.Name()
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.WriteString(string(body)); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp turn.creds: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp turn.creds: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod temp turn.creds: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("rename turn.creds: %w", err)
	}
	committed = true
	return nil
}

// RemoveTURNCreds removes <dir>/turn.creds; missing file is not an error.
func RemoveTURNCreds(dir string) error {
	err := os.Remove(filepath.Join(dir, TURNCredsFilename))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove turn.creds: %w", err)
	}
	return nil
}

// ReadTURNCreds returns the parsed turn.creds contents, or a zero-value
// TURNCreds when the file is missing.
func ReadTURNCreds(dir string) (TURNCreds, error) {
	data, err := os.ReadFile(filepath.Join(dir, TURNCredsFilename))
	if errors.Is(err, os.ErrNotExist) {
		return TURNCreds{}, nil
	}
	if err != nil {
		return TURNCreds{}, fmt.Errorf("read turn.creds: %w", err)
	}
	var on turnCredsOnDisk
	if err := json.Unmarshal(data, &on); err != nil {
		return TURNCreds{}, fmt.Errorf("parse turn.creds: %w", err)
	}
	return TURNCreds{
		Server: on.Server,
		User:   on.User,
		Pass:   on.Pass,
		Realm:  on.Realm,
	}, nil
}
