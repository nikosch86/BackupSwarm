package cli

import (
	"context"
	"errors"
	"os"
	"testing"

	"backupswarm/internal/nat"
)

// TestMain disables UPnP / NAT-PMP discovery for the CLI test binary so
// real SSDP probes don't slow every --advertise-addr=auto test by 1-3
// seconds. Tests that exercise port mapping behaviour swap
// cliPortMapDiscoverFunc explicitly inside the test.
func TestMain(m *testing.M) {
	cliPortMapDiscoverFunc = func(_ context.Context) (nat.PortMapper, error) {
		return nil, errors.New("test: port mapping discovery disabled")
	}
	os.Exit(m.Run())
}
