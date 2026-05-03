package nat

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway2"
	"github.com/jackpal/gateway"
	"github.com/jackpal/go-nat-pmp"
)

// ErrNoPortMapper is returned when neither UPnP nor NAT-PMP responded.
var ErrNoPortMapper = errors.New("nat: no port mapper found")

// Mapping is a single external-port reservation acquired from the local
// gateway via UPnP or NAT-PMP.
type Mapping struct {
	ExternalIP   net.IP
	ExternalPort int
	InternalPort int
	Protocol     string
	LeaseSeconds int
}

// RefreshInterval returns the recommended re-Map cadence for the lease;
// zero means the mapping has no expiry and never needs refresh.
func (m Mapping) RefreshInterval() time.Duration {
	if m.LeaseSeconds <= 0 {
		return 0
	}
	return time.Duration(m.LeaseSeconds/2) * time.Second
}

// PortMapper opens and tears down a single UDP port mapping on the local
// gateway. Callers Map once at startup and Unmap on shutdown.
type PortMapper interface {
	Map(ctx context.Context, internalPort int) (Mapping, error)
	Unmap(ctx context.Context, m Mapping) error
}

const (
	defaultUPnPLeaseSeconds   = 7200
	defaultNATPMPLeaseSeconds = 7200
	natpmpProbeTimeout        = 1 * time.Second
)

// upnpClient is the subset of goupnp's WANIPConnection client used by
// upnpMapper; tests substitute fakes.
type upnpClient interface {
	AddPortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string, internalPort uint16, internalClient string, enabled bool, description string, leaseDuration uint32) error
	DeletePortMappingCtx(ctx context.Context, remoteHost string, externalPort uint16, protocol string) error
	GetExternalIPAddressCtx(ctx context.Context) (string, error)
}

// natpmpClient is the subset of jackpal/go-nat-pmp's Client used by
// natpmpMapper; tests substitute fakes.
type natpmpClient interface {
	GetExternalAddress() (*natpmp.GetExternalAddressResult, error)
	AddPortMapping(protocol string, internalPort, requestedExternalPort, lifetime int) (*natpmp.AddPortMappingResult, error)
}

// upnpDiscoverFunc opens a UPnP IGD client; swappable test seam.
var upnpDiscoverFunc = upnpDiscover

// natpmpDiscoverFunc opens a NAT-PMP client against the default gateway;
// swappable test seam.
var natpmpDiscoverFunc = natpmpDiscover

// gatewayDiscoverFunc returns the local default-gateway IP; swappable test seam.
var gatewayDiscoverFunc = gateway.DiscoverGateway

// upnpDiscoverV2Func returns IGDv2 WANIPConnection clients adapted to the
// upnpClient interface; swappable test seam.
var upnpDiscoverV2Func = func(ctx context.Context) ([]upnpClient, error) {
	cs, _, err := internetgateway2.NewWANIPConnection2ClientsCtx(ctx)
	out := make([]upnpClient, len(cs))
	for i, c := range cs {
		out[i] = c
	}
	return out, err
}

// upnpDiscoverV1Func returns IGDv1 WANIPConnection clients adapted to the
// upnpClient interface; swappable test seam.
var upnpDiscoverV1Func = func(ctx context.Context) ([]upnpClient, error) {
	cs, _, err := internetgateway2.NewWANIPConnection1ClientsCtx(ctx)
	out := make([]upnpClient, len(cs))
	for i, c := range cs {
		out[i] = c
	}
	return out, err
}

// natpmpNewClientFunc constructs a NAT-PMP client against gw with the
// supplied timeout; swappable test seam.
var natpmpNewClientFunc = func(gw net.IP, timeout time.Duration) natpmpClient {
	return natpmp.NewClientWithTimeout(gw, timeout)
}

// DiscoverPortMapper tries UPnP first, then NAT-PMP. Returns the first
// implementation whose discovery succeeded; ErrNoPortMapper joined with
// each underlying failure when both fail.
func DiscoverPortMapper(ctx context.Context) (PortMapper, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if uc, err := upnpDiscoverFunc(ctx); err == nil {
		return &upnpMapper{client: uc}, nil
	} else if uerr := ctx.Err(); uerr != nil {
		return nil, uerr
	} else {
		if pc, perr := natpmpDiscoverFunc(ctx); perr == nil {
			return &natpmpMapper{client: pc}, nil
		} else {
			return nil, fmt.Errorf("%w: %w", ErrNoPortMapper, errors.Join(err, perr))
		}
	}
}

// upnpDiscover finds a UPnP IGDv2 (or v1) WANIPConnection client via SSDP.
func upnpDiscover(ctx context.Context) (upnpClient, error) {
	if v2, err := upnpDiscoverV2Func(ctx); err == nil && len(v2) > 0 {
		return v2[0], nil
	}
	v1, err := upnpDiscoverV1Func(ctx)
	if err != nil {
		return nil, fmt.Errorf("nat: upnp discover: %w", err)
	}
	if len(v1) == 0 {
		return nil, errors.New("nat: upnp discover: no IGD found")
	}
	return v1[0], nil
}

// natpmpDiscover finds the default gateway and probes it via GetExternalAddress.
func natpmpDiscover(ctx context.Context) (natpmpClient, error) {
	gw, err := gatewayDiscoverFunc()
	if err != nil {
		return nil, fmt.Errorf("nat: nat-pmp gateway discover: %w", err)
	}
	timeout := natpmpProbeTimeout
	if dl, ok := ctx.Deadline(); ok {
		if d := time.Until(dl); d > 0 && d < timeout {
			timeout = d
		}
	}
	client := natpmpNewClientFunc(gw, timeout)
	if _, err := client.GetExternalAddress(); err != nil {
		return nil, fmt.Errorf("nat: nat-pmp probe: %w", err)
	}
	return client, nil
}

// upnpMapper implements PortMapper via a UPnP IGD WANIPConnection client.
type upnpMapper struct {
	client upnpClient
}

func (m *upnpMapper) Map(ctx context.Context, internalPort int) (Mapping, error) {
	if internalPort <= 0 || internalPort > 65535 {
		return Mapping{}, fmt.Errorf("nat: internal port out of range: %d", internalPort)
	}
	internalIP, err := localOutboundIP()
	if err != nil {
		return Mapping{}, fmt.Errorf("nat: local outbound ip: %w", err)
	}
	port := uint16(internalPort)
	if err := m.client.AddPortMappingCtx(ctx, "", port, "UDP", port, internalIP.String(), true, "BackupSwarm", uint32(defaultUPnPLeaseSeconds)); err != nil {
		return Mapping{}, fmt.Errorf("nat: upnp add port mapping: %w", err)
	}
	extStr, err := m.client.GetExternalIPAddressCtx(ctx)
	if err != nil {
		_ = m.client.DeletePortMappingCtx(ctx, "", port, "UDP")
		return Mapping{}, fmt.Errorf("nat: upnp get external ip: %w", err)
	}
	extIP := net.ParseIP(extStr)
	if extIP == nil {
		_ = m.client.DeletePortMappingCtx(ctx, "", port, "UDP")
		return Mapping{}, fmt.Errorf("nat: upnp parse external ip %q", extStr)
	}
	return Mapping{
		ExternalIP:   extIP,
		ExternalPort: internalPort,
		InternalPort: internalPort,
		Protocol:     "upnp",
		LeaseSeconds: defaultUPnPLeaseSeconds,
	}, nil
}

func (m *upnpMapper) Unmap(ctx context.Context, mapping Mapping) error {
	if mapping.ExternalPort <= 0 || mapping.ExternalPort > 65535 {
		return fmt.Errorf("nat: unmap external port out of range: %d", mapping.ExternalPort)
	}
	return m.client.DeletePortMappingCtx(ctx, "", uint16(mapping.ExternalPort), "UDP")
}

// natpmpMapper implements PortMapper via a NAT-PMP client.
type natpmpMapper struct {
	client natpmpClient
}

func (m *natpmpMapper) Map(_ context.Context, internalPort int) (Mapping, error) {
	if internalPort <= 0 || internalPort > 65535 {
		return Mapping{}, fmt.Errorf("nat: internal port out of range: %d", internalPort)
	}
	ext, err := m.client.GetExternalAddress()
	if err != nil {
		return Mapping{}, fmt.Errorf("nat: nat-pmp get external: %w", err)
	}
	res, err := m.client.AddPortMapping("udp", internalPort, internalPort, defaultNATPMPLeaseSeconds)
	if err != nil {
		return Mapping{}, fmt.Errorf("nat: nat-pmp add port mapping: %w", err)
	}
	return Mapping{
		ExternalIP:   net.IPv4(ext.ExternalIPAddress[0], ext.ExternalIPAddress[1], ext.ExternalIPAddress[2], ext.ExternalIPAddress[3]),
		ExternalPort: int(res.MappedExternalPort),
		InternalPort: internalPort,
		Protocol:     "nat-pmp",
		LeaseSeconds: int(res.PortMappingLifetimeInSeconds),
	}, nil
}

func (m *natpmpMapper) Unmap(_ context.Context, mapping Mapping) error {
	if mapping.InternalPort <= 0 || mapping.InternalPort > 65535 {
		return fmt.Errorf("nat: unmap internal port out of range: %d", mapping.InternalPort)
	}
	_, err := m.client.AddPortMapping("udp", mapping.InternalPort, 0, 0)
	return err
}

// localOutboundIPFunc returns the local IP a UDP datagram to a public
// address would carry; swappable for tests.
var localOutboundIPFunc = defaultLocalOutboundIP

func localOutboundIP() (net.IP, error) { return localOutboundIPFunc() }

func defaultLocalOutboundIP() (net.IP, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer func() { _ = conn.Close() }()
	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("nat: unexpected local addr type %T", conn.LocalAddr())
	}
	return addr.IP, nil
}
