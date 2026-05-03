package nat

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jackpal/go-nat-pmp"
)

// fakeUPnPClient is a swappable in-memory upnpClient for tests.
type fakeUPnPClient struct {
	mu              sync.Mutex
	addCalls        int
	deleteCalls     int
	getExternalErr  error
	addErr          error
	deleteErr       error
	externalIP      string
	lastExternal    uint16
	lastInternal    uint16
	lastProto       string
	lastDeleteProto string
	lastDelExternal uint16
	lastLease       uint32
}

func (f *fakeUPnPClient) AddPortMappingCtx(_ context.Context, _ string, externalPort uint16, protocol string, internalPort uint16, _ string, _ bool, _ string, lease uint32) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls++
	f.lastExternal = externalPort
	f.lastInternal = internalPort
	f.lastProto = protocol
	f.lastLease = lease
	return f.addErr
}

func (f *fakeUPnPClient) DeletePortMappingCtx(_ context.Context, _ string, externalPort uint16, protocol string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleteCalls++
	f.lastDelExternal = externalPort
	f.lastDeleteProto = protocol
	return f.deleteErr
}

func (f *fakeUPnPClient) GetExternalIPAddressCtx(_ context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.getExternalErr != nil {
		return "", f.getExternalErr
	}
	return f.externalIP, nil
}

// fakeNATPMPClient is a swappable in-memory natpmpClient for tests.
type fakeNATPMPClient struct {
	mu              sync.Mutex
	addCalls        int
	getExternalCall int
	getExternalErr  error
	addErr          error
	externalIP      [4]byte
	mappedExternal  uint16
	lifetime        uint32
	lastInternal    int
	lastReqExternal int
	lastLifetime    int
	lastProtocol    string
}

func (f *fakeNATPMPClient) GetExternalAddress() (*natpmp.GetExternalAddressResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.getExternalCall++
	if f.getExternalErr != nil {
		return nil, f.getExternalErr
	}
	return &natpmp.GetExternalAddressResult{ExternalIPAddress: f.externalIP}, nil
}

func (f *fakeNATPMPClient) AddPortMapping(protocol string, internalPort, requestedExternalPort, lifetime int) (*natpmp.AddPortMappingResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addCalls++
	f.lastProtocol = protocol
	f.lastInternal = internalPort
	f.lastReqExternal = requestedExternalPort
	f.lastLifetime = lifetime
	if f.addErr != nil {
		return nil, f.addErr
	}
	return &natpmp.AddPortMappingResult{
		InternalPort:                 uint16(internalPort),
		MappedExternalPort:           f.mappedExternal,
		PortMappingLifetimeInSeconds: f.lifetime,
	}, nil
}

// withUPnPDiscover swaps upnpDiscoverFunc for the duration of the test.
func withUPnPDiscover(t *testing.T, fn func(context.Context) (upnpClient, error)) {
	t.Helper()
	prev := upnpDiscoverFunc
	upnpDiscoverFunc = fn
	t.Cleanup(func() { upnpDiscoverFunc = prev })
}

// withNATPMPDiscover swaps natpmpDiscoverFunc for the duration of the test.
func withNATPMPDiscover(t *testing.T, fn func(context.Context) (natpmpClient, error)) {
	t.Helper()
	prev := natpmpDiscoverFunc
	natpmpDiscoverFunc = fn
	t.Cleanup(func() { natpmpDiscoverFunc = prev })
}

func TestDiscoverPortMapper_UPnPSucceeds(t *testing.T) {
	upnp := &fakeUPnPClient{externalIP: "203.0.113.10"}
	withUPnPDiscover(t, func(_ context.Context) (upnpClient, error) { return upnp, nil })
	withNATPMPDiscover(t, func(_ context.Context) (natpmpClient, error) {
		t.Fatal("nat-pmp discover should not be called when upnp succeeds")
		return nil, nil
	})

	pm, err := DiscoverPortMapper(context.Background())
	if err != nil {
		t.Fatalf("DiscoverPortMapper: %v", err)
	}
	if _, ok := pm.(*upnpMapper); !ok {
		t.Fatalf("expected *upnpMapper, got %T", pm)
	}
}

func TestDiscoverPortMapper_UPnPFails_NATPMPSucceeds(t *testing.T) {
	withUPnPDiscover(t, func(_ context.Context) (upnpClient, error) {
		return nil, errors.New("forced upnp failure")
	})
	pmp := &fakeNATPMPClient{externalIP: [4]byte{198, 51, 100, 5}}
	withNATPMPDiscover(t, func(_ context.Context) (natpmpClient, error) { return pmp, nil })

	pm, err := DiscoverPortMapper(context.Background())
	if err != nil {
		t.Fatalf("DiscoverPortMapper: %v", err)
	}
	if _, ok := pm.(*natpmpMapper); !ok {
		t.Fatalf("expected *natpmpMapper, got %T", pm)
	}
}

func TestDiscoverPortMapper_BothFail(t *testing.T) {
	upnpErr := errors.New("forced upnp failure")
	pmpErr := errors.New("forced nat-pmp failure")
	withUPnPDiscover(t, func(_ context.Context) (upnpClient, error) { return nil, upnpErr })
	withNATPMPDiscover(t, func(_ context.Context) (natpmpClient, error) { return nil, pmpErr })

	_, err := DiscoverPortMapper(context.Background())
	if err == nil {
		t.Fatal("expected DiscoverPortMapper to error when both fail")
	}
	if !errors.Is(err, ErrNoPortMapper) {
		t.Fatalf("expected ErrNoPortMapper, got %v", err)
	}
	if !errors.Is(err, upnpErr) {
		t.Fatalf("expected joined upnp err in %v", err)
	}
	if !errors.Is(err, pmpErr) {
		t.Fatalf("expected joined nat-pmp err in %v", err)
	}
}

func TestDiscoverPortMapper_ContextCancelled(t *testing.T) {
	withUPnPDiscover(t, func(ctx context.Context) (upnpClient, error) {
		return nil, ctx.Err()
	})
	withNATPMPDiscover(t, func(ctx context.Context) (natpmpClient, error) {
		return nil, ctx.Err()
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := DiscoverPortMapper(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestUPnPMapper_Map(t *testing.T) {
	upnp := &fakeUPnPClient{externalIP: "203.0.113.10"}
	m := &upnpMapper{client: upnp}

	mapping, err := m.Map(context.Background(), 7777)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if mapping.Protocol != "upnp" {
		t.Errorf("Protocol = %q, want %q", mapping.Protocol, "upnp")
	}
	if mapping.ExternalPort != 7777 {
		t.Errorf("ExternalPort = %d, want 7777", mapping.ExternalPort)
	}
	if mapping.InternalPort != 7777 {
		t.Errorf("InternalPort = %d, want 7777", mapping.InternalPort)
	}
	if got := mapping.ExternalIP.String(); got != "203.0.113.10" {
		t.Errorf("ExternalIP = %q, want 203.0.113.10", got)
	}
	if mapping.LeaseSeconds <= 0 {
		t.Errorf("LeaseSeconds = %d, want > 0", mapping.LeaseSeconds)
	}
	if upnp.addCalls != 1 {
		t.Errorf("AddPortMapping calls = %d, want 1", upnp.addCalls)
	}
	if upnp.lastInternal != 7777 || upnp.lastExternal != 7777 {
		t.Errorf("ports = (%d,%d), want (7777,7777)", upnp.lastExternal, upnp.lastInternal)
	}
	if upnp.lastProto != "UDP" {
		t.Errorf("Protocol passed = %q, want UDP", upnp.lastProto)
	}
}

func TestUPnPMapper_Map_AddPortMappingFailure(t *testing.T) {
	upnp := &fakeUPnPClient{externalIP: "203.0.113.10", addErr: errors.New("forced add failure")}
	m := &upnpMapper{client: upnp}

	if _, err := m.Map(context.Background(), 7777); err == nil {
		t.Fatal("expected Map to surface add failure")
	}
}

func TestUPnPMapper_Map_GetExternalFailure(t *testing.T) {
	upnp := &fakeUPnPClient{getExternalErr: errors.New("forced external-ip failure")}
	m := &upnpMapper{client: upnp}

	if _, err := m.Map(context.Background(), 7777); err == nil {
		t.Fatal("expected Map to surface get-external failure")
	}
}

func TestUPnPMapper_Map_RejectsInvalidPort(t *testing.T) {
	m := &upnpMapper{client: &fakeUPnPClient{}}
	if _, err := m.Map(context.Background(), 0); err == nil {
		t.Fatal("expected error for internalPort=0")
	}
	if _, err := m.Map(context.Background(), 70000); err == nil {
		t.Fatal("expected error for internalPort > 65535")
	}
}

func TestUPnPMapper_Unmap(t *testing.T) {
	upnp := &fakeUPnPClient{}
	m := &upnpMapper{client: upnp}

	mapping := Mapping{ExternalPort: 7777, InternalPort: 7777, Protocol: "upnp"}
	if err := m.Unmap(context.Background(), mapping); err != nil {
		t.Fatalf("Unmap: %v", err)
	}
	if upnp.deleteCalls != 1 {
		t.Errorf("DeletePortMapping calls = %d, want 1", upnp.deleteCalls)
	}
	if upnp.lastDelExternal != 7777 {
		t.Errorf("DeletePortMapping external = %d, want 7777", upnp.lastDelExternal)
	}
	if upnp.lastDeleteProto != "UDP" {
		t.Errorf("DeletePortMapping protocol = %q, want UDP", upnp.lastDeleteProto)
	}
}

func TestNATPMPMapper_Map(t *testing.T) {
	pmp := &fakeNATPMPClient{
		externalIP:     [4]byte{198, 51, 100, 5},
		mappedExternal: 33333,
		lifetime:       7200,
	}
	m := &natpmpMapper{client: pmp}

	mapping, err := m.Map(context.Background(), 7777)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if mapping.Protocol != "nat-pmp" {
		t.Errorf("Protocol = %q, want %q", mapping.Protocol, "nat-pmp")
	}
	if mapping.ExternalPort != 33333 {
		t.Errorf("ExternalPort = %d, want 33333", mapping.ExternalPort)
	}
	if mapping.InternalPort != 7777 {
		t.Errorf("InternalPort = %d, want 7777", mapping.InternalPort)
	}
	if got := mapping.ExternalIP.String(); got != "198.51.100.5" {
		t.Errorf("ExternalIP = %q, want 198.51.100.5", got)
	}
	if mapping.LeaseSeconds != 7200 {
		t.Errorf("LeaseSeconds = %d, want 7200", mapping.LeaseSeconds)
	}
	if pmp.addCalls != 1 {
		t.Errorf("AddPortMapping calls = %d, want 1", pmp.addCalls)
	}
	if pmp.lastProtocol != "udp" {
		t.Errorf("Protocol passed = %q, want udp", pmp.lastProtocol)
	}
	if pmp.lastInternal != 7777 || pmp.lastReqExternal != 7777 {
		t.Errorf("ports = (%d,%d), want (7777,7777)", pmp.lastInternal, pmp.lastReqExternal)
	}
	if pmp.lastLifetime <= 0 {
		t.Errorf("Lifetime passed = %d, want > 0", pmp.lastLifetime)
	}
}

func TestNATPMPMapper_Map_AddPortMappingFailure(t *testing.T) {
	pmp := &fakeNATPMPClient{
		externalIP: [4]byte{198, 51, 100, 5},
		addErr:     errors.New("forced add failure"),
	}
	m := &natpmpMapper{client: pmp}
	if _, err := m.Map(context.Background(), 7777); err == nil {
		t.Fatal("expected Map to surface add failure")
	}
}

func TestNATPMPMapper_Map_GetExternalFailure(t *testing.T) {
	pmp := &fakeNATPMPClient{getExternalErr: errors.New("forced external failure")}
	m := &natpmpMapper{client: pmp}
	if _, err := m.Map(context.Background(), 7777); err == nil {
		t.Fatal("expected Map to surface get-external failure")
	}
}

func TestNATPMPMapper_Map_RejectsInvalidPort(t *testing.T) {
	m := &natpmpMapper{client: &fakeNATPMPClient{}}
	if _, err := m.Map(context.Background(), 0); err == nil {
		t.Fatal("expected error for internalPort=0")
	}
	if _, err := m.Map(context.Background(), 70000); err == nil {
		t.Fatal("expected error for internalPort > 65535")
	}
}

func TestNATPMPMapper_Unmap(t *testing.T) {
	pmp := &fakeNATPMPClient{externalIP: [4]byte{198, 51, 100, 5}}
	m := &natpmpMapper{client: pmp}

	mapping := Mapping{ExternalPort: 33333, InternalPort: 7777, Protocol: "nat-pmp"}
	if err := m.Unmap(context.Background(), mapping); err != nil {
		t.Fatalf("Unmap: %v", err)
	}
	if pmp.addCalls != 1 {
		t.Errorf("AddPortMapping (delete) calls = %d, want 1", pmp.addCalls)
	}
	if pmp.lastInternal != 7777 {
		t.Errorf("internal = %d, want 7777", pmp.lastInternal)
	}
	if pmp.lastReqExternal != 0 {
		t.Errorf("requestedExternal = %d, want 0", pmp.lastReqExternal)
	}
	if pmp.lastLifetime != 0 {
		t.Errorf("lifetime = %d, want 0 (delete)", pmp.lastLifetime)
	}
}

func TestMapping_Refresh(t *testing.T) {
	cases := []struct {
		name  string
		lease int
		want  bool // expect non-zero refresh interval
	}{
		{"with-lease", 7200, true},
		{"zero-lease", 0, false},
		{"negative-lease", -1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := Mapping{LeaseSeconds: tc.lease}
			d := m.RefreshInterval()
			if tc.want && d <= 0 {
				t.Errorf("RefreshInterval = %v, want > 0", d)
			}
			if !tc.want && d != 0 {
				t.Errorf("RefreshInterval = %v, want 0", d)
			}
		})
	}
}

// confirmIPv4 sanity-checks Mapping.ExternalIP.To4() conversion in tests
// where the external IP arrives as [4]byte from NAT-PMP.
func confirmIPv4(t *testing.T, ip net.IP, want string) {
	t.Helper()
	if ip.To4() == nil {
		t.Fatalf("expected IPv4, got %v", ip)
	}
	if ip.String() != want {
		t.Fatalf("ip = %q, want %q", ip.String(), want)
	}
}

func TestNATPMPMapper_Map_IPv4Encoding(t *testing.T) {
	pmp := &fakeNATPMPClient{
		externalIP:     [4]byte{1, 2, 3, 4},
		mappedExternal: 5555,
		lifetime:       3600,
	}
	m := &natpmpMapper{client: pmp}
	mapping, err := m.Map(context.Background(), 7777)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	confirmIPv4(t, mapping.ExternalIP, "1.2.3.4")
}

// withUPnPV2 swaps upnpDiscoverV2Func.
func withUPnPV2(t *testing.T, fn func(context.Context) ([]upnpClient, error)) {
	t.Helper()
	prev := upnpDiscoverV2Func
	upnpDiscoverV2Func = fn
	t.Cleanup(func() { upnpDiscoverV2Func = prev })
}

// withUPnPV1 swaps upnpDiscoverV1Func.
func withUPnPV1(t *testing.T, fn func(context.Context) ([]upnpClient, error)) {
	t.Helper()
	prev := upnpDiscoverV1Func
	upnpDiscoverV1Func = fn
	t.Cleanup(func() { upnpDiscoverV1Func = prev })
}

// withGatewayDiscover swaps gatewayDiscoverFunc.
func withGatewayDiscover(t *testing.T, fn func() (net.IP, error)) {
	t.Helper()
	prev := gatewayDiscoverFunc
	gatewayDiscoverFunc = fn
	t.Cleanup(func() { gatewayDiscoverFunc = prev })
}

// withNATPMPNewClient swaps natpmpNewClientFunc.
func withNATPMPNewClient(t *testing.T, fn func(net.IP, time.Duration) natpmpClient) {
	t.Helper()
	prev := natpmpNewClientFunc
	natpmpNewClientFunc = fn
	t.Cleanup(func() { natpmpNewClientFunc = prev })
}

// withLocalOutboundIP swaps localOutboundIPFunc.
func withLocalOutboundIP(t *testing.T, fn func() (net.IP, error)) {
	t.Helper()
	prev := localOutboundIPFunc
	localOutboundIPFunc = fn
	t.Cleanup(func() { localOutboundIPFunc = prev })
}

func TestUPnPDiscover_V2Succeeds(t *testing.T) {
	want := &fakeUPnPClient{externalIP: "1.2.3.4"}
	withUPnPV2(t, func(_ context.Context) ([]upnpClient, error) {
		return []upnpClient{want}, nil
	})
	withUPnPV1(t, func(_ context.Context) ([]upnpClient, error) {
		t.Fatal("V1 should not be called when V2 succeeds")
		return nil, nil
	})

	got, err := upnpDiscover(context.Background())
	if err != nil {
		t.Fatalf("upnpDiscover: %v", err)
	}
	if got != want {
		t.Fatalf("got %p, want %p", got, want)
	}
}

func TestUPnPDiscover_V2EmptyV1Succeeds(t *testing.T) {
	want := &fakeUPnPClient{externalIP: "5.6.7.8"}
	withUPnPV2(t, func(_ context.Context) ([]upnpClient, error) {
		return nil, nil
	})
	withUPnPV1(t, func(_ context.Context) ([]upnpClient, error) {
		return []upnpClient{want}, nil
	})

	got, err := upnpDiscover(context.Background())
	if err != nil {
		t.Fatalf("upnpDiscover: %v", err)
	}
	if got != want {
		t.Fatalf("got %p, want %p", got, want)
	}
}

func TestUPnPDiscover_V2ErrorsV1Succeeds(t *testing.T) {
	want := &fakeUPnPClient{externalIP: "9.10.11.12"}
	withUPnPV2(t, func(_ context.Context) ([]upnpClient, error) {
		return nil, errors.New("forced v2 failure")
	})
	withUPnPV1(t, func(_ context.Context) ([]upnpClient, error) {
		return []upnpClient{want}, nil
	})

	got, err := upnpDiscover(context.Background())
	if err != nil {
		t.Fatalf("upnpDiscover: %v", err)
	}
	if got != want {
		t.Fatalf("got %p, want %p", got, want)
	}
}

func TestUPnPDiscover_BothEmpty(t *testing.T) {
	withUPnPV2(t, func(_ context.Context) ([]upnpClient, error) { return nil, nil })
	withUPnPV1(t, func(_ context.Context) ([]upnpClient, error) { return nil, nil })

	if _, err := upnpDiscover(context.Background()); err == nil {
		t.Fatal("expected error when no IGD discovered")
	}
}

func TestUPnPDiscover_V1Errors(t *testing.T) {
	withUPnPV2(t, func(_ context.Context) ([]upnpClient, error) {
		return nil, errors.New("forced v2 failure")
	})
	v1Err := errors.New("forced v1 failure")
	withUPnPV1(t, func(_ context.Context) ([]upnpClient, error) { return nil, v1Err })

	_, err := upnpDiscover(context.Background())
	if !errors.Is(err, v1Err) {
		t.Fatalf("expected wrapped v1 err, got %v", err)
	}
}

func TestNATPMPDiscover_GatewayFails(t *testing.T) {
	gwErr := errors.New("forced gateway failure")
	withGatewayDiscover(t, func() (net.IP, error) { return nil, gwErr })
	withNATPMPNewClient(t, func(_ net.IP, _ time.Duration) natpmpClient {
		t.Fatal("NewClient should not be called when gateway discovery fails")
		return nil
	})

	if _, err := natpmpDiscover(context.Background()); !errors.Is(err, gwErr) {
		t.Fatalf("expected wrapped gateway err, got %v", err)
	}
}

func TestNATPMPDiscover_ProbeSucceeds(t *testing.T) {
	withGatewayDiscover(t, func() (net.IP, error) { return net.IPv4(192, 168, 1, 1), nil })
	pmp := &fakeNATPMPClient{externalIP: [4]byte{198, 51, 100, 5}}
	withNATPMPNewClient(t, func(_ net.IP, _ time.Duration) natpmpClient { return pmp })

	got, err := natpmpDiscover(context.Background())
	if err != nil {
		t.Fatalf("natpmpDiscover: %v", err)
	}
	if got != pmp {
		t.Fatalf("got %p, want %p", got, pmp)
	}
	if pmp.getExternalCall == 0 {
		t.Fatal("expected GetExternalAddress to be called as probe")
	}
}

func TestNATPMPDiscover_ProbeFails(t *testing.T) {
	withGatewayDiscover(t, func() (net.IP, error) { return net.IPv4(192, 168, 1, 1), nil })
	probeErr := errors.New("forced probe failure")
	withNATPMPNewClient(t, func(_ net.IP, _ time.Duration) natpmpClient {
		return &fakeNATPMPClient{getExternalErr: probeErr}
	})

	if _, err := natpmpDiscover(context.Background()); !errors.Is(err, probeErr) {
		t.Fatalf("expected wrapped probe err, got %v", err)
	}
}

func TestNATPMPDiscover_DeadlineShrinksTimeout(t *testing.T) {
	withGatewayDiscover(t, func() (net.IP, error) { return net.IPv4(192, 168, 1, 1), nil })
	pmp := &fakeNATPMPClient{externalIP: [4]byte{1, 2, 3, 4}}
	var gotTimeout time.Duration
	withNATPMPNewClient(t, func(_ net.IP, timeout time.Duration) natpmpClient {
		gotTimeout = timeout
		return pmp
	})

	short := 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), short)
	defer cancel()

	if _, err := natpmpDiscover(ctx); err != nil {
		t.Fatalf("natpmpDiscover: %v", err)
	}
	if gotTimeout > short {
		t.Errorf("timeout = %v, want <= %v", gotTimeout, short)
	}
}

func TestUPnPMapper_Map_LocalOutboundIPFails(t *testing.T) {
	withLocalOutboundIP(t, func() (net.IP, error) {
		return nil, errors.New("forced outbound-ip failure")
	})
	m := &upnpMapper{client: &fakeUPnPClient{externalIP: "1.2.3.4"}}
	if _, err := m.Map(context.Background(), 7777); err == nil {
		t.Fatal("expected Map to surface outbound-ip failure")
	}
}

func TestUPnPMapper_Map_ExternalIPParseFailure(t *testing.T) {
	upnp := &fakeUPnPClient{externalIP: "not-an-ip"}
	m := &upnpMapper{client: upnp}
	if _, err := m.Map(context.Background(), 7777); err == nil {
		t.Fatal("expected parse failure")
	}
	if upnp.deleteCalls != 1 {
		t.Errorf("expected DeletePortMapping rollback on parse failure, got %d calls", upnp.deleteCalls)
	}
}

func TestUPnPMapper_Map_GetExternalFailureRollsBack(t *testing.T) {
	upnp := &fakeUPnPClient{getExternalErr: errors.New("forced get-external failure")}
	m := &upnpMapper{client: upnp}
	_, _ = m.Map(context.Background(), 7777)
	if upnp.deleteCalls != 1 {
		t.Errorf("expected rollback DeletePortMapping, got %d calls", upnp.deleteCalls)
	}
}

func TestUPnPMapper_Unmap_RejectsInvalidPort(t *testing.T) {
	m := &upnpMapper{client: &fakeUPnPClient{}}
	if err := m.Unmap(context.Background(), Mapping{ExternalPort: 0}); err == nil {
		t.Fatal("expected error for ExternalPort=0")
	}
}

func TestNATPMPMapper_Unmap_RejectsInvalidPort(t *testing.T) {
	m := &natpmpMapper{client: &fakeNATPMPClient{}}
	if err := m.Unmap(context.Background(), Mapping{InternalPort: 0}); err == nil {
		t.Fatal("expected error for InternalPort=0")
	}
}

func TestRealThirdPartyGlue_Smoke(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	_, _ = upnpDiscoverV2Func(ctx)
	_, _ = upnpDiscoverV1Func(ctx)
	if c := natpmpNewClientFunc(net.IPv4(127, 0, 0, 1), time.Millisecond); c == nil {
		t.Fatal("natpmpNewClientFunc returned nil")
	}
}
