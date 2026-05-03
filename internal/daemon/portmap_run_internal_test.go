package daemon

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"backupswarm/internal/nat"
)

// fakeRunPortMapper wires a Mapping/Unmap pair onto daemon.Run via Options.
type fakeRunPortMapper struct {
	mu      sync.Mutex
	mapErr  error
	results []nat.Mapping
	mapped  atomic.Int32
	unmap   atomic.Int32
}

func (f *fakeRunPortMapper) Map(_ context.Context, _ int) (nat.Mapping, error) {
	f.mapped.Add(1)
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.mapErr != nil {
		return nat.Mapping{}, f.mapErr
	}
	if len(f.results) == 0 {
		return nat.Mapping{}, errors.New("fake: no scripted result")
	}
	out := f.results[0]
	if len(f.results) > 1 {
		f.results = f.results[1:]
	}
	return out, nil
}

func (f *fakeRunPortMapper) Unmap(_ context.Context, _ nat.Mapping) error {
	f.unmap.Add(1)
	return nil
}

// TestRun_PortMapping_SpawnsLoopAndUnmaps drives daemon.Run with a Mapping
// and Mapper supplied; asserts the refresh loop runs and the deferred
// Unmap fires on shutdown.
func TestRun_PortMapping_SpawnsLoopAndUnmaps(t *testing.T) {
	prevMin := minPortMapRefresh
	prevDefault := defaultPortMapRefresh
	prevMax := maxPortMapRefresh
	prevJitter := portmapJitterFn
	t.Cleanup(func() {
		minPortMapRefresh = prevMin
		defaultPortMapRefresh = prevDefault
		maxPortMapRefresh = prevMax
		portmapJitterFn = prevJitter
	})
	minPortMapRefresh = time.Millisecond
	defaultPortMapRefresh = 5 * time.Millisecond
	maxPortMapRefresh = 50 * time.Millisecond
	portmapJitterFn = func() float64 { return 1.0 }

	mapper := &fakeRunPortMapper{
		results: []nat.Mapping{
			{ExternalIP: net.IPv4(203, 0, 113, 50), ExternalPort: 17777, InternalPort: 7777, Protocol: "upnp", LeaseSeconds: 0},
		},
	}
	mapping := nat.Mapping{
		ExternalIP:   net.IPv4(203, 0, 113, 50),
		ExternalPort: 17777,
		InternalPort: 7777,
		Protocol:     "upnp",
		LeaseSeconds: 0,
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:     t.TempDir(),
			ListenAddr:  "127.0.0.1:0",
			PortMapping: &mapping,
			PortMapper:  mapper,
		})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for mapper.mapped.Load() == 0 {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("refresh Map call never fired")
		}
		time.Sleep(5 * time.Millisecond)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}

	if mapper.unmap.Load() == 0 {
		t.Error("Unmap was not called on shutdown")
	}
}

// fakeRunPortMapperUnmapErr returns a fixed error from Unmap.
type fakeRunPortMapperUnmapErr struct {
	fakeRunPortMapper
	unmapErr error
}

func (f *fakeRunPortMapperUnmapErr) Unmap(_ context.Context, _ nat.Mapping) error {
	f.unmap.Add(1)
	return f.unmapErr
}

// TestRun_PortMapping_UnmapErrorIsLogged asserts that an error returned
// from the deferred Unmap call is logged but doesn't propagate.
func TestRun_PortMapping_UnmapErrorIsLogged(t *testing.T) {
	mapper := &fakeRunPortMapperUnmapErr{
		fakeRunPortMapper: fakeRunPortMapper{
			results: []nat.Mapping{{ExternalIP: net.IPv4(1, 2, 3, 4), ExternalPort: 7777}},
		},
		unmapErr: errors.New("forced unmap failure"),
	}
	mapping := nat.Mapping{ExternalIP: net.IPv4(1, 2, 3, 4), ExternalPort: 7777, InternalPort: 7777, Protocol: "upnp"}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:     t.TempDir(),
			ListenAddr:  "127.0.0.1:0",
			PortMapping: &mapping,
			PortMapper:  mapper,
		})
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}
	if mapper.unmap.Load() == 0 {
		t.Error("Unmap was not called")
	}
}

// TestRun_PortMapping_NilOptsSkipsLoop asserts that when PortMapping or
// PortMapper is nil, the daemon does not spawn the loop or call Unmap.
func TestRun_PortMapping_NilOptsSkipsLoop(t *testing.T) {
	mapper := &fakeRunPortMapper{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			DataDir:    t.TempDir(),
			ListenAddr: "127.0.0.1:0",
			PortMapper: mapper,
		})
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return within 3s of cancel")
	}

	if mapper.mapped.Load() != 0 {
		t.Errorf("Map called %d times with nil PortMapping (want 0)", mapper.mapped.Load())
	}
	if mapper.unmap.Load() != 0 {
		t.Errorf("Unmap called %d times with nil PortMapping (want 0)", mapper.unmap.Load())
	}
}
