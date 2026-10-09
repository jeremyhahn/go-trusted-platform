package gateway

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/deviceverdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/stretchr/testify/require"
)

// backendOVS is an OVSDB holding the overlay's access port and the VXLAN
// port the handler creates.
type backendOVS struct {
	mu      sync.Mutex
	ports   map[string]*ovs.VXLANPort
	ofPorts map[string]int32
}

func newBackendOVS(accessPort string) *backendOVS {
	return &backendOVS{
		ports:   make(map[string]*ovs.VXLANPort),
		ofPorts: map[string]int32{accessPort: 3},
	}
}

func (f *backendOVS) AddVXLANPortWithName(_ context.Context, _, port string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := &ovs.VXLANPort{Name: port, IsFlowRemote: cfg.RemoteFlow, IsFlowKey: cfg.Key == 0, DstPort: cfg.DstPort}
	f.ports[port] = p
	f.ofPorts[port] = 7
	return p, nil
}

func (f *backendOVS) GetVXLANPortWithOptions(_ context.Context, _, port string) (*ovs.VXLANPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.ports[port]
	if !ok {
		return nil, ovs.ErrPortNotFound
	}
	return p, nil
}

func (f *backendOVS) DeleteVXLANPort(_ context.Context, _, port string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.ports, port)
	delete(f.ofPorts, port)
	return nil
}

func (f *backendOVS) GetOFPort(_ context.Context, port string) (int32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ofPort, ok := f.ofPorts[port]
	if !ok {
		return 0, ovs.ErrPortNotFound
	}
	return ofPort, nil
}

func (f *backendOVS) vxlanPorts() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.ports)
}

var errSwitchRefused = errors.New("switch refused the flow batch")

// backendSwitch counts the flow batches sent to it and refuses the one
// numbered refuse (1-based); zero refuses none.
type backendSwitch struct {
	mu      sync.Mutex
	batches int
	refuse  int
}

func (s *backendSwitch) SendFlowMods(context.Context, []*openflow.FlowMod) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.batches++
	if s.batches == s.refuse {
		return errSwitchRefused
	}
	return nil
}

func (s *backendSwitch) sent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.batches
}

// idleVerdictStream delivers no verdict and returns when ctx ends.
type idleVerdictStream struct{}

func (idleVerdictStream) Follow(ctx context.Context, _ func(context.Context, deviceverdict.DeviceVerdict)) error {
	<-ctx.Done()
	return ctx.Err()
}

func newTestOverlayBackend(t *testing.T, cfg *OverlayServiceConfig, of *backendSwitch) (*overlayBackend, *backendOVS) {
	t.Helper()
	fixture := newAdmissionFixture(t)
	ovsClient := newBackendOVS(cfg.AccessPort)
	return &overlayBackend{
		config:   cfg,
		ovs:      ovsClient,
		of:       of,
		ipam:     fixture.ipam,
		devices:  fixture.devices,
		verdicts: fixture.verdicts,
		stream:   idleVerdictStream{},
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
		bridge:   "br-overlay",
	}, ovsClient
}

// An overlay that reported running with no VNI joined forwarded nothing while
// its health said otherwise.
func TestOverlayBackend_StartJoinsConfiguredVNIs(t *testing.T) {
	cfg := validOverlayServiceConfig()
	backend, _ := newTestOverlayBackend(t, cfg, &backendSwitch{})
	ctx := context.Background()

	require.NoError(t, backend.Start(ctx))
	t.Cleanup(func() { require.NoError(t, backend.Stop(ctx)) })

	status := backend.Status()
	require.NotNil(t, status)
	require.Equal(t, len(cfg.VNIs), status.VNICount)
	require.True(t, backend.Active())
	require.True(t, backend.Healthy())
}

// Health tracks the joined VNIs: a VNI the overlay no longer carries makes it
// unhealthy while it still runs.
func TestOverlayBackend_HealthyNeedsEveryConfiguredVNI(t *testing.T) {
	cfg := validOverlayServiceConfig()
	backend, _ := newTestOverlayBackend(t, cfg, &backendSwitch{})
	ctx := context.Background()
	require.NoError(t, backend.Start(ctx))
	t.Cleanup(func() { require.NoError(t, backend.Stop(ctx)) })

	require.NoError(t, backend.handler.RemoveVNI(ctx, cfg.VNIs[1].VNI))

	require.True(t, backend.Active())
	require.False(t, backend.Healthy())
}

// With transit `bgp:` and overlay RR peers both configured, the transit
// speaker holds port 179 and an overlay speaker listening on the VTEP address
// failed the start with "address in use". The overlay speaker only dials,
// from the VTEP address the route reflectors know it by.
func TestOverlayBackend_SpeakerDialsTheRouteReflectorsWithoutListening(t *testing.T) {
	cfg := validOverlayServiceConfig()
	rr := netip.MustParseAddr("10.4.100.10")
	cfg.RRPeers = []bgp.NeighborConfig{{
		Name: "cp-01-rr", Address: rr, ASN: cfg.OverlayASN, EnabledFamilies: []bgp.AddressFamily{bgp.AFamilyEVPN},
	}}
	server := &fakeBGPServer{}
	backend, _ := newTestOverlayBackend(t, cfg, &backendSwitch{})
	backend.server = server
	ctx := context.Background()

	require.NoError(t, backend.Start(ctx))
	t.Cleanup(func() { require.NoError(t, backend.Stop(ctx)) })

	server.mu.Lock()
	defer server.mu.Unlock()
	require.NotNil(t, server.global)
	require.Equal(t, int32(-1), server.global.ListenPort, "the overlay speaker must open no listener")
	require.Empty(t, server.global.ListenAddresses)
	require.Len(t, server.added, 1)
	require.Equal(t, rr.String(), server.added[0].Conf.NeighborAddress)
	require.False(t, server.added[0].Transport.PassiveMode)
	require.Equal(t, cfg.LocalVTEP.String(), server.added[0].Transport.LocalAddress)
}

func TestOverlayBackend_StartFailsWhenAVNIJoinIsRefused(t *testing.T) {
	ctx := context.Background()

	// A start with no VNI to join sends the handler's own batches; the next
	// batch is the first VNI's segment.
	probeCfg := validOverlayServiceConfig()
	probeCfg.VNIs = nil
	probeSwitch := &backendSwitch{}
	probe, _ := newTestOverlayBackend(t, probeCfg, probeSwitch)
	require.NoError(t, probe.Start(ctx))
	handlerBatches := probeSwitch.sent()
	require.NoError(t, probe.Stop(ctx))

	cfg := validOverlayServiceConfig()
	backend, ovsClient := newTestOverlayBackend(t, cfg, &backendSwitch{refuse: handlerBatches + 2})

	err := backend.Start(ctx)

	var refused *modes.ErrVNIOperationFailed
	require.ErrorAs(t, err, &refused)
	require.Equal(t, cfg.VNIs[1].VNI, refused.VNI)
	require.ErrorIs(t, err, errSwitchRefused)
	require.False(t, backend.Active())
	require.False(t, backend.Healthy())
	require.Nil(t, backend.Status())
	require.Zero(t, ovsClient.vxlanPorts(), "a refused start must not leave the VXLAN port behind")
	require.NoError(t, backend.Start(ctx), "a refused start must leave the service startable")
	require.NoError(t, backend.Stop(ctx))
}
