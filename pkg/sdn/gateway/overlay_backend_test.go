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
	api "github.com/osrg/gobgp/v4/api"
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

// The backend tests drive VNI joins, not the neighbor discovery datapath:
// the switch stays connected and accepts every packet-out and meter.

func (s *backendSwitch) IsConnected() bool { return true }

func (s *backendSwitch) Connect(context.Context) error { return nil }

func (s *backendSwitch) SendPacketOut(context.Context, *openflow.PacketOut) error { return nil }

func (s *backendSwitch) SetMeter(context.Context, uint32, uint32, uint32) error { return nil }

func (s *backendSwitch) DeleteMeter(context.Context, uint32) error { return nil }

func (s *backendSwitch) GetMeterStats(context.Context, uint32) (openflow.MeterStats, error) {
	return openflow.MeterStats{}, nil
}

func (s *backendSwitch) SubscribePacketIn(queueSize int) (*openflow.PacketInSubscription, error) {
	return openflow.NewPacketInSubscription(queueSize, func() {})
}

func (s *backendSwitch) sent() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.batches
}

// idleVerdictStream delivers no verdict and returns when ctx ends.
type idleVerdictStream struct{}

func (idleVerdictStream) Follow(ctx context.Context, _ func(context.Context, deviceverdict.RecordedDeviceVerdict)) error {
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

// The documented rr-peers carry no policy, and RFC 8212 rejects every EVPN
// route a peer's route-target allowlists do not name: the session came up
// and carried no Type-2 or Type-3 route either way. A peer with no allowlist
// gets the route targets of the configured VNIs; a peer that names its own
// keeps them.
func TestOverlayBackend_RRPeersDefaultToTheOverlayRouteTargets(t *testing.T) {
	cfg := validOverlayServiceConfig()
	cfg.RRPeers = []bgp.NeighborConfig{
		{Name: "rr-default", Address: netip.MustParseAddr("10.4.100.10"), ASN: cfg.OverlayASN},
		{Name: "rr-explicit", Address: netip.MustParseAddr("10.4.100.11"), ASN: cfg.OverlayASN,
			Policy: bgp.PeerPolicyConfig{ImportRouteTargets: []string{"65000:7"}}},
	}
	var want []string
	for _, v := range cfg.VNIs {
		rt, err := bgp.AutoRouteTarget(uint16(cfg.OverlayASN), 0, v.VNI)
		require.NoError(t, err)
		want = append(want, rt.String())
	}

	peers, err := overlayRRPeers(cfg)

	require.NoError(t, err)
	require.Equal(t, want, peers[0].Policy.ImportRouteTargets)
	require.Equal(t, want, peers[0].Policy.ExportRouteTargets)
	require.Equal(t, []string{"65000:7"}, peers[1].Policy.ImportRouteTargets, "an explicit import allowlist is kept")
	require.Equal(t, want, peers[1].Policy.ExportRouteTargets)
	require.Empty(t, cfg.RRPeers[0].Policy.ImportRouteTargets, "the configuration is not rewritten")

	t.Run("the speaker installs both allowlists", func(t *testing.T) {
		cfg.RRPeers = cfg.RRPeers[:1]
		server := &fakeBGPServer{}
		backend, _ := newTestOverlayBackend(t, cfg, &backendSwitch{})
		backend.server = server
		ctx := context.Background()
		require.NoError(t, backend.Start(ctx))
		t.Cleanup(func() { require.NoError(t, backend.Stop(ctx)) })

		server.mu.Lock()
		defer server.mu.Unlock()
		require.NotNil(t, server.policies)
		var rtSets int
		for _, set := range server.policies.GetDefinedSets() {
			if set.GetDefinedType() == api.DefinedType_DEFINED_TYPE_EXT_COMMUNITY {
				rtSets++
				require.Len(t, set.GetList(), len(cfg.VNIs), set.GetName())
			}
		}
		require.Equal(t, 2, rtSets, "one import and one export route-target set")
	})

	t.Run("a VNI outside the route-target range is refused", func(t *testing.T) {
		bad := validOverlayServiceConfig()
		bad.RRPeers = cfg.RRPeers[:1]
		bad.OverlayASN = 64000
		_, err := overlayRRPeers(bad)
		var invalid bgp.ErrRouteTargetInvalid
		require.ErrorAs(t, err, &invalid)
	})
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
