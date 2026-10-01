// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package gateway

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// ---------------------------------------------------------------------------
// Fakes for the host-programming services.
// ---------------------------------------------------------------------------

// fakeBGPServer satisfies bgp.BGPServerInterface without GoBGP: it records
// the lifecycle so the transit backend can be started in a unit test.
type fakeBGPServer struct {
	mu        sync.Mutex
	started   bool
	stopped   bool
	peers     int
	startErr  error
	listPeers []*api.Peer
	listErr   error
}

func (f *fakeBGPServer) Start() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.startErr != nil {
		return f.startErr
	}
	f.started = true
	return nil
}
func (f *fakeBGPServer) Stop()                                                { f.mu.Lock(); f.stopped = true; f.mu.Unlock() }
func (f *fakeBGPServer) StartBgp(context.Context, *api.StartBgpRequest) error { return nil }
func (f *fakeBGPServer) StopBgp(context.Context, *api.StopBgpRequest) error   { return nil }
func (f *fakeBGPServer) AddPeer(context.Context, *api.AddPeerRequest) error {
	f.mu.Lock()
	f.peers++
	f.mu.Unlock()
	return nil
}
func (f *fakeBGPServer) DeletePeer(context.Context, *api.DeletePeerRequest) error { return nil }
func (f *fakeBGPServer) UpdatePeer(context.Context, *api.UpdatePeerRequest) (*api.UpdatePeerResponse, error) {
	return &api.UpdatePeerResponse{}, nil
}
func (f *fakeBGPServer) GetBgp(context.Context, *api.GetBgpRequest) (*api.GetBgpResponse, error) {
	return &api.GetBgpResponse{Global: &api.Global{}}, nil
}
func (f *fakeBGPServer) ListPeer(_ context.Context, _ *api.ListPeerRequest, fn func(*api.Peer)) error {
	f.mu.Lock()
	peers, err := f.listPeers, f.listErr
	f.mu.Unlock()
	if err != nil {
		return err
	}
	for _, peer := range peers {
		fn(peer)
	}
	return nil
}
func (f *fakeBGPServer) ResetPeer(context.Context, *api.ResetPeerRequest) error   { return nil }
func (f *fakeBGPServer) EnableMrt(context.Context, *api.EnableMrtRequest) error   { return nil }
func (f *fakeBGPServer) DisableMrt(context.Context, *api.DisableMrtRequest) error { return nil }
func (f *fakeBGPServer) AddPath(context.Context, *api.AddPathRequest) (*api.AddPathResponse, error) {
	return &api.AddPathResponse{}, nil
}
func (f *fakeBGPServer) DeletePath(context.Context, *api.DeletePathRequest) error { return nil }
func (f *fakeBGPServer) ListPath(context.Context, *api.ListPathRequest, func(*api.Destination)) error {
	return nil
}
func (f *fakeBGPServer) WatchEvent(context.Context, *api.WatchEventRequest, func(*api.WatchEventResponse)) error {
	return nil
}
func (f *fakeBGPServer) AddTcpAoKeychain(context.Context, *api.AddTcpAoKeychainRequest) error {
	return nil
}
func (f *fakeBGPServer) SetPolicies(context.Context, *api.SetPoliciesRequest) error { return nil }
func (f *fakeBGPServer) SetPolicyAssignment(context.Context, *api.SetPolicyAssignmentRequest) error {
	return nil
}

var _ bgp.BGPServerInterface = (*fakeBGPServer)(nil)

// fakeTunnelManager records tunnel lifecycle calls.
type fakeTunnelManager struct {
	mu        sync.Mutex
	ensured   []string
	removed   []string
	closed    bool
	down      map[string]bool
	ensureErr map[string]error
	listErr   error
	statuses  map[string]tunnel.TunnelStatus
	uplinks   []tunnel.UplinkStatus
}

func (f *fakeTunnelManager) EnsureTunnel(_ context.Context, cfg tunnel.TunnelConfig) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.ensureErr[cfg.Name]; ok {
		return err
	}
	f.ensured = append(f.ensured, cfg.Name)
	return nil
}

func (f *fakeTunnelManager) RemoveTunnel(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed = append(f.removed, name)
	for i, n := range f.ensured {
		if n == name {
			f.ensured = append(f.ensured[:i], f.ensured[i+1:]...)
			break
		}
	}
	return nil
}

func (f *fakeTunnelManager) ListTunnels(context.Context) ([]*tunnel.TunnelStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make([]*tunnel.TunnelStatus, 0, len(f.ensured))
	for _, n := range f.ensured {
		state := tunnel.TunnelStateUp
		if f.down[n] {
			state = tunnel.TunnelStateDown
		}
		if status, ok := f.statuses[n]; ok {
			status.Name = n
			status.State = state
			out = append(out, &status)
			continue
		}
		out = append(out, &tunnel.TunnelStatus{Name: n, State: state})
	}
	return out, nil
}

func (f *fakeTunnelManager) Uplinks() []tunnel.UplinkStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.uplinks
}

func (f *fakeTunnelManager) Close() error { f.mu.Lock(); f.closed = true; f.mu.Unlock(); return nil }

// fakeHostFWApplier records the rendered rulesets the host filter applies.
type fakeHostFWApplier struct {
	mu      sync.Mutex
	applied int
	removed int
	present bool
}

func (f *fakeHostFWApplier) Apply(context.Context, *hostfw.Rendered) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applied++
	f.present = true
	return nil
}
func (f *fakeHostFWApplier) Remove(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.removed++
	f.present = false
	return nil
}
func (f *fakeHostFWApplier) Installed(context.Context) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.present, nil
}

// baseGatewayConfig is an enabled gateway with valid requirement gates and
// no service section.
func baseGatewayConfig(id string) *GatewayConfig {
	return &GatewayConfig{
		Enabled:       true,
		ID:            id,
		MinReputation: MinReputation,
		MinAgeDays:    MinAgeDays,
		MinUptimePct:  MinUptimePct,
	}
}

func transitGatewayConfig(server bgp.BGPServerInterface) *GatewayConfig {
	cfg := baseGatewayConfig("transit-gw")
	cfg.BGP = &bgp.BGPConfig{
		RouterID: netip.MustParseAddr("203.0.113.4"),
		ASN:      64512,
		Neighbors: []bgp.NeighborConfig{{
			Address:         netip.MustParseAddr("10.255.0.2"),
			ASN:             64512,
			EnabledFamilies: []bgp.AddressFamily{bgp.AFamilyIPv4Unicast},
		}},
	}
	cfg.Host = &HostRuntime{BGPServer: server}
	return cfg
}

// ---------------------------------------------------------------------------
// The contract: every enabled section is a real builder or a typed refusal.
// ---------------------------------------------------------------------------

func TestEnabledServices_EveryEntryIsBuiltOrRefused(t *testing.T) {
	cfg := &GatewayConfig{
		Enabled:       true,
		ID:            "all-sections",
		Firewall:      &FirewallConfig{Enabled: true},
		NAT:           &NATConfig{Enabled: true},
		LoadBalancer:  &LoadBalancerConfig{Enabled: true},
		HostFW:        &hostfw.Config{Enabled: true},
		Tunnels:       []TunnelConfig{{Name: "gre1"}},
		BGP:           &bgp.BGPConfig{},
		Overlay:       &OverlayServiceConfig{Enabled: true},
		Edge:          &EdgeConfig{Enabled: true},
		DHCP:          &DHCPServiceConfig{Enabled: true},
		PXE:           &PXEServiceConfig{Enabled: true, HTTPPort: 8069},
		ManagementVPN: &ManagementVPNServiceConfig{Enabled: true},
		NAT64: &NAT64Config{
			Enabled:        true,
			TranslatorPort: "nat640",
			Pool4: NAT64Pool4Config{
				Addresses:      []string{"203.0.113.64-203.0.113.71"},
				PortRangeStart: 61001,
				PortRangeEnd:   65535,
			},
		},
	}
	names := cfg.EnabledServices()
	require.Len(t, names, 12)
	assert.Equal(t, []string{
		ServiceFirewall, ServiceNAT, ServiceLoadBalancer, ServiceNAT64, ServiceHostFW, ServiceTunnels, ServiceTransit,
		ServiceOverlay, ServiceEdge, ServiceDHCP, ServicePXE, ServiceManagementVPN,
	}, names, "datapath services first, then host services, then refused sections")

	built := map[string]bool{}
	refused := map[string]bool{}
	for _, name := range names {
		_, hasBuilder := serviceBuilders[name]
		_, hasRefusal := serviceRefusals[name]
		assert.True(t, hasBuilder != hasRefusal, "%s must be exactly one of built or refused (builder=%v refusal=%v)", name, hasBuilder, hasRefusal)
		if hasBuilder {
			built[name] = true
		} else {
			refused[name] = true
		}
	}
	assert.Equal(t, map[string]bool{ServiceFirewall: true, ServiceNAT: true, ServiceLoadBalancer: true, ServiceNAT64: true, ServiceHostFW: true, ServiceTunnels: true, ServiceTransit: true}, built)
	assert.Equal(t, map[string]bool{ServiceOverlay: true, ServiceEdge: true, ServiceDHCP: true, ServicePXE: true, ServiceManagementVPN: true}, refused)
	for name := range refused {
		assert.NotEmpty(t, serviceRefusals[name], "refusal for %s names no blocker", name)
	}
	assert.True(t, cfg.HasEnabledServices())
	assert.False(t, baseGatewayConfig("none").HasEnabledServices())
}

func TestNewGateway_RegistersHandlersInDeclaredOrder(t *testing.T) {
	cfg := firewallGatewayConfig()
	cfg.Tunnels = []TunnelConfig{{Name: "gre1", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30"}}
	cfg.Overlay = &OverlayServiceConfig{Enabled: true}
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	assert.Equal(t, []string{ServiceFirewall, ServiceTunnels, ServiceOverlay}, gw.serviceOrder)
	_, isBacked := gw.serviceHandlers[ServiceFirewall].(*backedServiceHandler)
	assert.True(t, isBacked)
	_, isRefused := gw.serviceHandlers[ServiceOverlay].(*refusedServiceHandler)
	assert.True(t, isRefused)
}

// TestGatewayStart_RefusedSectionIsATypedStartError pins the core of #568:
// an enabled section with no builder fails Start with an error naming the
// section and the blocker, and the gateway is left in the error state with
// no pipeline behind.
func TestGatewayStart_RefusedSectionIsATypedStartError(t *testing.T) {
	sections := map[string]func(*GatewayConfig){
		ServiceOverlay:       func(c *GatewayConfig) { c.Overlay = &OverlayServiceConfig{Enabled: true} },
		ServiceEdge:          func(c *GatewayConfig) { c.Edge = &EdgeConfig{Enabled: true, MaxDevices: 100, MaxServices: 50} },
		ServiceDHCP:          func(c *GatewayConfig) { c.DHCP = &DHCPServiceConfig{Enabled: true, Interface: "eth0"} },
		ServicePXE:           func(c *GatewayConfig) { c.PXE = &PXEServiceConfig{Enabled: true, HTTPPort: 8069} },
		ServiceManagementVPN: func(c *GatewayConfig) { c.ManagementVPN = &ManagementVPNServiceConfig{Enabled: true} },
	}
	for name, enable := range sections {
		t.Run(name, func(t *testing.T) {
			cfg := baseGatewayConfig("refused-" + name)
			enable(cfg)
			gw, err := NewGateway(cfg)
			require.NoError(t, err, "construction stays inspectable; the refusal is at Start")
			gw.SetNodeMetrics(validNodeMetrics())
			err = gw.Start(context.Background())
			var startup *ErrStartupFailed
			require.True(t, errors.As(err, &startup), "got %v", err)
			assert.Equal(t, "service-start", startup.Phase)
			var unavailable *ErrServiceUnavailable
			require.True(t, errors.As(err, &unavailable), "got %v", err)
			assert.Equal(t, name, unavailable.Service)
			assert.Contains(t, err.Error(), name)
			assert.Equal(t, GatewayStateError, gw.GetState())
			assert.Empty(t, gw.ActiveServices())
		})
	}
}

func TestGatewayStart_RefusedSectionRollsBackTheStartedOnes(t *testing.T) {
	cfg := firewallGatewayConfig()
	cfg.Overlay = &OverlayServiceConfig{Enabled: true}
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())
	var unavailable *ErrServiceUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, ServiceOverlay, unavailable.Service)
	assert.False(t, cfg.Runtime.PipelineInstalled(), "the pipeline installed for the firewall is rolled back")
	_, fwRunning := gw.FirewallHealth()
	assert.False(t, fwRunning, "the firewall started before the refusal is stopped again")
	assert.Empty(t, gw.ActiveServices())
}

func TestGatewayStart_RollbackStopFailureIsLoggedNotLost(t *testing.T) {
	var logs bytes.Buffer
	cfg := baseGatewayConfig("rollback-log")
	cfg.Host = &HostRuntime{Logger: slog.New(slog.NewTextHandler(&logs, nil))}
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	stuck := &fakeBacked{stopErr: errors.New("backend will not stop")}
	require.NoError(t, gw.RegisterServiceHandler(&backedServiceHandler{
		gateway: gw, name: "stuck", build: func(*Gateway) (backedService, error) { return stuck, nil },
	}))
	require.NoError(t, gw.RegisterServiceHandler(&refusedServiceHandler{name: "never", reason: "test refusal"}))
	gw.SetNodeMetrics(validNodeMetrics())

	err = gw.Start(context.Background())
	var unavailable *ErrServiceUnavailable
	require.True(t, errors.As(err, &unavailable), "the start error is the refusal, got %v", err)
	assert.Contains(t, logs.String(), "rollback stop failed")
	assert.Contains(t, logs.String(), "backend will not stop")
	assert.Empty(t, gw.ActiveServices())
}

// ---------------------------------------------------------------------------
// The generic handler.
// ---------------------------------------------------------------------------

type fakeBacked struct {
	mu         sync.Mutex
	started    bool
	healthy    bool
	startErr   error
	stopErr    error
	startCalls int
}

func (f *fakeBacked) Start(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.startCalls++
	if f.startErr != nil {
		return f.startErr
	}
	f.started = true
	f.healthy = true
	return nil
}
func (f *fakeBacked) Stop(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.stopErr != nil {
		return f.stopErr
	}
	f.started = false
	return nil
}
func (f *fakeBacked) Active() bool  { f.mu.Lock(); defer f.mu.Unlock(); return f.started }
func (f *fakeBacked) Healthy() bool { f.mu.Lock(); defer f.mu.Unlock(); return f.started && f.healthy }

func TestBackedServiceHandler_Lifecycle(t *testing.T) {
	svc := &fakeBacked{}
	h := newBackedServiceHandler(nil, "fake", func(*Gateway) (backedService, error) { return svc, nil })
	assert.Equal(t, "fake", h.Name())
	assert.False(t, h.IsActive())
	var notActive *ErrServiceNotActive
	require.True(t, errors.As(h.Health(), &notActive))
	require.True(t, errors.As(h.Stop(context.Background()), &notActive), "stopping a stopped service is the typed error")

	require.NoError(t, h.Start(context.Background()))
	assert.True(t, h.IsActive())
	assert.NoError(t, h.Health())
	var already *ErrServiceAlreadyActive
	require.True(t, errors.As(h.Start(context.Background()), &already))
	assert.Equal(t, 1, svc.startCalls)

	// Health follows the service, not a handler flag.
	svc.mu.Lock()
	svc.healthy = false
	svc.mu.Unlock()
	require.True(t, errors.As(h.Health(), &notActive))
	assert.True(t, h.IsActive(), "active and unhealthy are different answers")

	require.NoError(t, h.Stop(context.Background()))
	assert.False(t, h.IsActive())
	assert.Nil(t, h.service())
}

func TestBackedServiceHandler_Errors(t *testing.T) {
	t.Run("builder failure is returned as is", func(t *testing.T) {
		want := &ErrRuntimeMissing{Service: "fake"}
		h := newBackedServiceHandler(nil, "fake", func(*Gateway) (backedService, error) { return nil, want })
		err := h.Start(context.Background())
		var got *ErrRuntimeMissing
		require.True(t, errors.As(err, &got))
		assert.False(t, h.IsActive())
	})
	t.Run("service start failure is wrapped and leaves the handler inactive", func(t *testing.T) {
		svc := &fakeBacked{startErr: errors.New("boom")}
		h := newBackedServiceHandler(nil, "fake", func(*Gateway) (backedService, error) { return svc, nil })
		err := h.Start(context.Background())
		var failed *ErrServiceStartFailed
		require.True(t, errors.As(err, &failed))
		assert.Equal(t, "fake", failed.Service)
		assert.False(t, h.IsActive())
		assert.Nil(t, h.service())
	})
	t.Run("service stop failure is wrapped and the handler stays active", func(t *testing.T) {
		svc := &fakeBacked{stopErr: errors.New("stuck")}
		h := newBackedServiceHandler(nil, "fake", func(*Gateway) (backedService, error) { return svc, nil })
		require.NoError(t, h.Start(context.Background()))
		err := h.Stop(context.Background())
		var failed *ErrServiceStopFailed
		require.True(t, errors.As(err, &failed))
		assert.True(t, h.IsActive())
	})
}

func TestRefusedServiceHandler(t *testing.T) {
	h := &refusedServiceHandler{name: ServiceDHCP, reason: "no allocator"}
	assert.Equal(t, ServiceDHCP, h.Name())
	assert.False(t, h.IsActive())
	var unavailable *ErrServiceUnavailable
	require.True(t, errors.As(h.Start(context.Background()), &unavailable))
	assert.Equal(t, "no allocator", unavailable.Reason)
	require.True(t, errors.As(h.Health(), &unavailable))
	var notActive *ErrServiceNotActive
	require.True(t, errors.As(h.Stop(context.Background()), &notActive))
	assert.Contains(t, (&ErrServiceUnavailable{Service: "x", Reason: "y"}).Error(), "y")
}

// ---------------------------------------------------------------------------
// Builders.
// ---------------------------------------------------------------------------

func TestBuilders_RefuseWithoutTheirRuntime(t *testing.T) {
	for _, name := range []string{ServiceFirewall, ServiceNAT, ServiceLoadBalancer, ServiceNAT64} {
		t.Run(name, func(t *testing.T) {
			cfg := baseGatewayConfig("no-runtime")
			cfg.Firewall = &FirewallConfig{Enabled: true}
			cfg.NAT = &NATConfig{Enabled: true, ExternalIP: "203.0.113.10", PortRangeStart: 1024, PortRangeEnd: 65535, MaxSessions: 10, InternalCIDR: "10.0.0.0/24"}
			cfg.LoadBalancer = &LoadBalancerConfig{Enabled: true}
			cfg.NAT64 = &NAT64Config{
				Enabled:        true,
				TranslatorPort: "nat640",
				Pool4: NAT64Pool4Config{
					Addresses:      []string{"198.51.100.8-198.51.100.15"},
					PortRangeStart: 61001,
					PortRangeEnd:   65535,
				},
			}
			gw := &Gateway{config: cfg}
			_, err := serviceBuilders[name](gw)
			var missing *ErrRuntimeMissing
			require.True(t, errors.As(err, &missing), "got %v", err)
			assert.Equal(t, name, missing.Service)
		})
	}
	_, err := buildTransit(&Gateway{config: baseGatewayConfig("no-bgp")})
	var unavailable *ErrServiceUnavailable
	require.True(t, errors.As(err, &unavailable))
}

func TestTunnelsService_Lifecycle(t *testing.T) {
	mgr := &fakeTunnelManager{down: map[string]bool{}}
	cfg := baseGatewayConfig("tunnel-gw")
	cfg.Tunnels = []TunnelConfig{
		{Name: "gre-pri", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30"},
		{Name: "gre-alt", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.2", TunnelIP: "10.255.0.5/30"},
	}
	cfg.Host = &HostRuntime{TunnelManager: mgr}
	gw := startGateway(t, cfg)

	assert.True(t, gw.HasService(ServiceTunnels))
	assert.Equal(t, []string{"gre-pri", "gre-alt"}, mgr.ensured)
	assert.NoError(t, gw.serviceHandlers[ServiceTunnels].Health())
	assert.Equal(t, "healthy", gw.Snapshot().Health.Components[ServiceTunnels])

	// A tunnel that goes down degrades the service without stopping it.
	mgr.mu.Lock()
	mgr.down["gre-alt"] = true
	mgr.mu.Unlock()
	assert.Error(t, gw.serviceHandlers[ServiceTunnels].Health())
	assert.True(t, gw.serviceHandlers[ServiceTunnels].IsActive())
	assert.Equal(t, "degraded", gw.Snapshot().Health.Status)

	require.NoError(t, gw.Stop(context.Background()))
	assert.Equal(t, []string{"gre-alt", "gre-pri"}, mgr.removed, "removed in reverse order")
	assert.True(t, mgr.closed)
}

func TestTunnelsService_RollsBackOnEnsureFailure(t *testing.T) {
	mgr := &fakeTunnelManager{ensureErr: map[string]error{"gre-alt": errors.New("EPERM")}}
	cfg := baseGatewayConfig("tunnel-gw-fail")
	cfg.Tunnels = []TunnelConfig{
		{Name: "gre-pri", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30"},
		{Name: "gre-alt", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.2", TunnelIP: "10.255.0.5/30"},
	}
	cfg.Host = &HostRuntime{TunnelManager: mgr}
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())
	var failed *ErrServiceStartFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	assert.Equal(t, ServiceTunnels, failed.Service)
	assert.Equal(t, []string{"gre-pri"}, mgr.removed, "the tunnel created before the failure is removed")
	assert.Empty(t, mgr.ensured)
}

func TestTunnelConfig_MapsOntoTheTunnelPackage(t *testing.T) {
	got := TunnelConfig{Name: "gre1", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30"}.tunnelConfig()
	assert.Equal(t, tunnel.TunnelConfig{Name: "gre1", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30"}, got)
}

// TestTunnelConfig_CarriesTheIPv6Address: the gateway section decodes
// `tunnel-ipv6` and the tunnel manager applies it when present, so an adapter
// that drops it produces an IPv4-only interface from a configuration that
// asked for dual-stack — accepted and silently discarded, which is the defect
// class the bring-up runbook exists to describe. Every tunnel in the shipped
// X10 template sets this field.
func TestTunnelConfig_CarriesTheIPv6Address(t *testing.T) {
	got := TunnelConfig{
		Name:       "gre-pri-isp-a",
		Type:       "gre",
		Local:      "192.0.2.1",
		Remote:     "198.51.100.1",
		TunnelIP:   "10.255.0.33/30",
		TunnelIPv6: "2001:DB8:CAFE:11::1/64",
	}.tunnelConfig()

	assert.Equal(t, "2001:DB8:CAFE:11::1/64", got.TunnelIPv6,
		"the IPv6 address must reach the tunnel package or the interface comes up v4-only")
	assert.Equal(t, "10.255.0.33/30", got.TunnelIP, "the IPv4 address is unaffected")

	// An unset field stays unset rather than becoming an empty address the
	// manager would try to add.
	none := TunnelConfig{Name: "gre1", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30"}.tunnelConfig()
	assert.Empty(t, none.TunnelIPv6)
}

func TestHostFWService_Lifecycle(t *testing.T) {
	applier := &fakeHostFWApplier{}
	cfg := baseGatewayConfig("hostfw-gw")
	cfg.HostFW = &hostfw.Config{
		Enabled: true,
		Extra:   []hostfw.Listener{{Interface: "eth0", Protocol: hostfw.ProtocolTCP, Port: 22, Comment: "sshd"}},
		Tunnels: []string{"gre-pri"},
	}
	cfg.Tunnels = []TunnelConfig{{Name: "gre-pri", Type: "gre", Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30"}}
	cfg.Host = &HostRuntime{
		HostFWApplier: applier,
		Listeners:     hostfw.StaticInventory{{Protocol: hostfw.ProtocolTCP, Port: 8443, Comment: "proxy edge"}},
		TunnelManager: &fakeTunnelManager{},
	}
	gw := startGateway(t, cfg)
	defer func() { require.NoError(t, gw.Stop(context.Background())) }()

	assert.True(t, gw.HasService(ServiceHostFW))
	assert.Equal(t, 1, applier.applied)
	svc, ok := gw.HostFWService()
	require.True(t, ok)
	rendered := svc.Rendered()
	require.NotNil(t, rendered)
	text := rendered.Text
	assert.Contains(t, text, "dport 22")
	assert.Contains(t, text, "dport 8443", "the daemon's own listener inventory is admitted")
	assert.Contains(t, text, "gre-pri", "the gateway's tunnels are BGP/BFD carriers the filter admits on")
	assert.Equal(t, 1, strings.Count(text, `iifname "gre-pri" tcp dport 179`), "a tunnel the operator also listed is admitted once")

	require.NoError(t, gw.ReconcileHostFW(context.Background()))
	assert.Equal(t, "healthy", gw.Snapshot().Health.Components[ServiceHostFW])
}

func TestHostFWService_InvalidConfigIsRefusedAtValidate(t *testing.T) {
	cfg := baseGatewayConfig("hostfw-bad")
	cfg.HostFW = &hostfw.Config{Enabled: true, Extra: []hostfw.Listener{{Interface: "eth0", Protocol: hostfw.ProtocolTCP, Port: 0}}}
	_, err := NewGateway(cfg)
	var invalid *ErrHostFWConfigInvalid
	require.True(t, errors.As(err, &invalid), "got %v", err)
}

func TestTransitService_Lifecycle(t *testing.T) {
	server := &fakeBGPServer{}
	gw := startGateway(t, transitGatewayConfig(server))
	assert.True(t, gw.HasService(ServiceTransit))
	assert.True(t, server.started)
	assert.Equal(t, 1, server.peers)
	speaker, ok := gw.BGPSpeaker()
	require.True(t, ok)
	assert.True(t, speaker.IsStarted())
	assert.Equal(t, "healthy", gw.Snapshot().Health.Components[ServiceTransit])
	assert.Equal(t, uint32(64512), gw.Snapshot().BGP.LocalASN)

	require.NoError(t, gw.Stop(context.Background()))
	assert.True(t, server.stopped)
	_, ok = gw.BGPSpeaker()
	assert.False(t, ok)
}

func TestTransitService_SecretReferenceNeedsAResolver(t *testing.T) {
	cfg := transitGatewayConfig(&fakeBGPServer{})
	// A TCP-AO keychain carries its master key by reference only; it is
	// FIPS-neutral, so this test runs identically in both builds.
	cfg.BGP.Keychains = []bgp.TCPAOKeychainConfig{{
		Name: "pop-a",
		Keys: []bgp.TCPAOKeyConfig{{SendID: 1, ReceiveID: 1, Algorithm: bgp.TCPAOAlgorithmHMACSHA256_128, MasterKeyRef: "kms://platform/bgp/pop-a"}},
	}}
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())
	var required bgp.ErrSecretResolverRequired
	require.True(t, errors.As(err, &required), "got %v", err)
	assert.Equal(t, 1, strings.Count(err.Error(), "failed to start service transit"), "the service is named once: %v", err)
	assert.False(t, cfg.Host.BGPServer.(*fakeBGPServer).started, "no session starts without its secret")

	// With a resolver the secret is resolved into a private copy of the
	// config, never back into the shared configuration.
	cfg.Host.SecretResolver = func(context.Context, string) ([]byte, error) { return []byte("s3cret"), nil }
	gw, err = NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	require.NoError(t, gw.Start(context.Background()))
	assert.Empty(t, cfg.BGP.Keychains[0].Keys[0].MasterKey, "the configured keychain keeps only its reference")
	require.NoError(t, gw.Stop(context.Background()))
}

func TestTransitService_ServerStartFailure(t *testing.T) {
	server := &fakeBGPServer{startErr: errors.New("port 179 busy")}
	gw, err := NewGateway(transitGatewayConfig(server))
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())
	var failed *ErrServiceStartFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	assert.Equal(t, ServiceTransit, failed.Service)
	assert.Equal(t, GatewayStateError, gw.GetState())
}

func TestProxyListenerInventory(t *testing.T) {
	inv, err := ProxyListenerInventory(map[string]string{"edge": "0.0.0.0:8443", "v6": "[::]:443"})
	require.NoError(t, err)
	require.Len(t, inv, 2)
	ports := map[uint16]bool{}
	for _, l := range inv {
		ports[l.Port] = true
		assert.Equal(t, hostfw.ProtocolTCP, l.Protocol)
		assert.Empty(t, l.Interface, "an unpinned bind is every interface")
	}
	assert.True(t, ports[8443] && ports[443])

	ephemeral, err := ProxyListenerInventory(map[string]string{"test": "127.0.0.1:0", "edge": ":443"})
	require.NoError(t, err)
	require.Len(t, ephemeral, 1, "a kernel-assigned port cannot be opened ahead of the bind")
	assert.Equal(t, uint16(443), ephemeral[0].Port)

	for _, bad := range []string{"no-port", "10.0.0.1:70000", "10.0.0.1:x", "10.0.0.1:-1"} {
		_, err := ProxyListenerInventory(map[string]string{"bad": bad})
		var inventoryErr *ErrListenerInventory
		require.True(t, errors.As(err, &inventoryErr), "%s: got %v", bad, err)
		assert.Contains(t, err.Error(), "bad")
	}
	var portErr *ErrListenerPort
	_, err = ProxyListenerInventory(map[string]string{"bad": "10.0.0.1:70000"})
	require.True(t, errors.As(err, &portErr))
	assert.Equal(t, "70000", portErr.Port)
}

func TestHostRuntime_DefaultsLogger(t *testing.T) {
	cfg := baseGatewayConfig("host-rt")
	host := cfg.hostRuntime()
	assert.NotNil(t, host.Logger)
	cfg.Runtime = newTestRuntime()
	assert.NotNil(t, cfg.hostRuntime().Logger)
	cfg.Host = &HostRuntime{}
	assert.NotNil(t, cfg.hostRuntime().Logger)
}

func TestGateway_BackendAccessorsWhenNotRunning(t *testing.T) {
	gw, err := NewGateway(firewallGatewayConfig())
	require.NoError(t, err)
	_, ok := gw.FirewallHealth()
	assert.False(t, ok)
	assert.Error(t, gw.ReconcileFirewall(context.Background()))
	_, ok = gw.LBService()
	assert.False(t, ok)
	_, ok = gw.NATService()
	assert.False(t, ok)
	_, ok = gw.HostFWService()
	assert.False(t, ok)
	assert.Error(t, gw.ReconcileHostFW(context.Background()))
	_, ok = gw.BGPSpeaker()
	assert.False(t, ok)
	_, ok = gw.backend("not-registered")
	assert.False(t, ok)
}

func TestTunnelConfig_CarriesTheTransportSectionsThrough(t *testing.T) {
	ipsec := &tunnel.IPsecConfig{KeyRef: "kms://tunnel/pop-a/out", PeerKeyRef: "kms://tunnel/pop-a/in", SPIOut: 0x100, SPIIn: 0x101}
	got := TunnelConfig{
		Name: "ipsec-a", Type: "gre", Transport: tunnel.TransportIPsec,
		Local: "192.0.2.1", Remote: "198.51.100.1",
		TunnelIP: "10.255.0.1/30", TunnelIPv6: "2001:db8::1/126",
		IPsec: ipsec,
	}.tunnelConfig()
	assert.Equal(t, tunnel.TransportIPsec, got.Transport)
	assert.Same(t, ipsec, got.IPsec, "the ipsec section is passed through, not copied field by field")
	assert.Equal(t, "2001:db8::1/126", got.TunnelIPv6)
}

func TestBuildTunnels_AdaptsTheSecretResolverAsTheKeyProvider(t *testing.T) {
	var asked []string
	cfg := baseGatewayConfig("keyed-tunnels")
	cfg.Tunnels = []TunnelConfig{{
		Name: "ipsec-a", Type: "gre", Transport: tunnel.TransportIPsec,
		Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30",
		IPsec: &tunnel.IPsecConfig{KeyRef: "kms://tunnel/pop-a/out", SPIOut: 0x100, SPIIn: 0x101},
	}}
	cfg.Host = &HostRuntime{
		Logger: slog.Default(),
		SecretResolver: func(_ context.Context, ref string) ([]byte, error) {
			asked = append(asked, ref)
			return nil, errors.New("store unreachable")
		},
	}
	// No injected manager: the builder makes the real netlink one, whose
	// key provider must be the host runtime's resolver.
	svc, err := buildTunnels(&Gateway{config: cfg})
	require.NoError(t, err)
	err = svc.Start(context.Background())
	require.Error(t, err, "an ipsec tunnel whose key cannot be resolved must not start")
	var material *tunnel.ErrKeyMaterial
	require.True(t, errors.As(err, &material), "got %v", err)
	assert.Equal(t, []string{"kms://tunnel/pop-a/out"}, asked, "the resolver is the key provider")
}

func TestBuildTunnels_WithoutAResolverRefusesAKeyedTransport(t *testing.T) {
	cfg := baseGatewayConfig("unkeyed-tunnels")
	cfg.Tunnels = []TunnelConfig{{
		Name: "ipsec-a", Type: "gre", Transport: tunnel.TransportIPsec,
		Local: "192.0.2.1", Remote: "198.51.100.1", TunnelIP: "10.255.0.1/30",
		IPsec: &tunnel.IPsecConfig{KeyRef: "kms://tunnel/pop-a/out", SPIOut: 0x100, SPIIn: 0x101},
	}}
	cfg.Host = &HostRuntime{Logger: slog.Default()}
	svc, err := buildTunnels(&Gateway{config: cfg})
	require.NoError(t, err)
	err = svc.Start(context.Background())
	var required *tunnel.ErrKeyProviderRequired
	require.True(t, errors.As(err, &required), "got %v", err)
}

func TestTransitService_ZeroizesTheResolvedMasterKey(t *testing.T) {
	server := &fakeBGPServer{}
	cfg := transitGatewayConfig(server)
	cfg.BGP.Keychains = []bgp.TCPAOKeychainConfig{{
		Name: "pop-a",
		Keys: []bgp.TCPAOKeyConfig{{SendID: 1, ReceiveID: 1, Algorithm: bgp.TCPAOAlgorithmHMACSHA256_128, MasterKeyRef: "kms://platform/bgp/pop-a"}},
	}}
	var handed [][]byte
	cfg.Host.SecretResolver = func(context.Context, string) ([]byte, error) {
		material := []byte("master-key-material")
		handed = append(handed, material)
		return material, nil
	}
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	require.NoError(t, gw.Start(context.Background()))
	require.NoError(t, gw.Stop(context.Background()))

	require.Len(t, handed, 1)
	assert.Equal(t, make([]byte, len("master-key-material")), handed[0],
		"the resolved master key is wiped once GoBGP holds the keychain")
}

func TestTransitService_ZeroizesWhatItResolvedBeforeAFailure(t *testing.T) {
	server := &fakeBGPServer{}
	cfg := transitGatewayConfig(server)
	cfg.BGP.Keychains = []bgp.TCPAOKeychainConfig{
		{
			Name: "pop-a",
			Keys: []bgp.TCPAOKeyConfig{{SendID: 1, ReceiveID: 1, Algorithm: bgp.TCPAOAlgorithmHMACSHA256_128, MasterKeyRef: "kms://platform/bgp/pop-a"}},
		},
		{
			Name: "pop-b",
			Keys: []bgp.TCPAOKeyConfig{{SendID: 2, ReceiveID: 2, Algorithm: bgp.TCPAOAlgorithmHMACSHA256_128, MasterKeyRef: "kms://platform/bgp/pop-b"}},
		},
	}
	var handed [][]byte
	cfg.Host.SecretResolver = func(_ context.Context, ref string) ([]byte, error) {
		if ref == "kms://platform/bgp/pop-b" {
			return nil, errors.New("store unreachable")
		}
		material := []byte("master-key-material")
		handed = append(handed, material)
		return material, nil
	}
	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())
	require.Error(t, err, "a keychain whose key cannot be resolved must not start the speaker")
	assert.False(t, server.started, "no session starts on a half-resolved keychain set")

	require.Len(t, handed, 1, "the first reference resolved before the second failed")
	assert.Equal(t, make([]byte, len("master-key-material")), handed[0],
		"material resolved before the failure is wiped too")
}
