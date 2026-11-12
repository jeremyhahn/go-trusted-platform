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
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fhrp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
)

// fakeFHRPTransport opens in-memory group sockets and records each open.
type fakeFHRPTransport struct {
	mu     sync.Mutex
	opened []string
}

func (t *fakeFHRPTransport) Open(iface string, _ fhrp.Family, _ netip.Addr) (fhrp.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.opened = append(t.opened, iface)
	return &fakeFHRPConn{closed: make(chan struct{})}, nil
}

func (t *fakeFHRPTransport) Opened() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.opened...)
}

// fakeFHRPConn sends into the void and receives nothing until closed.
type fakeFHRPConn struct {
	once   sync.Once
	closed chan struct{}
}

func (c *fakeFHRPConn) Send([]byte, netip.Addr) error { return nil }

func (c *fakeFHRPConn) Receive(ctx context.Context) ([]byte, netip.Addr, int, error) {
	select {
	case <-ctx.Done():
		return nil, netip.Addr{}, 0, ctx.Err()
	case <-c.closed:
		return nil, netip.Addr{}, 0, net.ErrClosed
	}
}

func (c *fakeFHRPConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}

// fakeFHRPProgrammer records the virtual addresses it is asked to hold.
type fakeFHRPProgrammer struct {
	mu    sync.Mutex
	added []netip.Prefix
	// present holds the addresses found on the interface before Start.
	present map[netip.Prefix]bool
	deleted []netip.Prefix
}

func (p *fakeFHRPProgrammer) AddAddress(_ string, prefix netip.Prefix, _ net.HardwareAddr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.added = append(p.added, prefix)
	return nil
}

func (p *fakeFHRPProgrammer) DeleteAddress(_ string, prefix netip.Prefix, _ net.HardwareAddr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deleted = append(p.deleted, prefix)
	return nil
}

// HasAddress makes fakeFHRPProgrammer an fhrp.AddressReader.
func (p *fakeFHRPProgrammer) HasAddress(_ string, prefix netip.Prefix) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.present[prefix], nil
}

func (p *fakeFHRPProgrammer) Deleted() []netip.Prefix {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.Prefix(nil), p.deleted...)
}

func (p *fakeFHRPProgrammer) Announce(string, netip.Addr, net.HardwareAddr) error { return nil }

func (p *fakeFHRPProgrammer) Added() []netip.Prefix {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.Prefix(nil), p.added...)
}

// ownerFHRPConfig is one IPv4 group this node owns (priority 255), so the
// speaker becomes master at Start and claims the address at once.
func ownerFHRPConfig() *fhrp.Config {
	return &fhrp.Config{
		Enabled: true,
		Groups: []fhrp.GroupConfig{{
			VRID:      10,
			Interface: "trusted0",
			Priority:  255,
			Addresses: []string{"192.0.2.1/24"},
			Source:    "192.0.2.1",
		}},
	}
}

func TestBuildFHRP_StartsSpeakerWithInjectedTransport(t *testing.T) {
	cfg := baseGatewayConfig("fhrp-gw")
	cfg.FHRP = ownerFHRPConfig()
	transport := &fakeFHRPTransport{}
	programmer := &fakeFHRPProgrammer{}
	cfg.Host = &HostRuntime{FHRPTransport: transport, FHRPProgrammer: programmer}

	svc, err := buildFHRP(&Gateway{config: cfg})
	require.NoError(t, err)
	assert.False(t, svc.Active(), "a built speaker has not started yet")

	require.NoError(t, svc.Start(context.Background()))
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })

	assert.True(t, svc.Active())
	assert.True(t, svc.Healthy())
	assert.Equal(t, []string{"trusted0"}, transport.Opened(), "the group's socket opens on the injected transport")
	assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.1/24")}, programmer.Added(),
		"the owner claims its virtual address through the injected programmer")

	require.NoError(t, svc.Stop(context.Background()))
	assert.False(t, svc.Active())
}

func TestBuildFHRP_InvalidConfigRefused(t *testing.T) {
	cfg := baseGatewayConfig("fhrp-gw")
	cfg.FHRP = ownerFHRPConfig()
	cfg.FHRP.Groups[0].VRID = 0
	cfg.Host = &HostRuntime{FHRPTransport: &fakeFHRPTransport{}, FHRPProgrammer: &fakeFHRPProgrammer{}}

	var section *ErrFHRPConfigInvalid
	require.ErrorAs(t, cfg.Validate(), &section, "a broken fhrp section must fail the gateway config")

	_, err := buildFHRP(&Gateway{config: cfg})
	var startFailed *ErrServiceStartFailed
	require.ErrorAs(t, err, &startFailed)
	assert.Equal(t, ServiceFHRP, startFailed.Service)

	cfg.FHRP.Enabled = false
	assert.NoError(t, cfg.Validate(), "a disabled section is not held to the contract")
}

func TestEnabledServices_FHRP(t *testing.T) {
	cfg := baseGatewayConfig("fhrp-gw")
	assert.NotContains(t, cfg.EnabledServices(), ServiceFHRP)

	cfg.FHRP = ownerFHRPConfig()
	cfg.FHRP.Enabled = false
	assert.NotContains(t, cfg.EnabledServices(), ServiceFHRP, "a disabled section starts nothing")

	cfg.FHRP.Enabled = true
	assert.Contains(t, cfg.EnabledServices(), ServiceFHRP)
	assert.Contains(t, serviceBuilders, ServiceFHRP, "an enabled section has a builder")
}

// The owner's source is also its virtual address: when the node already
// holds it, Start and Stop leave it in place (Codex #1716 P1).
func TestBuildFHRP_StopKeepsThePreexistingOwnerAddress(t *testing.T) {
	cfg := baseGatewayConfig("fhrp-gw")
	cfg.FHRP = ownerFHRPConfig()
	programmer := &fakeFHRPProgrammer{present: map[netip.Prefix]bool{netip.MustParsePrefix("192.0.2.1/24"): true}}
	cfg.Host = &HostRuntime{FHRPTransport: &fakeFHRPTransport{}, FHRPProgrammer: programmer}

	svc, err := buildFHRP(&Gateway{config: cfg})
	require.NoError(t, err)
	require.NoError(t, svc.Start(context.Background()))
	require.NoError(t, svc.Stop(context.Background()))
	assert.Empty(t, programmer.Deleted(), "a preexisting owner address is never deleted")
}

// A group may name a tunnel interface, so tunnels come up before fhrp and
// the reverse stop takes fhrp down first (Codex #1716 P1).
func TestEnabledServices_TunnelsStartBeforeFHRP(t *testing.T) {
	cfg := baseGatewayConfig("fhrp-gw")
	cfg.FHRP = ownerFHRPConfig()
	cfg.Tunnels = []TunnelConfig{{Name: "gre-a", Type: "gre", Local: "198.51.100.6", Remote: "203.0.113.100", TunnelIP: "10.4.128.2/31"}}

	before := func(t *testing.T, order []string) {
		t.Helper()
		tun, fh := indexOf(order, ServiceTunnels), indexOf(order, ServiceFHRP)
		require.GreaterOrEqual(t, tun, 0, "tunnels is in %v", order)
		require.GreaterOrEqual(t, fh, 0, "fhrp is in %v", order)
		assert.Less(t, tun, fh, "tunnels precede fhrp in %v", order)
	}
	before(t, cfg.EnabledServices())

	g := &Gateway{config: cfg, serviceHandlers: make(map[string]ServiceHandler)}
	g.registerConfiguredServices()
	before(t, g.serviceOrder)
}

func indexOf(list []string, name string) int {
	for i, s := range list {
		if s == name {
			return i
		}
	}
	return -1
}

// The host filter admits the FHRP peers' VRRP advertisements on every
// enabled group's interface, and on none when FHRP is off.
func TestBuildHostFW_AdmitsVRRPOnFHRPInterfaces(t *testing.T) {
	text := func(t *testing.T, f *fhrp.Config) string {
		t.Helper()
		cfg := baseGatewayConfig("fhrp-gw")
		cfg.FHRP = f
		cfg.HostFW = &hostfw.Config{Enabled: true}
		cfg.Host = &HostRuntime{HostFWApplier: &fakeHostFWApplier{}}
		svc, err := buildHostFW(&Gateway{config: cfg})
		require.NoError(t, err)
		require.NoError(t, svc.Start(context.Background()))
		t.Cleanup(func() { _ = svc.Stop(context.Background()) })
		backend, ok := svc.(hostFWBackend)
		require.True(t, ok)
		rendered := backend.Rendered()
		require.NotNil(t, rendered)
		return rendered.Text
	}
	assert.Contains(t, text(t, ownerFHRPConfig()), `iifname "trusted0" meta l4proto 112 accept`)
	off := ownerFHRPConfig()
	off.Enabled = false
	assert.NotContains(t, text(t, off), "l4proto 112")
	assert.NotContains(t, text(t, nil), "l4proto 112")
}

// A claim failure keeps the gateway unhealthy even after a later successful
// advertisement has cleared LastError.
func TestFHRPHealthy_ClaimErrorKeepsItUnhealthy(t *testing.T) {
	assert.True(t, fhrpHealthy(fhrp.Health{Active: true, Groups: []fhrp.GroupStatus{{VRID: 10}}}))
	assert.False(t, fhrpHealthy(fhrp.Health{Active: true, Groups: []fhrp.GroupStatus{
		{VRID: 10, ClaimError: errors.New("netlink EPERM")},
	}}))
	assert.False(t, fhrpHealthy(fhrp.Health{Active: false}))
}
