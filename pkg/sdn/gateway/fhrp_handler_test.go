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
}

func (p *fakeFHRPProgrammer) AddAddress(_ string, prefix netip.Prefix, _ net.HardwareAddr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.added = append(p.added, prefix)
	return nil
}

func (p *fakeFHRPProgrammer) DeleteAddress(string, netip.Prefix, net.HardwareAddr) error {
	return nil
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
