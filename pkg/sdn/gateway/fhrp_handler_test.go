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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/fhrp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
)

// fakeFHRPTransport opens in-memory group sockets and records each open.
type fakeFHRPTransport struct {
	mu     sync.Mutex
	opened []string
	// failOpen lists the interfaces whose Open fails with errFHRPOpen.
	failOpen map[string]bool
}

// errFHRPOpen is the typed failure an Open on a failOpen interface returns.
type errFHRPOpen struct{ iface string }

func (e errFHRPOpen) Error() string { return "fake fhrp open failed on " + e.iface }

func (t *fakeFHRPTransport) Open(iface string, _ fhrp.Family, _ netip.Addr) (fhrp.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.failOpen[iface] {
		return nil, errFHRPOpen{iface: iface}
	}
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
	// present holds the addresses on the interface: seeded ones are found
	// there before Start, AddAddress sets one and DeleteAddress clears it.
	present map[netip.Prefix]bool
	deleted []netip.Prefix
	// delErr, when set, fails DeleteAddress and leaves the address present.
	delErr error
	// announced holds the addresses the speaker announced on takeover.
	announced []netip.Addr
}

func (p *fakeFHRPProgrammer) AddAddress(_ string, prefix netip.Prefix, _ net.HardwareAddr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.added = append(p.added, prefix)
	if p.present == nil {
		p.present = make(map[netip.Prefix]bool)
	}
	p.present[prefix] = true
	return nil
}

func (p *fakeFHRPProgrammer) DeleteAddress(_ string, prefix netip.Prefix, _ net.HardwareAddr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.delErr != nil {
		return p.delErr
	}
	p.deleted = append(p.deleted, prefix)
	delete(p.present, prefix)
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

func (p *fakeFHRPProgrammer) Announce(_ string, addr netip.Addr, _ net.HardwareAddr) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.announced = append(p.announced, addr)
	return nil
}

func (p *fakeFHRPProgrammer) Announced() []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]netip.Addr(nil), p.announced...)
}

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

// TestFHRPSweepsVIPsOfRemovedGroups: a datapath child that died while a
// group held its VIPs left them on the interface; a restart without that
// group (or without FHRP) deletes exactly the recorded ones, and never an
// owner's own address, which is never recorded (Codex #1716 round 2).
func TestFHRPSweepsVIPsOfRemovedGroups(t *testing.T) {
	kept := netip.MustParsePrefix("192.0.2.1/24")
	removed := netip.MustParsePrefix("198.51.100.1/24")
	crashed := func(t *testing.T) (string, *fakeFHRPProgrammer) {
		t.Helper()
		path := filepath.Join(t.TempDir(), FHRPStateDir, FHRPInventoryFile)
		inv := fhrp.NewInventory(path)
		require.NoError(t, inv.Record("trusted0", 10, kept))
		require.NoError(t, inv.Record("trusted1", 20, removed))
		return path, &fakeFHRPProgrammer{present: map[netip.Prefix]bool{kept: true, removed: true}}
	}

	t.Run("a group removed after a crash", func(t *testing.T) {
		path, programmer := crashed(t)
		cfg := baseGatewayConfig("fhrp-sweep-removed")
		cfg.FHRP = ownerFHRPConfig()
		cfg.Host = &HostRuntime{FHRPProgrammer: programmer, FHRPInventory: path}

		require.NoError(t, sweepRemovedFHRPGroups(cfg))
		assert.Equal(t, []netip.Prefix{removed}, programmer.Deleted(), "only the removed group's VIP goes")
		assert.True(t, programmer.holds(kept), "a configured group's VIP is left to its runner")
		entries, err := fhrp.NewInventory(path).Entries()
		require.NoError(t, err)
		assert.Equal(t, []fhrp.InventoryEntry{{Interface: "trusted0", VRID: 10, Prefix: kept}}, entries)
	})

	t.Run("FHRP disabled after a crash", func(t *testing.T) {
		path, programmer := crashed(t)
		cfg := baseGatewayConfig("fhrp-sweep-disabled")
		cfg.Host = &HostRuntime{FHRPProgrammer: programmer, FHRPInventory: path}

		require.NoError(t, sweepRemovedFHRPGroups(cfg))
		assert.ElementsMatch(t, []netip.Prefix{kept, removed}, programmer.Deleted())
		entries, err := fhrp.NewInventory(path).Entries()
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("an owner address is never swept", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), FHRPStateDir, FHRPInventoryFile)
		programmer := &fakeFHRPProgrammer{present: map[netip.Prefix]bool{kept: true}}
		cfg := baseGatewayConfig("fhrp-sweep-owner")
		cfg.FHRP = ownerFHRPConfig()
		cfg.Host = &HostRuntime{FHRPTransport: &fakeFHRPTransport{}, FHRPProgrammer: programmer, FHRPInventory: path}

		svc, err := buildFHRP(&Gateway{config: cfg})
		require.NoError(t, err)
		require.NoError(t, svc.Start(context.Background()))
		require.NoError(t, svc.Stop(context.Background()))

		cfg.FHRP = nil
		require.NoError(t, sweepRemovedFHRPGroups(cfg))
		assert.Empty(t, programmer.Deleted())
		assert.True(t, programmer.holds(kept), "the owner's own address stays")
	})

	t.Run("a VIP the speaker adds is recorded until it is released", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), FHRPStateDir, FHRPInventoryFile)
		cfg := baseGatewayConfig("fhrp-sweep-record")
		cfg.FHRP = ownerFHRPConfig()
		cfg.Host = &HostRuntime{FHRPTransport: &fakeFHRPTransport{}, FHRPProgrammer: &fakeFHRPProgrammer{}, FHRPInventory: path}

		svc, err := buildFHRP(&Gateway{config: cfg})
		require.NoError(t, err)
		require.NoError(t, svc.Start(context.Background()))
		entries, err := fhrp.NewInventory(path).Entries()
		require.NoError(t, err)
		assert.Equal(t, []fhrp.InventoryEntry{{Interface: "trusted0", VRID: 10, Prefix: kept}}, entries)

		require.NoError(t, svc.Stop(context.Background()))
		entries, err = fhrp.NewInventory(path).Entries()
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("a sweep that fails fails the start", func(t *testing.T) {
		path, programmer := crashed(t)
		programmer.delErr = &ErrServiceUnavailable{Service: ServiceFHRP, Reason: "test delete failure"}
		cfg := baseGatewayConfig("fhrp-sweep-fails")
		cfg.Host = &HostRuntime{FHRPProgrammer: programmer, FHRPInventory: path}
		gw, err := NewGateway(cfg)
		require.NoError(t, err)
		gw.SetNodeMetrics(validNodeMetrics())

		err = gw.Start(context.Background())
		var startup *ErrStartupFailed
		require.True(t, errors.As(err, &startup), "got %v", err)
		var inv *fhrp.ErrInventory
		assert.True(t, errors.As(err, &inv))
		assert.Equal(t, GatewayStateStopped, gw.GetState())
		entries, err := fhrp.NewInventory(path).Entries()
		require.NoError(t, err)
		assert.Len(t, entries, 2, "an address not deleted stays recorded")
	})
}

// TestFHRPSweepsAddressRemovedFromARetainedGroup: a crashed runner's VIP
// whose address the group no longer configures is deleted and forgotten
// although the group itself stays; the group's configured address is left
// to its runner, and a recorded address of the other family never matches
// a configured one.
func TestFHRPSweepsAddressRemovedFromARetainedGroup(t *testing.T) {
	kept := netip.MustParsePrefix("192.0.2.1/24")
	dropped := netip.MustParsePrefix("192.0.2.2/24")
	mapped := netip.MustParsePrefix("::ffff:192.0.2.1/120")
	path := filepath.Join(t.TempDir(), FHRPStateDir, FHRPInventoryFile)
	inv := fhrp.NewInventory(path)
	for _, p := range []netip.Prefix{kept, dropped, mapped} {
		require.NoError(t, inv.Record("trusted0", 10, p))
	}
	programmer := &fakeFHRPProgrammer{present: map[netip.Prefix]bool{kept: true, dropped: true, mapped: true}}
	cfg := baseGatewayConfig("fhrp-sweep-address")
	cfg.FHRP = ownerFHRPConfig()
	cfg.Host = &HostRuntime{FHRPProgrammer: programmer, FHRPInventory: path}

	require.NoError(t, sweepRemovedFHRPGroups(cfg))
	assert.ElementsMatch(t, []netip.Prefix{dropped, mapped}, programmer.Deleted(),
		"a recorded address the retained group no longer configures goes")
	assert.True(t, programmer.holds(kept), "the group's configured address is left to its runner")
	entries, err := fhrp.NewInventory(path).Entries()
	require.NoError(t, err)
	assert.Equal(t, []fhrp.InventoryEntry{{Interface: "trusted0", VRID: 10, Prefix: kept}}, entries)
}

// TestBuildFHRP_IPv6TakeoverAnnouncesTheVIP: an IPv6 owner group built by
// gatewayd announces its virtual address through the programmer on
// takeover. The default programmer (fhrp.NewNetlinkProgrammer) sends that
// announcement as a neighbor advertisement with Router and Override set
// (RFC 4861 7.2.5), pinned in pkg/sdn/fhrp by
// TestNetlinkProgrammer_AnnounceSendsAnUnsolicitedNA.
func TestBuildFHRP_IPv6TakeoverAnnouncesTheVIP(t *testing.T) {
	cfg := baseGatewayConfig("fhrp-gw6")
	cfg.FHRP = &fhrp.Config{
		Enabled: true,
		Groups: []fhrp.GroupConfig{{
			VRID:      10,
			Interface: "trusted0",
			Priority:  255,
			Addresses: []string{"2001:db8::1/64"},
			Source:    "fe80::1",
		}},
	}
	programmer := &fakeFHRPProgrammer{}
	cfg.Host = &HostRuntime{FHRPTransport: &fakeFHRPTransport{}, FHRPProgrammer: programmer}

	svc, err := buildFHRP(&Gateway{config: cfg})
	require.NoError(t, err)
	require.NoError(t, svc.Start(context.Background()))
	t.Cleanup(func() { _ = svc.Stop(context.Background()) })

	require.Eventually(t, func() bool { return len(programmer.Announced()) > 0 }, 5*time.Second, 10*time.Millisecond,
		"the owner announces its IPv6 virtual address on takeover")
	assert.Equal(t, netip.MustParseAddr("2001:db8::1"), programmer.Announced()[0])
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

func (p *fakeFHRPProgrammer) setDelErr(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.delErr = err
}

func (p *fakeFHRPProgrammer) holds(prefix netip.Prefix) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.present[prefix]
}

func (t *fakeFHRPTransport) setFailOpen(failOpen map[string]bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.failOpen = failOpen
}

// errFHRPDelete is the typed VIP delete failure the rollback tests inject.
type errFHRPDelete struct{}

func (errFHRPDelete) Error() string { return "fake fhrp delete failed" }

// rollbackFHRPHandler builds a handler over an owner group on trusted0
// that adds its VIP (the source is not the VIP) and a second group whose
// Open fails, with VIP deletes failing, so its first Start fails with the
// VIP rollback outstanding.
func rollbackFHRPHandler(t *testing.T) (*backedServiceHandler, *fakeFHRPTransport, *fakeFHRPProgrammer) {
	t.Helper()
	cfg := baseGatewayConfig("fhrp-gw")
	cfg.FHRP = ownerFHRPConfig()
	cfg.FHRP.Groups[0].Source = "192.0.2.2"
	cfg.FHRP.Groups = append(cfg.FHRP.Groups, fhrp.GroupConfig{
		VRID: 11, Interface: "public0", Priority: 100,
		Addresses: []string{"198.51.100.1/24"}, Source: "198.51.100.6",
	})
	transport := &fakeFHRPTransport{failOpen: map[string]bool{"public0": true}}
	programmer := &fakeFHRPProgrammer{delErr: errFHRPDelete{}}
	cfg.Host = &HostRuntime{FHRPTransport: transport, FHRPProgrammer: programmer}
	h := newBackedServiceHandler(&Gateway{config: cfg}, ServiceFHRP, buildFHRP)

	var sf *ErrServiceStartFailed
	require.True(t, errors.As(h.Start(context.Background()), &sf))
	require.True(t, programmer.holds(netip.MustParsePrefix("192.0.2.1/24")), "the failed rollback left the VIP installed")
	return h, transport, programmer
}

func TestBackedFHRPHandler_FailedRollbackIsCleanedUpOnRestartAndStop(t *testing.T) {
	vip := netip.MustParsePrefix("192.0.2.1/24")

	t.Run("restart then stop", func(t *testing.T) {
		h, transport, programmer := rollbackFHRPHandler(t)
		programmer.setDelErr(nil)
		transport.setFailOpen(nil)
		require.NoError(t, h.Start(context.Background()))
		require.NoError(t, h.Stop(context.Background()))
		assert.False(t, programmer.holds(vip), "the VIP the rollback left is released")
		assert.Contains(t, programmer.Deleted(), vip)
	})

	t.Run("stop after the failed start", func(t *testing.T) {
		h, _, programmer := rollbackFHRPHandler(t)
		programmer.setDelErr(nil)
		require.NoError(t, h.Stop(context.Background()))
		assert.False(t, programmer.holds(vip))
		assert.Contains(t, programmer.Deleted(), vip)
		var na *ErrServiceNotActive
		assert.True(t, errors.As(h.Stop(context.Background()), &na))
	})
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

// accept-mode false on a non-owner group (RFC 5798 §6.4.3) is enforced by
// host-filter drop rules for the group's VIPs (Codex #1716 round 3 P1).
func TestBuildHostFW_DeniesVIPsWithoutAcceptMode(t *testing.T) {
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
	// Every ingress, not only the group's interface (Codex #1716 round 4).
	deny := "\tip daddr 192.0.2.1 drop"

	backup := ownerFHRPConfig()
	backup.Groups[0].Priority = 100
	backup.Groups[0].Source = "192.0.2.2"
	assert.Contains(t, text(t, backup), deny, "accept-mode false on a backup drops traffic to the VIP")

	byDefault := ownerFHRPConfig()
	byDefault.Groups[0].Priority = 0
	byDefault.Groups[0].Source = "192.0.2.2"
	assert.Contains(t, text(t, byDefault), deny, "priority 0 means the default 100, not the owner")

	accepting := ownerFHRPConfig()
	accepting.Groups[0].Priority = 100
	accepting.Groups[0].Source = "192.0.2.2"
	accepting.Groups[0].AcceptMode = true
	assert.NotContains(t, text(t, accepting), "accept-mode off", "accept-mode true admits the VIP")

	assert.NotContains(t, text(t, ownerFHRPConfig()), "accept-mode off", "the owner always accepts its own address")
}

func TestGatewayConfig_FHRPAcceptModeOffNeedsHostFW(t *testing.T) {
	cfg := baseGatewayConfig("fhrp-gw")
	cfg.FHRP = ownerFHRPConfig()
	cfg.FHRP.Groups[0].Priority = 100
	cfg.FHRP.Groups[0].Source = "192.0.2.2"

	var section *ErrFHRPConfigInvalid
	require.ErrorAs(t, cfg.Validate(), &section, "accept-mode false cannot be enforced without hostfw")
	assert.Contains(t, section.Error(), "hostfw")

	cfg.HostFW = &hostfw.Config{Enabled: true}
	assert.NoError(t, cfg.Validate(), "hostfw enforces accept-mode false")

	cfg.HostFW = nil
	cfg.FHRP.Groups[0].AcceptMode = true
	assert.NoError(t, cfg.Validate(), "accept-mode true needs no filter")

	cfg.FHRP.Groups[0].AcceptMode = false
	cfg.FHRP.Groups[0].Priority = 255
	cfg.FHRP.Groups[0].Source = "192.0.2.1"
	assert.NoError(t, cfg.Validate(), "the owner always accepts its own address")
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
