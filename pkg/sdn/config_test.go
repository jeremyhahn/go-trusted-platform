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

package sdn_test

import (
	"bytes"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn"
	ipsecconfig "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// minValidConfig returns the smallest valid enabled Config: environment 4,
// the built-in zones, no IPAM, no OVS. Callers layer fields on top.
func minValidConfig() *sdn.Config {
	return &sdn.Config{Enabled: true, Environment: &netplan.Environment{ID: 4}}
}

func TestValidate_NilConfig(t *testing.T) {
	var c *sdn.Config
	require.ErrorIs(t, c.Validate(), sdn.ErrInvalidConfig{})
}

func TestValidate_DisabledConfig_NoError(t *testing.T) {
	c := &sdn.Config{Enabled: false}
	require.NoError(t, c.Validate())
	assert.Nil(t, c.Plan(), "a disabled section derives no plan")
}

// TestValidate_EnvironmentRequired refuses an enabled section without an
// environment: nothing could be numbered.
func TestValidate_EnvironmentRequired(t *testing.T) {
	c := &sdn.Config{Enabled: true}
	err := c.Validate()
	require.ErrorIs(t, err, sdn.ErrEnvironmentRequired{})
	assert.Contains(t, err.Error(), "sdn.environment")
	assert.Nil(t, c.Plan())
	assert.Nil(t, c.ResolvedZones())
}

// TestValidate_DerivesPlan derives the reference plan and resolved zones.
func TestValidate_DerivesPlan(t *testing.T) {
	c := minValidConfig()
	require.NoError(t, c.Validate())
	plan := c.Plan()
	require.NotNil(t, plan)
	cp, ok := plan.Zone(zone.ZoneControlPlane)
	require.True(t, ok)
	assert.Equal(t, uint16(406), cp.VLAN)
	assert.Len(t, c.ResolvedZones(), 9)
	assert.Len(t, c.ZoneIndex(), 9)
}

// TestValidate_EnvironmentErrors surfaces netplan and zone errors.
func TestValidate_EnvironmentErrors(t *testing.T) {
	c := &sdn.Config{Enabled: true, Environment: &netplan.Environment{ID: 41}}
	var envErr netplan.ErrEnvironmentID
	require.ErrorAs(t, c.Validate(), &envErr)

	c = minValidConfig()
	c.Zones = []zone.ZoneConfig{{Name: "trusted", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassHypervisor}}}
	var reserved zone.ErrReservedZoneName
	require.ErrorAs(t, c.Validate(), &reserved)

	c = minValidConfig()
	c.Zones = []zone.ZoneConfig{{Name: zone.ZoneFabric, Omit: true}}
	var omit zone.ErrOmitRequired
	require.ErrorAs(t, c.Validate(), &omit)

	c = minValidConfig()
	c.Environment.Overrides = []netplan.Override{{Zone: zone.ZoneBackup, VLAN: 401}}
	var dup netplan.ErrDuplicateVLAN
	require.ErrorAs(t, c.Validate(), &dup)
}

func TestValidate_OVS(t *testing.T) {
	c := minValidConfig()
	c.OVS = &sdn.OVSConfig{Bridge: "br-fabric"}
	require.ErrorIs(t, c.Validate(), sdn.ErrInvalidOVSSocket{})

	c = minValidConfig()
	c.OVS = &sdn.OVSConfig{Socket: "/var/run/openvswitch/db.sock"}
	require.ErrorIs(t, c.Validate(), sdn.ErrInvalidBridge{})

	c = minValidConfig()
	c.OVS = &sdn.OVSConfig{Socket: "/var/run/openvswitch/db.sock", Bridge: "br-fabric"}
	require.NoError(t, c.Validate())
}

func TestValidate_IPAM_PoolShape(t *testing.T) {
	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{Pools: []sdn.PoolConfig{
		{Name: "public", CIDR: netip.MustParsePrefix("203.0.113.0/24")},
		{Name: "public", CIDR: netip.MustParsePrefix("198.51.100.0/24")},
	}}
	require.ErrorIs(t, c.Validate(), sdn.ErrDuplicatePoolName{Name: "public"})

	c.IPAM.Pools = []sdn.PoolConfig{{Name: "public"}}
	require.ErrorIs(t, c.Validate(), sdn.ErrInvalidPoolCIDR{})

	c.IPAM.Pools = []sdn.PoolConfig{{CIDR: netip.MustParsePrefix("203.0.113.0/24")}}
	require.ErrorIs(t, c.Validate(), sdn.ErrInvalidPoolName{})
}

// TestValidate_IPAM_ExplicitPools accepts a public block and an overlay
// subnet carved from the tenant default range.
func TestValidate_IPAM_ExplicitPools(t *testing.T) {
	c := minValidConfig()
	c.IPAM = &sdn.IPAMConfig{Pools: []sdn.PoolConfig{
		{Name: "public", CIDR: netip.MustParsePrefix("203.0.113.0/24")},
		{Name: "tenant-a", CIDR: netip.MustParsePrefix("10.4.192.0/24")},
		{Name: "lab-hosts", CIDR: netip.MustParsePrefix("198.51.100.0/24"), Zone: "storage"},
	}}
	require.NoError(t, c.Validate())
}

// TestValidate_IPAM_AgainstPlan refuses explicit pools that collide with
// the plan's pools, its reserved ranges, or name an undeclared zone.
func TestValidate_IPAM_AgainstPlan(t *testing.T) {
	cases := []struct {
		name  string
		pool  sdn.PoolConfig
		check func(t *testing.T, err error)
	}{
		{"derived name", sdn.PoolConfig{Name: "provisioning", CIDR: netip.MustParsePrefix("203.0.113.0/24")}, func(t *testing.T, err error) {
			var target sdn.ErrPoolNameReserved
			require.ErrorAs(t, err, &target)
			assert.Contains(t, err.Error(), "derived")
		}},
		{"range name", sdn.PoolConfig{Name: "loopbacks", CIDR: netip.MustParsePrefix("203.0.113.0/24")}, func(t *testing.T, err error) {
			require.ErrorAs(t, err, new(sdn.ErrPoolNameReserved))
		}},
		{"zone subnet", sdn.PoolConfig{Name: "x", CIDR: netip.MustParsePrefix("10.4.6.0/25")}, func(t *testing.T, err error) {
			var target sdn.ErrPoolOverlap
			require.ErrorAs(t, err, &target)
			assert.Contains(t, err.Error(), "control-plane")
		}},
		{"platform hosts range", sdn.PoolConfig{Name: "x", CIDR: netip.MustParsePrefix("10.4.144.0/24")}, func(t *testing.T, err error) {
			require.ErrorAs(t, err, new(sdn.ErrPoolOverlap))
		}},
		{"host services", sdn.PoolConfig{Name: "x", CIDR: netip.MustParsePrefix("169.254.169.0/24")}, func(t *testing.T, err error) {
			var target sdn.ErrPoolOverlap
			require.ErrorAs(t, err, &target)
			assert.Contains(t, err.Error(), "reserved")
		}},
		{"undeclared zone", sdn.PoolConfig{Name: "x", CIDR: netip.MustParsePrefix("203.0.113.0/24"), Zone: "trusted"}, func(t *testing.T, err error) {
			var target sdn.ErrPoolZoneUndeclared
			require.ErrorAs(t, err, &target)
			assert.Equal(t, "trusted", target.Zone)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := minValidConfig()
			c.IPAM = &sdn.IPAMConfig{Pools: []sdn.PoolConfig{tc.pool}}
			err := c.Validate()
			require.Error(t, err)
			tc.check(t, err)
			assert.Nil(t, c.Plan(), "a failed validation publishes no plan")
		})
	}
}

func TestValidate_ManagementVPN(t *testing.T) {
	c := minValidConfig()
	c.ManagementVPN = &sdn.ManagementVPNConfig{Enabled: true, AllowTo: []string{"management"}}
	require.NoError(t, c.Validate())

	c = minValidConfig()
	c.ManagementVPN = &sdn.ManagementVPNConfig{Enabled: true, AllowTo: []string{"trusted"}}
	var target sdn.ErrManagementVPNUnknownZone
	require.ErrorAs(t, c.Validate(), &target)
	assert.Equal(t, "trusted", target.Zone)
}

// TestValidate_OverlayIPsec checks that sdn.Config.Validate reaches the
// overlay.ipsec section: an overlay without one is valid, and a broken one
// fails the whole configuration.
func TestValidate_OverlayIPsec(t *testing.T) {
	c := minValidConfig()
	c.Overlay = &sdn.OverlayConfig{Enabled: true}
	require.NoError(t, c.Validate())

	c = minValidConfig()
	c.Overlay = &sdn.OverlayConfig{Enabled: true, IPsec: &ipsecconfig.Config{
		Enabled:         true,
		FabricInterface: "bond0",
		LocalAddress:    "10.20.0.11",
		Token:           ipsecconfig.TokenConfig{Handle: "01"},
	}}
	require.NoError(t, c.Validate())

	c.Overlay.IPsec.LocalAddress = ""
	var target *ipsecconfig.ConfigError
	require.ErrorAs(t, c.Validate(), &target)
	assert.Equal(t, "local-address", target.Field)
}

func TestResolvedZonesAndPlan_Nil(t *testing.T) {
	var c *sdn.Config
	assert.Nil(t, c.ResolvedZones())
	assert.Nil(t, c.Plan())
	assert.Empty(t, c.ZoneIndex())
	assert.Nil(t, (&sdn.Config{}).ResolvedZones())
}

func TestGatewayDatapathSocket_ReadsTheGatewaySection(t *testing.T) {
	cfg := &sdn.Config{Gateway: &sdn.GatewayConfig{Enabled: true, DatapathSocket: "/run/gatewayd/datapath.sock"}}
	assert.Equal(t, "/run/gatewayd/datapath.sock", cfg.GatewayDatapathSocket())
}

func TestGatewayDatapathSocket_UnsetIsEmpty(t *testing.T) {
	var nilConfig *sdn.Config
	for name, cfg := range map[string]*sdn.Config{
		"nil config":      nilConfig,
		"no gateway":      {},
		"no socket given": {Gateway: &sdn.GatewayConfig{Enabled: true}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Empty(t, cfg.GatewayDatapathSocket())
		})
	}
}

// TestLogPrivilegedPaths writes one audit record per privileged path.
func TestLogPrivilegedPaths(t *testing.T) {
	c := minValidConfig()
	c.Zones = []zone.ZoneConfig{{
		Name: "lab", Offset: 9, PortClasses: []zone.PortClass{zone.PortClassHypervisor}, Isolate: true,
		AllowTo:          []zone.ZonePath{{Zone: zone.ZoneControlPlane, Services: []string{"api"}}},
		PrivilegedAccess: &zone.PrivilegedAccess{Reason: "lab CI", ApprovedBy: "owner"},
	}}
	require.NoError(t, c.Validate())

	var buf bytes.Buffer
	c.LogPrivilegedPaths(slog.New(slog.NewTextHandler(&buf, nil)))
	out := buf.String()
	assert.Equal(t, 1, strings.Count(out, "privileged zone path"))
	for _, want := range []string{"audit=true", "from=lab", "to=control-plane", `reason="lab CI"`, "approved_by=owner"} {
		assert.Contains(t, out, want)
	}

	// Nothing to log for the reference defaults, a nil config or a nil logger.
	buf.Reset()
	ref := minValidConfig()
	require.NoError(t, ref.Validate())
	ref.LogPrivilegedPaths(slog.New(slog.NewTextHandler(&buf, nil)))
	assert.Empty(t, buf.String())
	var nilCfg *sdn.Config
	nilCfg.LogPrivilegedPaths(slog.New(slog.NewTextHandler(&buf, nil)))
	c.LogPrivilegedPaths(nil)
	assert.Empty(t, buf.String())
}

func TestErrorStrings_Config(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{sdn.ErrInvalidConfig{}, "invalid configuration"},
		{sdn.ErrInvalidOVSSocket{}, "socket"},
		{sdn.ErrInvalidBridge{}, "bridge"},
		{sdn.ErrInvalidPoolName{}, "pool name"},
		{sdn.ErrInvalidPoolCIDR{}, "cidr"},
		{sdn.ErrDuplicatePoolName{Name: "a"}, `"a"`},
		{sdn.ErrEnvironmentRequired{}, "sdn.environment"},
		{sdn.ErrPoolNameReserved{Pool: "fabric"}, `"fabric"`},
		{sdn.ErrPoolOverlap{Pool: "x", CIDR: netip.MustParsePrefix("10.4.6.0/25"), Other: "zone"}, "10.4.6.0/25"},
		{sdn.ErrPoolZoneUndeclared{Pool: "x", Zone: "z"}, `"z"`},
		{sdn.ErrIPAMBackendUnconfigured{Backend: "quicbaas"}, "quicbaas"},
		{sdn.ErrIPAMBackendUnknown{Backend: "x"}, `"x"`},
		{sdn.ErrIPAMBackendP2PRequired{}, "platform_p2p"},
		{sdn.ErrManagementVPNUnknownZone{Zone: "z"}, `"z"`},
	}
	for _, tc := range cases {
		assert.Contains(t, tc.err.Error(), tc.want, "%T", tc.err)
		assert.True(t, strings.HasPrefix(tc.err.Error(), "sdn:"), "%T", tc.err)
		assert.False(t, errors.Is(tc.err, nil))
	}
}
