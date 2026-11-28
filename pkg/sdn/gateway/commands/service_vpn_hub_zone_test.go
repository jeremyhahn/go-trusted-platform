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

//go:build !fips

package commands

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// hubZoneMatrix is a compiled zone matrix in which the management-VPN zone
// opens management (every service) and control-plane (https only), and not
// storage.
func hubZoneMatrix() zone.Matrix {
	return zone.CompileMatrix([]zone.ZoneConfig{
		{Name: vpnHubZone, AllowTo: []zone.ZonePath{
			{Zone: zone.ZoneManagement},
			{Zone: zone.ZoneControlPlane, Services: []string{"https"}},
		}},
		{Name: zone.ZoneManagement},
		{Name: zone.ZoneControlPlane},
		{Name: zone.ZoneStorage},
	})
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// withHubZoneInstall replaces the enforcement install for one test.
func withHubZoneInstall(t *testing.T, install func(cfg *ServeConfig, logger *slog.Logger) (*vpnHubZoneEnforcement, error)) {
	t.Helper()
	prev := installVPNHubZoneEnforcement
	installVPNHubZoneEnforcement = install
	t.Cleanup(func() { installVPNHubZoneEnforcement = prev })
}

// installedHubZones is an install that succeeds with e.
func installedHubZones(e *vpnHubZoneEnforcement) func(*ServeConfig, *slog.Logger) (*vpnHubZoneEnforcement, error) {
	return func(*ServeConfig, *slog.Logger) (*vpnHubZoneEnforcement, error) { return e, nil }
}

func TestVPNHubZone_ClassifiesHubIngressIntoTheManagementVPNZone(t *testing.T) {
	z, ok := classifyVPNHubIngress(vpnHubInterface)
	require.True(t, ok)
	assert.Equal(t, vpnHubZone, z)

	_, ok = classifyVPNHubIngress("eth0")
	assert.False(t, ok, "only the hub interface is classified as management-VPN ingress")
}

func TestVPNHubZone_AdmitsOnlyTheLeasesAllowToThroughTheMatrix(t *testing.T) {
	e := newVPNHubZoneEnforcement(hubZoneMatrix())
	lease := &vpn.Lease{Zones: []string{string(zone.ZoneManagement), string(zone.ZoneControlPlane)}}

	assert.True(t, e.Allow(vpnHubInterface, lease, zone.ZoneManagement, "ssh"), "a lease zone the matrix opens passes")
	assert.True(t, e.Allow(vpnHubInterface, lease, zone.ZoneControlPlane, "https"), "a scoped service the matrix opens passes")
	assert.False(t, e.Allow(vpnHubInterface, lease, zone.ZoneControlPlane, "ssh"), "a service outside the matrix scope is dropped")
	assert.False(t, e.Allow(vpnHubInterface, lease, zone.ZoneStorage, ""), "a zone outside the lease's AllowTo is dropped")

	wide := &vpn.Lease{Zones: []string{string(zone.ZoneStorage)}}
	assert.False(t, e.Allow(vpnHubInterface, wide, zone.ZoneStorage, ""), "a lease zone the matrix does not open is dropped")

	assert.False(t, e.Allow("eth0", lease, zone.ZoneManagement, ""), "traffic not entering from the hub is not admitted by the hub check")
	assert.False(t, e.Allow(vpnHubInterface, nil, zone.ZoneManagement, ""), "no lease, no admission")

	var none *vpnHubZoneEnforcement
	assert.False(t, none.Allow(vpnHubInterface, lease, zone.ZoneManagement, ""), "no enforcement installed drops everything")
}

func TestVPNHubZone_InstallPeerRefusesALeaseZoneTheMatrixDoesNotOpen(t *testing.T) {
	plane := hubNetworkPlane{
		network: netip.MustParsePrefix("10.99.0.0/24"),
		hub:     netip.MustParseAddr("10.99.0.1"),
		zones:   newVPNHubZoneEnforcement(hubZoneMatrix()),
	}
	lease := &vpn.Lease{
		Address: netip.MustParsePrefix("10.99.0.7/32"),
		Zones:   []string{string(zone.ZoneManagement), string(zone.ZoneStorage)},
	}
	err := plane.InstallPeer(context.Background(), lease)
	var refused *vpn.ErrZoneNotAllowed
	require.ErrorAs(t, err, &refused)
	assert.Equal(t, string(zone.ZoneStorage), refused.Zone)
}

func TestVPNHubZone_DefaultInstallNeedsTheManagementVPNZone(t *testing.T) {
	_, err := compileVPNHubZoneEnforcement(nil)
	require.Error(t, err, "no zone declarations: nothing to enforce")

	_, err = compileVPNHubZoneEnforcement([]zone.ZoneConfig{{Name: zone.ZoneManagement}})
	require.Error(t, err, "the management-VPN zone must be declared")

	e, err := compileVPNHubZoneEnforcement([]zone.ZoneConfig{
		{Name: vpnHubZone, AllowTo: []zone.ZonePath{{Zone: zone.ZoneManagement}}},
		{Name: zone.ZoneManagement},
	})
	require.NoError(t, err)
	assert.True(t, e.Allow(vpnHubInterface, &vpn.Lease{Zones: []string{string(zone.ZoneManagement)}}, zone.ZoneManagement, ""))
}

func TestVPNDataPlanes_RefusesTheHubWhenTheEnforcementInstallFails(t *testing.T) {
	withHubZoneInstall(t, func(*ServeConfig, *slog.Logger) (*vpnHubZoneEnforcement, error) {
		return nil, errors.New("zone matrix not installed")
	})
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, &stubSecrets{})
	require.NotNil(t, hubKey)

	planes, err := vpnDataPlanes(cfg, hubKey, discardLogger())
	var unenforced *ErrVPNHubZoneUnenforced
	require.ErrorAs(t, err, &unenforced, "a failed install keeps the plane refused")
	assert.Equal(t, "kms://vpn/hub0", unenforced.KeyRef)
	assert.Empty(t, planes)
}

func TestVPNDataPlanes_BuildsTheHubOnlyAfterTheEnforcementInstalls(t *testing.T) {
	installed := newVPNHubZoneEnforcement(hubZoneMatrix())
	calls := 0
	withHubZoneInstall(t, func(*ServeConfig, *slog.Logger) (*vpnHubZoneEnforcement, error) {
		calls++
		return installed, nil
	})
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, &stubSecrets{})
	require.NotNil(t, hubKey)

	planes, err := vpnDataPlanes(cfg, hubKey, discardLogger())
	require.NoError(t, err)
	require.Len(t, planes, 1)
	assert.Equal(t, 1, calls)
	hub, ok := planes[0].(hubNetworkPlane)
	require.True(t, ok)
	assert.Same(t, installed, hub.zones, "the plane carries the installed enforcement")
}

// hubZoneDeclarations declares the management-vpn zone, so the matrix
// compiles; only the forwarding-path filter is left to install.
func hubZoneDeclarations() []zone.ZoneConfig {
	return []zone.ZoneConfig{
		{Name: vpnHubZone, AllowTo: []zone.ZonePath{{Zone: zone.ZoneManagement}}},
		{Name: zone.ZoneManagement},
	}
}

// withHubForwardFilter replaces the vpn-hub0 forwarding-path filter install
// for one test.
func withHubForwardFilter(t *testing.T, install func(e *vpnHubZoneEnforcement, logger *slog.Logger) error) {
	t.Helper()
	prev := installVPNHubForwardFilter
	installVPNHubForwardFilter = install
	t.Cleanup(func() { installVPNHubForwardFilter = prev })
}

// A valid management-vpn matrix is not enforcement on its own: when the
// vpn-hub0 forward chain fails to program, the hub stays refused (Tenant
// Agent ruling 1028).
func TestVPNDataPlanes_RefusesTheHubWhenTheForwardFilterFailsToProgram(t *testing.T) {
	withHubNFTConn(t, &recordingHubConn{flushErr: errors.New("netlink refused")})
	withHubZoneInstall(t, func(_ *ServeConfig, logger *slog.Logger) (*vpnHubZoneEnforcement, error) {
		return installVPNHubZones(hubZoneDeclarations(), hubForwardNetworks(), logger)
	})
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, &stubSecrets{})
	require.NotNil(t, hubKey)

	planes, err := vpnDataPlanes(cfg, hubKey, discardLogger())
	var unenforced *ErrVPNHubZoneUnenforced
	require.ErrorAs(t, err, &unenforced, "a forward chain that fails to program keeps the plane refused")
	assert.Empty(t, planes)
}

// The forwarding-path filter receives the compiled enforcement, whose Allow
// is its decision; only once it installs is the enforcement returned.
func TestVPNHubZone_InstallNeedsTheForwardingFilter(t *testing.T) {
	var got *vpnHubZoneEnforcement
	withHubForwardFilter(t, func(e *vpnHubZoneEnforcement, _ *slog.Logger) error {
		got = e
		return nil
	})
	e, err := installVPNHubZones(hubZoneDeclarations(), hubForwardNetworks(), discardLogger())
	require.NoError(t, err)
	require.NotNil(t, e)
	assert.Same(t, e, got, "the filter decides with the compiled enforcement")
	assert.True(t, got.Allow(vpnHubInterface, &vpn.Lease{Zones: []string{string(zone.ZoneManagement)}}, zone.ZoneManagement, ""))

	withHubForwardFilter(t, func(*vpnHubZoneEnforcement, *slog.Logger) error { return errors.New("filter not installed") })
	_, err = installVPNHubZones(hubZoneDeclarations(), hubForwardNetworks(), discardLogger())
	require.Error(t, err, "a failed filter install fails the enforcement install")
}
