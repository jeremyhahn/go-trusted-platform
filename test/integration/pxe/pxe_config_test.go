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

//go:build integration

package pxe

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	pxesvc "github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ipxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

const (
	// pxeConfigOverlay is the pxe: section run-integration-tests.sh appends
	// to test/integration/config.yaml for the pxe target (#1896).
	pxeConfigOverlay = "platformd-pxe.yaml"

	// integrationEnvironment is sdn.environment.id in
	// test/integration/config.yaml.
	integrationEnvironment uint16 = 4
)

// integrationPlan is the network plan the integration daemon derives:
// environment integrationEnvironment over the default zones.
func integrationPlan(t *testing.T) *netplan.Plan {
	t.Helper()
	plan, err := netplan.New(netplan.Environment{ID: integrationEnvironment}, zone.Defaults())
	require.NoError(t, err)
	return plan
}

// integrationTargetVLAN is a VLAN the integration plan carries (the
// control-plane zone's), so an authorize call can map it to a zone.
func integrationTargetVLAN(t *testing.T) uint16 {
	t.Helper()
	n, err := integrationPlan(t).MustZone(zone.ZoneControlPlane)
	require.NoError(t, err)
	return n.VLAN
}

type integrationDaemonConfig struct {
	PXE *pxesvc.DaemonConfig `yaml:"pxe"`
	SDN struct {
		Environment struct {
			ID uint16 `yaml:"id"`
		} `yaml:"environment"`
		OVS struct {
			Bridge string `yaml:"bridge"`
		} `yaml:"ovs"`
	} `yaml:"sdn"`
}

// TestPXEIntegrationConfigEnablesPXE requires the pxe target's daemon
// config (config.yaml plus the pxe: overlay) to turn the PXE backend on,
// on the integration bridge and plan, so PXE calls are not answered
// SERVICE_NOT_CONFIGURED (#1896 F50).
func TestPXEIntegrationConfigEnablesPXE(t *testing.T) {
	base, err := os.ReadFile("../config.yaml")
	require.NoError(t, err)
	overlay, err := os.ReadFile(pxeConfigOverlay)
	require.NoError(t, err)

	var baseOnly integrationDaemonConfig
	require.NoError(t, yaml.Unmarshal(base, &baseOnly))
	require.Nil(t, baseOnly.PXE, "test/integration/config.yaml carries no pxe: section; the overlay is only for the pxe target")

	var cfg integrationDaemonConfig
	require.NoError(t, yaml.Unmarshal([]byte(string(base)+"\n"+string(overlay)), &cfg))
	require.NotNil(t, cfg.PXE)
	require.True(t, cfg.PXE.Enabled)
	require.Equal(t, DefaultPXETestBridge, cfg.SDN.OVS.Bridge)
	require.Equal(t, cfg.SDN.OVS.Bridge, cfg.PXE.BridgeName)
	require.Equal(t, integrationEnvironment, cfg.SDN.Environment.ID)

	svc, err := cfg.PXE.ToServiceConfig(integrationPlan(t))
	require.NoError(t, err)
	require.NotNil(t, svc)
	require.NotEmpty(t, svc.IPXEConfig.BootEntries, "the overlay carries a boot entry; the iPXE server refuses to initialize without one")

	// The fixture must survive backend initialization, not only conversion.
	b := pxesvc.NewService()
	require.NoError(t, b.Initialize(context.Background(), svc))
	t.Cleanup(func() { _ = b.Close() })

	// The pxe leg's iPXE HTTP server must not take the ipxe suite's 8080 on
	// the shared host network.
	require.NotZero(t, cfg.PXE.HTTPPort, "the overlay sets http-port")
	require.NotEqual(t, ipxe.DefaultHTTPPort, cfg.PXE.HTTPPort, "the overlay's http-port is not the ipxe default")
	require.Equal(t, cfg.PXE.HTTPPort, svc.IPXEConfig.HTTPPort)
}

// TestPXEIntegrationTargetVLANIsInThePlan requires the authorize cases'
// target VLAN to be one the integration plan maps to a zone; a fixed VLAN
// 100 is not in the plan, so the daemon refuses it (#1896 F47).
func TestPXEIntegrationTargetVLANIsInThePlan(t *testing.T) {
	plan := integrationPlan(t)

	z, ok := plan.ZoneForVLAN(integrationTargetVLAN(t))
	require.True(t, ok)
	require.Equal(t, zone.ZoneControlPlane, z)

	_, ok = plan.ZoneForVLAN(100)
	require.False(t, ok, "VLAN 100 is not in the integration plan")
}
