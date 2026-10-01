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

package pxe

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

var testMAC = net.HardwareAddr{0x52, 0x54, 0x00, 0x12, 0x34, 0x56}

// TestNewServiceConfig_FromPlan numbers quarantine and provisioning from the
// plan, including an overridden VLAN.
func TestNewServiceConfig_FromPlan(t *testing.T) {
	cfg := testServiceConfig()
	assert.Equal(t, testQuarantineVLAN, cfg.QuarantineVLAN)
	assert.Equal(t, testProvisioningVLAN, cfg.ProvisioningVLAN)

	p, err := netplan.New(netplan.Environment{ID: 4, Overrides: []netplan.Override{{Zone: zone.ZoneProvisioning, VLAN: 3005}}}, zone.Defaults())
	require.NoError(t, err)
	cfg, err = NewServiceConfig(p)
	require.NoError(t, err)
	assert.Equal(t, uint16(3005), cfg.ProvisioningVLAN)
}

// TestNewServiceConfig_NoPlan refuses to number anything without a plan.
func TestNewServiceConfig_NoPlan(t *testing.T) {
	_, err := NewServiceConfig(nil)
	require.ErrorIs(t, err, ErrNetworkPlanRequired{})
	assert.Contains(t, err.Error(), "sdn.environment")
}

// TestNoopVLANIntegration_NoPlan fails every zone operation without a plan.
func TestNoopVLANIntegration_NoPlan(t *testing.T) {
	vi := NewNoopVLANIntegration(nil)
	ctx := context.Background()
	require.ErrorIs(t, vi.ApplyZoneVLAN(ctx, "p", zone.ZoneStorage), ErrNetworkPlanRequired{})
	require.ErrorIs(t, vi.ApplyQuarantineFlows(ctx, "p", testMAC), ErrNetworkPlanRequired{})
	require.ErrorIs(t, vi.ApplyProvisioningFlows(ctx, "p", testMAC), ErrNetworkPlanRequired{})
	require.ErrorIs(t, vi.ApplyAuthorizedFlows(ctx, "p", testMAC, 406), ErrNetworkPlanRequired{})
}

// TestNoopVLANIntegration_UnknownZoneAndVLAN refuses what the plan lacks.
func TestNoopVLANIntegration_UnknownZoneAndVLAN(t *testing.T) {
	vi := NewNoopVLANIntegration(testNetPlan)
	ctx := context.Background()
	require.Error(t, vi.ApplyZoneVLAN(ctx, "p", "trusted"))
	err := vi.ApplyAuthorizedFlows(ctx, "p", testMAC, 200)
	var target ErrVLANNotInPlan
	require.ErrorAs(t, err, &target)
	assert.Equal(t, uint16(200), target.VLAN)
	assert.Contains(t, err.Error(), "VLAN 200")
}

// recordingPort is an OVSPortController for the wrapper tests.
type recordingPort struct{ vlans []int64 }

func (r *recordingPort) InstallFlow(string, int, string, string) error             { return nil }
func (r *recordingPort) InstallFlows(string, []zoneflows.FlowRule) error           { return nil }
func (r *recordingPort) DeleteFlow(string, string) error                           { return nil }
func (r *recordingPort) DeleteFlowsByPort(string, string) error                    { return nil }
func (r *recordingPort) ListFlows(string) ([]string, error)                        { return nil, nil }
func (r *recordingPort) GetOFPort(context.Context, string) (int32, error)          { return 1, nil }
func (r *recordingPort) SetPortState(context.Context, string, ovs.PortState) error { return nil }
func (r *recordingPort) SetPortTrunk(context.Context, string, []uint16, uint16) error {
	return nil
}
func (r *recordingPort) SetPortVLAN(_ context.Context, _ string, v int64) error {
	r.vlans = append(r.vlans, v)
	return nil
}

// TestVLANIntegrationWrapper_ApplyAuthorizedFlows admits the device to the
// zone the plan carries on the target VLAN, and refuses a VLAN outside it.
func TestVLANIntegrationWrapper_ApplyAuthorizedFlows(t *testing.T) {
	port := &recordingPort{}
	zfm, err := policy.NewZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName: "br-fabric", FlowController: port, PortController: port, Plan: testNetPlan,
	})
	require.NoError(t, err)
	vi := NewVLANIntegrationWrapper(WithFlowManager(zfm))
	ctx := context.Background()

	require.NoError(t, vi.ApplyAuthorizedFlows(ctx, "port-1", testMAC, testControlPlaneVLAN))
	assert.Equal(t, []int64{406}, port.vlans)
	got, err := vi.GetCurrentVLAN(ctx, "port-1")
	require.NoError(t, err)
	assert.Equal(t, testControlPlaneVLAN, got)

	err = vi.ApplyAuthorizedFlows(ctx, "port-1", testMAC, 200)
	var transition ErrVLANTransitionFailed
	require.ErrorAs(t, err, &transition)
	assert.True(t, errors.As(err, new(ErrVLANNotInPlan)))
	assert.True(t, strings.Contains(err.Error(), "authorize"))

	require.Error(t, vi.ApplyAuthorizedFlows(ctx, "", testMAC, 406))
	require.NoError(t, vi.Close())
	require.ErrorIs(t, vi.ApplyAuthorizedFlows(ctx, "port-1", testMAC, 406), ErrServiceNotRunning{})
}
