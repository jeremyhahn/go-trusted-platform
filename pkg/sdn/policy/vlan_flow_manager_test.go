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

// Package policy tests: zone-template flow generation for ZoneFlowManager.
// These tests replace the old VLAN-keyed tests and verify:
//   - per-zone template flow installation and VLAN tracking
//   - inter-zone matrix compilation spot-checks against the reference policy
//   - port-class trunk admission (ApplyPortClassFlows)
//   - ApplyZoneFlows happy-path and typed-error paths
//   - RemoveFlows lifecycle and error handling
//   - concurrent access safety
package policy

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// ---------------------------------------------------------------------------
// zoneTestController satisfies OVSPortController (FlowController + VLAN/state).
// A single instance can be used for both FlowController and PortController
// configuration fields.
// ---------------------------------------------------------------------------

// zoneTestController implements OVSPortController for zone-manager tests.
type zoneTestController struct {
	mu         sync.Mutex
	flows      map[string][]string // bridge → recorded flow strings
	installErr error
	deleteErr  error
	setVLANErr error
	vlanCalls  []int64
	trunkErr   error
	trunks     [][]uint16
	natives    []uint16

	// installBatches records the size of each InstallFlows batch.
	installBatches []int
}

// newZoneTestController returns a zoneTestController ready for use.
func newZoneTestController() *zoneTestController {
	return &zoneTestController{
		flows: make(map[string][]string),
	}
}

func (c *zoneTestController) InstallFlow(bridge string, priority int, match, actions string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.installErr != nil {
		return c.installErr
	}
	c.flows[bridge] = append(c.flows[bridge], fmt.Sprintf("p=%d %s -> %s", priority, match, actions))
	return nil
}

func (c *zoneTestController) InstallFlows(bridge string, rules []zoneflows.FlowRule) error {
	c.mu.Lock()
	c.installBatches = append(c.installBatches, len(rules))
	c.mu.Unlock()
	for _, rule := range rules {
		if err := c.InstallFlow(bridge, rule.Priority, rule.Match, rule.Actions); err != nil {
			return err
		}
	}
	return nil
}

func (c *zoneTestController) DeleteFlow(bridge, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deleteErr != nil {
		return c.deleteErr
	}
	return nil
}

func (c *zoneTestController) DeleteFlowsByPort(bridge, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.deleteErr != nil {
		return c.deleteErr
	}
	delete(c.flows, bridge)
	return nil
}

func (c *zoneTestController) ListFlows(bridge string) ([]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.flows[bridge]...), nil
}

func (c *zoneTestController) SetPortVLAN(_ context.Context, _ string, vlanID int64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.vlanCalls = append(c.vlanCalls, vlanID)
	return c.setVLANErr
}

func (c *zoneTestController) SetPortTrunk(_ context.Context, _ string, allowed []uint16, native uint16) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trunks = append(c.trunks, allowed)
	c.natives = append(c.natives, native)
	return c.trunkErr
}

func (c *zoneTestController) SetPortState(context.Context, string, ovs.PortState) error {
	return nil
}

func (c *zoneTestController) GetOFPort(_ context.Context, _ string) (int32, error) {
	return 1, nil
}

func (c *zoneTestController) count(bridge string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.flows[bridge])
}

// Compile-time interface check.
var _ OVSPortController = (*zoneTestController)(nil)

// newZFM creates a ZoneFlowManager backed by a single zoneTestController.
func newZFM(t *testing.T, ctrl *zoneTestController) *ZoneFlowManager {
	t.Helper()
	m, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
		PortController: ctrl,
		Plan:           testPlan(t),
	})
	require.NoError(t, err)
	return m
}

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestNewZoneFlowManager_Success(t *testing.T) {
	ctrl := newZoneTestController()
	m, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
		PortController: ctrl,
		Plan:           testPlan(t),
	})
	require.NoError(t, err)
	require.NotNil(t, m)
	assert.Equal(t, "br0", m.bridgeName)
}

func TestNewZoneFlowManager_MissingBridgeName(t *testing.T) {
	ctrl := newZoneTestController()
	_, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		FlowController: ctrl,
		PortController: ctrl,
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidBridgeName)
}

func TestNewZoneFlowManager_NilFlowController(t *testing.T) {
	ctrl := newZoneTestController()
	_, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		PortController: ctrl,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "flow controller is required")
}

func TestNewZoneFlowManager_NilPlan(t *testing.T) {
	ctrl := newZoneTestController()
	_, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
		PortController: ctrl,
	})
	var target ErrNetworkPlanRequired
	require.ErrorAs(t, err, &target)
	assert.Contains(t, err.Error(), "sdn.environment")
}

func TestNewZoneFlowManager_NilPortController(t *testing.T) {
	ctrl := newZoneTestController()
	_, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port controller is required")
}

func TestNewZoneFlowManager_NilGeneratorSet_UsesDefault(t *testing.T) {
	ctrl := newZoneTestController()
	m, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
		PortController: ctrl,
		Plan:           testPlan(t),
	})
	require.NoError(t, err)
	assert.NotNil(t, m.generators)
}

func TestNewZoneFlowManager_CustomGeneratorSet(t *testing.T) {
	ctrl := newZoneTestController()
	gs := zoneflows.NewGeneratorSet(zoneflows.ZoneFlowConfig{BridgeName: "br0"})
	m, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
		PortController: ctrl,
		GeneratorSet:   gs,
		Plan:           testPlan(t),
	})
	require.NoError(t, err)
	assert.Equal(t, gs, m.generators)
}

// ---------------------------------------------------------------------------
// ApplyZoneFlows per-zone template tests
// ---------------------------------------------------------------------------

// applyAndAssert applies zone flows and checks that at least one flow was
// installed and that the port's VLAN is tracked as the expected value.
func applyAndAssert(t *testing.T, m *ZoneFlowManager, ctrl *zoneTestController, portID string, z zone.Zone, expectedVLAN uint16) {
	t.Helper()
	ctx := context.Background()
	require.NoError(t, m.ApplyZoneFlows(ctx, portID, z))
	assert.Greater(t, ctrl.count("br0"), 0, "expected at least one flow installed for zone %s", z)
	vlanID, err := m.GetPortVLAN(portID)
	require.NoError(t, err)
	assert.Equal(t, expectedVLAN, vlanID, "VLAN mismatch for zone %s", z)
	got, err := m.GetPortZone(portID)
	require.NoError(t, err)
	assert.Equal(t, z, got, "zone mismatch")
}

func TestApplyZoneFlows_Provisioning(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	applyAndAssert(t, m, ctrl, "eth0", zone.ZoneProvisioning, testProvisioningVLAN)
}

func TestApplyZoneFlows_Quarantine(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	applyAndAssert(t, m, ctrl, "eth0", zone.ZoneQuarantine, testQuarantineVLAN)
}

func TestApplyZoneFlows_ControlPlane(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	applyAndAssert(t, m, ctrl, "eth0", zone.ZoneControlPlane, testControlPlaneVLAN)
}

func TestApplyZoneFlows_Management(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	applyAndAssert(t, m, ctrl, "eth0", zone.ZoneManagement, testManagementVLAN)
}

func TestApplyZoneFlows_Storage(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	applyAndAssert(t, m, ctrl, "eth0", zone.ZoneStorage, testStorageVLAN)
}

func TestApplyZoneFlows_EmptyPortID(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	err := m.ApplyZoneFlows(context.Background(), "", zone.ZoneProvisioning)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPortID)
}

func TestApplyZoneFlows_UnknownUserDefinedZone_Errors(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	// A zone the plan does not hold → typed error, never a default VLAN.
	err := m.ApplyZoneFlows(context.Background(), "eth0", zone.Zone("custom-zone"))
	require.Error(t, err)
	var errUnresolvable zoneflows.ErrUnresolvableNetwork
	assert.ErrorAs(t, err, &errUnresolvable)
	assert.Equal(t, zone.Zone("custom-zone"), errUnresolvable.Zone)
}

func TestApplyZoneFlows_FlowInstallError(t *testing.T) {
	ctrl := newZoneTestController()
	ctrl.installErr = &MessageError{Msg: "OVS unreachable"}
	m := newZFM(t, ctrl)
	err := m.ApplyZoneFlows(context.Background(), "eth0", zone.ZoneProvisioning)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFlowInstallFailed)
}

func TestApplyZoneFlows_PortControllerSetVLANError(t *testing.T) {
	ctrl := newZoneTestController()
	ctrl.setVLANErr = &MessageError{Msg: "ovsdb error"}
	m := newZFM(t, ctrl)
	err := m.ApplyZoneFlows(context.Background(), "eth0", zone.ZoneProvisioning)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set port VLAN")
}

func TestApplyZoneFlows_ReplacesExistingFlows(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	ctx := context.Background()

	require.NoError(t, m.ApplyZoneFlows(ctx, "eth0", zone.ZoneProvisioning))
	first := ctrl.count("br0")

	// Apply again — DeleteFlowsByPort clears old flows, so the new count
	// represents only the second apply.
	require.NoError(t, m.ApplyZoneFlows(ctx, "eth0", zone.ZoneProvisioning))
	second := ctrl.count("br0")

	assert.Equal(t, first, second, "re-applying same zone should install same number of flows")
}

// ---------------------------------------------------------------------------
// RemoveFlows tests
// ---------------------------------------------------------------------------

func TestRemoveFlows_Success(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	ctx := context.Background()

	require.NoError(t, m.ApplyZoneFlows(ctx, "eth0", zone.ZoneProvisioning))
	require.NoError(t, m.RemoveFlows("eth0"))

	_, err := m.GetPortVLAN("eth0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port not found")

	_, err = m.GetPortZone("eth0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port not found")
}

func TestRemoveFlows_EmptyPortID(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	err := m.RemoveFlows("")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidPortID)
}

func TestRemoveFlows_DeletionError(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	ctrl.deleteErr = &MessageError{Msg: "delete failed"}

	err := m.RemoveFlows("eth0")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "remove flows")
}

// ---------------------------------------------------------------------------
// GetPortZone / GetPortVLAN error tests
// ---------------------------------------------------------------------------

func TestGetPortZone_NotFound(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	_, err := m.GetPortZone("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port not found")
}

func TestGetPortVLAN_NotFound(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	_, err := m.GetPortVLAN("nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port not found")
}

// ---------------------------------------------------------------------------
// Inter-zone matrix spot-checks
// ---------------------------------------------------------------------------

// TestZoneMatrix_DefaultZones_SpotChecks verifies the allow/deny verdicts from
// zone.CompileMatrix against the built-in zones (reference-network.md).
func TestZoneMatrix_DefaultZones_SpotChecks(t *testing.T) {
	defaults := zone.Defaults()
	matrix := zone.CompileMatrix(defaults)

	cases := []struct {
		from, to  zone.Zone
		wantAllow bool
	}{
		{zone.ZoneProvisioning, zone.ZoneControlPlane, true},
		{zone.ZoneQuarantine, zone.ZoneControlPlane, true},
		{zone.ZoneControlPlane, zone.ZoneProvisioning, false},
		{zone.ZoneStorage, zone.ZoneControlPlane, false},
		{zone.ZoneQuarantine, zone.ZoneProvisioning, false},
		{zone.ZoneManagement, zone.ZoneControlPlane, false},
		{zone.ZoneTransit, zone.ZoneFabric, false},
	}

	for _, tc := range cases {
		name := fmt.Sprintf("%s→%s", tc.from, tc.to)
		t.Run(name, func(t *testing.T) {
			verdict := matrix.Allowed(tc.from, tc.to)
			assert.Equal(t, tc.wantAllow, verdict.Allowed, "unexpected verdict for %s", name)
		})
	}
}

// ---------------------------------------------------------------------------
// Port lifecycle: provisioning → role's zones → quarantine → removed
// ---------------------------------------------------------------------------

func TestZoneFlowManager_FullLifecycle(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	ctx := context.Background()
	portID := "eth0"

	// 1. Start in provisioning
	require.NoError(t, m.ApplyZoneFlows(ctx, portID, zone.ZoneProvisioning))
	v, err := m.GetPortVLAN(portID)
	require.NoError(t, err)
	assert.Equal(t, testProvisioningVLAN, v)

	// 2. Admitted: the port carries the hypervisor class (its role's zones)
	require.NoError(t, m.ApplyPortClassFlows(ctx, portID, zone.PortClassHypervisor))
	v, err = m.GetPortVLAN(portID)
	require.NoError(t, err)
	assert.Equal(t, testProvisioningVLAN, v, "the hypervisor trunk's native VLAN is provisioning")
	c, err := m.GetPortClass(portID)
	require.NoError(t, err)
	assert.Equal(t, zone.PortClassHypervisor, c)

	// 3. Compliance failure → quarantine access port
	require.NoError(t, m.ApplyZoneFlows(ctx, portID, zone.ZoneQuarantine))
	v, err = m.GetPortVLAN(portID)
	require.NoError(t, err)
	assert.Equal(t, testQuarantineVLAN, v)
	_, err = m.GetPortClass(portID)
	require.Error(t, err, "a quarantined port carries no class")

	// 4. Disconnect
	require.NoError(t, m.RemoveFlows(portID))
	_, err = m.GetPortVLAN(portID)
	require.Error(t, err, "expected port-not-found after remove")
}

// ---------------------------------------------------------------------------
// Concurrent access safety
// ---------------------------------------------------------------------------

func TestZoneFlowManager_ConcurrentAccess(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	ctx := context.Background()

	const n = 10
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			portID := fmt.Sprintf("eth%d", id)
			err := m.ApplyZoneFlows(ctx, portID, zone.ZoneProvisioning)
			assert.NoError(t, err)
		}(i)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		portID := fmt.Sprintf("eth%d", i)
		v, err := m.GetPortVLAN(portID)
		assert.NoError(t, err)
		assert.Equal(t, testProvisioningVLAN, v, "port %s VLAN mismatch", portID)
	}
}

// ---------------------------------------------------------------------------
// PortController VLAN recording
// ---------------------------------------------------------------------------

func TestApplyZoneFlows_PortControllerReceivesVLAN(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)

	require.NoError(t, m.ApplyZoneFlows(context.Background(), "eth0", zone.ZoneProvisioning))
	require.Len(t, ctrl.vlanCalls, 1)
	assert.Equal(t, int64(testProvisioningVLAN), ctrl.vlanCalls[0])
}

// ---------------------------------------------------------------------------
// Port-class admission
// ---------------------------------------------------------------------------

// TestApplyPortClassFlows_HypervisorTrunk admits a port to the hypervisor
// class: a trunk of 401, 403-408 with native 405, and the templates of every
// carried zone installed.
func TestApplyPortClassFlows_HypervisorTrunk(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	require.NoError(t, m.ApplyPortClassFlows(context.Background(), "eth0", zone.PortClassHypervisor))

	require.Len(t, ctrl.trunks, 1)
	assert.Equal(t, []uint16{401, 403, 404, 405, 406, 407, 408}, ctrl.trunks[0])
	assert.Equal(t, uint16(405), ctrl.natives[0])
	flows, err := ctrl.ListFlows("br0")
	require.NoError(t, err)
	joined := fmt.Sprint(flows)
	// Tagged zones match their VLAN; the native zone (405) arrives untagged
	// in the flow tables, so its template matches untagged frames instead.
	for _, vid := range []string{"dl_vlan=401", "dl_vlan=404", "dl_vlan=406", "in_port=eth0,vlan_tci=0x0000/0x1fff"} {
		assert.Contains(t, joined, vid)
	}
	assert.NotContains(t, joined, "dl_vlan=405", "the native zone never arrives tagged")
	_, err = m.GetPortZone("eth0")
	require.Error(t, err, "a trunk port carries a class, not a single zone")
}

// TestApplyPortClassFlows_GatewayTrunkHasNoNative admits a gateway port:
// tagged only, transit included.
func TestApplyPortClassFlows_GatewayTrunkHasNoNative(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	require.NoError(t, m.ApplyPortClassFlows(context.Background(), "gw0", zone.PortClassGateway))
	assert.Equal(t, []uint16{400, 401, 404, 405, 406, 408}, ctrl.trunks[0])
	assert.Zero(t, ctrl.natives[0])
}

// TestApplyPortClassFlows_BMCIsAccess turns an access class into an access
// port on management.
func TestApplyPortClassFlows_BMCIsAccess(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	require.NoError(t, m.ApplyPortClassFlows(context.Background(), "bmc0", zone.PortClassBMC))
	assert.Empty(t, ctrl.trunks)
	assert.Equal(t, []int64{402}, ctrl.vlanCalls)
	z, err := m.GetPortZone("bmc0")
	require.NoError(t, err)
	assert.Equal(t, zone.ZoneManagement, z)
}

// TestApplyPortClassFlows_Errors covers an empty port, an unknown class, a
// trunk failure and a flow failure.
func TestApplyPortClassFlows_Errors(t *testing.T) {
	ctx := context.Background()
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)

	require.ErrorIs(t, m.ApplyPortClassFlows(ctx, "", zone.PortClassHypervisor), ErrInvalidPortID)

	var unresolved ErrPortClassUnresolved
	require.ErrorAs(t, m.ApplyPortClassFlows(ctx, "eth0", "uplink"), &unresolved)
	assert.Contains(t, unresolved.Error(), "uplink")

	ctrl.trunkErr = &MessageError{Msg: "ovsdb down"}
	err := m.ApplyPortClassFlows(ctx, "eth0", zone.PortClassHypervisor)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set port trunk")

	ctrl.trunkErr = nil
	ctrl.installErr = assert.AnError
	require.ErrorIs(t, m.ApplyPortClassFlows(ctx, "eth0", zone.PortClassHypervisor), ErrFlowInstallFailed)
	_, err = m.GetPortClass("eth0")
	require.Error(t, err, "a failed admission records no class")
}

// TestZoneFlowManager_ApplyZoneFlows_BatchesTemplateFlows verifies that
// template and matrix flows are installed through batched InstallFlows calls
// rather than per-flow InstallFlow calls.
func TestZoneFlowManager_ApplyZoneFlows_BatchesTemplateFlows(t *testing.T) {
	ctrl := newZoneTestController()
	m, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
		PortController: ctrl,
		Plan:           testPlan(t),
	})
	require.NoError(t, err)

	require.NoError(t, m.ApplyZoneFlows(context.Background(), "port1", zone.ZoneControlPlane))

	ctrl.mu.Lock()
	batches := append([]int(nil), ctrl.installBatches...)
	installed := len(ctrl.flows["br0"])
	ctrl.mu.Unlock()

	// One batch for template flows and one (empty) batch for matrix rules.
	require.Len(t, batches, 2)
	assert.Equal(t, installed, batches[0], "template batch must contain every generated flow")
	assert.Zero(t, batches[1], "matrix batch must be empty without a zone set")
	assert.Positive(t, installed)
}

// TestZoneFlowManager_ApplyZoneFlows_BatchInstallError verifies that a failed
// template flow batch surfaces ErrFlowInstallFailed with the batch error as
// the cause.
func TestZoneFlowManager_ApplyZoneFlows_BatchInstallError(t *testing.T) {
	ctrl := newZoneTestController()
	ctrl.installErr = assert.AnError
	m, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
		PortController: ctrl,
		Plan:           testPlan(t),
	})
	require.NoError(t, err)

	err = m.ApplyZoneFlows(context.Background(), "port1", zone.ZoneControlPlane)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFlowInstallFailed)
	assert.ErrorIs(t, err, assert.AnError)
}

// newZFMWithMatrix builds a manager with the built-in zone set and matrix,
// so matrix rules are installed.
func newZFMWithMatrix(t *testing.T, ctrl *zoneTestController) *ZoneFlowManager {
	t.Helper()
	defaults := zone.Defaults()
	m, err := NewZoneFlowManager(ZoneFlowManagerConfig{
		BridgeName:     "br0",
		FlowController: ctrl,
		PortController: ctrl,
		Plan:           testPlan(t),
		Zones:          defaults,
		Matrix:         zone.CompileMatrix(defaults),
	})
	require.NoError(t, err)
	return m
}

// TestApplyZoneFlows_AccessPortMatchesUntagged installs an access port's
// template and its zone's matrix rows on untagged ingress: the flow tables
// see an access port's frames without a VLAN header.
func TestApplyZoneFlows_AccessPortMatchesUntagged(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFMWithMatrix(t, ctrl)
	require.NoError(t, m.ApplyZoneFlows(context.Background(), "eth0", zone.ZoneBackup))

	flows, err := ctrl.ListFlows("br0")
	require.NoError(t, err)
	// Each recorded flow reads "p=<priority> <match> -> <actions>".
	var portTemplate, portMatrix int
	for _, f := range flows {
		if !strings.Contains(f, " in_port=eth0,") {
			continue
		}
		assert.Contains(t, f, "vlan_tci=0x0000/0x1fff", f)
		assert.NotContains(t, f, "dl_vlan", f)
		if strings.HasSuffix(f, "-> drop") && strings.Contains(f, "nw_dst=") {
			portMatrix++
		} else {
			portTemplate++
		}
	}
	assert.Positive(t, portTemplate, "the backup template on untagged ingress")
	assert.Positive(t, portMatrix, "backup's matrix denies on untagged ingress")
}

// TestApplyPortClassFlows_NativeZoneMatrixRows adds untagged matrix rows for
// a trunk's native zone only; a trunk with no native zone gets none.
func TestApplyPortClassFlows_NativeZoneMatrixRows(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFMWithMatrix(t, ctrl)
	require.NoError(t, m.ApplyPortClassFlows(context.Background(), "eth0", zone.PortClassHypervisor))
	require.NotEmpty(t, m.compilePortMatrixFlows("eth0", zone.ZoneProvisioning))
	assert.Nil(t, m.compilePortMatrixFlows("eth0", ""), "no native zone, no untagged rows")

	bare := newZFM(t, ctrl)
	assert.Nil(t, bare.compilePortMatrixFlows("eth0", zone.ZoneProvisioning), "no zone set, no matrix rows")
}
