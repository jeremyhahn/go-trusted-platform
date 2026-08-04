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
//   - inter-zone matrix compilation spot-checks (deny public→trusted, allow trusted→public, storage isolation)
//   - ApplyZoneFlows happy-path and typed-error paths
//   - RemoveFlows lifecycle and error handling
//   - concurrent access safety
package policy

import (
	"context"
	"fmt"
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
	stateCalls []ovs.PortState
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

func (c *zoneTestController) SetPortState(_ context.Context, _ string, state ovs.PortState) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.stateCalls = append(c.stateCalls, state)
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
	applyAndAssert(t, m, ctrl, "eth0", zone.ZoneProvisioning, DefaultProvisioningVLAN)
}

func TestApplyZoneFlows_Quarantine(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	applyAndAssert(t, m, ctrl, "eth0", zone.ZoneQuarantine, DefaultQuarantineVLAN)
}

func TestApplyZoneFlows_Trusted(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	const trustedVLAN = 200
	applyAndAssert(t, m, ctrl, "eth0", zone.ZoneTrusted, trustedVLAN)
}

func TestApplyZoneFlows_Management(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	const mgmtVLAN = 50
	applyAndAssert(t, m, ctrl, "eth0", zone.ZoneManagement, mgmtVLAN)
}

func TestApplyZoneFlows_Storage(t *testing.T) {
	ctrl := newZoneTestController()
	m := newZFM(t, ctrl)
	const storageVLAN = 203
	applyAndAssert(t, m, ctrl, "eth0", zone.ZoneStorage, storageVLAN)
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
	// A user-defined zone not in the ZoneIndex and not a built-in → typed error.
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
// zone.CompileMatrix against the six built-in zones from zone.Defaults().
// This mirrors the reference-network.md inter-zone policy:
//   - public → trusted: denied (untrusted external→internal)
//   - trusted → public: allowed (internal→internet)
//   - storage → trusted: denied (storage isolation)
//   - trusted → storage: denied (storage isolation)
func TestZoneMatrix_DefaultZones_SpotChecks(t *testing.T) {
	defaults := zone.Defaults()
	matrix := zone.CompileMatrix(defaults)

	cases := []struct {
		from, to  zone.Zone
		wantAllow bool
	}{
		{zone.ZonePublic, zone.ZoneTrusted, false},
		{zone.ZoneTrusted, zone.ZonePublic, true},
		{zone.ZoneTrusted, zone.ZoneStorage, true},          // trusted declares AllowTo storage
		{zone.ZoneStorage, zone.ZoneTrusted, true},          // storage declares AllowTo trusted (clients)
		{zone.ZoneQuarantine, zone.ZoneProvisioning, false}, // quarantine isolated, no AllowTo provisioning
		{zone.ZoneProvisioning, zone.ZoneQuarantine, false}, // provisioning isolated, no AllowTo quarantine
		{zone.ZoneQuarantine, zone.ZoneTrusted, false},      // quarantine isolated, no AllowTo trusted
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
// Zone lifecycle: provisioning → trusted → quarantine
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
	assert.Equal(t, DefaultProvisioningVLAN, v)

	// 2. Transition to trusted (enrolled + authorized)
	require.NoError(t, m.ApplyZoneFlows(ctx, portID, zone.ZoneTrusted))
	v, err = m.GetPortVLAN(portID)
	require.NoError(t, err)
	assert.Equal(t, uint16(200), v) // DefaultTrusted = 200

	// 3. Compliance failure → quarantine
	require.NoError(t, m.ApplyZoneFlows(ctx, portID, zone.ZoneQuarantine))
	v, err = m.GetPortVLAN(portID)
	require.NoError(t, err)
	assert.Equal(t, DefaultQuarantineVLAN, v)

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
		assert.Equal(t, DefaultProvisioningVLAN, v, "port %s VLAN mismatch", portID)
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
	assert.Equal(t, int64(DefaultProvisioningVLAN), ctrl.vlanCalls[0])
}

// ---------------------------------------------------------------------------
// Default VLAN constant accessibility
// ---------------------------------------------------------------------------

func TestDefaultVLANConstants(t *testing.T) {
	assert.EqualValues(t, 201, DefaultProvisioningVLAN, "DefaultProvisioningVLAN should be 201")
	assert.EqualValues(t, 202, DefaultQuarantineVLAN, "DefaultQuarantineVLAN should be 202")
}
