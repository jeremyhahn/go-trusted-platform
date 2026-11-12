// Copyright 2025 Jeremy Hahn, Automate The Things, LLC
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-trusted-platform is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with go-trusted-platform. If not, see <https://www.gnu.org/licenses/>.
//
// For commercial licensing options, please contact: licensing@automatethethings.com
//
// SPDX-FileType: SOURCE
// SPDX-FileCopyrightText: 2025 Jeremy Hahn, Automate The Things, LLC
// SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial

package adapter

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	devicedao "github.com/jeremyhahn/go-trusted-platform/pkg/device/dao"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// ---------------------------------------------------------------------------
// Mock OVSPortController for ZoneFlowManager construction
// ---------------------------------------------------------------------------

// mockOVSPortController implements policy.OVSPortController for testing.
type mockOVSPortController struct {
	installErr    error
	setTrunkCalls [][]uint16
	setVLANCalls  []int64
}

func (m *mockOVSPortController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	if m.installErr != nil {
		return m.installErr
	}
	return nil
}

func (m *mockOVSPortController) InstallFlows(bridgeName string, rules []zoneflows.FlowRule) error {
	if m.installErr != nil {
		return m.installErr
	}
	return nil
}

func (m *mockOVSPortController) DeleteFlow(bridgeName string, match string) error {
	return nil
}

func (m *mockOVSPortController) DeleteFlowsByPort(bridgeName string, portID string) error {
	return nil
}

func (m *mockOVSPortController) ListFlows(bridgeName string) ([]string, error) {
	return nil, nil
}

func (m *mockOVSPortController) SetPortVLAN(ctx context.Context, portName string, vlan int64) error {
	m.setVLANCalls = append(m.setVLANCalls, vlan)
	return nil
}

func (m *mockOVSPortController) SetPortTrunk(ctx context.Context, portName string, allowed []uint16, native uint16) error {
	m.setTrunkCalls = append(m.setTrunkCalls, allowed)
	return nil
}

func (m *mockOVSPortController) SetPortState(context.Context, string, ovs.PortState) error {
	return nil
}

func (m *mockOVSPortController) GetOFPort(ctx context.Context, portName string) (int32, error) {
	return 1, nil
}

// newTestZoneFlowManager creates a ZoneFlowManager backed by a mock OVS controller.
func newTestZoneFlowManager(ovsCtrl *mockOVSPortController) *policy.ZoneFlowManager {
	if ovsCtrl == nil {
		ovsCtrl = &mockOVSPortController{}
	}
	plan, err := netplan.New(netplan.Environment{ID: 4}, zone.Defaults())
	if err != nil {
		panic(err)
	}
	mgr, err := policy.NewZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName:     "br-test",
		FlowController: ovsCtrl,
		PortController: ovsCtrl,
		Plan:           plan,
	})
	if err != nil {
		panic(err)
	}
	return mgr
}

// ---------------------------------------------------------------------------
// Mock PolicyEngine
// ---------------------------------------------------------------------------

// MockPolicyEngine implements policy.PolicyEngine for testing.
type MockPolicyEngine struct {
	SetPortStateFunc     func(portID string, state policy.PortState) error
	GetPortStateFunc     func(portID string) (policy.PortState, error)
	GetPortInfoFunc      func(portID string) (*policy.PortInfo, error)
	ApplyPolicyFunc      func(portID string, pol *policy.PortPolicy) error
	RemovePolicyFunc     func(portID string) error
	GetPolicyFunc        func(portID string) (*policy.PortPolicy, error)
	SetPortVLANFunc      func(portID string, vlan uint16) error
	GetPortVLANFunc      func(portID string) (uint16, error)
	BlockPortFunc        func(portID string) error
	UnblockPortFunc      func(portID string) error
	GetOFPortFunc        func(portID string) (int32, error)
	AuthenticatePortFunc func(portID string, cert *x509.Certificate) error
	OnCertExpiredFunc    func(portID string) error
	OnCertRevokedFunc    func(portID string) error
	GetMonitorFunc       func() *policy.CertificateMonitor
}

func (m *MockPolicyEngine) SetPortState(portID string, state policy.PortState) error {
	if m.SetPortStateFunc != nil {
		return m.SetPortStateFunc(portID, state)
	}
	return nil
}

func (m *MockPolicyEngine) GetPortState(portID string) (policy.PortState, error) {
	if m.GetPortStateFunc != nil {
		return m.GetPortStateFunc(portID)
	}
	return policy.PortStateUnconnected, nil
}

func (m *MockPolicyEngine) GetPortInfo(portID string) (*policy.PortInfo, error) {
	if m.GetPortInfoFunc != nil {
		return m.GetPortInfoFunc(portID)
	}
	return &policy.PortInfo{}, nil
}

func (m *MockPolicyEngine) ApplyPolicy(portID string, pol *policy.PortPolicy) error {
	if m.ApplyPolicyFunc != nil {
		return m.ApplyPolicyFunc(portID, pol)
	}
	return nil
}

func (m *MockPolicyEngine) RemovePolicy(portID string) error {
	if m.RemovePolicyFunc != nil {
		return m.RemovePolicyFunc(portID)
	}
	return nil
}

func (m *MockPolicyEngine) GetPolicy(portID string) (*policy.PortPolicy, error) {
	if m.GetPolicyFunc != nil {
		return m.GetPolicyFunc(portID)
	}
	return &policy.PortPolicy{}, nil
}

func (m *MockPolicyEngine) SetPortVLAN(portID string, vlan uint16) error {
	if m.SetPortVLANFunc != nil {
		return m.SetPortVLANFunc(portID, vlan)
	}
	return nil
}

func (m *MockPolicyEngine) GetPortVLAN(portID string) (uint16, error) {
	if m.GetPortVLANFunc != nil {
		return m.GetPortVLANFunc(portID)
	}
	return 0, nil
}

func (m *MockPolicyEngine) BlockPort(portID string) error {
	if m.BlockPortFunc != nil {
		return m.BlockPortFunc(portID)
	}
	return nil
}

func (m *MockPolicyEngine) UnblockPort(portID string) error {
	if m.UnblockPortFunc != nil {
		return m.UnblockPortFunc(portID)
	}
	return nil
}

func (m *MockPolicyEngine) GetOFPort(portID string) (int32, error) {
	if m.GetOFPortFunc != nil {
		return m.GetOFPortFunc(portID)
	}
	return 0, nil
}

func (m *MockPolicyEngine) AuthenticatePort(portID string, cert *x509.Certificate) error {
	if m.AuthenticatePortFunc != nil {
		return m.AuthenticatePortFunc(portID, cert)
	}
	return nil
}

func (m *MockPolicyEngine) OnCertificateExpired(portID string) error {
	if m.OnCertExpiredFunc != nil {
		return m.OnCertExpiredFunc(portID)
	}
	return nil
}

func (m *MockPolicyEngine) OnCertificateRevoked(portID string) error {
	if m.OnCertRevokedFunc != nil {
		return m.OnCertRevokedFunc(portID)
	}
	return nil
}

func (m *MockPolicyEngine) GetMonitor() *policy.CertificateMonitor {
	if m.GetMonitorFunc != nil {
		return m.GetMonitorFunc()
	}
	return nil
}

// ---------------------------------------------------------------------------
// Mock ProfileDAO
// ---------------------------------------------------------------------------

// MockProfileDAO implements devicedao.DeviceProfileDAO for testing.
type MockProfileDAO struct {
	SaveFunc                func(ctx context.Context, entity *entities.DeviceProfile) error
	GetFunc                 func(ctx context.Context, id uint64) (*entities.DeviceProfile, error)
	DeleteFunc              func(ctx context.Context, entity *entities.DeviceProfile) error
	CountFunc               func(ctx context.Context) (int, error)
	PageFunc                func(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error)
	ForEachPageFunc         func(ctx context.Context, query datastore.PageQuery, fn datastore.PagerFunc[*entities.DeviceProfile]) error
	FindByMACPrefixFunc     func(ctx context.Context, macAddr string) (*entities.DeviceProfile, error)
	FindBySerialPrefixFunc  func(ctx context.Context, serial string) (*entities.DeviceProfile, error)
	FindMatchingProfileFunc func(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error)
}

func (m *MockProfileDAO) Save(ctx context.Context, entity *entities.DeviceProfile) error {
	if m.SaveFunc != nil {
		return m.SaveFunc(ctx, entity)
	}
	return nil
}

func (m *MockProfileDAO) Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
	if m.GetFunc != nil {
		return m.GetFunc(ctx, id)
	}
	return &entities.DeviceProfile{}, nil
}

func (m *MockProfileDAO) Delete(ctx context.Context, entity *entities.DeviceProfile) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(ctx, entity)
	}
	return nil
}

func (m *MockProfileDAO) Count(ctx context.Context) (int, error) {
	if m.CountFunc != nil {
		return m.CountFunc(ctx)
	}
	return 0, nil
}

func (m *MockProfileDAO) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error) {
	if m.PageFunc != nil {
		return m.PageFunc(ctx, query)
	}
	return datastore.PageResult[*entities.DeviceProfile]{}, nil
}

func (m *MockProfileDAO) ForEachPage(ctx context.Context, query datastore.PageQuery, fn datastore.PagerFunc[*entities.DeviceProfile]) error {
	if m.ForEachPageFunc != nil {
		return m.ForEachPageFunc(ctx, query, fn)
	}
	return nil
}

func (m *MockProfileDAO) FindByMACPrefix(ctx context.Context, macAddr string) (*entities.DeviceProfile, error) {
	if m.FindByMACPrefixFunc != nil {
		return m.FindByMACPrefixFunc(ctx, macAddr)
	}
	return &entities.DeviceProfile{}, nil
}

func (m *MockProfileDAO) FindBySerialPrefix(ctx context.Context, serial string) (*entities.DeviceProfile, error) {
	if m.FindBySerialPrefixFunc != nil {
		return m.FindBySerialPrefixFunc(ctx, serial)
	}
	return &entities.DeviceProfile{}, nil
}

func (m *MockProfileDAO) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	if m.FindMatchingProfileFunc != nil {
		return m.FindMatchingProfileFunc(ctx, macAddr, serial, model)
	}
	return &entities.DeviceProfile{}, nil
}

func (m *MockProfileDAO) FindByEKSerial(ctx context.Context, ekSerial string) (*entities.DeviceProfile, error) {
	return &entities.DeviceProfile{}, nil
}

func (m *MockProfileDAO) FindByDICEDeviceID(ctx context.Context, diceDeviceID string) (*entities.DeviceProfile, error) {
	return &entities.DeviceProfile{}, nil
}

func (m *MockProfileDAO) FindByExactMAC(ctx context.Context, mac string) (*entities.DeviceProfile, error) {
	return &entities.DeviceProfile{}, nil
}

func (m *MockProfileDAO) FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
	return &entities.DeviceProfile{}, nil
}

var _ devicedao.DeviceProfileDAO = (*MockProfileDAO)(nil)

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

// testDeps bundles all mock dependencies.
type testDeps struct {
	engine     *MockPolicyEngine
	ovsCtrl    *mockOVSPortController
	profileDAO *MockProfileDAO
}

func newTestDeps() *testDeps {
	return &testDeps{
		engine:     &MockPolicyEngine{},
		ovsCtrl:    &mockOVSPortController{},
		profileDAO: &MockProfileDAO{},
	}
}

func wrapEnrollmentHook(pe policy.PolicyEngine, dao devicedao.DeviceProfileDAO) *policy.SDNEnrollmentHook {
	hook, _ := policy.NewSDNEnrollmentHook(policy.SDNEnrollmentHookConfig{
		PolicyEngine: pe,
		ProfileDAO:   dao,
		MACExtractor: func(ipAddr string) string { return "52:54:00:12:34:56" },
	})
	return hook
}

func newAdapter(t *testing.T, deps *testDeps) *DeviceSDNAdapter {
	t.Helper()
	zfm := newTestZoneFlowManager(deps.ovsCtrl)
	hook := wrapEnrollmentHook(deps.engine, deps.profileDAO)
	a, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:    deps.engine,
		ZoneFlowManager: zfm,
		EnrollmentHook:  hook,
		ProfileDAO:      deps.profileDAO,
	})
	require.NoError(t, err)
	return a
}

func createValidProfile() *entities.DeviceProfile {
	return &entities.DeviceProfile{
		ID:       1,
		TenantID: "test-tenant",
		Name:     "test-profile",
		Role:     entities.DeviceRoleWorker,
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN:       100,
				AuthMethod: entities.AuthMethod802_1X,
			},
			entities.DefaultFailureNetwork: {
				VLAN:       666,
				AuthMethod: entities.AuthMethodNone,
			},
			entities.DefaultEnrollmentNetwork: {
				VLAN:       998,
				AuthMethod: entities.AuthMethodNone,
			},
		},
	}
}

func createValidEvent() *device.NetworkEventContext {
	return &device.NetworkEventContext{
		DeviceID: "device-001",
		PortID:   "port-001",
		MAC:      "52:54:00:12:34:56",
		Serial:   "SN12345",
		Profile:  createValidProfile(),
		Phase:    device.NetworkPhaseProvisioning,
	}
}

// ---------------------------------------------------------------------------
// Constructor Tests
// ---------------------------------------------------------------------------

func TestNewDeviceSDNAdapter_Success(t *testing.T) {
	deps := newTestDeps()
	zfm := newTestZoneFlowManager(deps.ovsCtrl)
	hook := wrapEnrollmentHook(deps.engine, deps.profileDAO)

	a, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:    deps.engine,
		ZoneFlowManager: zfm,
		EnrollmentHook:  hook,
		ProfileDAO:      deps.profileDAO,
	})

	require.NoError(t, err)
	require.NotNil(t, a)
	assert.Len(t, a.handlers, 4)
}

func TestNewDeviceSDNAdapter_NilPolicyEngine(t *testing.T) {
	deps := newTestDeps()
	zfm := newTestZoneFlowManager(deps.ovsCtrl)
	hook := wrapEnrollmentHook(deps.engine, deps.profileDAO)

	_, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:    nil,
		ZoneFlowManager: zfm,
		EnrollmentHook:  hook,
		ProfileDAO:      deps.profileDAO,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPolicyEngineNil)
}

func TestNewDeviceSDNAdapter_NilZoneFlowManager(t *testing.T) {
	deps := newTestDeps()
	hook := wrapEnrollmentHook(deps.engine, deps.profileDAO)

	_, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:    deps.engine,
		ZoneFlowManager: nil,
		EnrollmentHook:  hook,
		ProfileDAO:      deps.profileDAO,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrZoneFlowManagerNil)
}

func TestNewDeviceSDNAdapter_NilEnrollmentHook(t *testing.T) {
	deps := newTestDeps()
	zfm := newTestZoneFlowManager(deps.ovsCtrl)

	_, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:    deps.engine,
		ZoneFlowManager: zfm,
		EnrollmentHook:  nil,
		ProfileDAO:      deps.profileDAO,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEnrollmentHookNil)
}

func TestNewDeviceSDNAdapter_NilProfileDAO(t *testing.T) {
	deps := newTestDeps()
	zfm := newTestZoneFlowManager(deps.ovsCtrl)
	hook := wrapEnrollmentHook(deps.engine, deps.profileDAO)

	_, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:    deps.engine,
		ZoneFlowManager: zfm,
		EnrollmentHook:  hook,
		ProfileDAO:      nil,
	})

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrProfileDAONil)
}

func TestNewDeviceSDNAdapter_NilLogger_UsesDefault(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)
	assert.NotNil(t, a.logger)
}

// ---------------------------------------------------------------------------
// OnDeviceConnect Tests
// ---------------------------------------------------------------------------

func TestOnDeviceConnect_Success(t *testing.T) {
	deps := newTestDeps()

	setPortStateCalled := false
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, "port-001", portID)
		assert.Equal(t, policy.PortStateProvisioning, state)
		return nil
	}

	a := newAdapter(t, deps)
	err := a.OnDeviceConnect(context.Background(), createValidEvent())
	require.NoError(t, err)
	assert.True(t, setPortStateCalled)
}

func TestOnDeviceConnect_EmptyPortID(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.PortID = ""
	err := a.OnDeviceConnect(context.Background(), event)
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

func TestOnDeviceConnect_EmptyMAC(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.MAC = ""
	err := a.OnDeviceConnect(context.Background(), event)
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrMACEmpty)
}

func TestOnDeviceConnect_FlowInstallFailed(t *testing.T) {
	deps := newTestDeps()
	deps.ovsCtrl.installErr = errors.New("OVS unreachable")

	a := newAdapter(t, deps)
	err := a.OnDeviceConnect(context.Background(), createValidEvent())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFlowInstallFailed)
}

// ---------------------------------------------------------------------------
// OnDeviceEnrolled Tests
// ---------------------------------------------------------------------------

func TestOnDeviceEnrolled_Success(t *testing.T) {
	deps := newTestDeps()

	setPortStateCalled := false
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, "port-001", portID)
		assert.Equal(t, policy.PortStateAuthorized, state)
		return nil
	}

	a := newAdapter(t, deps)
	event := createValidEvent()
	event.Phase = device.NetworkPhaseAdmitted
	err := a.OnDeviceEnrolled(context.Background(), event)
	require.NoError(t, err)
	assert.True(t, setPortStateCalled)
}

func TestOnDeviceEnrolled_NilProfile(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Profile = nil
	err := a.OnDeviceEnrolled(context.Background(), event)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidProfile)
}

// TestOnDeviceEnrolled_RoleZones admits a worker with no profile zone to
// the hypervisor trunk (its role's zones).
func TestOnDeviceEnrolled_RoleZones(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Profile.Networks = nil
	require.NoError(t, a.OnDeviceEnrolled(context.Background(), event))
	require.NotEmpty(t, deps.ovsCtrl.setTrunkCalls)
	assert.Equal(t, []uint16{401, 403, 404, 405, 406, 407, 408}, deps.ovsCtrl.setTrunkCalls[len(deps.ovsCtrl.setTrunkCalls)-1])
}

// TestOnDeviceEnrolled_ExplicitZone admits a device whose profile names a
// zone to that zone as an access port.
func TestOnDeviceEnrolled_ExplicitZone(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Profile.Zone = string(zone.ZoneStorage)
	require.NoError(t, a.OnDeviceEnrolled(context.Background(), event))
	assert.Empty(t, deps.ovsCtrl.setTrunkCalls)
	assert.Contains(t, deps.ovsCtrl.setVLANCalls, int64(407))
}

// TestOnDeviceEnrolled_RoleWithoutPortClass fails closed for a role with no
// port class and no profile zone: the port is not touched.
func TestOnDeviceEnrolled_RoleWithoutPortClass(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Profile.Role = entities.DeviceRoleIoT
	err := a.OnDeviceEnrolled(context.Background(), event)
	var target ErrNoAdmissionTarget
	require.ErrorAs(t, err, &target)
	assert.Equal(t, "iot", target.Role)
	assert.Contains(t, err.Error(), "port left unchanged")
	var roleErr entities.ErrNoPortClassForRole
	assert.ErrorAs(t, err, &roleErr)
	assert.Empty(t, deps.ovsCtrl.setTrunkCalls)
	assert.Empty(t, deps.ovsCtrl.setVLANCalls)
}

// TestOnDeviceEnrolled_UnknownProfileZone refuses a zone the zone set does
// not declare, before any port change.
func TestOnDeviceEnrolled_UnknownProfileZone(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Profile.Zone = "nowhere"
	var target policy.ErrAdmissionZone
	require.ErrorAs(t, a.OnDeviceEnrolled(context.Background(), event), &target)
	assert.Equal(t, zone.Zone("nowhere"), target.Zone)
	assert.Empty(t, deps.ovsCtrl.setVLANCalls, "a refused zone leaves the port unchanged")
}

// TestOnDeviceEnrolled_RefusedAdmissionZones refuses every zone a device
// may not be admitted onto, and admits onto storage.
func TestOnDeviceEnrolled_RefusedAdmissionZones(t *testing.T) {
	for _, z := range []zone.Zone{zone.ZoneManagement, zone.ZoneTransit, zone.ZoneFabric,
		zone.ZoneProvisioning, zone.ZoneQuarantine, zone.ZoneControlPlane} {
		t.Run(string(z), func(t *testing.T) {
			deps := newTestDeps()
			a := newAdapter(t, deps)
			event := createValidEvent()
			event.Profile.Zone = string(z)
			var target policy.ErrAdmissionZone
			require.ErrorAs(t, a.OnDeviceEnrolled(context.Background(), event), &target)
			assert.Empty(t, deps.ovsCtrl.setVLANCalls)
		})
	}

	deps := newTestDeps()
	a := newAdapter(t, deps)
	event := createValidEvent()
	event.Profile.Zone = string(zone.ZoneStorage)
	require.NoError(t, a.OnDeviceEnrolled(context.Background(), event))
	assert.NotEmpty(t, deps.ovsCtrl.setVLANCalls, "storage is an admission zone")
}

func TestOnDeviceEnrolled_EmptyPortID(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.PortID = ""
	err := a.OnDeviceEnrolled(context.Background(), event)
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

// ---------------------------------------------------------------------------
// OnComplianceFail Tests
// ---------------------------------------------------------------------------

func TestOnComplianceFail_Success(t *testing.T) {
	deps := newTestDeps()

	setPortStateCalled := false
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, "port-001", portID)
		assert.Equal(t, policy.PortStateQuarantined, state)
		return nil
	}

	a := newAdapter(t, deps)
	event := createValidEvent()
	event.Reason = "compliance check failed"
	err := a.OnComplianceFail(context.Background(), event)
	require.NoError(t, err)
	assert.True(t, setPortStateCalled)
}

func TestOnComplianceFail_EmptyPortID(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.PortID = ""
	err := a.OnComplianceFail(context.Background(), event)
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

func TestOnComplianceFail_EmptyMAC(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.MAC = ""
	err := a.OnComplianceFail(context.Background(), event)
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrMACEmpty)
}

// ---------------------------------------------------------------------------
// ApplyNetworkPhase Tests
// ---------------------------------------------------------------------------

func TestApplyNetworkPhase_Provisioning(t *testing.T) {
	deps := newTestDeps()

	var calledState policy.PortState
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		calledState = state
		return nil
	}

	a := newAdapter(t, deps)
	event := createValidEvent()
	event.Phase = device.NetworkPhaseProvisioning
	require.NoError(t, a.ApplyNetworkPhase(context.Background(), event))
	assert.Equal(t, policy.PortStateProvisioning, calledState)
}

func TestApplyNetworkPhase_Production(t *testing.T) {
	deps := newTestDeps()

	var calledState policy.PortState
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		calledState = state
		return nil
	}

	a := newAdapter(t, deps)
	event := createValidEvent()
	event.Phase = device.NetworkPhaseAdmitted
	require.NoError(t, a.ApplyNetworkPhase(context.Background(), event))
	assert.Equal(t, policy.PortStateAuthorized, calledState)
}

func TestApplyNetworkPhase_Quarantine(t *testing.T) {
	deps := newTestDeps()

	var calledState policy.PortState
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		calledState = state
		return nil
	}

	a := newAdapter(t, deps)
	event := createValidEvent()
	event.Phase = device.NetworkPhaseQuarantine
	require.NoError(t, a.ApplyNetworkPhase(context.Background(), event))
	assert.Equal(t, policy.PortStateQuarantined, calledState)
}

func TestApplyNetworkPhase_InvalidPhase(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Phase = device.NetworkPhase("invalid-phase")
	err := a.ApplyNetworkPhase(context.Background(), event)
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrInvalidNetworkPhase)
}

func TestApplyNetworkPhase_ValidationError_EmptyPortID(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.PortID = ""
	err := a.ApplyNetworkPhase(context.Background(), event)
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

func TestApplyNetworkPhase_ValidationError_EmptyMAC(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.MAC = ""
	err := a.ApplyNetworkPhase(context.Background(), event)
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrMACEmpty)
}

func TestApplyNetworkPhase_ValidationError_NilProfile(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Profile = nil
	err := a.ApplyNetworkPhase(context.Background(), event)
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrProfileNil)
}

func TestApplyNetworkPhase_Admitted_BareProfileWithoutRole(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Phase = device.NetworkPhaseAdmitted
	event.Profile = &entities.DeviceProfile{ID: 1, Name: "bare"}
	err := a.ApplyNetworkPhase(context.Background(), event)
	var target ErrNoAdmissionTarget
	require.ErrorAs(t, err, &target)
}

// ---------------------------------------------------------------------------
// GetPortState Tests
// ---------------------------------------------------------------------------

func TestGetPortState_Success(t *testing.T) {
	deps := newTestDeps()
	deps.engine.GetPortStateFunc = func(portID string) (policy.PortState, error) {
		return policy.PortStateAuthorized, nil
	}

	a := newAdapter(t, deps)
	state, err := a.GetPortState(context.Background(), "port-001")
	require.NoError(t, err)
	assert.Equal(t, "authorized", state)
}

func TestGetPortState_EmptyPortID(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	_, err := a.GetPortState(context.Background(), "")
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

func TestGetPortState_EngineError(t *testing.T) {
	deps := newTestDeps()
	expected := errors.New("engine failure")
	deps.engine.GetPortStateFunc = func(portID string) (policy.PortState, error) {
		return policy.PortStateUnconnected, expected
	}

	a := newAdapter(t, deps)
	_, err := a.GetPortState(context.Background(), "port-001")
	require.Error(t, err)
	assert.Equal(t, expected, err)
}

// ---------------------------------------------------------------------------
// Disconnect Handler Tests
// ---------------------------------------------------------------------------

func TestHandleDisconnect_Success(t *testing.T) {
	deps := newTestDeps()

	var calledState policy.PortState
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		calledState = state
		return nil
	}

	a := newAdapter(t, deps)
	event := createValidEvent()
	err := a.dispatch(context.Background(), device.NetworkEventDisconnect, event)
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateUnconnected, calledState)
}

func TestHandleDisconnect_EmptyPortID(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.PortID = ""
	err := a.dispatch(context.Background(), device.NetworkEventDisconnect, event)
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

func TestHandleDisconnect_FlowRemoveError_ContinuesToSetState(t *testing.T) {
	deps := newTestDeps()
	// Force flow deletion to fail
	deps.ovsCtrl.installErr = nil // deletion won't fail via this path

	var calledState policy.PortState
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		calledState = state
		return nil
	}

	a := newAdapter(t, deps)
	event := createValidEvent()
	// First apply flows so there's something to remove
	_ = a.zoneFlowManager.ApplyZoneFlows(context.Background(), event.PortID, "provisioning")

	err := a.dispatch(context.Background(), device.NetworkEventDisconnect, event)
	require.NoError(t, err)
	assert.Equal(t, policy.PortStateUnconnected, calledState)
}

func TestHandleDisconnect_SetPortStateError(t *testing.T) {
	deps := newTestDeps()
	expected := errors.New("set state failed")
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		return expected
	}

	a := newAdapter(t, deps)
	event := createValidEvent()
	err := a.dispatch(context.Background(), device.NetworkEventDisconnect, event)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set state failed")
}

// ---------------------------------------------------------------------------
// Dispatch Tests
// ---------------------------------------------------------------------------

func TestDispatch_HandlerNotFound(t *testing.T) {
	deps := newTestDeps()
	a := newAdapter(t, deps)
	a.handlers = make(map[device.NetworkEvent]HandlerFunc)

	err := a.dispatch(context.Background(), device.NetworkEventConnect, createValidEvent())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrHandlerNotFound)
}

// ---------------------------------------------------------------------------
// Full Lifecycle Integration Test
// ---------------------------------------------------------------------------

func TestAdapter_FullLifecycle_Connect_Enroll_Disconnect(t *testing.T) {
	deps := newTestDeps()

	var states []policy.PortState
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		states = append(states, state)
		return nil
	}

	a := newAdapter(t, deps)
	ctx := context.Background()
	event := createValidEvent()

	require.NoError(t, a.OnDeviceConnect(ctx, event))
	require.NoError(t, a.OnDeviceEnrolled(ctx, event))
	require.NoError(t, a.dispatch(ctx, device.NetworkEventDisconnect, event))

	assert.GreaterOrEqual(t, len(states), 3)
	assert.Contains(t, states, policy.PortStateProvisioning)
	assert.Contains(t, states, policy.PortStateAuthorized)
	assert.Contains(t, states, policy.PortStateUnconnected)
}

func TestAdapter_ComplianceFailure_MovesToQuarantine(t *testing.T) {
	deps := newTestDeps()

	var finalState policy.PortState
	deps.engine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		finalState = state
		return nil
	}

	a := newAdapter(t, deps)
	event := createValidEvent()
	event.Reason = "failed attestation"

	require.NoError(t, a.OnComplianceFail(context.Background(), event))
	assert.Equal(t, policy.PortStateQuarantined, finalState)
}

// ---------------------------------------------------------------------------
// SetPortState String Coverage
// ---------------------------------------------------------------------------

func TestGetPortState_AllStates(t *testing.T) {
	cases := []struct {
		state    policy.PortState
		expected string
	}{
		{policy.PortStateUnconnected, "unconnected"},
		{policy.PortStateProvisioning, "provisioning"},
		{policy.PortStateEnrolled, "enrolled"},
		{policy.PortStateUnauthorized, "unauthorized"},
		{policy.PortStateAuthenticating, "authenticating"},
		{policy.PortStateAuthorized, "authorized"},
		{policy.PortStateQuarantined, "quarantined"},
		{policy.PortStateBlocked, "blocked"},
	}
	for _, tc := range cases {
		t.Run(tc.expected, func(t *testing.T) {
			deps := newTestDeps()
			deps.engine.GetPortStateFunc = func(portID string) (policy.PortState, error) {
				return tc.state, nil
			}
			a := newAdapter(t, deps)
			s, err := a.GetPortState(context.Background(), "p")
			require.NoError(t, err)
			assert.Equal(t, tc.expected, s)
		})
	}
}

// ---------------------------------------------------------------------------
// NetworkEvent / NetworkPhase helper tests
// ---------------------------------------------------------------------------

func TestNetworkEvent_String(t *testing.T) {
	cases := []struct {
		event    device.NetworkEvent
		expected string
	}{
		{device.NetworkEventConnect, "connect"},
		{device.NetworkEventEnrolled, "enrolled"},
		{device.NetworkEventComplianceFail, "compliance_fail"},
		{device.NetworkEventDisconnect, "disconnect"},
	}
	for _, tc := range cases {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.event.String())
		})
	}
}

func TestNetworkPhase_String(t *testing.T) {
	cases := []struct {
		phase    device.NetworkPhase
		expected string
	}{
		{device.NetworkPhaseProvisioning, "provisioning"},
		{device.NetworkPhaseAdmitted, "admitted"},
		{device.NetworkPhaseQuarantine, "quarantine"},
	}
	for _, tc := range cases {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.phase.String())
		})
	}
}

// TestOnDeviceEnrolled_AllowedZoneFlowFailure surfaces a flow install
// failure on an admission zone that passed the admission rule.
func TestOnDeviceEnrolled_AllowedZoneFlowFailure(t *testing.T) {
	deps := newTestDeps()
	deps.ovsCtrl.installErr = errors.New("OVS unreachable")
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Profile.Zone = string(zone.ZoneStorage)
	assert.ErrorIs(t, a.OnDeviceEnrolled(context.Background(), event), ErrFlowInstallFailed)
}

// TestOnComplianceFail_FlowInstallFailed surfaces a quarantine flow install
// failure and leaves the port state untouched.
func TestOnComplianceFail_FlowInstallFailed(t *testing.T) {
	deps := newTestDeps()
	deps.ovsCtrl.installErr = errors.New("OVS unreachable")
	called := false
	deps.engine.SetPortStateFunc = func(string, policy.PortState) error {
		called = true
		return nil
	}
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Reason = "compliance check failed"
	assert.ErrorIs(t, a.OnComplianceFail(context.Background(), event), ErrFlowInstallFailed)
	assert.False(t, called, "no state change when the quarantine flows did not install")
}

// TestOnComplianceFail_PortStateError surfaces a policy engine failure after
// the quarantine flows installed.
func TestOnComplianceFail_PortStateError(t *testing.T) {
	deps := newTestDeps()
	deps.engine.SetPortStateFunc = func(string, policy.PortState) error {
		return errors.New("engine down")
	}
	a := newAdapter(t, deps)

	event := createValidEvent()
	event.Reason = "compliance check failed"
	assert.EqualError(t, a.OnComplianceFail(context.Background(), event), "engine down")
}
