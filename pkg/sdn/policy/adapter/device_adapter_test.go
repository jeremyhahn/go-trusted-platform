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
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// ---------------------------------------------------------------------------
// Mock Types
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

// MockVLANFlowManager provides configurable mock behavior for VLANFlowManager.
type MockVLANFlowManager struct {
	ApplyProvisioningFlowsFunc func(portID, mac string) error
	ApplyProductionFlowsFunc   func(portID string, profile *entities.DeviceProfile) error
	ApplyQuarantineFlowsFunc   func(portID, mac string) error
	RemoveFlowsFunc            func(portID string) error
}

func (m *MockVLANFlowManager) ApplyProvisioningFlows(portID, mac string) error {
	if m.ApplyProvisioningFlowsFunc != nil {
		return m.ApplyProvisioningFlowsFunc(portID, mac)
	}
	return nil
}

func (m *MockVLANFlowManager) ApplyProductionFlows(portID string, profile *entities.DeviceProfile) error {
	if m.ApplyProductionFlowsFunc != nil {
		return m.ApplyProductionFlowsFunc(portID, profile)
	}
	return nil
}

func (m *MockVLANFlowManager) ApplyQuarantineFlows(portID, mac string) error {
	if m.ApplyQuarantineFlowsFunc != nil {
		return m.ApplyQuarantineFlowsFunc(portID, mac)
	}
	return nil
}

func (m *MockVLANFlowManager) RemoveFlows(portID string) error {
	if m.RemoveFlowsFunc != nil {
		return m.RemoveFlowsFunc(portID)
	}
	return nil
}

// MockEnrollmentHook provides configurable mock behavior for SDNEnrollmentHook.
type MockEnrollmentHook struct {
	RegisterPortFunc func(mac string, portID string)
	RegisteredPorts  map[string]string
}

func NewMockEnrollmentHook() *MockEnrollmentHook {
	return &MockEnrollmentHook{
		RegisteredPorts: make(map[string]string),
	}
}

func (m *MockEnrollmentHook) RegisterPort(mac string, portID string) {
	if m.RegisterPortFunc != nil {
		m.RegisterPortFunc(mac, portID)
		return
	}
	m.RegisteredPorts[mac] = portID
}

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

func (m *MockProfileDAO) FindByExactMAC(ctx context.Context, mac string) (*entities.DeviceProfile, error) {
	return &entities.DeviceProfile{}, nil
}

func (m *MockProfileDAO) FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
	return &entities.DeviceProfile{}, nil
}

// Ensure mock implements the interface
var _ devicedao.DeviceProfileDAO = (*MockProfileDAO)(nil)

// ---------------------------------------------------------------------------
// Test Helpers
// ---------------------------------------------------------------------------

// testDependencies holds all mock dependencies for testing.
type testDependencies struct {
	policyEngine   *MockPolicyEngine
	vlanManager    *MockVLANFlowManager
	enrollmentHook *MockEnrollmentHook
	profileDAO     *MockProfileDAO
}

// newTestDependencies creates a new set of test dependencies with default mock behavior.
func newTestDependencies() *testDependencies {
	return &testDependencies{
		policyEngine:   &MockPolicyEngine{},
		vlanManager:    &MockVLANFlowManager{},
		enrollmentHook: NewMockEnrollmentHook(),
		profileDAO:     &MockProfileDAO{},
	}
}

// createValidProfile creates a valid device profile for testing.
func createValidProfile() *entities.DeviceProfile {
	return &entities.DeviceProfile{
		ID:       1,
		TenantID: "test-tenant",
		Name:     "test-profile",
		Role:     entities.DeviceRoleServer,
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

// createValidEventContext creates a valid NetworkEventContext for testing.
func createValidEventContext() *device.NetworkEventContext {
	return &device.NetworkEventContext{
		DeviceID: "device-001",
		PortID:   "port-001",
		MAC:      "52:54:00:12:34:56",
		Serial:   "SN12345",
		Profile:  createValidProfile(),
		Phase:    device.NetworkPhaseProvisioning,
	}
}

// wrapVLANManager wraps MockVLANFlowManager to satisfy the adapter config.
// This helper creates a real VLANFlowManager that delegates to our mock functions.
func wrapVLANManager(mock *MockVLANFlowManager) *policy.VLANFlowManager {
	// Create a minimal flow controller mock for VLANFlowManager initialization
	flowController := &mockFlowController{}

	mgr, _ := policy.NewVLANFlowManager(policy.VLANFlowManagerConfig{
		BridgeName:     "br-test",
		FlowController: flowController,
	})
	return mgr
}

// mockFlowController implements policy.FlowController for VLANFlowManager creation.
type mockFlowController struct{}

func (m *mockFlowController) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	return nil
}

func (m *mockFlowController) DeleteFlow(bridgeName string, match string) error {
	return nil
}

func (m *mockFlowController) DeleteFlowsByPort(bridgeName string, portID string) error {
	return nil
}

func (m *mockFlowController) ListFlows(bridgeName string) ([]string, error) {
	return nil, nil
}

// wrapEnrollmentHook wraps MockEnrollmentHook to satisfy the adapter config.
func wrapEnrollmentHook(mock *MockEnrollmentHook, policyEngine policy.PolicyEngine, profileDAO devicedao.DeviceProfileDAO) *policy.SDNEnrollmentHook {
	hook, _ := policy.NewSDNEnrollmentHook(policy.SDNEnrollmentHookConfig{
		PolicyEngine: policyEngine,
		ProfileDAO:   profileDAO,
		MACExtractor: func(ipAddr string) string { return "52:54:00:12:34:56" },
	})
	return hook
}

// ---------------------------------------------------------------------------
// Constructor Tests
// ---------------------------------------------------------------------------

func TestNewDeviceSDNAdapter_Success(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})

	require.NoError(t, err)
	require.NotNil(t, adapter)
	assert.NotNil(t, adapter.handlers)
	assert.Len(t, adapter.handlers, 4)
}

func TestNewDeviceSDNAdapter_NilPolicyEngine(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   nil,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})

	require.Error(t, err)
	assert.Nil(t, adapter)
	assert.ErrorIs(t, err, ErrPolicyEngineNil)
}

func TestNewDeviceSDNAdapter_NilVLANManager(t *testing.T) {
	deps := newTestDependencies()
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    nil,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})

	require.Error(t, err)
	assert.Nil(t, adapter)
	assert.ErrorIs(t, err, ErrVLANManagerNil)
}

func TestNewDeviceSDNAdapter_NilEnrollmentHook(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: nil,
		ProfileDAO:     deps.profileDAO,
	})

	require.Error(t, err)
	assert.Nil(t, adapter)
	assert.ErrorIs(t, err, ErrEnrollmentHookNil)
}

func TestNewDeviceSDNAdapter_NilProfileDAO(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     nil,
	})

	require.Error(t, err)
	assert.Nil(t, adapter)
	assert.ErrorIs(t, err, ErrProfileDAONil)
}

func TestNewDeviceSDNAdapter_NilLogger_UsesDefault(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		Logger:         nil,
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})

	require.NoError(t, err)
	require.NotNil(t, adapter)
	assert.NotNil(t, adapter.logger)
}

// ---------------------------------------------------------------------------
// OnDeviceConnect Tests
// ---------------------------------------------------------------------------

func TestOnDeviceConnect_Success(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	setPortStateCalled := false
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, "port-001", portID)
		assert.Equal(t, policy.PortStateProvisioning, state)
		return nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	ctx := context.Background()

	err = adapter.OnDeviceConnect(ctx, event)

	require.NoError(t, err)
	assert.True(t, setPortStateCalled)
}

func TestOnDeviceConnect_EmptyPortID(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.PortID = ""
	ctx := context.Background()

	err = adapter.OnDeviceConnect(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

func TestOnDeviceConnect_EmptyMAC(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.MAC = ""
	ctx := context.Background()

	err = adapter.OnDeviceConnect(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrMACEmpty)
}

func TestOnDeviceConnect_FlowInstallFailed(t *testing.T) {
	deps := newTestDependencies()
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	// Use a custom flow controller that fails
	flowController := &mockFlowControllerFailing{}
	vlanMgr, _ := policy.NewVLANFlowManager(policy.VLANFlowManagerConfig{
		BridgeName:     "br-test",
		FlowController: flowController,
	})

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	ctx := context.Background()

	err = adapter.OnDeviceConnect(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrFlowInstallFailed)
}

// mockFlowControllerFailing always fails on InstallFlow.
type mockFlowControllerFailing struct{}

func (m *mockFlowControllerFailing) InstallFlow(bridgeName string, priority int, match string, actions string) error {
	return errors.New("flow install failed")
}

func (m *mockFlowControllerFailing) DeleteFlow(bridgeName string, match string) error {
	return nil
}

func (m *mockFlowControllerFailing) DeleteFlowsByPort(bridgeName string, portID string) error {
	return nil
}

func (m *mockFlowControllerFailing) ListFlows(bridgeName string) ([]string, error) {
	return nil, nil
}

// ---------------------------------------------------------------------------
// OnDeviceEnrolled Tests
// ---------------------------------------------------------------------------

func TestOnDeviceEnrolled_Success(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	setPortStateCalled := false
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, "port-001", portID)
		assert.Equal(t, policy.PortStateAuthorized, state)
		return nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Phase = device.NetworkPhaseProduction
	ctx := context.Background()

	err = adapter.OnDeviceEnrolled(ctx, event)

	require.NoError(t, err)
	assert.True(t, setPortStateCalled)
}

func TestOnDeviceEnrolled_NilProfile(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Profile = nil
	ctx := context.Background()

	err = adapter.OnDeviceEnrolled(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidProfile)
}

func TestOnDeviceEnrolled_NoProductionNetwork(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Profile.Networks = nil
	ctx := context.Background()

	err = adapter.OnDeviceEnrolled(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoProductionNetwork)
}

func TestOnDeviceEnrolled_EmptyPortID(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.PortID = ""
	ctx := context.Background()

	err = adapter.OnDeviceEnrolled(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

// ---------------------------------------------------------------------------
// OnComplianceFail Tests
// ---------------------------------------------------------------------------

func TestOnComplianceFail_Success(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	setPortStateCalled := false
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, "port-001", portID)
		assert.Equal(t, policy.PortStateQuarantined, state)
		return nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Reason = "compliance check failed"
	ctx := context.Background()

	err = adapter.OnComplianceFail(ctx, event)

	require.NoError(t, err)
	assert.True(t, setPortStateCalled)
}

func TestOnComplianceFail_EmptyPortID(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.PortID = ""
	ctx := context.Background()

	err = adapter.OnComplianceFail(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

func TestOnComplianceFail_EmptyMAC(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.MAC = ""
	ctx := context.Background()

	err = adapter.OnComplianceFail(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrMACEmpty)
}

// ---------------------------------------------------------------------------
// ApplyNetworkPhase Tests
// ---------------------------------------------------------------------------

func TestApplyNetworkPhase_Provisioning(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	setPortStateCalled := false
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, "port-001", portID)
		assert.Equal(t, policy.PortStateProvisioning, state)
		return nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Phase = device.NetworkPhaseProvisioning
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.NoError(t, err)
	assert.True(t, setPortStateCalled)
}

func TestApplyNetworkPhase_Production(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	setPortStateCalled := false
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, "port-001", portID)
		assert.Equal(t, policy.PortStateAuthorized, state)
		return nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Phase = device.NetworkPhaseProduction
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.NoError(t, err)
	assert.True(t, setPortStateCalled)
}

func TestApplyNetworkPhase_Quarantine(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	setPortStateCalled := false
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, "port-001", portID)
		assert.Equal(t, policy.PortStateQuarantined, state)
		return nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Phase = device.NetworkPhaseQuarantine
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.NoError(t, err)
	assert.True(t, setPortStateCalled)
}

func TestApplyNetworkPhase_InvalidPhase(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Phase = device.NetworkPhase("invalid-phase")
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrInvalidNetworkPhase)
}

func TestApplyNetworkPhase_ValidationError_EmptyPortID(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.PortID = ""
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

func TestApplyNetworkPhase_ValidationError_EmptyMAC(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.MAC = ""
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrMACEmpty)
}

func TestApplyNetworkPhase_ValidationError_NilProfile(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Profile = nil
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrProfileNil)
}

// ---------------------------------------------------------------------------
// GetPortState Tests
// ---------------------------------------------------------------------------

func TestGetPortState_Success(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	deps.policyEngine.GetPortStateFunc = func(portID string) (policy.PortState, error) {
		assert.Equal(t, "port-001", portID)
		return policy.PortStateAuthorized, nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	ctx := context.Background()
	state, err := adapter.GetPortState(ctx, "port-001")

	require.NoError(t, err)
	assert.Equal(t, "authorized", state)
}

func TestGetPortState_EmptyPortID(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	ctx := context.Background()
	state, err := adapter.GetPortState(ctx, "")

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
	assert.Empty(t, state)
}

func TestGetPortState_EngineError(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	expectedError := errors.New("policy engine error")
	deps.policyEngine.GetPortStateFunc = func(portID string) (policy.PortState, error) {
		return policy.PortStateUnconnected, expectedError
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	ctx := context.Background()
	state, err := adapter.GetPortState(ctx, "port-001")

	require.Error(t, err)
	assert.Equal(t, expectedError, err)
	assert.Empty(t, state)
}

func TestGetPortState_AllStates(t *testing.T) {
	testCases := []struct {
		name        string
		state       policy.PortState
		expectedStr string
	}{
		{"Unconnected", policy.PortStateUnconnected, "unconnected"},
		{"Provisioning", policy.PortStateProvisioning, "provisioning"},
		{"Enrolled", policy.PortStateEnrolled, "enrolled"},
		{"Unauthorized", policy.PortStateUnauthorized, "unauthorized"},
		{"Authenticating", policy.PortStateAuthenticating, "authenticating"},
		{"Authorized", policy.PortStateAuthorized, "authorized"},
		{"Quarantined", policy.PortStateQuarantined, "quarantined"},
		{"Blocked", policy.PortStateBlocked, "blocked"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			deps := newTestDependencies()
			vlanMgr := wrapVLANManager(deps.vlanManager)
			enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

			deps.policyEngine.GetPortStateFunc = func(portID string) (policy.PortState, error) {
				return tc.state, nil
			}

			adapter, err := NewDeviceSDNAdapter(AdapterConfig{
				PolicyEngine:   deps.policyEngine,
				VLANManager:    vlanMgr,
				EnrollmentHook: enrollHook,
				ProfileDAO:     deps.profileDAO,
			})
			require.NoError(t, err)

			ctx := context.Background()
			state, err := adapter.GetPortState(ctx, "port-001")

			require.NoError(t, err)
			assert.Equal(t, tc.expectedStr, state)
		})
	}
}

// ---------------------------------------------------------------------------
// Handler Dispatch Tests
// ---------------------------------------------------------------------------

func TestDispatch_HandlerNotFound(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	// Clear handlers to force handler not found
	adapter.handlers = make(map[device.NetworkEvent]HandlerFunc)

	event := createValidEventContext()
	ctx := context.Background()

	err = adapter.OnDeviceConnect(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrHandlerNotFound)
}

// ---------------------------------------------------------------------------
// Disconnect Handler Tests
// ---------------------------------------------------------------------------

func TestOnDeviceDisconnect_Success(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	setPortStateCalled := false
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, "port-001", portID)
		assert.Equal(t, policy.PortStateUnconnected, state)
		return nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	ctx := context.Background()

	// Call the disconnect handler through the dispatch mechanism
	err = adapter.dispatch(ctx, device.NetworkEventDisconnect, event)

	require.NoError(t, err)
	assert.True(t, setPortStateCalled)
}

func TestOnDeviceDisconnect_EmptyPortID(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.PortID = ""
	ctx := context.Background()

	err = adapter.dispatch(ctx, device.NetworkEventDisconnect, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

// ---------------------------------------------------------------------------
// Table-Driven Tests for NetworkEvent String Representation
// ---------------------------------------------------------------------------

func TestNetworkEvent_String(t *testing.T) {
	testCases := []struct {
		event    device.NetworkEvent
		expected string
	}{
		{device.NetworkEventConnect, "connect"},
		{device.NetworkEventEnrolled, "enrolled"},
		{device.NetworkEventComplianceFail, "compliance_fail"},
		{device.NetworkEventDisconnect, "disconnect"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.event.String())
		})
	}
}

func TestNetworkEvent_IsValid(t *testing.T) {
	testCases := []struct {
		name     string
		event    device.NetworkEvent
		expected bool
	}{
		{"Connect", device.NetworkEventConnect, true},
		{"Enrolled", device.NetworkEventEnrolled, true},
		{"ComplianceFail", device.NetworkEventComplianceFail, true},
		{"Disconnect", device.NetworkEventDisconnect, true},
		{"Invalid", device.NetworkEvent(100), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.event.IsValid())
		})
	}
}

// ---------------------------------------------------------------------------
// Table-Driven Tests for NetworkPhase
// ---------------------------------------------------------------------------

func TestNetworkPhase_String(t *testing.T) {
	testCases := []struct {
		phase    device.NetworkPhase
		expected string
	}{
		{device.NetworkPhaseProvisioning, "provisioning"},
		{device.NetworkPhaseProduction, "production"},
		{device.NetworkPhaseQuarantine, "quarantine"},
	}

	for _, tc := range testCases {
		t.Run(tc.expected, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.phase.String())
		})
	}
}

func TestNetworkPhase_IsValid(t *testing.T) {
	testCases := []struct {
		name     string
		phase    device.NetworkPhase
		expected bool
	}{
		{"Provisioning", device.NetworkPhaseProvisioning, true},
		{"Production", device.NetworkPhaseProduction, true},
		{"Quarantine", device.NetworkPhaseQuarantine, true},
		{"Invalid", device.NetworkPhase("invalid"), false},
		{"Empty", device.NetworkPhase(""), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.phase.IsValid())
		})
	}
}

// ---------------------------------------------------------------------------
// NetworkEventContext Validation Tests
// ---------------------------------------------------------------------------

func TestNetworkEventContext_Validate_Success(t *testing.T) {
	event := createValidEventContext()
	err := event.Validate()
	require.NoError(t, err)
}

func TestNetworkEventContext_Validate_EmptyPortID(t *testing.T) {
	event := createValidEventContext()
	event.PortID = ""
	err := event.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

func TestNetworkEventContext_Validate_EmptyMAC(t *testing.T) {
	event := createValidEventContext()
	event.MAC = ""
	err := event.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrMACEmpty)
}

func TestNetworkEventContext_Validate_NilProfile(t *testing.T) {
	event := createValidEventContext()
	event.Profile = nil
	err := event.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrProfileNil)
}

func TestNetworkEventContext_Validate_InvalidPhase(t *testing.T) {
	event := createValidEventContext()
	event.Phase = device.NetworkPhase("invalid")
	err := event.Validate()
	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrInvalidNetworkPhase)
}

// ---------------------------------------------------------------------------
// Error Path Tests - SetPortState Failures
// ---------------------------------------------------------------------------

func TestApplyNetworkPhase_Provisioning_SetPortStateError(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	expectedErr := errors.New("port state update failed")
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		return expectedErr
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Phase = device.NetworkPhaseProvisioning
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "port state update failed")
}

func TestApplyNetworkPhase_Production_SetPortStateError(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	expectedErr := errors.New("port state update failed")
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		return expectedErr
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Phase = device.NetworkPhaseProduction
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "port state update failed")
}

func TestApplyNetworkPhase_Quarantine_SetPortStateError(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	expectedErr := errors.New("port state update failed")
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		return expectedErr
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Phase = device.NetworkPhaseQuarantine
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "port state update failed")
}

// ---------------------------------------------------------------------------
// Error Path Tests - Production Phase Validation
// ---------------------------------------------------------------------------

func TestApplyNetworkPhase_Production_NilProductionNetwork(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.Phase = device.NetworkPhaseProduction
	event.Profile = &entities.DeviceProfile{
		ID:   1,
		Name: "Test Profile",
	}
	ctx := context.Background()

	err = adapter.ApplyNetworkPhase(ctx, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoProductionNetwork)
}

// ---------------------------------------------------------------------------
// Error Path Tests - Disconnect Handler
// ---------------------------------------------------------------------------

func TestHandleDisconnect_RemoveFlowsError_ContinuesToSetState(t *testing.T) {
	deps := newTestDependencies()
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	deps.vlanManager.RemoveFlowsFunc = func(portID string) error {
		return errors.New("flow removal failed")
	}
	vlanMgr := wrapVLANManager(deps.vlanManager)

	setPortStateCalled := false
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		setPortStateCalled = true
		assert.Equal(t, policy.PortStateUnconnected, state)
		return nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	ctx := context.Background()

	// Disconnect should continue even if flow removal fails
	err = adapter.dispatch(ctx, device.NetworkEventDisconnect, event)

	require.NoError(t, err)
	assert.True(t, setPortStateCalled, "SetPortState should be called even after RemoveFlows failure")
}

func TestHandleDisconnect_SetPortStateError(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	expectedErr := errors.New("set port state failed")
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		return expectedErr
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	ctx := context.Background()

	err = adapter.dispatch(ctx, device.NetworkEventDisconnect, event)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "set port state failed")
}

func TestHandleDisconnect_EmptyPortID(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	event := createValidEventContext()
	event.PortID = ""
	ctx := context.Background()

	err = adapter.dispatch(ctx, device.NetworkEventDisconnect, event)

	require.Error(t, err)
	assert.ErrorIs(t, err, device.ErrPortIDEmpty)
}

// ---------------------------------------------------------------------------
// Integration-style Tests (Testing Multiple Components Together)
// ---------------------------------------------------------------------------

func TestAdapter_FullLifecycle_Connect_Enroll_Disconnect(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	stateTransitions := make([]policy.PortState, 0)
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		stateTransitions = append(stateTransitions, state)
		return nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	ctx := context.Background()
	event := createValidEventContext()

	// Step 1: Device connects
	err = adapter.OnDeviceConnect(ctx, event)
	require.NoError(t, err)

	// Step 2: Device enrolls
	err = adapter.OnDeviceEnrolled(ctx, event)
	require.NoError(t, err)

	// Step 3: Device disconnects
	err = adapter.dispatch(ctx, device.NetworkEventDisconnect, event)
	require.NoError(t, err)

	// Verify state transitions occurred
	assert.GreaterOrEqual(t, len(stateTransitions), 3)
	assert.Contains(t, stateTransitions, policy.PortStateProvisioning)
	assert.Contains(t, stateTransitions, policy.PortStateAuthorized)
	assert.Contains(t, stateTransitions, policy.PortStateUnconnected)
}

func TestAdapter_ComplianceFailure_MovesToQuarantine(t *testing.T) {
	deps := newTestDependencies()
	vlanMgr := wrapVLANManager(deps.vlanManager)
	enrollHook := wrapEnrollmentHook(deps.enrollmentHook, deps.policyEngine, deps.profileDAO)

	finalState := policy.PortStateUnconnected
	deps.policyEngine.SetPortStateFunc = func(portID string, state policy.PortState) error {
		finalState = state
		return nil
	}

	adapter, err := NewDeviceSDNAdapter(AdapterConfig{
		PolicyEngine:   deps.policyEngine,
		VLANManager:    vlanMgr,
		EnrollmentHook: enrollHook,
		ProfileDAO:     deps.profileDAO,
	})
	require.NoError(t, err)

	ctx := context.Background()
	event := createValidEventContext()
	event.Reason = "failed attestation"

	err = adapter.OnComplianceFail(ctx, event)
	require.NoError(t, err)

	assert.Equal(t, policy.PortStateQuarantined, finalState)
}
