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

package cluster

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// mockOVSClient is a mock implementation of OVSClient for testing.
type mockOVSClient struct {
	mu sync.RWMutex

	// Bridge state
	bridges map[string]*ovs.Bridge

	// Port state
	ports map[string]map[string]*ovs.Port // bridgeName -> portName -> port

	// Flow state
	flows map[string][]*ovs.Flow // bridgeName -> flows

	// Connection state
	connected atomic.Bool

	// Error injection
	createBridgeErr   error
	deleteBridgeErr   error
	getBridgeErr      error
	listBridgesErr    error
	updateBridgeErr   error
	addPortErr        error
	deletePortErr     error
	getPortErr        error
	listPortsErr      error
	setPortVLANErr    error
	setPortTrunksErr  error
	addFlowErr        error
	deleteFlowErr     error
	listFlowsErr      error
	deleteAllFlowsErr error

	// Call tracking
	createBridgeCalls  []string
	deleteBridgeCalls  []string
	addPortCalls       []string
	deletePortCalls    []string
	addFlowCalls       []string
	setFailModeCalls   []string
	setProtocolsCalls  []string
	setPortVLANCalls   []string
	setPortTrunksCalls []string
	updateBridgeCalls  []map[string]interface{}
}

func newMockOVSClient() *mockOVSClient {
	m := &mockOVSClient{
		bridges: make(map[string]*ovs.Bridge),
		ports:   make(map[string]map[string]*ovs.Port),
		flows:   make(map[string][]*ovs.Flow),
	}
	m.connected.Store(true)
	return m
}

func (m *mockOVSClient) CreateBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.createBridgeCalls = append(m.createBridgeCalls, name)

	if m.createBridgeErr != nil {
		return nil, m.createBridgeErr
	}

	bridge := &ovs.Bridge{
		UUID:        "uuid-" + name,
		Name:        name,
		ExternalIDs: map[string]string{"managed-by": "quicbaas"},
	}
	m.bridges[name] = bridge
	m.ports[name] = make(map[string]*ovs.Port)

	// Create internal port
	m.ports[name][name] = &ovs.Port{
		UUID: "uuid-port-" + name,
		Name: name,
	}

	return bridge, nil
}

func (m *mockOVSClient) DeleteBridge(ctx context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.deleteBridgeCalls = append(m.deleteBridgeCalls, name)

	if m.deleteBridgeErr != nil {
		return m.deleteBridgeErr
	}

	delete(m.bridges, name)
	delete(m.ports, name)
	delete(m.flows, name)
	return nil
}

func (m *mockOVSClient) GetBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getBridgeErr != nil {
		return nil, m.getBridgeErr
	}

	if bridge, ok := m.bridges[name]; ok {
		return bridge, nil
	}
	return nil, errors.New("bridge not found")
}

func (m *mockOVSClient) ListBridges(ctx context.Context) ([]*ovs.Bridge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listBridgesErr != nil {
		return nil, m.listBridgesErr
	}

	bridges := make([]*ovs.Bridge, 0, len(m.bridges))
	for _, b := range m.bridges {
		bridges = append(bridges, b)
	}
	return bridges, nil
}

func (m *mockOVSClient) UpdateBridge(ctx context.Context, name string, updates map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.updateBridgeCalls = append(m.updateBridgeCalls, updates)

	if m.updateBridgeErr != nil {
		return m.updateBridgeErr
	}

	if bridge, ok := m.bridges[name]; ok {
		if failMode, ok := updates["fail_mode"].(string); ok {
			bridge.FailMode = failMode
		}
		if stp, ok := updates["stp_enable"].(bool); ok {
			bridge.STP = stp
		}
		return nil
	}
	return errors.New("bridge not found")
}

func (m *mockOVSClient) SetBridgeFailMode(ctx context.Context, name string, failMode string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.setFailModeCalls = append(m.setFailModeCalls, name+":"+failMode)

	if bridge, ok := m.bridges[name]; ok {
		bridge.FailMode = failMode
		return nil
	}
	return errors.New("bridge not found")
}

func (m *mockOVSClient) SetBridgeProtocols(ctx context.Context, name string, protocols []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.setProtocolsCalls = append(m.setProtocolsCalls, name)

	if bridge, ok := m.bridges[name]; ok {
		bridge.FlowProtocols = protocols
		return nil
	}
	return errors.New("bridge not found")
}

func (m *mockOVSClient) AddPort(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.addPortCalls = append(m.addPortCalls, bridgeName+":"+portName)

	if m.addPortErr != nil {
		return nil, m.addPortErr
	}

	if _, ok := m.ports[bridgeName]; !ok {
		return nil, errors.New("bridge not found")
	}

	port := &ovs.Port{
		UUID:        "uuid-port-" + portName,
		Name:        portName,
		ExternalIDs: map[string]string{"managed-by": "quicbaas"},
	}
	m.ports[bridgeName][portName] = port
	return port, nil
}

func (m *mockOVSClient) DeletePort(ctx context.Context, bridgeName, portName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.deletePortCalls = append(m.deletePortCalls, bridgeName+":"+portName)

	if m.deletePortErr != nil {
		return m.deletePortErr
	}

	if ports, ok := m.ports[bridgeName]; ok {
		delete(ports, portName)
		return nil
	}
	return errors.New("bridge not found")
}

func (m *mockOVSClient) GetPort(ctx context.Context, name string) (*ovs.Port, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getPortErr != nil {
		return nil, m.getPortErr
	}

	for _, ports := range m.ports {
		if port, ok := ports[name]; ok {
			return port, nil
		}
	}
	return nil, errors.New("port not found")
}

func (m *mockOVSClient) ListPorts(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listPortsErr != nil {
		return nil, m.listPortsErr
	}

	if ports, ok := m.ports[bridgeName]; ok {
		result := make([]*ovs.Port, 0, len(ports))
		for _, p := range ports {
			result = append(result, p)
		}
		return result, nil
	}
	return nil, errors.New("bridge not found")
}

func (m *mockOVSClient) SetPortVLAN(ctx context.Context, portName string, tag int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.setPortVLANCalls = append(m.setPortVLANCalls, portName)

	if m.setPortVLANErr != nil {
		return m.setPortVLANErr
	}

	for _, ports := range m.ports {
		if port, ok := ports[portName]; ok {
			port.Tag = tag
			return nil
		}
	}
	return errors.New("port not found")
}

func (m *mockOVSClient) SetPortTrunks(ctx context.Context, portName string, trunks []int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.setPortTrunksCalls = append(m.setPortTrunksCalls, portName)

	if m.setPortTrunksErr != nil {
		return m.setPortTrunksErr
	}

	for _, ports := range m.ports {
		if port, ok := ports[portName]; ok {
			port.Trunks = trunks
			return nil
		}
	}
	return errors.New("port not found")
}

func (m *mockOVSClient) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.addFlowCalls = append(m.addFlowCalls, bridgeName)

	if m.addFlowErr != nil {
		return m.addFlowErr
	}

	if _, ok := m.bridges[bridgeName]; !ok {
		return errors.New("bridge not found")
	}

	ovsFlow := &ovs.Flow{
		Table:    flow.Table,
		Priority: flow.Priority,
		Match:    flow.Match,
		Actions:  flow.Actions,
		Cookie:   flow.Cookie,
	}
	m.flows[bridgeName] = append(m.flows[bridgeName], ovsFlow)
	return nil
}

func (m *mockOVSClient) DeleteFlow(ctx context.Context, bridgeName string, match string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteFlowErr != nil {
		return m.deleteFlowErr
	}

	// Simplified: just clear flows for this test
	return nil
}

func (m *mockOVSClient) ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listFlowsErr != nil {
		return nil, m.listFlowsErr
	}

	if flows, ok := m.flows[bridgeName]; ok {
		return flows, nil
	}
	return []*ovs.Flow{}, nil
}

func (m *mockOVSClient) DeleteAllFlows(ctx context.Context, bridgeName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.deleteAllFlowsErr != nil {
		return m.deleteAllFlowsErr
	}

	m.flows[bridgeName] = nil
	return nil
}

func (m *mockOVSClient) IsConnected() bool {
	return m.connected.Load()
}

// mockStateManager is a mock implementation of StateManager for testing.
type mockStateManager struct {
	mu sync.RWMutex

	bridges map[string]*BridgeState
	ports   map[string]*PortState
	flows   map[string]*FlowState // key: bridgeID:flowID
	vlans   map[uint16]*VLANState

	// Error injection
	listBridgesErr error
	listPortsErr   error
	listFlowsErr   error
	listVLANsErr   error
	getBridgeErr   error
}

func newMockStateManager() *mockStateManager {
	return &mockStateManager{
		bridges: make(map[string]*BridgeState),
		ports:   make(map[string]*PortState),
		flows:   make(map[string]*FlowState),
		vlans:   make(map[uint16]*VLANState),
	}
}

func (m *mockStateManager) CreateBridge(ctx context.Context, bridge *BridgeState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bridges[bridge.ID] = bridge
	return nil
}

func (m *mockStateManager) UpdateBridge(ctx context.Context, bridgeID string, updates *BridgeState, expectedVersion uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if bridge, ok := m.bridges[bridgeID]; ok {
		bridge.Name = updates.Name
		bridge.FailMode = updates.FailMode
		bridge.Version = expectedVersion + 1
	}
	return nil
}

func (m *mockStateManager) DeleteBridge(ctx context.Context, bridgeID string, expectedVersion uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.bridges, bridgeID)
	return nil
}

func (m *mockStateManager) GetBridge(ctx context.Context, bridgeID string) (*BridgeState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.getBridgeErr != nil {
		return nil, m.getBridgeErr
	}

	if bridge, ok := m.bridges[bridgeID]; ok {
		return bridge, nil
	}
	return nil, ErrBridgeNotFound{BridgeID: bridgeID}
}

func (m *mockStateManager) ListBridges(ctx context.Context) ([]*BridgeState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listBridgesErr != nil {
		return nil, m.listBridgesErr
	}

	bridges := make([]*BridgeState, 0, len(m.bridges))
	for _, b := range m.bridges {
		bridges = append(bridges, b)
	}
	return bridges, nil
}

func (m *mockStateManager) CreatePort(ctx context.Context, port *PortState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ports[port.ID] = port
	return nil
}

func (m *mockStateManager) UpdatePort(ctx context.Context, portID string, updates *PortState, expectedVersion uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if port, ok := m.ports[portID]; ok {
		port.Tag = updates.Tag
		port.Trunks = updates.Trunks
		port.Version = expectedVersion + 1
	}
	return nil
}

func (m *mockStateManager) DeletePort(ctx context.Context, portID string, expectedVersion uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ports, portID)
	return nil
}

func (m *mockStateManager) GetPort(ctx context.Context, portID string) (*PortState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if port, ok := m.ports[portID]; ok {
		return port, nil
	}
	return nil, ErrPortNotFound{PortID: portID}
}

func (m *mockStateManager) ListPorts(ctx context.Context, bridgeID string) ([]*PortState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listPortsErr != nil {
		return nil, m.listPortsErr
	}

	ports := make([]*PortState, 0)
	for _, p := range m.ports {
		if p.BridgeID == bridgeID {
			ports = append(ports, p)
		}
	}
	return ports, nil
}

func (m *mockStateManager) CreateFlow(ctx context.Context, flow *FlowState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := flow.BridgeID + ":" + flow.ID
	m.flows[key] = flow
	return nil
}

func (m *mockStateManager) UpdateFlow(ctx context.Context, bridgeID, flowID string, updates *FlowState, expectedVersion uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := bridgeID + ":" + flowID
	if flow, ok := m.flows[key]; ok {
		flow.Priority = updates.Priority
		flow.Version = expectedVersion + 1
	}
	return nil
}

func (m *mockStateManager) DeleteFlow(ctx context.Context, bridgeID, flowID string, expectedVersion uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := bridgeID + ":" + flowID
	delete(m.flows, key)
	return nil
}

func (m *mockStateManager) GetFlow(ctx context.Context, bridgeID, flowID string) (*FlowState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	key := bridgeID + ":" + flowID
	if flow, ok := m.flows[key]; ok {
		return flow, nil
	}
	return nil, ErrFlowNotFound{BridgeID: bridgeID, FlowID: flowID}
}

func (m *mockStateManager) ListFlows(ctx context.Context, bridgeID string) ([]*FlowState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listFlowsErr != nil {
		return nil, m.listFlowsErr
	}

	flows := make([]*FlowState, 0)
	for _, f := range m.flows {
		if f.BridgeID == bridgeID {
			flows = append(flows, f)
		}
	}
	return flows, nil
}

func (m *mockStateManager) CreateVLAN(ctx context.Context, vlan *VLANState) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.vlans[vlan.ID] = vlan
	return nil
}

func (m *mockStateManager) UpdateVLAN(ctx context.Context, vlanID uint16, updates *VLANState, expectedVersion uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if vlan, ok := m.vlans[vlanID]; ok {
		vlan.Name = updates.Name
		vlan.Version = expectedVersion + 1
	}
	return nil
}

func (m *mockStateManager) DeleteVLAN(ctx context.Context, vlanID uint16, expectedVersion uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.vlans, vlanID)
	return nil
}

func (m *mockStateManager) GetVLAN(ctx context.Context, vlanID uint16) (*VLANState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if vlan, ok := m.vlans[vlanID]; ok {
		return vlan, nil
	}
	return nil, ErrVLANNotFound{VLANID: vlanID}
}

func (m *mockStateManager) ListVLANs(ctx context.Context) ([]*VLANState, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if m.listVLANsErr != nil {
		return nil, m.listVLANsErr
	}

	vlans := make([]*VLANState, 0, len(m.vlans))
	for _, v := range m.vlans {
		vlans = append(vlans, v)
	}
	return vlans, nil
}

// Test helpers
func createTestLogger() *logging.Logger {
	return logging.DefaultLogger()
}

// Test: NewOVSSynchronizer creates synchronizer with default options
func TestNewOVSSynchronizer(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(stateManager, ovsClient, logger)

	if sync == nil {
		t.Fatal("NewOVSSynchronizer returned nil")
	}

	status := sync.GetSyncStatus()
	if status.SyncInProgress {
		t.Error("Expected SyncInProgress to be false for new synchronizer")
	}
}

// Test: NewOVSSynchronizer with custom options
func TestNewOVSSynchronizerWithOptions(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithSyncInterval(5*time.Second),
		WithRetryConfig(500*time.Millisecond, 3, 1.5),
		WithMaxRetryInterval(10*time.Second),
		WithReconcileOnStartup(false),
		WithNodeID(42),
	)

	if sync == nil {
		t.Fatal("NewOVSSynchronizer with options returned nil")
	}
}

// Test: Start and Stop lifecycle
func TestSynchronizerStartStop(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithSyncInterval(100*time.Millisecond),
	)

	ctx := context.Background()

	// Start the synchronizer
	err := sync.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Give it time to start
	time.Sleep(50 * time.Millisecond)

	// Stop the synchronizer
	err = sync.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
}

// Test: Start when already running returns error
func TestSynchronizerStartAlreadyRunning(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
	)

	ctx := context.Background()

	// Start the synchronizer
	err := sync.Start(ctx)
	if err != nil {
		t.Fatalf("First Start failed: %v", err)
	}

	// Try to start again
	err = sync.Start(ctx)
	if err == nil {
		t.Error("Expected error when starting already running synchronizer")
	}

	var alreadyRunning ErrSyncAlreadyRunning
	if !errors.As(err, &alreadyRunning) {
		t.Errorf("Expected ErrSyncAlreadyRunning, got: %T", err)
	}

	// Cleanup
	sync.Stop()
}

// Test: Stop when not running returns error
func TestSynchronizerStopNotRunning(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(stateManager, ovsClient, logger)

	err := sync.Stop()
	if err == nil {
		t.Error("Expected error when stopping non-running synchronizer")
	}

	var notRunning ErrSyncNotRunning
	if !errors.As(err, &notRunning) {
		t.Errorf("Expected ErrSyncNotRunning, got: %T", err)
	}
}

// Test: SyncAll creates missing bridges
func TestSyncAllCreatesBridges(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add a bridge to QuicBaaS state
	bridge := &BridgeState{
		ID:       "bridge-1",
		Name:     "br0",
		NodeID:   1,
		FailMode: "secure",
	}
	stateManager.CreateBridge(context.Background(), bridge)

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	// Perform sync
	err := sync.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Verify bridge was created in OVS
	if len(ovsClient.createBridgeCalls) != 1 {
		t.Errorf("Expected 1 CreateBridge call, got %d", len(ovsClient.createBridgeCalls))
	}

	if ovsClient.createBridgeCalls[0] != "br0" {
		t.Errorf("Expected bridge name 'br0', got '%s'", ovsClient.createBridgeCalls[0])
	}

	// Verify sync status
	status := sync.GetSyncStatus()
	if status.LastError != nil {
		t.Errorf("Expected no error, got: %v", status.LastError)
	}
	if status.BridgesSynced != 1 {
		t.Errorf("Expected 1 bridge synced, got %d", status.BridgesSynced)
	}
}

// Test: SyncAll creates missing ports
func TestSyncAllCreatesPorts(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add a bridge
	bridge := &BridgeState{
		ID:     "bridge-1",
		Name:   "br0",
		NodeID: 1,
	}
	stateManager.CreateBridge(context.Background(), bridge)

	// Add ports
	port1 := &PortState{
		ID:       "port-1",
		Name:     "eth0",
		BridgeID: "bridge-1",
		Tag:      100,
	}
	stateManager.CreatePort(context.Background(), port1)

	port2 := &PortState{
		ID:       "port-2",
		Name:     "eth1",
		BridgeID: "bridge-1",
		Tag:      200,
	}
	stateManager.CreatePort(context.Background(), port2)

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	// Perform sync
	err := sync.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Verify ports were created
	if len(ovsClient.addPortCalls) != 2 {
		t.Errorf("Expected 2 AddPort calls, got %d", len(ovsClient.addPortCalls))
	}

	// Verify VLAN tags were set
	if len(ovsClient.setPortVLANCalls) != 2 {
		t.Errorf("Expected 2 SetPortVLAN calls, got %d", len(ovsClient.setPortVLANCalls))
	}

	status := sync.GetSyncStatus()
	if status.PortsSynced != 2 {
		t.Errorf("Expected 2 ports synced, got %d", status.PortsSynced)
	}
}

// Test: SyncAll creates flows
func TestSyncAllCreatesFlows(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add a bridge
	bridge := &BridgeState{
		ID:     "bridge-1",
		Name:   "br0",
		NodeID: 1,
	}
	stateManager.CreateBridge(context.Background(), bridge)

	// Add a flow
	inPort := uint32(1)
	outPort := uint32(2)
	flow := &FlowState{
		ID:       "flow-1",
		BridgeID: "bridge-1",
		Table:    0,
		Priority: 100,
		Cookie:   0x1234,
		Match: &FlowMatch{
			InPort: &inPort,
		},
		Actions: []*FlowAction{
			{Type: ActionOutput, Port: &outPort},
		},
	}
	stateManager.CreateFlow(context.Background(), flow)

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	// Perform sync
	err := sync.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Verify flow was created
	if len(ovsClient.addFlowCalls) != 1 {
		t.Errorf("Expected 1 AddFlow call, got %d", len(ovsClient.addFlowCalls))
	}

	status := sync.GetSyncStatus()
	if status.FlowsSynced != 1 {
		t.Errorf("Expected 1 flow synced, got %d", status.FlowsSynced)
	}
}

// Test: SyncBridge with empty ID returns error
func TestSyncBridgeEmptyID(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(stateManager, ovsClient, logger)

	err := sync.SyncBridge("")
	if err == nil {
		t.Error("Expected error for empty bridge ID")
	}

	var invalidID ErrInvalidBridgeID
	if !errors.As(err, &invalidID) {
		t.Errorf("Expected ErrInvalidBridgeID, got: %T", err)
	}
}

// Test: SyncBridge syncs single bridge
func TestSyncBridgeSingle(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add a bridge
	bridge := &BridgeState{
		ID:     "bridge-1",
		Name:   "br0",
		NodeID: 1,
	}
	stateManager.CreateBridge(context.Background(), bridge)

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithNodeID(1),
	)

	// Sync specific bridge
	err := sync.SyncBridge("bridge-1")
	if err != nil {
		t.Fatalf("SyncBridge failed: %v", err)
	}

	// Verify bridge was created
	if len(ovsClient.createBridgeCalls) != 1 {
		t.Errorf("Expected 1 CreateBridge call, got %d", len(ovsClient.createBridgeCalls))
	}
}

// Test: SyncBridge with non-local node returns error
func TestSyncBridgeNonLocalNode(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add a bridge owned by a different node
	bridge := &BridgeState{
		ID:     "bridge-1",
		Name:   "br0",
		NodeID: 99, // Different node
	}
	stateManager.CreateBridge(context.Background(), bridge)

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithNodeID(1),
	)

	err := sync.SyncBridge("bridge-1")
	if err == nil {
		t.Error("Expected error for non-local node bridge")
	}

	var syncFailed ErrSyncFailed
	if !errors.As(err, &syncFailed) {
		t.Errorf("Expected ErrSyncFailed, got: %T", err)
	}
}

// Test: GetSyncStatus returns correct status
func TestGetSyncStatus(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(stateManager, ovsClient, logger)

	status := sync.GetSyncStatus()

	if status.SyncInProgress {
		t.Error("Expected SyncInProgress to be false")
	}
	if status.ErrorCount != 0 {
		t.Errorf("Expected ErrorCount 0, got %d", status.ErrorCount)
	}
	if status.LastError != nil {
		t.Errorf("Expected no LastError, got: %v", status.LastError)
	}
}

// Test: Retry logic on transient failures
func TestRetryOnTransientFailure(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add a bridge
	bridge := &BridgeState{
		ID:     "bridge-1",
		Name:   "br0",
		NodeID: 1,
	}
	stateManager.CreateBridge(context.Background(), bridge)

	// Make first two attempts fail
	callCount := 0
	ovsClient.createBridgeErr = errors.New("temporary failure")

	// Create a custom mock that fails twice then succeeds
	customClient := &mockOVSClientWithRetry{
		mockOVSClient: ovsClient,
		failCount:     2,
		currentCount:  &callCount,
	}

	// maxRetries=2 means: 1 initial attempt + 2 retries = 3 total attempts max
	// With failCount=2, we fail on attempts 1 and 2, succeed on attempt 3
	sync := NewOVSSynchronizer(
		stateManager,
		customClient,
		logger,
		WithRetryConfig(10*time.Millisecond, 2, 1.5),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	err := sync.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Should have retried and succeeded on the 3rd attempt
	if callCount != 3 {
		t.Errorf("Expected 3 calls (2 failures + 1 success), got %d", callCount)
	}
}

// mockOVSClientWithRetry wraps mockOVSClient to simulate transient failures
type mockOVSClientWithRetry struct {
	*mockOVSClient
	failCount    int
	currentCount *int
}

func (m *mockOVSClientWithRetry) CreateBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	*m.currentCount++
	if *m.currentCount <= m.failCount {
		return nil, errors.New("temporary failure")
	}
	return m.mockOVSClient.CreateBridge(ctx, name)
}

// Test: Max retries exceeded returns error
func TestMaxRetriesExceeded(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add a bridge
	bridge := &BridgeState{
		ID:     "bridge-1",
		Name:   "br0",
		NodeID: 1,
	}
	stateManager.CreateBridge(context.Background(), bridge)

	// Always fail
	ovsClient.createBridgeErr = errors.New("persistent failure")

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithRetryConfig(10*time.Millisecond, 2, 1.5),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	// This should not return an error at the top level because
	// we continue to the next entity on failure
	err := sync.SyncAll()
	if err != nil {
		t.Logf("SyncAll returned expected error (continue on failure): %v", err)
	}

	// But the status should reflect errors
	status := sync.GetSyncStatus()
	if status.BridgesSynced != 0 {
		t.Errorf("Expected 0 bridges synced due to failure, got %d", status.BridgesSynced)
	}
}

// Test: Bridge drift detection and update
func TestBridgeDriftDetection(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add bridge to QuicBaaS with specific config
	bridge := &BridgeState{
		ID:         "bridge-1",
		Name:       "br0",
		NodeID:     1,
		FailMode:   "secure",
		STPEnabled: true,
	}
	stateManager.CreateBridge(context.Background(), bridge)

	// Pre-create bridge in OVS with different config
	ovsClient.bridges["br0"] = &ovs.Bridge{
		UUID:        "uuid-br0",
		Name:        "br0",
		FailMode:    "standalone", // Different from desired
		STP:         false,        // Different from desired
		ExternalIDs: map[string]string{"managed-by": "quicbaas"},
	}
	ovsClient.ports["br0"] = make(map[string]*ovs.Port)

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	err := sync.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Verify update was called (not create)
	if len(ovsClient.createBridgeCalls) != 0 {
		t.Error("Should not create bridge that already exists")
	}

	if len(ovsClient.updateBridgeCalls) != 1 {
		t.Errorf("Expected 1 UpdateBridge call, got %d", len(ovsClient.updateBridgeCalls))
	}

	status := sync.GetSyncStatus()
	if status.BridgesSynced != 1 {
		t.Errorf("Expected 1 bridge synced (updated), got %d", status.BridgesSynced)
	}
}

// Test: Port drift detection and update
func TestPortDriftDetection(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add bridge
	bridge := &BridgeState{
		ID:     "bridge-1",
		Name:   "br0",
		NodeID: 1,
	}
	stateManager.CreateBridge(context.Background(), bridge)

	// Add port with VLAN 100
	port := &PortState{
		ID:       "port-1",
		Name:     "eth0",
		BridgeID: "bridge-1",
		Tag:      100,
	}
	stateManager.CreatePort(context.Background(), port)

	// Pre-create in OVS with VLAN 50 (drift)
	ovsClient.bridges["br0"] = &ovs.Bridge{
		UUID:        "uuid-br0",
		Name:        "br0",
		ExternalIDs: map[string]string{"managed-by": "quicbaas"},
	}
	ovsClient.ports["br0"] = map[string]*ovs.Port{
		"br0": {UUID: "uuid-port-br0", Name: "br0"},
		"eth0": {
			UUID:        "uuid-port-eth0",
			Name:        "eth0",
			Tag:         50, // Different VLAN
			ExternalIDs: map[string]string{"managed-by": "quicbaas"},
		},
	}

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	err := sync.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Verify VLAN was updated
	if len(ovsClient.setPortVLANCalls) != 1 {
		t.Errorf("Expected 1 SetPortVLAN call to fix drift, got %d", len(ovsClient.setPortVLANCalls))
	}

	status := sync.GetSyncStatus()
	if status.PortsSynced != 1 {
		t.Errorf("Expected 1 port synced (updated), got %d", status.PortsSynced)
	}
}

// Test: Node filtering - only syncs local node bridges
func TestNodeFiltering(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add bridges for different nodes
	bridge1 := &BridgeState{ID: "bridge-1", Name: "br0", NodeID: 1}
	bridge2 := &BridgeState{ID: "bridge-2", Name: "br1", NodeID: 2}
	bridge3 := &BridgeState{ID: "bridge-3", Name: "br2", NodeID: 1}

	stateManager.CreateBridge(context.Background(), bridge1)
	stateManager.CreateBridge(context.Background(), bridge2)
	stateManager.CreateBridge(context.Background(), bridge3)

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithNodeID(1), // Only sync node 1 bridges
	)

	err := sync.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Should only create 2 bridges (node 1)
	if len(ovsClient.createBridgeCalls) != 2 {
		t.Errorf("Expected 2 CreateBridge calls for node 1, got %d", len(ovsClient.createBridgeCalls))
	}

	// Verify correct bridges
	bridgeNames := make(map[string]bool)
	for _, name := range ovsClient.createBridgeCalls {
		bridgeNames[name] = true
	}

	if !bridgeNames["br0"] || !bridgeNames["br2"] {
		t.Error("Expected br0 and br2 to be created")
	}
	if bridgeNames["br1"] {
		t.Error("br1 should not be created (belongs to node 2)")
	}
}

// Test: Flow match string building
func TestBuildMatchString(t *testing.T) {
	sync := &quicbaasSynchronizer{}

	tests := []struct {
		name     string
		match    *FlowMatch
		expected string
	}{
		{
			name:     "nil match",
			match:    nil,
			expected: "",
		},
		{
			name:     "empty match",
			match:    &FlowMatch{},
			expected: "",
		},
		{
			name: "in_port only",
			match: &FlowMatch{
				InPort: ptrUint32(1),
			},
			expected: "in_port=1",
		},
		{
			name: "multiple fields",
			match: &FlowMatch{
				InPort:  ptrUint32(1),
				EthSrc:  "00:11:22:33:44:55",
				EthType: ptrUint16(0x0800),
				IPv4Src: "192.168.1.0/24",
			},
			expected: "in_port=1,dl_src=00:11:22:33:44:55,dl_type=0x0800,nw_src=192.168.1.0/24",
		},
		{
			name: "VLAN and protocol",
			match: &FlowMatch{
				VLANVid: ptrUint16(100),
				IPProto: ptrUint8(6),
				TCPDst:  ptrUint16(80),
			},
			expected: "dl_vlan=100,nw_proto=6,tp_dst=80",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sync.buildMatchString(tt.match)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// Test: Flow actions string building
func TestBuildActionsString(t *testing.T) {
	sync := &quicbaasSynchronizer{}

	tests := []struct {
		name     string
		actions  []*FlowAction
		expected string
	}{
		{
			name:     "nil actions",
			actions:  nil,
			expected: "drop",
		},
		{
			name:     "empty actions",
			actions:  []*FlowAction{},
			expected: "drop",
		},
		{
			name: "output action",
			actions: []*FlowAction{
				{Type: ActionOutput, Port: ptrUint32(2)},
			},
			expected: "output:2",
		},
		{
			name: "multiple actions",
			actions: []*FlowAction{
				{Type: ActionSetVLAN, VLANVid: ptrUint16(100)},
				{Type: ActionOutput, Port: ptrUint32(2)},
			},
			expected: "mod_vlan_vid:100,output:2",
		},
		{
			name: "special actions",
			actions: []*FlowAction{
				{Type: ActionNormal},
			},
			expected: "NORMAL",
		},
		{
			name: "strip vlan and flood",
			actions: []*FlowAction{
				{Type: ActionStripVLAN},
				{Type: ActionFlood},
			},
			expected: "strip_vlan,FLOOD",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sync.buildActionsString(tt.actions)
			if result != tt.expected {
				t.Errorf("Expected '%s', got '%s'", tt.expected, result)
			}
		})
	}
}

// Test: Trunks equality comparison
func TestTrunksEqual(t *testing.T) {
	sync := &quicbaasSynchronizer{}

	tests := []struct {
		name     string
		a        []uint16
		b        []int64
		expected bool
	}{
		{
			name:     "both empty",
			a:        []uint16{},
			b:        []int64{},
			expected: true,
		},
		{
			name:     "equal values",
			a:        []uint16{100, 200, 300},
			b:        []int64{100, 200, 300},
			expected: true,
		},
		{
			name:     "different order same values",
			a:        []uint16{100, 200, 300},
			b:        []int64{300, 100, 200},
			expected: true,
		},
		{
			name:     "different lengths",
			a:        []uint16{100, 200},
			b:        []int64{100, 200, 300},
			expected: false,
		},
		{
			name:     "different values",
			a:        []uint16{100, 200},
			b:        []int64{100, 300},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sync.trunksEqual(tt.a, tt.b)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Test: Managed bridge detection
func TestIsManagedBridge(t *testing.T) {
	sync := &quicbaasSynchronizer{}

	tests := []struct {
		name     string
		bridge   *ovs.Bridge
		expected bool
	}{
		{
			name:     "nil external IDs",
			bridge:   &ovs.Bridge{Name: "br0"},
			expected: false,
		},
		{
			name: "no managed-by key",
			bridge: &ovs.Bridge{
				Name:        "br0",
				ExternalIDs: map[string]string{"other": "value"},
			},
			expected: false,
		},
		{
			name: "managed by different system",
			bridge: &ovs.Bridge{
				Name:        "br0",
				ExternalIDs: map[string]string{"managed-by": "other"},
			},
			expected: false,
		},
		{
			name: "managed by quicbaas",
			bridge: &ovs.Bridge{
				Name:        "br0",
				ExternalIDs: map[string]string{"managed-by": "quicbaas"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sync.isManagedBridge(tt.bridge)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Test: Error handling in ListBridges
func TestSyncAllListBridgesError(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Inject error
	stateManager.listBridgesErr = errors.New("database error")

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
	)

	err := sync.SyncAll()
	if err == nil {
		t.Error("Expected error when ListBridges fails")
	}

	var syncFailed ErrSyncFailed
	if !errors.As(err, &syncFailed) {
		t.Errorf("Expected ErrSyncFailed, got: %T", err)
	}
}

// Test: Error handling in ListPorts
func TestSyncAllListPortsError(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add a bridge
	bridge := &BridgeState{ID: "bridge-1", Name: "br0", NodeID: 1}
	stateManager.CreateBridge(context.Background(), bridge)

	// Inject error
	stateManager.listPortsErr = errors.New("port error")

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	// Should not fail completely - continues with other entities
	err := sync.SyncAll()
	if err != nil {
		t.Logf("SyncAll returned: %v (expected to continue despite port error)", err)
	}
}

// Test: Periodic sync loop execution
func TestPeriodicSyncLoop(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add a bridge
	bridge := &BridgeState{ID: "bridge-1", Name: "br0", NodeID: 1}
	stateManager.CreateBridge(context.Background(), bridge)

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithSyncInterval(50*time.Millisecond),
		WithNodeID(1),
	)

	ctx := context.Background()
	err := sync.Start(ctx)
	if err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Wait for at least 2 sync cycles
	time.Sleep(150 * time.Millisecond)

	err = sync.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// Should have called CreateBridge multiple times (initial + periodic)
	if len(ovsClient.createBridgeCalls) < 1 {
		t.Error("Expected at least 1 sync to have occurred")
	}
}

// Test: DefaultSynchronizerConfig returns valid config
func TestDefaultSynchronizerConfig(t *testing.T) {
	cfg := DefaultSynchronizerConfig()

	if cfg.SyncInterval != 30*time.Second {
		t.Errorf("Expected SyncInterval 30s, got %v", cfg.SyncInterval)
	}
	if cfg.RetryInterval != 1*time.Second {
		t.Errorf("Expected RetryInterval 1s, got %v", cfg.RetryInterval)
	}
	if cfg.MaxRetries != 5 {
		t.Errorf("Expected MaxRetries 5, got %d", cfg.MaxRetries)
	}
	if cfg.RetryBackoffFactor != 2.0 {
		t.Errorf("Expected RetryBackoffFactor 2.0, got %f", cfg.RetryBackoffFactor)
	}
	if cfg.MaxRetryInterval != 30*time.Second {
		t.Errorf("Expected MaxRetryInterval 30s, got %v", cfg.MaxRetryInterval)
	}
	if !cfg.ReconcileOnStartup {
		t.Error("Expected ReconcileOnStartup true")
	}
	if cfg.NodeID != 1 {
		t.Errorf("Expected NodeID 1, got %d", cfg.NodeID)
	}
}

// Test: Context cancellation stops retry
func TestContextCancellationStopsRetry(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Add a bridge
	bridge := &BridgeState{ID: "bridge-1", Name: "br0", NodeID: 1}
	stateManager.CreateBridge(context.Background(), bridge)

	// Always fail to trigger retries
	ovsClient.createBridgeErr = errors.New("always fail")

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithRetryConfig(100*time.Millisecond, 10, 1.0),
		WithReconcileOnStartup(true),
		WithNodeID(1),
	)

	ctx, cancel := context.WithCancel(context.Background())

	// Start sync in goroutine
	done := make(chan error, 1)
	go func() {
		done <- sync.Start(ctx)
	}()

	// Give it time to start retrying
	time.Sleep(50 * time.Millisecond)

	// Cancel context
	cancel()

	// Should complete quickly
	select {
	case <-done:
		// Expected
	case <-time.After(500 * time.Millisecond):
		t.Error("Expected sync to stop on context cancellation")
	}
}

// Test: Delete orphaned bridges
func TestDeleteOrphanedBridges(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Create a bridge in OVS that's not in QuicBaaS
	ovsClient.bridges["orphan-br"] = &ovs.Bridge{
		UUID:        "uuid-orphan",
		Name:        "orphan-br",
		ExternalIDs: map[string]string{"managed-by": "quicbaas"},
	}
	ovsClient.ports["orphan-br"] = make(map[string]*ovs.Port)

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	err := sync.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Orphan bridge should be deleted
	if len(ovsClient.deleteBridgeCalls) != 1 {
		t.Errorf("Expected 1 DeleteBridge call, got %d", len(ovsClient.deleteBridgeCalls))
	}

	if len(ovsClient.deleteBridgeCalls) > 0 && ovsClient.deleteBridgeCalls[0] != "orphan-br" {
		t.Errorf("Expected 'orphan-br' to be deleted, got '%s'", ovsClient.deleteBridgeCalls[0])
	}
}

// Test: Delete orphaned ports
func TestDeleteOrphanedPorts(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Create bridge in both QuicBaaS and OVS
	bridge := &BridgeState{ID: "bridge-1", Name: "br0", NodeID: 1}
	stateManager.CreateBridge(context.Background(), bridge)

	ovsClient.bridges["br0"] = &ovs.Bridge{
		UUID:        "uuid-br0",
		Name:        "br0",
		ExternalIDs: map[string]string{"managed-by": "quicbaas"},
	}
	ovsClient.ports["br0"] = map[string]*ovs.Port{
		"br0": {UUID: "uuid-port-br0", Name: "br0"}, // Internal port
		"orphan-port": {
			UUID:        "uuid-orphan",
			Name:        "orphan-port",
			ExternalIDs: map[string]string{"managed-by": "quicbaas"},
		},
	}

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	err := sync.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Orphan port should be deleted
	if len(ovsClient.deletePortCalls) != 1 {
		t.Errorf("Expected 1 DeletePort call, got %d", len(ovsClient.deletePortCalls))
	}
}

// Test: Port with trunk VLANs
func TestPortWithTrunkVLANs(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	// Create bridge
	bridge := &BridgeState{ID: "bridge-1", Name: "br0", NodeID: 1}
	stateManager.CreateBridge(context.Background(), bridge)

	// Create trunk port
	port := &PortState{
		ID:       "port-1",
		Name:     "eth0",
		BridgeID: "bridge-1",
		Trunks:   []uint16{100, 200, 300},
	}
	stateManager.CreatePort(context.Background(), port)

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	err := sync.SyncAll()
	if err != nil {
		t.Fatalf("SyncAll failed: %v", err)
	}

	// Verify trunk VLANs were set
	if len(ovsClient.setPortTrunksCalls) != 1 {
		t.Errorf("Expected 1 SetPortTrunks call, got %d", len(ovsClient.setPortTrunksCalls))
	}
}

// Helper functions for creating pointers
func ptrUint8(v uint8) *uint8    { return &v }
func ptrUint16(v uint16) *uint16 { return &v }
func ptrUint32(v uint32) *uint32 { return &v }

// Test error types
func TestSyncErrorTypes(t *testing.T) {
	t.Run("ErrSyncAlreadyRunning", func(t *testing.T) {
		err := ErrSyncAlreadyRunning{}
		if err.Error() != "synchronizer is already running" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrSyncNotRunning", func(t *testing.T) {
		err := ErrSyncNotRunning{}
		if err.Error() != "synchronizer is not running" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrSyncStopped", func(t *testing.T) {
		err := ErrSyncStopped{}
		if err.Error() != "synchronizer was stopped" {
			t.Errorf("Unexpected error message: %s", err.Error())
		}
	})

	t.Run("ErrSyncFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrSyncFailed{Entity: "bridge", Operation: "create", Cause: cause}
		expected := "sync failed: create bridge: underlying error"
		if err.Error() != expected {
			t.Errorf("Expected '%s', got '%s'", expected, err.Error())
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return cause")
		}
	})

	t.Run("ErrSyncFailed without cause", func(t *testing.T) {
		err := ErrSyncFailed{Entity: "port", Operation: "delete"}
		expected := "sync failed: delete port"
		if err.Error() != expected {
			t.Errorf("Expected '%s', got '%s'", expected, err.Error())
		}
	})

	t.Run("ErrMaxRetriesExceeded", func(t *testing.T) {
		cause := errors.New("last error")
		err := ErrMaxRetriesExceeded{Operation: "create bridge", LastError: cause}
		expected := "max retries exceeded for create bridge: last error"
		if err.Error() != expected {
			t.Errorf("Expected '%s', got '%s'", expected, err.Error())
		}
		if err.Unwrap() != cause {
			t.Error("Unwrap should return cause")
		}
	})

	t.Run("ErrMaxRetriesExceeded without cause", func(t *testing.T) {
		err := ErrMaxRetriesExceeded{Operation: "create bridge"}
		expected := "max retries exceeded for create bridge"
		if err.Error() != expected {
			t.Errorf("Expected '%s', got '%s'", expected, err.Error())
		}
	})

	t.Run("ErrOVSConnectionFailed", func(t *testing.T) {
		cause := errors.New("connection refused")
		err := ErrOVSConnectionFailed{Cause: cause}
		expected := "OVS connection failed: connection refused"
		if err.Error() != expected {
			t.Errorf("Expected '%s', got '%s'", expected, err.Error())
		}
	})

	t.Run("ErrOVSConnectionFailed without cause", func(t *testing.T) {
		err := ErrOVSConnectionFailed{}
		expected := "OVS connection failed"
		if err.Error() != expected {
			t.Errorf("Expected '%s', got '%s'", expected, err.Error())
		}
	})
}

// Test: Bridge needs update detection
func TestBridgeNeedsUpdate(t *testing.T) {
	sync := &quicbaasSynchronizer{}

	tests := []struct {
		name     string
		desired  *BridgeState
		current  *ovs.Bridge
		expected bool
	}{
		{
			name: "no changes needed",
			desired: &BridgeState{
				FailMode:             "secure",
				STPEnabled:           true,
				RSTPEnabled:          false,
				McastSnoopingEnabled: false,
			},
			current: &ovs.Bridge{
				FailMode:      "secure",
				STP:           true,
				RSTP:          false,
				McastSnooping: false,
			},
			expected: false,
		},
		{
			name: "fail mode changed",
			desired: &BridgeState{
				FailMode: "secure",
			},
			current: &ovs.Bridge{
				FailMode: "standalone",
			},
			expected: true,
		},
		{
			name: "STP changed",
			desired: &BridgeState{
				STPEnabled: true,
			},
			current: &ovs.Bridge{
				STP: false,
			},
			expected: true,
		},
		{
			name: "RSTP changed",
			desired: &BridgeState{
				RSTPEnabled: true,
			},
			current: &ovs.Bridge{
				RSTP: false,
			},
			expected: true,
		},
		{
			name: "mcast snooping changed",
			desired: &BridgeState{
				McastSnoopingEnabled: true,
			},
			current: &ovs.Bridge{
				McastSnooping: false,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sync.bridgeNeedsUpdate(tt.desired, tt.current)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Test: Port needs update detection
func TestPortNeedsUpdate(t *testing.T) {
	sync := &quicbaasSynchronizer{}

	tests := []struct {
		name     string
		desired  *PortState
		current  *ovs.Port
		expected bool
	}{
		{
			name: "no changes needed",
			desired: &PortState{
				Tag:    100,
				Trunks: []uint16{200, 300},
			},
			current: &ovs.Port{
				Tag:    100,
				Trunks: []int64{200, 300},
			},
			expected: false,
		},
		{
			name: "VLAN tag changed",
			desired: &PortState{
				Tag: 100,
			},
			current: &ovs.Port{
				Tag: 50,
			},
			expected: true,
		},
		{
			name: "trunks changed",
			desired: &PortState{
				Trunks: []uint16{100, 200},
			},
			current: &ovs.Port{
				Trunks: []int64{100, 300},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sync.portNeedsUpdate(tt.desired, tt.current)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// Test: FlowState to FlowMod conversion
func TestConvertFlowStateToFlowMod(t *testing.T) {
	sync := &quicbaasSynchronizer{}

	inPort := uint32(1)
	outPort := uint32(2)
	vlanID := uint16(100)

	flow := &FlowState{
		ID:          "flow-1",
		BridgeID:    "bridge-1",
		Table:       1,
		Priority:    200,
		Cookie:      0xABCD,
		IdleTimeout: 60,
		HardTimeout: 120,
		Match: &FlowMatch{
			InPort:  &inPort,
			EthSrc:  "00:11:22:33:44:55",
			VLANVid: &vlanID,
		},
		Actions: []*FlowAction{
			{Type: ActionStripVLAN},
			{Type: ActionOutput, Port: &outPort},
		},
	}

	flowMod := sync.convertFlowStateToFlowMod(flow)

	if flowMod.Table != 1 {
		t.Errorf("Expected table 1, got %d", flowMod.Table)
	}
	if flowMod.Priority != 200 {
		t.Errorf("Expected priority 200, got %d", flowMod.Priority)
	}
	if flowMod.Cookie != "0xabcd" {
		t.Errorf("Expected cookie '0xabcd', got '%s'", flowMod.Cookie)
	}
	if flowMod.IdleTimeout != 60 {
		t.Errorf("Expected idle timeout 60, got %d", flowMod.IdleTimeout)
	}
	if flowMod.HardTimeout != 120 {
		t.Errorf("Expected hard timeout 120, got %d", flowMod.HardTimeout)
	}

	expectedMatch := "in_port=1,dl_src=00:11:22:33:44:55,dl_vlan=100"
	if flowMod.Match != expectedMatch {
		t.Errorf("Expected match '%s', got '%s'", expectedMatch, flowMod.Match)
	}

	expectedActions := "strip_vlan,output:2"
	if flowMod.Actions != expectedActions {
		t.Errorf("Expected actions '%s', got '%s'", expectedActions, flowMod.Actions)
	}
}

// Additional sync tests for edge cases and better coverage

// createSyncTestFixture creates a standard test fixture for sync tests
func createSyncTestFixture(t *testing.T) (*mockStateManager, *mockOVSClient, OVSSynchronizer) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithSyncInterval(100*time.Millisecond),
		WithRetryConfig(10*time.Millisecond, 2, 2.0),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	return stateManager, ovsClient, sync
}

func TestBuildActionsString_AllActionTypes(t *testing.T) {
	_, _, sync := createSyncTestFixture(t)
	ds := sync.(*quicbaasSynchronizer)

	port := uint32(1)
	vlanVid := uint16(100)
	table := uint8(1)

	tests := []struct {
		name     string
		actions  []*FlowAction
		expected string
	}{
		{
			name:     "empty actions returns drop",
			actions:  []*FlowAction{},
			expected: "drop",
		},
		{
			name:     "nil actions returns drop",
			actions:  nil,
			expected: "drop",
		},
		{
			name: "output action with port",
			actions: []*FlowAction{
				{Type: ActionOutput, Port: &port},
			},
			expected: "output:1",
		},
		{
			name: "drop action",
			actions: []*FlowAction{
				{Type: ActionDrop},
			},
			expected: "drop",
		},
		{
			name: "normal action",
			actions: []*FlowAction{
				{Type: ActionNormal},
			},
			expected: "NORMAL",
		},
		{
			name: "flood action",
			actions: []*FlowAction{
				{Type: ActionFlood},
			},
			expected: "FLOOD",
		},
		{
			name: "all action",
			actions: []*FlowAction{
				{Type: ActionAll},
			},
			expected: "ALL",
		},
		{
			name: "controller action",
			actions: []*FlowAction{
				{Type: ActionController},
			},
			expected: "CONTROLLER",
		},
		{
			name: "local action",
			actions: []*FlowAction{
				{Type: ActionLocal},
			},
			expected: "LOCAL",
		},
		{
			name: "in_port action",
			actions: []*FlowAction{
				{Type: ActionInPort},
			},
			expected: "IN_PORT",
		},
		{
			name: "set_vlan action",
			actions: []*FlowAction{
				{Type: ActionSetVLAN, VLANVid: &vlanVid},
			},
			expected: "mod_vlan_vid:100",
		},
		{
			name: "strip_vlan action",
			actions: []*FlowAction{
				{Type: ActionStripVLAN},
			},
			expected: "strip_vlan",
		},
		{
			name: "set_eth_src action",
			actions: []*FlowAction{
				{Type: ActionSetEthSrc, MAC: "00:11:22:33:44:55"},
			},
			expected: "mod_dl_src:00:11:22:33:44:55",
		},
		{
			name: "set_eth_dst action",
			actions: []*FlowAction{
				{Type: ActionSetEthDst, MAC: "66:77:88:99:aa:bb"},
			},
			expected: "mod_dl_dst:66:77:88:99:aa:bb",
		},
		{
			name: "set_ipv4_src action",
			actions: []*FlowAction{
				{Type: ActionSetIPv4Src, IPv4: "192.168.1.1"},
			},
			expected: "mod_nw_src:192.168.1.1",
		},
		{
			name: "set_ipv4_dst action",
			actions: []*FlowAction{
				{Type: ActionSetIPv4Dst, IPv4: "10.0.0.1"},
			},
			expected: "mod_nw_dst:10.0.0.1",
		},
		{
			name: "goto_table action",
			actions: []*FlowAction{
				{Type: ActionGotoTable, Table: &table},
			},
			expected: "resubmit(,1)",
		},
		{
			name: "multiple actions",
			actions: []*FlowAction{
				{Type: ActionSetVLAN, VLANVid: &vlanVid},
				{Type: ActionOutput, Port: &port},
			},
			expected: "mod_vlan_vid:100,output:1",
		},
		{
			name: "output without port is skipped",
			actions: []*FlowAction{
				{Type: ActionOutput, Port: nil},
				{Type: ActionNormal},
			},
			expected: "NORMAL",
		},
		{
			name: "set_vlan without vid is skipped",
			actions: []*FlowAction{
				{Type: ActionSetVLAN, VLANVid: nil},
				{Type: ActionNormal},
			},
			expected: "NORMAL",
		},
		{
			name: "set_eth_src without mac is skipped",
			actions: []*FlowAction{
				{Type: ActionSetEthSrc, MAC: ""},
				{Type: ActionNormal},
			},
			expected: "NORMAL",
		},
		{
			name: "set_eth_dst without mac is skipped",
			actions: []*FlowAction{
				{Type: ActionSetEthDst, MAC: ""},
				{Type: ActionNormal},
			},
			expected: "NORMAL",
		},
		{
			name: "set_ipv4_src without ipv4 is skipped",
			actions: []*FlowAction{
				{Type: ActionSetIPv4Src, IPv4: ""},
				{Type: ActionNormal},
			},
			expected: "NORMAL",
		},
		{
			name: "set_ipv4_dst without ipv4 is skipped",
			actions: []*FlowAction{
				{Type: ActionSetIPv4Dst, IPv4: ""},
				{Type: ActionNormal},
			},
			expected: "NORMAL",
		},
		{
			name: "goto_table without table is skipped",
			actions: []*FlowAction{
				{Type: ActionGotoTable, Table: nil},
				{Type: ActionNormal},
			},
			expected: "NORMAL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ds.buildActionsString(tt.actions)
			if result != tt.expected {
				t.Errorf("buildActionsString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestBuildMatchString_AllMatchFields(t *testing.T) {
	_, _, sync := createSyncTestFixture(t)
	ds := sync.(*quicbaasSynchronizer)

	inPort := uint32(1)
	ethType := uint16(0x0800)
	vlanVid := uint16(100)
	ipProto := uint8(6)
	tcpSrc := uint16(80)
	tcpDst := uint16(443)
	udpSrc := uint16(53)
	udpDst := uint16(53)

	tests := []struct {
		name     string
		match    *FlowMatch
		contains []string
	}{
		{
			name:     "nil match returns empty",
			match:    nil,
			contains: []string{},
		},
		{
			name:     "empty match returns empty",
			match:    &FlowMatch{},
			contains: []string{},
		},
		{
			name: "in_port match",
			match: &FlowMatch{
				InPort: &inPort,
			},
			contains: []string{"in_port=1"},
		},
		{
			name: "eth_src match",
			match: &FlowMatch{
				EthSrc: "00:11:22:33:44:55",
			},
			contains: []string{"dl_src=00:11:22:33:44:55"},
		},
		{
			name: "eth_dst match",
			match: &FlowMatch{
				EthDst: "66:77:88:99:aa:bb",
			},
			contains: []string{"dl_dst=66:77:88:99:aa:bb"},
		},
		{
			name: "eth_type match",
			match: &FlowMatch{
				EthType: &ethType,
			},
			contains: []string{"dl_type=0x0800"},
		},
		{
			name: "vlan_vid match",
			match: &FlowMatch{
				VLANVid: &vlanVid,
			},
			contains: []string{"dl_vlan=100"},
		},
		{
			name: "ipv4_src match",
			match: &FlowMatch{
				IPv4Src: "192.168.1.0/24",
			},
			contains: []string{"nw_src=192.168.1.0/24"},
		},
		{
			name: "ipv4_dst match",
			match: &FlowMatch{
				IPv4Dst: "10.0.0.0/8",
			},
			contains: []string{"nw_dst=10.0.0.0/8"},
		},
		{
			name: "ip_proto match",
			match: &FlowMatch{
				IPProto: &ipProto,
			},
			contains: []string{"nw_proto=6"},
		},
		{
			name: "tcp_src match",
			match: &FlowMatch{
				TCPSrc: &tcpSrc,
			},
			contains: []string{"tp_src=80"},
		},
		{
			name: "tcp_dst match",
			match: &FlowMatch{
				TCPDst: &tcpDst,
			},
			contains: []string{"tp_dst=443"},
		},
		{
			name: "udp_src match",
			match: &FlowMatch{
				UDPSrc: &udpSrc,
			},
			contains: []string{"tp_src=53"},
		},
		{
			name: "udp_dst match",
			match: &FlowMatch{
				UDPDst: &udpDst,
			},
			contains: []string{"tp_dst=53"},
		},
		{
			name: "multiple matches",
			match: &FlowMatch{
				InPort: &inPort,
				EthSrc: "00:11:22:33:44:55",
				EthDst: "66:77:88:99:aa:bb",
			},
			contains: []string{"in_port=1", "dl_src=00:11:22:33:44:55", "dl_dst=66:77:88:99:aa:bb"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ds.buildMatchString(tt.match)
			for _, expected := range tt.contains {
				if !strings.Contains(result, expected) {
					t.Errorf("buildMatchString() = %q, expected to contain %q", result, expected)
				}
			}
		})
	}
}

func TestIsManagedPort_EdgeCases(t *testing.T) {
	_, _, sync := createSyncTestFixture(t)
	ds := sync.(*quicbaasSynchronizer)

	tests := []struct {
		name     string
		port     *ovs.Port
		expected bool
	}{
		{
			name:     "nil external IDs",
			port:     &ovs.Port{Name: "port1", ExternalIDs: nil},
			expected: false,
		},
		{
			name:     "empty external IDs",
			port:     &ovs.Port{Name: "port1", ExternalIDs: map[string]string{}},
			expected: false,
		},
		{
			name:     "managed-by not quicbaas",
			port:     &ovs.Port{Name: "port1", ExternalIDs: map[string]string{"managed-by": "other"}},
			expected: false,
		},
		{
			name:     "managed-by quicbaas",
			port:     &ovs.Port{Name: "port1", ExternalIDs: map[string]string{"managed-by": "quicbaas"}},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ds.isManagedPort(tt.port)
			if result != tt.expected {
				t.Errorf("isManagedPort() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestUpdatePortWithRetry_TagUpdate(t *testing.T) {
	_, ovsClient, sync := createSyncTestFixture(t)
	ds := sync.(*quicbaasSynchronizer)

	// Set up port in OVS
	ovsClient.CreateBridge(context.Background(), "br-1")
	ovsClient.AddPort(context.Background(), "br-1", "eth0")

	// Set up port state with different tag
	desired := &PortState{
		ID:       "port-1",
		Name:     "eth0",
		BridgeID: "br-1",
		Tag:      100,
	}

	current := &ovs.Port{
		Name: "eth0",
		Tag:  50, // Different tag
	}

	ctx := context.Background()
	err := ds.updatePortWithRetry(ctx, desired, current)

	if err != nil {
		t.Errorf("updatePortWithRetry() error = %v", err)
	}
}

func TestUpdatePortWithRetry_TrunksUpdate(t *testing.T) {
	_, ovsClient, sync := createSyncTestFixture(t)
	ds := sync.(*quicbaasSynchronizer)

	// Set up port in OVS
	ovsClient.CreateBridge(context.Background(), "br-1")
	ovsClient.AddPort(context.Background(), "br-1", "eth0")

	// Set up port with different trunks
	desired := &PortState{
		ID:       "port-1",
		Name:     "eth0",
		BridgeID: "br-1",
		Tag:      0,
		Trunks:   []uint16{100, 200, 300},
	}

	current := &ovs.Port{
		Name:   "eth0",
		Tag:    0,
		Trunks: []int64{100, 200}, // Different trunks
	}

	ctx := context.Background()
	err := ds.updatePortWithRetry(ctx, desired, current)

	if err != nil {
		t.Errorf("updatePortWithRetry() error = %v", err)
	}
}

func TestSyncSingleBridge_NodeMismatch(t *testing.T) {
	stateManager, _, sync := createSyncTestFixture(t)

	// Set up bridge for different node
	bridge := &BridgeState{
		ID:     "br-1",
		Name:   "bridge1",
		NodeID: 99, // Different from synchronizer's node ID (which is 1)
	}
	stateManager.CreateBridge(context.Background(), bridge)

	err := sync.SyncBridge("br-1")

	if err == nil {
		t.Error("SyncBridge() should return error for node mismatch")
	}
}

func TestSyncSingleBridge_BridgeExists(t *testing.T) {
	stateManager, ovsClient, sync := createSyncTestFixture(t)

	// Set up existing bridge in both state manager and OVS
	bridge := &BridgeState{
		ID:       "br-1",
		Name:     "bridge1",
		NodeID:   1,
		FailMode: "standalone",
	}
	stateManager.CreateBridge(context.Background(), bridge)
	ovsClient.CreateBridge(context.Background(), "bridge1")

	err := sync.SyncBridge("br-1")

	if err != nil {
		t.Errorf("SyncBridge() error = %v", err)
	}
}

func TestSyncSingleBridge_BridgeDoesNotExist(t *testing.T) {
	stateManager, ovsClient, sync := createSyncTestFixture(t)

	// Set up bridge in state manager but not in OVS
	bridge := &BridgeState{
		ID:     "br-1",
		Name:   "bridge1",
		NodeID: 1,
	}
	stateManager.CreateBridge(context.Background(), bridge)

	err := sync.SyncBridge("br-1")

	if err != nil {
		t.Errorf("SyncBridge() error = %v", err)
	}
	// Verify bridge was created in OVS
	_, getBridgeErr := ovsClient.GetBridge(context.Background(), "bridge1")
	if getBridgeErr != nil {
		t.Errorf("Bridge should have been created in OVS")
	}
}

func TestWithRetry_ContextCancellation(t *testing.T) {
	_, _, sync := createSyncTestFixture(t)
	ds := sync.(*quicbaasSynchronizer)

	// Create already cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	callCount := 0
	err := ds.withRetry(ctx, "test", func() error {
		callCount++
		return errors.New("error")
	})

	if err != context.Canceled {
		t.Errorf("withRetry() error = %v, want context.Canceled", err)
	}
	if callCount != 0 {
		t.Errorf("withRetry() callCount = %d, want 0", callCount)
	}
}

func TestReconcileFlows_ListBridgeError(t *testing.T) {
	stateManager, _, sync := createSyncTestFixture(t)
	ds := sync.(*quicbaasSynchronizer)

	// Make ListBridges return error
	stateManager.listBridgesErr = errors.New("database error")

	ctx := context.Background()
	_, err := ds.reconcileFlows(ctx)

	if err == nil {
		t.Error("reconcileFlows() should return error")
	}
}

func TestReconcileVLANs_ListVLANsError(t *testing.T) {
	stateManager, _, sync := createSyncTestFixture(t)
	ds := sync.(*quicbaasSynchronizer)

	// Make ListVLANs return error
	stateManager.listVLANsErr = errors.New("database error")

	ctx := context.Background()
	_, err := ds.reconcileVLANs(ctx)

	if err == nil {
		t.Error("reconcileVLANs() should return error")
	}
}

func TestReconcilePorts_ListBridgesError(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithSyncInterval(100*time.Millisecond),
		WithRetryConfig(10*time.Millisecond, 2, 2.0),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)
	ds := sync.(*quicbaasSynchronizer)

	// Make ListBridges return error
	stateManager.listBridgesErr = errors.New("database error")

	ctx := context.Background()
	_, err := ds.reconcilePorts(ctx)

	if err == nil {
		t.Error("reconcilePorts() should return error when ListBridges fails")
	}
}

func TestReconcileBridges_ListBridgesError(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithSyncInterval(100*time.Millisecond),
		WithRetryConfig(10*time.Millisecond, 2, 2.0),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)
	ds := sync.(*quicbaasSynchronizer)

	// Make ListBridges return error
	stateManager.listBridgesErr = errors.New("database error")

	ctx := context.Background()
	_, err := ds.reconcileBridges(ctx)

	if err == nil {
		t.Error("reconcileBridges() should return error when ListBridges fails")
	}
}

func TestSyncAllWithContext_Success(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithSyncInterval(100*time.Millisecond),
		WithRetryConfig(10*time.Millisecond, 2, 2.0),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	// Add a bridge to sync
	bridge := &BridgeState{ID: "br-1", Name: "bridge1", NodeID: 1}
	stateManager.CreateBridge(context.Background(), bridge)

	err := sync.SyncAll()

	if err != nil {
		t.Errorf("SyncAll() error = %v", err)
	}
}

func TestCreateBridgeWithRetry_OVSError(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithSyncInterval(100*time.Millisecond),
		WithRetryConfig(10*time.Millisecond, 2, 2.0),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)
	ds := sync.(*quicbaasSynchronizer)

	// Make OVS client fail
	ovsClient.createBridgeErr = errors.New("OVS error")

	bridge := &BridgeState{ID: "br-1", Name: "bridge1", NodeID: 1}
	ctx := context.Background()
	err := ds.createBridgeWithRetry(ctx, bridge)

	if err == nil {
		t.Error("createBridgeWithRetry() should return error when OVS fails")
	}
}

func TestCreatePortWithRetry_OVSError(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithSyncInterval(100*time.Millisecond),
		WithRetryConfig(10*time.Millisecond, 2, 2.0),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)
	ds := sync.(*quicbaasSynchronizer)

	// Set up bridge first
	ovsClient.CreateBridge(context.Background(), "bridge1")

	// Make OVS client fail for ports
	ovsClient.addPortErr = errors.New("OVS error")

	port := &PortState{ID: "port-1", Name: "eth0", BridgeID: "br-1"}
	bridge := &BridgeState{ID: "br-1", Name: "bridge1", NodeID: 1}
	ctx := context.Background()
	err := ds.createPortWithRetry(ctx, bridge.Name, port)

	if err == nil {
		t.Error("createPortWithRetry() should return error when OVS fails")
	}
}

func TestUpdateBridgeWithRetry_NoChange(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithSyncInterval(100*time.Millisecond),
		WithRetryConfig(10*time.Millisecond, 2, 2.0),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)
	ds := sync.(*quicbaasSynchronizer)

	// Set up matching bridge in OVS
	ovsClient.CreateBridge(context.Background(), "bridge1")

	desired := &BridgeState{ID: "br-1", Name: "bridge1", FailMode: "standalone", NodeID: 1}
	current := &ovs.Bridge{Name: "bridge1", FailMode: "standalone"}

	ctx := context.Background()
	err := ds.updateBridgeWithRetry(ctx, desired, current)

	if err != nil {
		t.Errorf("updateBridgeWithRetry() error = %v", err)
	}
}

func TestReconcile_Success(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithSyncInterval(100*time.Millisecond),
		WithRetryConfig(10*time.Millisecond, 2, 2.0),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)
	ds := sync.(*quicbaasSynchronizer)

	// Create a bridge to sync
	bridge := &BridgeState{ID: "br-1", Name: "bridge1", NodeID: 1}
	stateManager.CreateBridge(context.Background(), bridge)

	ctx := context.Background()
	err := ds.reconcile(ctx)

	if err != nil {
		t.Errorf("reconcile() error = %v", err)
	}
}

func TestSyncLoop_ContextCancelled(t *testing.T) {
	stateManager := newMockStateManager()
	ovsClient := newMockOVSClient()
	logger := createTestLogger()

	sync := NewOVSSynchronizer(
		stateManager,
		ovsClient,
		logger,
		WithSyncInterval(100*time.Millisecond),
		WithRetryConfig(10*time.Millisecond, 2, 2.0),
		WithReconcileOnStartup(false),
		WithNodeID(1),
	)

	// Start and immediately stop
	if err := sync.Start(context.Background()); err != nil {
		t.Errorf("Start() error = %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	if err := sync.Stop(); err != nil {
		t.Errorf("Stop() error = %v", err)
	}
}
