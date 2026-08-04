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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// =============================================================================
// Mock OVS Client implementing ovs.ClientInterface for Testing
// =============================================================================

// MockOVSClientInterface provides a mock implementation of ovs.ClientInterface
// for testing SDN handlers without a real OVSDB connection.
type MockOVSClientInterface struct {
	mu sync.RWMutex

	// State storage
	bridges    map[string]*ovs.Bridge
	ports      map[string]*ovs.Port
	flows      map[string][]*ovs.Flow
	interfaces map[string]*ovs.Interface
	connected  bool

	// Error injection for testing error paths
	connectErr        error
	disconnectErr     error
	createBridgeErr   error
	deleteBridgeErr   error
	getBridgeErr      error
	listBridgesErr    error
	updateBridgeErr   error
	setBridgeFailErr  error
	setBridgeProtoErr error
	addPortErr        error
	deletePortErr     error
	getPortErr        error
	listPortsErr      error
	updatePortErr     error
	setPortVLANErr    error
	setPortTrunksErr  error
	setPortStateErr   error
	getInterfaceErr   error
	getOFPortErr      error
	addFlowErr        error
	deleteFlowErr     error
	listFlowsErr      error
	deleteAllFlowsErr error
	modifyFlowErr     error
	getFlowStatsErr   error
	listDatabasesErr  error
	getSchemaErr      error
	echoErr           error
	transactErr       error
	selectErr         error
}

// Verify MockOVSClientInterface implements ovs.ClientInterface at compile time
var _ ovs.ClientInterface = (*MockOVSClientInterface)(nil)

// NewMockOVSClientInterface creates a new mock OVS client
func NewMockOVSClientInterface() *MockOVSClientInterface {
	return &MockOVSClientInterface{
		bridges:    make(map[string]*ovs.Bridge),
		ports:      make(map[string]*ovs.Port),
		flows:      make(map[string][]*ovs.Flow),
		interfaces: make(map[string]*ovs.Interface),
		connected:  true,
	}
}

// AddBond creates a bonded OVS port (stub — used only for interface conformance).
func (m *MockOVSClientInterface) AddBond(ctx context.Context, bridgeName, bondName string, members []string, mode string, lacp string) (*ovs.Port, error) {
	return nil, nil
}

// Connection management
func (m *MockOVSClientInterface) Connect(ctx context.Context) error {
	if m.connectErr != nil {
		return m.connectErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = true
	return nil
}

func (m *MockOVSClientInterface) Disconnect() error {
	if m.disconnectErr != nil {
		return m.disconnectErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.connected = false
	return nil
}

func (m *MockOVSClientInterface) IsConnected() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.connected
}

func (m *MockOVSClientInterface) Close() error {
	return m.Disconnect()
}

// Bridge operations
func (m *MockOVSClientInterface) CreateBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	if m.createBridgeErr != nil {
		return nil, m.createBridgeErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	bridge := &ovs.Bridge{
		UUID: "mock-uuid-" + name,
		Name: name,
	}
	m.bridges[name] = bridge
	return bridge, nil
}

func (m *MockOVSClientInterface) DeleteBridge(ctx context.Context, name string) error {
	if m.deleteBridgeErr != nil {
		return m.deleteBridgeErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.bridges, name)
	return nil
}

func (m *MockOVSClientInterface) GetBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	if m.getBridgeErr != nil {
		return nil, m.getBridgeErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	bridge, ok := m.bridges[name]
	if !ok {
		return nil, errors.New("bridge not found")
	}
	return bridge, nil
}

func (m *MockOVSClientInterface) ListBridges(ctx context.Context) ([]*ovs.Bridge, error) {
	if m.listBridgesErr != nil {
		return nil, m.listBridgesErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	bridges := make([]*ovs.Bridge, 0, len(m.bridges))
	for _, b := range m.bridges {
		bridges = append(bridges, b)
	}
	return bridges, nil
}

func (m *MockOVSClientInterface) UpdateBridge(ctx context.Context, name string, updates map[string]interface{}) error {
	if m.updateBridgeErr != nil {
		return m.updateBridgeErr
	}
	return nil
}

func (m *MockOVSClientInterface) SetBridgeFailMode(ctx context.Context, name string, failMode string) error {
	if m.setBridgeFailErr != nil {
		return m.setBridgeFailErr
	}
	return nil
}

func (m *MockOVSClientInterface) SetBridgeProtocols(ctx context.Context, name string, protocols []string) error {
	if m.setBridgeProtoErr != nil {
		return m.setBridgeProtoErr
	}
	return nil
}

// Port operations
func (m *MockOVSClientInterface) AddPort(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
	if m.addPortErr != nil {
		return nil, m.addPortErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	port := &ovs.Port{
		UUID: "mock-port-uuid-" + portName,
		Name: portName,
	}
	m.ports[portName] = port
	return port, nil
}

func (m *MockOVSClientInterface) DeletePort(ctx context.Context, bridgeName, portName string) error {
	if m.deletePortErr != nil {
		return m.deletePortErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.ports, portName)
	return nil
}

func (m *MockOVSClientInterface) GetPort(ctx context.Context, name string) (*ovs.Port, error) {
	if m.getPortErr != nil {
		return nil, m.getPortErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	port, ok := m.ports[name]
	if !ok {
		return nil, errors.New("port not found")
	}
	return port, nil
}

func (m *MockOVSClientInterface) ListPorts(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
	if m.listPortsErr != nil {
		return nil, m.listPortsErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	ports := make([]*ovs.Port, 0, len(m.ports))
	for _, p := range m.ports {
		ports = append(ports, p)
	}
	return ports, nil
}

func (m *MockOVSClientInterface) UpdatePort(ctx context.Context, name string, updates map[string]interface{}) error {
	if m.updatePortErr != nil {
		return m.updatePortErr
	}
	return nil
}

func (m *MockOVSClientInterface) SetPortVLAN(ctx context.Context, portName string, tag int64) error {
	if m.setPortVLANErr != nil {
		return m.setPortVLANErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if port, ok := m.ports[portName]; ok {
		port.Tag = tag
	}
	return nil
}

func (m *MockOVSClientInterface) SetPortTrunks(ctx context.Context, portName string, trunks []int64) error {
	if m.setPortTrunksErr != nil {
		return m.setPortTrunksErr
	}
	return nil
}

func (m *MockOVSClientInterface) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	if m.setPortStateErr != nil {
		return m.setPortStateErr
	}
	return nil
}

// Interface operations
func (m *MockOVSClientInterface) GetInterface(ctx context.Context, name string) (*ovs.Interface, error) {
	if m.getInterfaceErr != nil {
		return nil, m.getInterfaceErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	iface, ok := m.interfaces[name]
	if !ok {
		iface = &ovs.Interface{
			Name:       name,
			AdminState: "up",
		}
	}
	return iface, nil
}

func (m *MockOVSClientInterface) GetOFPort(ctx context.Context, portName string) (int32, error) {
	if m.getOFPortErr != nil {
		return 0, m.getOFPortErr
	}
	return 1, nil
}

func (m *MockOVSClientInterface) GetInterfaceOptions(ctx context.Context, name string) (map[string]string, error) {
	return map[string]string{}, nil
}

// VXLAN operations
func (m *MockOVSClientInterface) AddVXLANPort(ctx context.Context, bridgeName string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	portName := "vxlan-" + bridgeName
	vxlanPort := &ovs.VXLANPort{
		Port: ovs.Port{
			UUID: "mock-vxlan-uuid-" + portName,
			Name: portName,
		},
		RemoteIP: cfg.RemoteIP,
		LocalIP:  cfg.LocalIP,
		Key:      cfg.Key,
		DstPort:  cfg.DstPort,
	}
	return vxlanPort, nil
}

func (m *MockOVSClientInterface) AddVXLANPortWithName(ctx context.Context, bridgeName, portName string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	vxlanPort := &ovs.VXLANPort{
		Port: ovs.Port{
			UUID: "mock-vxlan-uuid-" + portName,
			Name: portName,
		},
		RemoteIP: cfg.RemoteIP,
		LocalIP:  cfg.LocalIP,
		Key:      cfg.Key,
		DstPort:  cfg.DstPort,
	}
	return vxlanPort, nil
}

func (m *MockOVSClientInterface) DeleteVXLANPort(ctx context.Context, bridgeName, portName string) error {
	return nil
}

func (m *MockOVSClientInterface) ListVXLANPorts(ctx context.Context, bridgeName string) ([]*ovs.VXLANPort, error) {
	return []*ovs.VXLANPort{}, nil
}

func (m *MockOVSClientInterface) GetVXLANPort(ctx context.Context, bridgeName, portName string) (*ovs.VXLANPort, error) {
	return &ovs.VXLANPort{
		Port: ovs.Port{
			UUID: "mock-vxlan-uuid-" + portName,
			Name: portName,
		},
	}, nil
}

func (m *MockOVSClientInterface) GetVXLANPortWithOptions(ctx context.Context, bridgeName, portName string) (*ovs.VXLANPort, error) {
	return m.GetVXLANPort(ctx, bridgeName, portName)
}

func (m *MockOVSClientInterface) UpdateVXLANPort(ctx context.Context, bridgeName, portName string, cfg *ovs.VXLANPortConfig) error {
	return nil
}

// Flow operations
func (m *MockOVSClientInterface) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	if m.addFlowErr != nil {
		return m.addFlowErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.flows[bridgeName] == nil {
		m.flows[bridgeName] = make([]*ovs.Flow, 0)
	}
	m.flows[bridgeName] = append(m.flows[bridgeName], &ovs.Flow{
		Table:    flow.Table,
		Priority: flow.Priority,
		Match:    flow.Match,
		Actions:  flow.Actions,
		Cookie:   flow.Cookie,
	})
	return nil
}

func (m *MockOVSClientInterface) DeleteFlow(ctx context.Context, bridgeName string, match string) error {
	if m.deleteFlowErr != nil {
		return m.deleteFlowErr
	}
	return nil
}

func (m *MockOVSClientInterface) ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
	if m.listFlowsErr != nil {
		return nil, m.listFlowsErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	flows := m.flows[bridgeName]
	if flows == nil {
		return []*ovs.Flow{}, nil
	}
	return flows, nil
}

func (m *MockOVSClientInterface) DeleteAllFlows(ctx context.Context, bridgeName string) error {
	if m.deleteAllFlowsErr != nil {
		return m.deleteAllFlowsErr
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.flows, bridgeName)
	return nil
}

func (m *MockOVSClientInterface) ModifyFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	if m.modifyFlowErr != nil {
		return m.modifyFlowErr
	}
	return nil
}

func (m *MockOVSClientInterface) GetFlowStats(ctx context.Context, bridgeName string, match string) ([]*ovs.Flow, error) {
	if m.getFlowStatsErr != nil {
		return nil, m.getFlowStatsErr
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	flows := m.flows[bridgeName]
	if flows == nil {
		return []*ovs.Flow{}, nil
	}
	return flows, nil
}

// OVSDB operations
func (m *MockOVSClientInterface) ListDatabases(ctx context.Context) ([]string, error) {
	if m.listDatabasesErr != nil {
		return nil, m.listDatabasesErr
	}
	return []string{"Open_vSwitch"}, nil
}

func (m *MockOVSClientInterface) GetSchema(ctx context.Context) (*ovs.GetSchemaResult, error) {
	if m.getSchemaErr != nil {
		return nil, m.getSchemaErr
	}
	return &ovs.GetSchemaResult{
		Name:    "Open_vSwitch",
		Version: "8.3.0",
	}, nil
}

func (m *MockOVSClientInterface) Echo(ctx context.Context, data []interface{}) ([]interface{}, error) {
	if m.echoErr != nil {
		return nil, m.echoErr
	}
	return data, nil
}

func (m *MockOVSClientInterface) Transact(ctx context.Context, operations ...ovs.Operation) (ovs.TransactResponse, error) {
	if m.transactErr != nil {
		return nil, m.transactErr
	}
	return ovs.TransactResponse{}, nil
}

func (m *MockOVSClientInterface) Select(ctx context.Context, table string, where []ovs.Condition, columns []string) ([]map[string]interface{}, error) {
	if m.selectErr != nil {
		return nil, m.selectErr
	}
	return []map[string]interface{}{}, nil
}

// Helper methods for testing
func (m *MockOVSClientInterface) AddBridgeToMock(name string, bridge *ovs.Bridge) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.bridges[name] = bridge
}

func (m *MockOVSClientInterface) AddPortToMock(name string, port *ovs.Port) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ports[name] = port
}

func (m *MockOVSClientInterface) AddFlowsToMock(bridgeName string, flows []*ovs.Flow) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.flows[bridgeName] = flows
}

func (m *MockOVSClientInterface) AddInterfaceToMock(name string, iface *ovs.Interface) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interfaces[name] = iface
}

// newTestSDNServiceWithMock creates an SDNService wrapping the mock OVS client
// for use in QUIC handler tests.
func newTestSDNServiceWithMock(t *testing.T, mockOVS *MockOVSClientInterface) *SDNService {
	t.Helper()
	svc, err := NewSDNService("", WithOVSClient(mockOVS))
	require.NoError(t, err)
	return svc
}

// seedBridge creates a bridge through the SDNService API, populating both
// the mock OVS client and the SDNService's internal tracking maps.
func seedBridge(t *testing.T, sdnSvc *SDNService, name string) {
	t.Helper()
	ctx := context.Background()
	_, err := sdnSvc.CreateBridge(ctx, &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{
			Name: name,
		},
	})
	require.NoError(t, err)
}

// seedPort creates a port through the SDNService API on the given bridge,
// populating both the mock OVS client and the SDNService's internal tracking maps.
// The bridge must already exist (call seedBridge first).
func seedPort(t *testing.T, sdnSvc *SDNService, bridgeName, portName string) {
	t.Helper()
	ctx := context.Background()
	_, err := sdnSvc.AddPort(ctx, &platformv1.AddPortRequest{
		BridgeId: bridgeName,
		Config: &platformv1.PortConfig{
			Name: portName,
		},
	})
	require.NoError(t, err)
}

// =============================================================================
// Bridge Handler Tests
// =============================================================================

func TestHandleSDNCreateBridge_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	createReq := &platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{Name: "br-test"}}

	payload, err := quic.EncodePayload(createReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNCreateBridge,
		Payload: payload,
	}

	resp := handler.handleSDNCreateBridge(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var createResp platformv1.CreateBridgeResponse
	err = quic.DecodePayload(resp.Payload, &createResp)
	require.NoError(t, err)
	assert.Equal(t, "br-test", createResp.GetBridge().GetConfig().GetName())
	assert.Contains(t, createResp.GetBridge().GetId(), "mock-uuid-")
}

func TestHandleSDNCreateBridge_MissingName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	createReq := &platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{Name: ""}}

	payload, err := quic.EncodePayload(createReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNCreateBridge,
		Payload: payload,
	}

	resp := handler.handleSDNCreateBridge(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNCreateBridge_ClientError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	mockSDN.createBridgeErr = errors.New("mock create error")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(newTestSDNServiceWithMock(t, mockSDN)))
	ctx := context.Background()

	createReq := &platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{Name: "br-test"}}

	payload, err := quic.EncodePayload(createReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNCreateBridge,
		Payload: payload,
	}

	resp := handler.handleSDNCreateBridge(ctx, req)
	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

func TestHandleSDNCreateBridge_DecodeError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpSDNCreateBridge,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.handleSDNCreateBridge(ctx, req)
	assert.Equal(t, quic.StatusInvalidRequest, resp.Status)
}

func TestHandleSDNDeleteBridge_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br-test")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	deleteReq := &platformv1.DeleteBridgeRequest{Id: "br-test"}

	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNDeleteBridge,
		Payload: payload,
	}

	resp := handler.handleSDNDeleteBridge(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var deleteResp platformv1.DeleteBridgeResponse
	err = quic.DecodePayload(resp.Payload, &deleteResp)
	require.NoError(t, err)
	assert.True(t, deleteResp.GetStatus().GetSuccess())
}

func TestHandleSDNDeleteBridge_MissingName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	deleteReq := &platformv1.DeleteBridgeRequest{Id: ""}

	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNDeleteBridge,
		Payload: payload,
	}

	resp := handler.handleSDNDeleteBridge(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNDeleteBridge_ClientError(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	mockSDN.deleteBridgeErr = errors.New("mock delete error")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(newTestSDNServiceWithMock(t, mockSDN)))
	ctx := context.Background()

	deleteReq := &platformv1.DeleteBridgeRequest{Id: "br-test"}

	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNDeleteBridge,
		Payload: payload,
	}

	resp := handler.handleSDNDeleteBridge(ctx, req)
	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

func TestHandleSDNGetBridge_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br-test")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &platformv1.GetBridgeRequest{Id: "br-test"}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetBridge,
		Payload: payload,
	}

	resp := handler.handleSDNGetBridge(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var getResp platformv1.GetBridgeResponse
	err = quic.DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)
	require.NotNil(t, getResp.GetBridge())
	assert.Equal(t, "br-test", getResp.GetBridge().GetConfig().GetName())
	assert.Equal(t, "mock-uuid-br-test", getResp.GetBridge().GetId())
}

func TestHandleSDNGetBridge_MissingName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &platformv1.GetBridgeRequest{Id: ""}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetBridge,
		Payload: payload,
	}

	resp := handler.handleSDNGetBridge(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNGetBridge_NotFound(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &platformv1.GetBridgeRequest{Id: "nonexistent"}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetBridge,
		Payload: payload,
	}

	resp := handler.handleSDNGetBridge(ctx, req)
	assert.Equal(t, quic.StatusNotFound, resp.Status)
}

func TestHandleSDNListBridges_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	mockSDN.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-0", Name: "br0"})
	mockSDN.AddBridgeToMock("br1", &ovs.Bridge{UUID: "uuid-1", Name: "br1"})
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(newTestSDNServiceWithMock(t, mockSDN)))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpSDNListBridges,
		Payload: []byte{},
	}

	resp := handler.handleSDNListBridges(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var listResp platformv1.ListBridgesResponse
	err := quic.DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)
	assert.Len(t, listResp.GetBridges(), 2)
}

func TestHandleSDNListBridges_Error(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	mockSDN.listBridgesErr = errors.New("mock list error")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(newTestSDNServiceWithMock(t, mockSDN)))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpSDNListBridges,
		Payload: []byte{},
	}

	resp := handler.handleSDNListBridges(ctx, req)
	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

// =============================================================================
// Port Handler Tests
// =============================================================================

func TestHandleSDNCreatePort_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	createReq := &platformv1.AddPortRequest{BridgeId: "br0", Config: &platformv1.PortConfig{Name: "eth0"}}

	payload, err := quic.EncodePayload(createReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNCreatePort,
		Payload: payload,
	}

	resp := handler.handleSDNCreatePort(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var createResp platformv1.AddPortResponse
	err = quic.DecodePayload(resp.Payload, &createResp)
	require.NoError(t, err)
	assert.Equal(t, "eth0", createResp.GetPort().GetConfig().GetName())
}

func TestHandleSDNCreatePort_MissingBridgeName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	createReq := &platformv1.AddPortRequest{BridgeId: "", Config: &platformv1.PortConfig{Name: "eth0"}}

	payload, err := quic.EncodePayload(createReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNCreatePort,
		Payload: payload,
	}

	resp := handler.handleSDNCreatePort(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNCreatePort_MissingPortName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	createReq := &platformv1.AddPortRequest{BridgeId: "br0", Config: &platformv1.PortConfig{Name: ""}}

	payload, err := quic.EncodePayload(createReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNCreatePort,
		Payload: payload,
	}

	resp := handler.handleSDNCreatePort(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNCreatePort_Error(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	mockSDN.addPortErr = errors.New("mock add port error")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(newTestSDNServiceWithMock(t, mockSDN)))
	ctx := context.Background()

	createReq := &platformv1.AddPortRequest{BridgeId: "br0", Config: &platformv1.PortConfig{Name: "eth0"}}

	payload, err := quic.EncodePayload(createReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNCreatePort,
		Payload: payload,
	}

	resp := handler.handleSDNCreatePort(ctx, req)
	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

func TestHandleSDNDeletePort_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	seedPort(t, sdnSvc, "br0", "eth0")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	deleteReq := &platformv1.DeletePortRequest{BridgeId: "br0", PortId: "eth0"}

	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNDeletePort,
		Payload: payload,
	}

	resp := handler.handleSDNDeletePort(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var deleteResp platformv1.DeletePortResponse
	err = quic.DecodePayload(resp.Payload, &deleteResp)
	require.NoError(t, err)
	assert.True(t, deleteResp.GetStatus().GetSuccess())
}

func TestHandleSDNDeletePort_MissingFields(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	tests := []struct {
		name       string
		bridgeName string
		portName   string
	}{
		{"missing_bridge", "", "eth0"},
		{"missing_port", "br0", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			deleteReq := &platformv1.DeletePortRequest{BridgeId: tc.bridgeName, PortId: tc.portName}

			payload, err := quic.EncodePayload(deleteReq)
			require.NoError(t, err)

			req := &quic.Request{
				Opcode:  quic.OpSDNDeletePort,
				Payload: payload,
			}

			resp := handler.handleSDNDeletePort(ctx, req)
			assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
		})
	}
}

func TestHandleSDNGetPort_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	seedPort(t, sdnSvc, "br0", "eth0")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &platformv1.GetPortRequest{PortId: "eth0"}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetPort,
		Payload: payload,
	}

	resp := handler.handleSDNGetPort(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var getResp platformv1.GetPortResponse
	err = quic.DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)
	require.NotNil(t, getResp.GetPort())
	assert.Equal(t, "eth0", getResp.GetPort().GetConfig().GetName())
}

func TestHandleSDNGetPort_MissingName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &platformv1.GetPortRequest{PortId: ""}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetPort,
		Payload: payload,
	}

	resp := handler.handleSDNGetPort(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNListPorts_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	seedPort(t, sdnSvc, "br0", "eth0")
	seedPort(t, sdnSvc, "br0", "eth1")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	listReq := &platformv1.ListPortsRequest{BridgeId: "br0"}

	payload, err := quic.EncodePayload(listReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNListPorts,
		Payload: payload,
	}

	resp := handler.handleSDNListPorts(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var listResp platformv1.ListPortsResponse
	err = quic.DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)
	assert.Len(t, listResp.GetPorts(), 2)
}

func TestHandleSDNListPorts_MissingBridge(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	listReq := &platformv1.ListPortsRequest{BridgeId: ""}

	payload, err := quic.EncodePayload(listReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNListPorts,
		Payload: payload,
	}

	resp := handler.handleSDNListPorts(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

// =============================================================================
// Port State Handler Tests
// =============================================================================

func TestHandleSDNGetPortState_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	seedPort(t, sdnSvc, "br0", "eth0")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &SDNGetPortStateRequest{
		PortName: "eth0",
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetPortState,
		Payload: payload,
	}

	resp := handler.handleSDNGetPortState(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var getResp SDNGetPortStateResponse
	err = quic.DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)
	assert.Equal(t, "eth0", getResp.PortName)
	// State field contains the state
	assert.NotEmpty(t, getResp.State)
}

func TestHandleSDNGetPortState_MissingPortName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &SDNGetPortStateRequest{
		PortName: "",
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetPortState,
		Payload: payload,
	}

	resp := handler.handleSDNGetPortState(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNSetPortState_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	seedPort(t, sdnSvc, "br0", "eth0")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	setReq := &platformv1.SetPortStateRequest{PortId: "eth0", AdminState: "up"}

	payload, err := quic.EncodePayload(setReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNSetPortState,
		Payload: payload,
	}

	resp := handler.handleSDNSetPortState(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var setResp platformv1.SetPortStateResponse
	err = quic.DecodePayload(resp.Payload, &setResp)
	require.NoError(t, err)
	assert.True(t, setResp.GetStatus().GetSuccess())
}

func TestHandleSDNSetPortState_AnyStateWithoutPolicyEngine(t *testing.T) {
	// SDNService validates admin_state and only accepts "up" or "down".
	// An invalid state like "any_state_value" is rejected with an error.
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	seedPort(t, sdnSvc, "br0", "eth0")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	setReq := &platformv1.SetPortStateRequest{PortId: "eth0", AdminState: "any_state_value"}

	payload, err := quic.EncodePayload(setReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNSetPortState,
		Payload: payload,
	}

	resp := handler.handleSDNSetPortState(ctx, req)
	// SDNService rejects invalid admin_state values
	assert.Equal(t, quic.StatusInternalError, resp.Status)
}

func TestHandleSDNSetPortState_MissingPortName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	setReq := &platformv1.SetPortStateRequest{PortId: "", AdminState: "up"}

	payload, err := quic.EncodePayload(setReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNSetPortState,
		Payload: payload,
	}

	resp := handler.handleSDNSetPortState(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNSetPortState_MissingState(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	setReq := &platformv1.SetPortStateRequest{PortId: "eth0", AdminState: ""}

	payload, err := quic.EncodePayload(setReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNSetPortState,
		Payload: payload,
	}

	resp := handler.handleSDNSetPortState(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

// =============================================================================
// VLAN Handler Tests
// =============================================================================

func TestHandleSDNSetVLAN_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	seedPort(t, sdnSvc, "br0", "eth0")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	setReq := &SDNSetVLANRequest{
		PortName: "eth0",
		VLAN:     100,
	}

	payload, err := quic.EncodePayload(setReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNSetVLAN,
		Payload: payload,
	}

	resp := handler.handleSDNSetVLAN(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var setResp SDNSetVLANResponse
	err = quic.DecodePayload(resp.Payload, &setResp)
	require.NoError(t, err)
	assert.Equal(t, "eth0", setResp.PortName)
	assert.Equal(t, uint16(100), setResp.VLAN)
	assert.True(t, setResp.Success)
}

func TestHandleSDNSetVLAN_MissingPortName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	setReq := &SDNSetVLANRequest{
		PortName: "",
		VLAN:     100,
	}

	payload, err := quic.EncodePayload(setReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNSetVLAN,
		Payload: payload,
	}

	resp := handler.handleSDNSetVLAN(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNGetVLAN_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	seedPort(t, sdnSvc, "br0", "eth0")
	// Set the VLAN tag on the mock port for retrieval
	mockSDN.mu.Lock()
	if port, ok := mockSDN.ports["eth0"]; ok {
		port.Tag = 200
	}
	mockSDN.mu.Unlock()
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &SDNGetVLANRequest{
		PortName: "eth0",
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetVLAN,
		Payload: payload,
	}

	resp := handler.handleSDNGetVLAN(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var getResp SDNGetVLANResponse
	err = quic.DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)
	assert.Equal(t, "eth0", getResp.PortName)
	assert.Equal(t, uint16(200), getResp.VLAN)
}

func TestHandleSDNGetVLAN_MissingPortName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &SDNGetVLANRequest{
		PortName: "",
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetVLAN,
		Payload: payload,
	}

	resp := handler.handleSDNGetVLAN(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

// =============================================================================
// Flow Handler Tests
// =============================================================================

func TestHandleSDNAddFlow_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	addReq := &platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{BridgeId: "br0", Priority: 100}}

	payload, err := quic.EncodePayload(addReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNAddFlow,
		Payload: payload,
	}

	resp := handler.handleSDNAddFlow(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var addResp platformv1.AddFlowResponse
	err = quic.DecodePayload(resp.Payload, &addResp)
	require.NoError(t, err)
	assert.True(t, addResp.GetStatus().GetSuccess())
}

func TestHandleSDNAddFlow_MissingBridgeName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	addReq := &platformv1.AddFlowRequest{Config: &platformv1.FlowConfig{BridgeId: ""}}

	payload, err := quic.EncodePayload(addReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNAddFlow,
		Payload: payload,
	}

	resp := handler.handleSDNAddFlow(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNDeleteFlow_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	deleteReq := &platformv1.DeleteFlowRequest{BridgeId: "br0", FlowId: "in_port=1"}

	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNDeleteFlow,
		Payload: payload,
	}

	resp := handler.handleSDNDeleteFlow(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var deleteResp platformv1.DeleteFlowResponse
	err = quic.DecodePayload(resp.Payload, &deleteResp)
	require.NoError(t, err)
	assert.True(t, deleteResp.GetStatus().GetSuccess())
}

func TestHandleSDNDeleteFlow_MissingBridgeName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	deleteReq := &platformv1.DeleteFlowRequest{BridgeId: "", FlowId: "in_port=1"}

	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNDeleteFlow,
		Payload: payload,
	}

	resp := handler.handleSDNDeleteFlow(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNGetFlow_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	mockSDN.AddFlowsToMock("br0", []*ovs.Flow{
		{Table: 0, Priority: 100, Match: "in_port=1", Actions: "output:2"},
	})
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &SDNGetFlowRequest{
		BridgeName: "br0",
		Match:      "in_port=1",
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetFlow,
		Payload: payload,
	}

	resp := handler.handleSDNGetFlow(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var getResp SDNGetFlowResponse
	err = quic.DecodePayload(resp.Payload, &getResp)
	require.NoError(t, err)
	assert.Len(t, getResp.Flows, 1)
}

func TestHandleSDNGetFlow_MissingBridgeName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	getReq := &SDNGetFlowRequest{
		BridgeName: "",
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetFlow,
		Payload: payload,
	}

	resp := handler.handleSDNGetFlow(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

func TestHandleSDNListFlows_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	seedBridge(t, sdnSvc, "br0")
	mockSDN.AddFlowsToMock("br0", []*ovs.Flow{
		{Table: 0, Priority: 100, Match: "in_port=1", Actions: "output:2"},
		{Table: 0, Priority: 200, Match: "in_port=2", Actions: "output:1"},
	})
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	listReq := &platformv1.ListFlowsRequest{BridgeId: "br0"}

	payload, err := quic.EncodePayload(listReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNListFlows,
		Payload: payload,
	}

	resp := handler.handleSDNListFlows(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var listResp platformv1.ListFlowsResponse
	err = quic.DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)
	assert.Len(t, listResp.GetFlows(), 2)
}

func TestHandleSDNListFlows_MissingBridgeName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	listReq := &platformv1.ListFlowsRequest{BridgeId: ""}

	payload, err := quic.EncodePayload(listReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNListFlows,
		Payload: payload,
	}

	resp := handler.handleSDNListFlows(ctx, req)
	assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
}

// =============================================================================
// Metrics Handler Tests
// =============================================================================

func TestHandleSDNGetMetrics_Success(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	mockSDN.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-0", Name: "br0"})
	mockSDN.AddBridgeToMock("br1", &ovs.Bridge{UUID: "uuid-1", Name: "br1"})
	mockSDN.AddPortToMock("eth0", &ovs.Port{UUID: "port-uuid-0", Name: "eth0"})
	mockSDN.AddFlowsToMock("br0", []*ovs.Flow{{Match: "in_port=1"}})
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(newTestSDNServiceWithMock(t, mockSDN)))
	ctx := context.Background()

	metricsReq := &SDNGetMetricsRequest{
		BridgeName: "",
	}

	payload, err := quic.EncodePayload(metricsReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetMetrics,
		Payload: payload,
	}

	resp := handler.handleSDNGetMetrics(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var metricsResp SDNGetMetricsResponse
	err = quic.DecodePayload(resp.Payload, &metricsResp)
	require.NoError(t, err)
	require.NotNil(t, metricsResp.Metrics)
	assert.Equal(t, 2, metricsResp.Metrics.BridgeCount)
}

func TestHandleSDNGetMetrics_WithBridgeName(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	mockSDN.AddBridgeToMock("br0", &ovs.Bridge{UUID: "uuid-0", Name: "br0"})
	mockSDN.AddFlowsToMock("br0", []*ovs.Flow{
		{Match: "in_port=1", PacketCount: 100, ByteCount: 5000},
	})
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(newTestSDNServiceWithMock(t, mockSDN)))
	ctx := context.Background()

	metricsReq := &SDNGetMetricsRequest{
		BridgeName: "br0",
	}

	payload, err := quic.EncodePayload(metricsReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetMetrics,
		Payload: payload,
	}

	resp := handler.handleSDNGetMetrics(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var metricsResp SDNGetMetricsResponse
	err = quic.DecodePayload(resp.Payload, &metricsResp)
	require.NoError(t, err)
	require.NotNil(t, metricsResp.Metrics)
}

// =============================================================================
// handleSDNOperation Routing Tests
// =============================================================================

func TestHandleSDNOperation_NilClient(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger) // No SDN client
	ctx := context.Background()

	createReq := &platformv1.CreateBridgeRequest{Config: &platformv1.BridgeConfig{Name: "br0"}}

	payload, err := quic.EncodePayload(createReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNCreateBridge,
		Payload: payload,
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleSDNOperation_UnknownOpcode_Handler(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  0xFF, // Unknown opcode
		Payload: []byte{},
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quic.StatusNotImplemented, resp.Status)
}

// =============================================================================
// Policy Handler Tests (with MockSDNPolicyEngine from existing tests)
// =============================================================================

func TestHandleSDNApplyPolicy_Success_Handler(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	applyReq := &SDNApplyPolicyRequest{
		PortID:   "test-policy",
		TenantID: "tenant-001",
		VLAN:     100,
		ACLs: []*SDNACLRule{
			{
				Priority: 100,
				Action:   "allow",
				Match: &SDNFlowMatch{
					IPProto: 6,
					TCPDst:  80,
				},
			},
		},
	}

	payload, err := quic.EncodePayload(applyReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNApplyPolicy,
		Payload: payload,
	}

	resp := handler.handleSDNApplyPolicy(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)
}

func TestHandleSDNDeletePolicy_Success_Handler(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	// First apply a policy so we can delete it
	applyReq := &SDNApplyPolicyRequest{
		PortID:   "delete-test-policy",
		TenantID: "tenant-001",
		VLAN:     100,
	}
	applyPayload, err := quic.EncodePayload(applyReq)
	require.NoError(t, err)
	applyResp := handler.handleSDNApplyPolicy(ctx, &quic.Request{
		Opcode:  quic.OpSDNApplyPolicy,
		Payload: applyPayload,
	})
	require.Equal(t, quic.StatusOK, applyResp.Status)

	deleteReq := &SDNDeletePolicyRequest{
		PortID: "delete-test-policy",
	}

	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNDeletePolicy,
		Payload: payload,
	}

	resp := handler.handleSDNDeletePolicy(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)
}

func TestHandleSDNGetPolicy_Success_Handler(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	// First apply a policy so we can get it
	applyReq := &SDNApplyPolicyRequest{
		PortID:   "get-test-policy",
		TenantID: "tenant-001",
		VLAN:     100,
	}
	applyPayload, err := quic.EncodePayload(applyReq)
	require.NoError(t, err)
	applyResp := handler.handleSDNApplyPolicy(ctx, &quic.Request{
		Opcode:  quic.OpSDNApplyPolicy,
		Payload: applyPayload,
	})
	require.Equal(t, quic.StatusOK, applyResp.Status)

	getReq := &SDNGetPolicyRequest{
		PortID: "get-test-policy",
	}

	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpSDNGetPolicy,
		Payload: payload,
	}

	resp := handler.handleSDNGetPolicy(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)
}

func TestHandleSDNListPolicies_Success_Handler(t *testing.T) {
	logger := logging.DefaultLogger()
	mockSDN := NewMockOVSClientInterface()
	sdnSvc := newTestSDNServiceWithMock(t, mockSDN)
	handler := NewQUICServiceHandler(logger, WithQUICSDNService(sdnSvc))
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpSDNListPolicies,
		Payload: []byte{},
	}

	resp := handler.handleSDNListPolicies(ctx, req)
	assert.Equal(t, quic.StatusOK, resp.Status)

	var listResp SDNListPoliciesResponse
	err := quic.DecodePayload(resp.Payload, &listResp)
	require.NoError(t, err)
	assert.Equal(t, 0, listResp.Total)
}

func TestHandleSDNListPolicies_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger) // No SDN service
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpSDNListPolicies,
		Payload: []byte{},
	}

	resp := handler.handleSDNOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// Type Conversion Tests
// =============================================================================

func TestConvertSDNACLsToPbRules_FullRequest_Handler(t *testing.T) {
	acls := []*SDNACLRule{
		{
			Priority: 100,
			Action:   "allow",
			Match: &SDNFlowMatch{
				IPv4Src: "192.168.1.0/24",
				IPv4Dst: "10.0.0.0/8",
				TCPSrc:  12345,
				TCPDst:  80,
			},
		},
	}

	result := convertSDNACLsToPbRules(acls)
	require.NotNil(t, result)
	require.Len(t, result, 1)
	assert.Equal(t, int32(100), result[0].Priority)
	assert.Equal(t, platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW, result[0].Action)
}

func TestConvertPbPolicyToSDNPolicy_FullPolicy_Handler(t *testing.T) {
	now := time.Now()

	pol := &platformv1.Policy{
		Id: "policy-1",
		Config: &platformv1.PolicyConfig{
			Rules: []*platformv1.PolicyRule{
				{
					Priority: 100,
					Action:   platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW,
				},
			},
		},
		CreatedAt: timestamppb.New(now),
	}

	result := convertPbPolicyToSDNPolicy("port1", pol)
	require.NotNil(t, result)
	assert.Equal(t, "port1", result.PortID)
	assert.Equal(t, now.Unix(), result.IssuedAt)
	require.Len(t, result.ACLs, 1)
	assert.Equal(t, "allow", result.ACLs[0].Action)
}
