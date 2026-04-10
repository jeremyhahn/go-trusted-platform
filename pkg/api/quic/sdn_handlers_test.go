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

//go:build codec_msgpack

package quic

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Mock SDN Service
// =============================================================================

// mockSDNService implements SDNServiceInterface for testing
type mockSDNService struct {
	bridges             map[string]*ovs.Bridge
	ports               map[string]*ovs.Port
	flows               map[string][]*ovs.Flow
	createBridgeError   error
	deleteBridgeError   error
	getBridgeError      error
	listBridgesError    error
	addPortError        error
	deletePortError     error
	getPortError        error
	listPortsError      error
	setVLANError        error
	setTrunksError      error
	addFlowError        error
	deleteFlowError     error
	listFlowsError      error
	deleteAllFlowsError error
	setFailModeError    error
	setProtocolsError   error
}

func newMockSDNService() *mockSDNService {
	return &mockSDNService{
		bridges: make(map[string]*ovs.Bridge),
		ports:   make(map[string]*ovs.Port),
		flows:   make(map[string][]*ovs.Flow),
	}
}

func (m *mockSDNService) CreateBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	if m.createBridgeError != nil {
		return nil, m.createBridgeError
	}

	if _, exists := m.bridges[name]; exists {
		return nil, ovs.ErrBridgeExists
	}

	bridge := &ovs.Bridge{
		UUID:          "bridge-uuid-" + name,
		Name:          name,
		DatapathType:  "system",
		FailMode:      "standalone",
		FlowProtocols: []string{"OpenFlow13"},
		STP:           false,
		Ports:         []string{},
		ExternalIDs:   map[string]string{},
		OtherConfig:   map[string]string{},
		Status:        map[string]string{"state": "up"},
	}

	m.bridges[name] = bridge
	return bridge, nil
}

func (m *mockSDNService) DeleteBridge(ctx context.Context, name string) error {
	if m.deleteBridgeError != nil {
		return m.deleteBridgeError
	}

	if _, exists := m.bridges[name]; !exists {
		return ovs.ErrBridgeNotFound
	}

	delete(m.bridges, name)
	return nil
}

func (m *mockSDNService) GetBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	if m.getBridgeError != nil {
		return nil, m.getBridgeError
	}

	bridge, exists := m.bridges[name]
	if !exists {
		return nil, ovs.ErrBridgeNotFound
	}

	return bridge, nil
}

func (m *mockSDNService) ListBridges(ctx context.Context) ([]*ovs.Bridge, error) {
	if m.listBridgesError != nil {
		return nil, m.listBridgesError
	}

	result := make([]*ovs.Bridge, 0, len(m.bridges))
	for _, b := range m.bridges {
		result = append(result, b)
	}

	return result, nil
}

func (m *mockSDNService) SetBridgeFailMode(ctx context.Context, name, failMode string) error {
	if m.setFailModeError != nil {
		return m.setFailModeError
	}

	bridge, exists := m.bridges[name]
	if !exists {
		return ovs.ErrBridgeNotFound
	}

	bridge.FailMode = failMode
	return nil
}

func (m *mockSDNService) SetBridgeProtocols(ctx context.Context, name string, protocols []string) error {
	if m.setProtocolsError != nil {
		return m.setProtocolsError
	}

	bridge, exists := m.bridges[name]
	if !exists {
		return ovs.ErrBridgeNotFound
	}

	bridge.FlowProtocols = protocols
	return nil
}

func (m *mockSDNService) AddPort(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
	if m.addPortError != nil {
		return nil, m.addPortError
	}

	if _, exists := m.bridges[bridgeName]; !exists {
		return nil, ovs.ErrBridgeNotFound
	}

	if _, exists := m.ports[portName]; exists {
		return nil, ovs.ErrPortExists
	}

	port := &ovs.Port{
		UUID:        "port-uuid-" + portName,
		Name:        portName,
		Tag:         0,
		Trunks:      []int64{},
		MAC:         "00:00:00:00:00:01",
		ExternalIDs: map[string]string{},
		OtherConfig: map[string]string{},
	}

	m.ports[portName] = port
	m.bridges[bridgeName].Ports = append(m.bridges[bridgeName].Ports, portName)
	return port, nil
}

func (m *mockSDNService) DeletePort(ctx context.Context, bridgeName, portName string) error {
	if m.deletePortError != nil {
		return m.deletePortError
	}

	if _, exists := m.bridges[bridgeName]; !exists {
		return ovs.ErrBridgeNotFound
	}

	if _, exists := m.ports[portName]; !exists {
		return ovs.ErrPortNotFound
	}

	delete(m.ports, portName)
	return nil
}

func (m *mockSDNService) GetPort(ctx context.Context, name string) (*ovs.Port, error) {
	if m.getPortError != nil {
		return nil, m.getPortError
	}

	port, exists := m.ports[name]
	if !exists {
		return nil, ovs.ErrPortNotFound
	}

	return port, nil
}

func (m *mockSDNService) ListPorts(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
	if m.listPortsError != nil {
		return nil, m.listPortsError
	}

	if _, exists := m.bridges[bridgeName]; !exists {
		return nil, ovs.ErrBridgeNotFound
	}

	result := make([]*ovs.Port, 0)
	for _, portName := range m.bridges[bridgeName].Ports {
		if port, exists := m.ports[portName]; exists {
			result = append(result, port)
		}
	}

	return result, nil
}

func (m *mockSDNService) SetPortVLAN(ctx context.Context, portName string, tag int64) error {
	if m.setVLANError != nil {
		return m.setVLANError
	}

	port, exists := m.ports[portName]
	if !exists {
		return ovs.ErrPortNotFound
	}

	port.Tag = tag
	return nil
}

func (m *mockSDNService) SetPortTrunks(ctx context.Context, portName string, trunks []int64) error {
	if m.setTrunksError != nil {
		return m.setTrunksError
	}

	port, exists := m.ports[portName]
	if !exists {
		return ovs.ErrPortNotFound
	}

	port.Trunks = trunks
	return nil
}

func (m *mockSDNService) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	if m.addFlowError != nil {
		return m.addFlowError
	}

	if _, exists := m.bridges[bridgeName]; !exists {
		return ovs.ErrBridgeNotFound
	}

	ovsFlow := &ovs.Flow{
		Table:       flow.Table,
		Priority:    flow.Priority,
		Match:       flow.Match,
		Actions:     flow.Actions,
		Cookie:      flow.Cookie,
		PacketCount: 0,
		ByteCount:   0,
		Duration:    0,
	}

	m.flows[bridgeName] = append(m.flows[bridgeName], ovsFlow)
	return nil
}

func (m *mockSDNService) DeleteFlow(ctx context.Context, bridgeName string, match string) error {
	if m.deleteFlowError != nil {
		return m.deleteFlowError
	}

	if _, exists := m.bridges[bridgeName]; !exists {
		return ovs.ErrBridgeNotFound
	}

	// Remove flow by match
	flows := m.flows[bridgeName]
	for i, f := range flows {
		if f.Match == match {
			m.flows[bridgeName] = append(flows[:i], flows[i+1:]...)
			return nil
		}
	}

	return nil
}

func (m *mockSDNService) ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
	if m.listFlowsError != nil {
		return nil, m.listFlowsError
	}

	if _, exists := m.bridges[bridgeName]; !exists {
		return nil, ovs.ErrBridgeNotFound
	}

	return m.flows[bridgeName], nil
}

func (m *mockSDNService) DeleteAllFlows(ctx context.Context, bridgeName string) error {
	if m.deleteAllFlowsError != nil {
		return m.deleteAllFlowsError
	}

	if _, exists := m.bridges[bridgeName]; !exists {
		return ovs.ErrBridgeNotFound
	}

	m.flows[bridgeName] = []*ovs.Flow{}
	return nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newSDNTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestSDNHandler() (*SDNHandler, *mockSDNService) {
	logger := newSDNTestLogger()
	service := newMockSDNService()
	handler := NewSDNHandler(logger, service)
	return handler, service
}

func createTestBridge(service *mockSDNService, name string) *ovs.Bridge {
	bridge := &ovs.Bridge{
		UUID:          "bridge-uuid-" + name,
		Name:          name,
		DatapathType:  "system",
		FailMode:      "standalone",
		FlowProtocols: []string{"OpenFlow13"},
		STP:           false,
		Ports:         []string{},
		ExternalIDs:   map[string]string{"test": "value"},
		OtherConfig:   map[string]string{},
		Status:        map[string]string{"state": "up"},
	}
	service.bridges[name] = bridge
	return bridge
}

func createTestPort(service *mockSDNService, bridgeName, portName string) *ovs.Port {
	port := &ovs.Port{
		UUID:        "port-uuid-" + portName,
		Name:        portName,
		Tag:         100,
		Trunks:      []int64{200, 300},
		MAC:         "00:00:00:00:00:01",
		ExternalIDs: map[string]string{"test": "value"},
		OtherConfig: map[string]string{},
	}
	service.ports[portName] = port
	if bridge, exists := service.bridges[bridgeName]; exists {
		bridge.Ports = append(bridge.Ports, portName)
	}
	return port
}

func createTestFlow(service *mockSDNService, bridgeName string) *ovs.Flow {
	flow := &ovs.Flow{
		Table:       0,
		Priority:    100,
		Match:       "in_port=1",
		Actions:     "output:2",
		Cookie:      "0x1234",
		PacketCount: 1000,
		ByteCount:   100000,
		Duration:    3600,
	}
	service.flows[bridgeName] = append(service.flows[bridgeName], flow)
	return flow
}

// =============================================================================
// Test: NewSDNHandler
// =============================================================================

func TestNewSDNHandler(t *testing.T) {
	t.Run("creates handler with valid inputs", func(t *testing.T) {
		logger := newSDNTestLogger()
		service := newMockSDNService()
		handler := NewSDNHandler(logger, service)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, service, handler.sdnService)
		assert.NotNil(t, handler.policies)
	})

	t.Run("creates handler with nil service", func(t *testing.T) {
		logger := newSDNTestLogger()
		handler := NewSDNHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.sdnService)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestSDNHandleRequest(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		resp := handler.HandleRequest(context.Background(), nil)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "nil")
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		req := &Request{
			Opcode: 0x00, // Unknown opcode for SDN handler
		}

		resp := handler.HandleRequest(context.Background(), req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown SDN operation")
	})
}

// =============================================================================
// Test: CreateBridge
// =============================================================================

func TestHandleCreateBridge(t *testing.T) {
	ctx := context.Background()

	t.Run("creates bridge successfully", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		createReq := &SDNCreateBridgeRequest{
			Name:         "br0",
			DatapathType: "system",
			FailMode:     "secure",
			Protocols:    []string{"OpenFlow13", "OpenFlow14"},
			STP:          true,
			Labels:       map[string]string{"env": "test"},
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNCreateBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var createResp SDNCreateBridgeResponse
		err = DecodePayload(resp.Payload, &createResp)
		require.NoError(t, err)

		assert.NotNil(t, createResp.Bridge)
		assert.Equal(t, "br0", createResp.Bridge.Name)
		assert.Greater(t, createResp.Timestamp, int64(0))
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		createReq := &SDNCreateBridgeRequest{
			Name: "br0",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNCreateBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
		assert.Contains(t, string(resp.Payload), "not available")
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		createReq := &SDNCreateBridgeRequest{}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNCreateBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "name")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		req := &Request{
			Opcode:  OpSDNCreateBridge,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when bridge exists", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		createReq := &SDNCreateBridgeRequest{
			Name: "br0",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNCreateBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusAlreadyExists, resp.Status)
	})
}

// =============================================================================
// Test: DeleteBridge
// =============================================================================

func TestHandleDeleteBridge(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes bridge successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		deleteReq := &SDNDeleteBridgeRequest{
			Name: "br0",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeleteBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var deleteResp SDNDeleteBridgeResponse
		err = DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, "br0", deleteResp.Name)
		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		deleteReq := &SDNDeleteBridgeRequest{
			Name: "br0",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeleteBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		deleteReq := &SDNDeleteBridgeRequest{}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeleteBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when bridge not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		deleteReq := &SDNDeleteBridgeRequest{
			Name: "nonexistent",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeleteBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: GetBridge
// =============================================================================

func TestHandleGetBridge(t *testing.T) {
	ctx := context.Background()

	t.Run("gets bridge successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		getReq := &SDNGetBridgeRequest{
			Name: "br0",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp SDNGetBridgeResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Bridge)
		assert.Equal(t, "br0", getResp.Bridge.Name)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		getReq := &SDNGetBridgeRequest{
			Name: "br0",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		getReq := &SDNGetBridgeRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when bridge not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		getReq := &SDNGetBridgeRequest{
			Name: "nonexistent",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetBridge,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: ListBridges
// =============================================================================

func TestHandleListBridges(t *testing.T) {
	ctx := context.Background()

	t.Run("lists bridges successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")
		createTestBridge(service, "br1")

		listReq := &SDNListBridgesRequest{
			Limit: 10,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListBridges,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp SDNListBridgesResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(2), listResp.Count)
		assert.Len(t, listResp.Bridges, 2)
	})

	t.Run("uses default limit when not specified", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		listReq := &SDNListBridgesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListBridges,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("caps limit at max", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		listReq := &SDNListBridgesRequest{
			Limit: 5000, // exceeds max
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListBridges,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		listReq := &SDNListBridgesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListBridges,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		service.listBridgesError = errors.New("list failed")

		listReq := &SDNListBridgesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListBridges,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: CreatePort
// =============================================================================

func TestHandleCreatePort(t *testing.T) {
	ctx := context.Background()

	t.Run("creates port successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		createReq := &SDNCreatePortRequest{
			BridgeName: "br0",
			PortName:   "eth0",
			VLAN:       100,
			Trunks:     []int64{200, 300},
			Labels:     map[string]string{"env": "test"},
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNCreatePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var createResp SDNCreatePortResponse
		err = DecodePayload(resp.Payload, &createResp)
		require.NoError(t, err)

		assert.NotNil(t, createResp.Port)
		assert.Equal(t, "eth0", createResp.Port.Name)
		assert.Equal(t, "br0", createResp.Port.BridgeName)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		createReq := &SDNCreatePortRequest{
			BridgeName: "br0",
			PortName:   "eth0",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNCreatePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bridge name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		createReq := &SDNCreatePortRequest{
			PortName: "eth0",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNCreatePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "bridge")
	})

	t.Run("returns error for missing port name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		createReq := &SDNCreatePortRequest{
			BridgeName: "br0",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNCreatePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "port")
	})

	t.Run("returns error when bridge not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		createReq := &SDNCreatePortRequest{
			BridgeName: "nonexistent",
			PortName:   "eth0",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNCreatePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error when port exists", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")
		createTestPort(service, "br0", "eth0")

		createReq := &SDNCreatePortRequest{
			BridgeName: "br0",
			PortName:   "eth0",
		}

		payload, err := EncodePayload(createReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNCreatePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusAlreadyExists, resp.Status)
	})
}

// =============================================================================
// Test: DeletePort
// =============================================================================

func TestHandleDeletePort(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes port successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")
		createTestPort(service, "br0", "eth0")

		deleteReq := &SDNDeletePortRequest{
			BridgeName: "br0",
			PortName:   "eth0",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeletePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var deleteResp SDNDeletePortResponse
		err = DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, "eth0", deleteResp.PortName)
		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		deleteReq := &SDNDeletePortRequest{
			BridgeName: "br0",
			PortName:   "eth0",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeletePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bridge name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		deleteReq := &SDNDeletePortRequest{
			PortName: "eth0",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeletePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing port name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		deleteReq := &SDNDeletePortRequest{
			BridgeName: "br0",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeletePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when port not found", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		deleteReq := &SDNDeletePortRequest{
			BridgeName: "br0",
			PortName:   "nonexistent",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeletePort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: GetPort
// =============================================================================

func TestHandleGetPort(t *testing.T) {
	ctx := context.Background()

	t.Run("gets port successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")
		createTestPort(service, "br0", "eth0")

		getReq := &SDNGetPortRequest{
			PortName: "eth0",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetPort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp SDNGetPortResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Port)
		assert.Equal(t, "eth0", getResp.Port.Name)
		assert.Equal(t, int64(100), getResp.Port.VLAN)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		getReq := &SDNGetPortRequest{
			PortName: "eth0",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetPort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing port name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		getReq := &SDNGetPortRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetPort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when port not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		getReq := &SDNGetPortRequest{
			PortName: "nonexistent",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetPort,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: ListPorts
// =============================================================================

func TestHandleListPorts(t *testing.T) {
	ctx := context.Background()

	t.Run("lists ports successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")
		createTestPort(service, "br0", "eth0")
		createTestPort(service, "br0", "eth1")

		listReq := &SDNListPortsRequest{
			BridgeName: "br0",
			Limit:      10,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPorts,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp SDNListPortsResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(2), listResp.Count)
		assert.Len(t, listResp.Ports, 2)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		listReq := &SDNListPortsRequest{
			BridgeName: "br0",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPorts,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bridge name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		listReq := &SDNListPortsRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPorts,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when bridge not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		listReq := &SDNListPortsRequest{
			BridgeName: "nonexistent",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPorts,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("uses default limit", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		listReq := &SDNListPortsRequest{
			BridgeName: "br0",
			Limit:      0, // zero uses default
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPorts,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("caps limit at max", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		listReq := &SDNListPortsRequest{
			BridgeName: "br0",
			Limit:      5000, // exceeds max
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPorts,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})
}

// =============================================================================
// Test: SetVLAN
// =============================================================================

func TestHandleSetVLAN(t *testing.T) {
	ctx := context.Background()

	t.Run("sets VLAN successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")
		createTestPort(service, "br0", "eth0")

		setReq := &SDNSetVLANRequest{
			PortName: "eth0",
			VLAN:     200,
		}

		payload, err := EncodePayload(setReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNSetVLAN,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var setResp SDNSetVLANResponse
		err = DecodePayload(resp.Payload, &setResp)
		require.NoError(t, err)

		assert.Equal(t, "eth0", setResp.PortName)
		assert.Equal(t, int64(200), setResp.VLAN)
		assert.True(t, setResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		setReq := &SDNSetVLANRequest{
			PortName: "eth0",
			VLAN:     200,
		}

		payload, err := EncodePayload(setReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNSetVLAN,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing port name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		setReq := &SDNSetVLANRequest{
			VLAN: 200,
		}

		payload, err := EncodePayload(setReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNSetVLAN,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when port not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		setReq := &SDNSetVLANRequest{
			PortName: "nonexistent",
			VLAN:     200,
		}

		payload, err := EncodePayload(setReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNSetVLAN,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: GetVLAN
// =============================================================================

func TestHandleGetVLAN(t *testing.T) {
	ctx := context.Background()

	t.Run("gets VLAN successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")
		createTestPort(service, "br0", "eth0")

		getReq := &SDNGetVLANRequest{
			PortName: "eth0",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetVLAN,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp SDNGetVLANResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.Equal(t, "eth0", getResp.PortName)
		assert.Equal(t, int64(100), getResp.VLAN)
		assert.Equal(t, []int64{200, 300}, getResp.Trunks)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		getReq := &SDNGetVLANRequest{
			PortName: "eth0",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetVLAN,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing port name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		getReq := &SDNGetVLANRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetVLAN,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when port not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		getReq := &SDNGetVLANRequest{
			PortName: "nonexistent",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetVLAN,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: AddFlow
// =============================================================================

func TestHandleAddFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("adds flow successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		addReq := &SDNAddFlowRequest{
			BridgeName:  "br0",
			Table:       0,
			Priority:    100,
			Match:       "in_port=1",
			Actions:     "output:2",
			Cookie:      "0x1234",
			IdleTimeout: 300,
			HardTimeout: 600,
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNAddFlow,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var addResp SDNAddFlowResponse
		err = DecodePayload(resp.Payload, &addResp)
		require.NoError(t, err)

		assert.Equal(t, "0x1234", addResp.FlowID)
		assert.True(t, addResp.Success)
	})

	t.Run("generates flow ID when cookie not provided", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		addReq := &SDNAddFlowRequest{
			BridgeName: "br0",
			Table:      0,
			Priority:   100,
			Match:      "in_port=1",
			Actions:    "output:2",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNAddFlow,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var addResp SDNAddFlowResponse
		err = DecodePayload(resp.Payload, &addResp)
		require.NoError(t, err)

		assert.NotEmpty(t, addResp.FlowID)
		assert.True(t, addResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		addReq := &SDNAddFlowRequest{
			BridgeName: "br0",
			Table:      0,
			Priority:   100,
			Match:      "in_port=1",
			Actions:    "output:2",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNAddFlow,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bridge name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		addReq := &SDNAddFlowRequest{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNAddFlow,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when bridge not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		addReq := &SDNAddFlowRequest{
			BridgeName: "nonexistent",
			Table:      0,
			Priority:   100,
			Match:      "in_port=1",
			Actions:    "output:2",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNAddFlow,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: DeleteFlow
// =============================================================================

func TestHandleDeleteFlow(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes flow successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")
		createTestFlow(service, "br0")

		deleteReq := &SDNDeleteFlowRequest{
			BridgeName: "br0",
			Match:      "in_port=1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeleteFlow,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var deleteResp SDNDeleteFlowResponse
		err = DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		deleteReq := &SDNDeleteFlowRequest{
			BridgeName: "br0",
			Match:      "in_port=1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeleteFlow,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bridge name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		deleteReq := &SDNDeleteFlowRequest{
			Match: "in_port=1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeleteFlow,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when bridge not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		deleteReq := &SDNDeleteFlowRequest{
			BridgeName: "nonexistent",
			Match:      "in_port=1",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeleteFlow,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: ListFlows
// =============================================================================

func TestHandleListFlows(t *testing.T) {
	ctx := context.Background()

	t.Run("lists flows successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")
		createTestFlow(service, "br0")

		listReq := &SDNListFlowsRequest{
			BridgeName: "br0",
			Limit:      10,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListFlows,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp SDNListFlowsResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(1), listResp.Count)
		assert.Len(t, listResp.Flows, 1)
		assert.Equal(t, "in_port=1", listResp.Flows[0].Match)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		listReq := &SDNListFlowsRequest{
			BridgeName: "br0",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListFlows,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing bridge name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		listReq := &SDNListFlowsRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListFlows,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when bridge not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		listReq := &SDNListFlowsRequest{
			BridgeName: "nonexistent",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListFlows,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("uses default limit", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		listReq := &SDNListFlowsRequest{
			BridgeName: "br0",
			Limit:      0, // zero uses default
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListFlows,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("caps limit at max", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")

		listReq := &SDNListFlowsRequest{
			BridgeName: "br0",
			Limit:      5000, // exceeds max
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListFlows,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})
}

// =============================================================================
// Test: ApplyPolicy
// =============================================================================

func TestHandleApplyPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("applies policy successfully", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		applyReq := &SDNApplyPolicyRequest{
			Name:        "test-policy",
			Description: "Test network policy",
			Priority:    100,
			Rules: []SDNPolicyRule{
				{
					Direction: "ingress",
					Protocol:  "tcp",
					PortRange: "80-443",
					Source:    "10.0.0.0/8",
					Action:    "allow",
				},
			},
			Labels: map[string]string{"env": "test"},
		}

		payload, err := EncodePayload(applyReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var applyResp SDNApplyPolicyResponse
		err = DecodePayload(resp.Payload, &applyResp)
		require.NoError(t, err)

		assert.NotNil(t, applyResp.Policy)
		assert.Equal(t, "test-policy", applyResp.Policy.Name)
		assert.Equal(t, "Test network policy", applyResp.Policy.Description)
		assert.Equal(t, 100, applyResp.Policy.Priority)
		assert.Len(t, applyResp.Policy.Rules, 1)
		assert.Equal(t, "active", applyResp.Policy.Status)
	})

	t.Run("updates existing policy", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		// Create initial policy
		applyReq := &SDNApplyPolicyRequest{
			Name:     "test-policy",
			Priority: 100,
			Rules: []SDNPolicyRule{
				{Direction: "ingress", Action: "allow"},
			},
		}

		payload, err := EncodePayload(applyReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		}

		handler.HandleRequest(ctx, req)

		// Update policy
		applyReq.Priority = 200
		payload, err = EncodePayload(applyReq)
		require.NoError(t, err)

		req = &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		applyReq := &SDNApplyPolicyRequest{
			Name: "test-policy",
		}

		payload, err := EncodePayload(applyReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		applyReq := &SDNApplyPolicyRequest{
			Priority: 100,
		}

		payload, err := EncodePayload(applyReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// Test: GetPolicy
// =============================================================================

func TestHandleGetPolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("gets policy successfully", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		// Create a policy first
		applyReq := &SDNApplyPolicyRequest{
			Name:     "test-policy",
			Priority: 100,
			Rules: []SDNPolicyRule{
				{Direction: "ingress", Action: "allow"},
			},
		}

		payload, _ := EncodePayload(applyReq)
		applyResp := handler.HandleRequest(ctx, &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		})

		var applyRespData SDNApplyPolicyResponse
		DecodePayload(applyResp.Payload, &applyRespData)

		// Now get the policy
		getReq := &SDNGetPolicyRequest{
			ID: applyRespData.Policy.ID,
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp SDNGetPolicyResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Policy)
		assert.Equal(t, "test-policy", getResp.Policy.Name)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		getReq := &SDNGetPolicyRequest{
			ID: "test-id",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		getReq := &SDNGetPolicyRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when policy not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		getReq := &SDNGetPolicyRequest{
			ID: "nonexistent",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: ListPolicies
// =============================================================================

func TestSDNHandleListPolicies(t *testing.T) {
	ctx := context.Background()

	t.Run("lists policies successfully", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		// Create some policies
		for i := 0; i < 3; i++ {
			applyReq := &SDNApplyPolicyRequest{
				Name:     "test-policy-" + string(rune('a'+i)),
				Priority: 100 + i,
			}
			payload, _ := EncodePayload(applyReq)
			handler.HandleRequest(ctx, &Request{
				Opcode:  OpSDNApplyPolicy,
				Payload: payload,
			})
		}

		listReq := &SDNListPoliciesRequest{
			Limit: 10,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp SDNListPoliciesResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(3), listResp.Count)
		assert.Len(t, listResp.Policies, 3)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		listReq := &SDNListPoliciesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})
}

// =============================================================================
// Test: DeletePolicy
// =============================================================================

func TestHandleDeletePolicy(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes policy successfully", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		// Create a policy first
		applyReq := &SDNApplyPolicyRequest{
			Name:     "test-policy",
			Priority: 100,
		}

		payload, _ := EncodePayload(applyReq)
		applyResp := handler.HandleRequest(ctx, &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		})

		var applyRespData SDNApplyPolicyResponse
		DecodePayload(applyResp.Payload, &applyRespData)

		// Now delete the policy
		deleteReq := &SDNDeletePolicyRequest{
			ID: applyRespData.Policy.ID,
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeletePolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var deleteResp SDNDeletePolicyResponse
		err = DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, applyRespData.Policy.ID, deleteResp.ID)
		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		deleteReq := &SDNDeletePolicyRequest{
			ID: "test-id",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeletePolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing ID", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		deleteReq := &SDNDeletePolicyRequest{}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeletePolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when policy not found", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		deleteReq := &SDNDeletePolicyRequest{
			ID: "nonexistent",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNDeletePolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: GetMetrics
// =============================================================================

func TestHandleGetMetrics(t *testing.T) {
	ctx := context.Background()

	t.Run("gets metrics successfully", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		createTestBridge(service, "br0")
		createTestPort(service, "br0", "eth0")
		createTestFlow(service, "br0")

		getReq := &SDNGetMetricsRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetMetrics,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp SDNGetMetricsResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Metrics)
		assert.Equal(t, 1, getResp.Metrics.TotalBridges)
		assert.Equal(t, 1, getResp.Metrics.TotalPorts)
		assert.Equal(t, 1, getResp.Metrics.TotalFlows)
		assert.Equal(t, int64(100000), getResp.Metrics.TotalBytes)
		assert.Equal(t, int64(1000), getResp.Metrics.TotalPackets)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		handler := NewSDNHandler(newSDNTestLogger(), nil)

		getReq := &SDNGetMetricsRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetMetrics,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error when list bridges fails", func(t *testing.T) {
		handler, service := createTestSDNHandler()
		service.listBridgesError = errors.New("list bridges failed")

		getReq := &SDNGetMetricsRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNGetMetrics,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: Error Types
// =============================================================================

func TestSDNErrorTypes(t *testing.T) {
	t.Run("ErrSDNEncodingFailed", func(t *testing.T) {
		cause := errors.New("encoding error")
		err := ErrSDNEncodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "encoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrSDNDecodingFailed", func(t *testing.T) {
		cause := errors.New("decoding error")
		err := ErrSDNDecodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "decoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrSDNOperationFailed", func(t *testing.T) {
		cause := errors.New("operation error")
		err := ErrSDNOperationFailed{
			Operation: "create_bridge",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "create_bridge")
		assert.Contains(t, err.Error(), "operation error")
		assert.Equal(t, cause, err.Unwrap())
	})
}

// =============================================================================
// Test: sdnErrorResponse - Comprehensive Error Mapping
// =============================================================================

func TestSDNErrorResponse(t *testing.T) {
	handler, _ := createTestSDNHandler()

	testCases := []struct {
		name           string
		err            error
		expectedStatus byte
	}{
		{"bridge not found", ovs.ErrBridgeNotFound, StatusNotFound},
		{"bridge exists", ovs.ErrBridgeExists, StatusAlreadyExists},
		{"port not found", ovs.ErrPortNotFound, StatusNotFound},
		{"port exists", ovs.ErrPortExists, StatusAlreadyExists},
		{"flow not found", ovs.ErrFlowNotFound, StatusNotFound},
		{"invalid flow", ovs.ErrInvalidFlow, StatusInvalidArgument},
		{"invalid bridge name", ovs.ErrInvalidBridgeName, StatusInvalidArgument},
		{"invalid port name", ovs.ErrInvalidPortName, StatusInvalidArgument},
		{"not connected", ovs.ErrNotConnected, StatusUnavailable},
		{"connection failed", ovs.ErrConnectionFailed, StatusUnavailable},
		{"operation timeout", ovs.ErrOperationTimeout, StatusTimeout},
		{"transaction failed", ovs.ErrTransactionFailed, StatusInternalError},
		{"generic error", errors.New("unknown error"), StatusInternalError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.sdnErrorResponse(tc.err)
			assert.Equal(t, tc.expectedStatus, resp.Status)
		})
	}
}

// =============================================================================
// Test: Helper Methods
// =============================================================================

func TestOvsBridgeToInfo(t *testing.T) {
	handler, _ := createTestSDNHandler()

	t.Run("converts complete bridge", func(t *testing.T) {
		bridge := &ovs.Bridge{
			UUID:          "test-uuid",
			Name:          "br0",
			DatapathType:  "system",
			FailMode:      "secure",
			FlowProtocols: []string{"OpenFlow13"},
			STP:           true,
			Ports:         []string{"eth0", "eth1"},
			ExternalIDs:   map[string]string{"key": "value"},
			OtherConfig:   map[string]string{"config": "value"},
			Status:        map[string]string{"state": "connected"},
		}

		info := handler.ovsBridgeToInfo(bridge)

		assert.NotNil(t, info)
		assert.Equal(t, "test-uuid", info.ID)
		assert.Equal(t, "br0", info.Name)
		assert.Equal(t, "system", info.DatapathType)
		assert.Equal(t, "secure", info.FailMode)
		assert.Equal(t, []string{"OpenFlow13"}, info.Protocols)
		assert.True(t, info.STP)
		assert.Equal(t, "connected", info.Status)
		assert.Equal(t, []string{"eth0", "eth1"}, info.Ports)
	})

	t.Run("handles nil bridge", func(t *testing.T) {
		info := handler.ovsBridgeToInfo(nil)
		assert.Nil(t, info)
	})

	t.Run("handles bridge without status", func(t *testing.T) {
		bridge := &ovs.Bridge{
			UUID: "test-uuid",
			Name: "br0",
		}

		info := handler.ovsBridgeToInfo(bridge)

		assert.NotNil(t, info)
		assert.Equal(t, "up", info.Status)
	})
}

func TestOvsPortToInfo(t *testing.T) {
	handler, _ := createTestSDNHandler()

	t.Run("converts complete port", func(t *testing.T) {
		port := &ovs.Port{
			UUID:        "test-uuid",
			Name:        "eth0",
			Tag:         100,
			Trunks:      []int64{200, 300},
			MAC:         "00:00:00:00:00:01",
			ExternalIDs: map[string]string{"key": "value"},
			OtherConfig: map[string]string{"config": "value"},
		}

		info := handler.ovsPortToInfo(port, "br0")

		assert.NotNil(t, info)
		assert.Equal(t, "test-uuid", info.ID)
		assert.Equal(t, "eth0", info.Name)
		assert.Equal(t, "br0", info.BridgeName)
		assert.Equal(t, int64(100), info.VLAN)
		assert.Equal(t, []int64{200, 300}, info.Trunks)
		assert.Equal(t, "00:00:00:00:00:01", info.MACAddress)
		assert.Equal(t, "up", info.Status)
	})

	t.Run("handles nil port", func(t *testing.T) {
		info := handler.ovsPortToInfo(nil, "br0")
		assert.Nil(t, info)
	})
}

func TestOvsFlowToInfo(t *testing.T) {
	handler, _ := createTestSDNHandler()

	t.Run("converts complete flow", func(t *testing.T) {
		flow := &ovs.Flow{
			Table:       0,
			Priority:    100,
			Match:       "in_port=1",
			Actions:     "output:2",
			Cookie:      "0x1234",
			PacketCount: 1000,
			ByteCount:   100000,
			Duration:    3600,
		}

		info := handler.ovsFlowToInfo(flow, "br0")

		assert.NotNil(t, info)
		assert.Equal(t, "0x1234", info.ID)
		assert.Equal(t, "br0", info.BridgeName)
		assert.Equal(t, 0, info.Table)
		assert.Equal(t, 100, info.Priority)
		assert.Equal(t, "in_port=1", info.Match)
		assert.Equal(t, "output:2", info.Actions)
		assert.Equal(t, int64(1000), info.PacketCount)
		assert.Equal(t, int64(100000), info.ByteCount)
		assert.Equal(t, 3600, info.Duration)
	})

	t.Run("handles nil flow", func(t *testing.T) {
		info := handler.ovsFlowToInfo(nil, "br0")
		assert.Nil(t, info)
	})
}

// =============================================================================
// Test: Pagination Constants
// =============================================================================

func TestSDNPaginationConstants(t *testing.T) {
	assert.Equal(t, int32(100), sdnDefaultLimit)
	assert.Equal(t, int32(1000), sdnMaxLimit)
	assert.Less(t, sdnDefaultLimit, sdnMaxLimit)
}

// =============================================================================
// Test: Sentinel Errors
// =============================================================================

func TestSDNSentinelErrors(t *testing.T) {
	assert.NotEmpty(t, ErrSDNServiceNotAvailable.Error())
	assert.NotEmpty(t, ErrSDNMissingBridgeName.Error())
	assert.NotEmpty(t, ErrSDNMissingBridgeID.Error())
	assert.NotEmpty(t, ErrSDNMissingPortName.Error())
	assert.NotEmpty(t, ErrSDNMissingPolicyID.Error())
	assert.NotEmpty(t, ErrSDNMissingPolicyName.Error())
	assert.NotEmpty(t, ErrSDNPolicyNotFound.Error())
	assert.NotEmpty(t, ErrSDNPolicyAlreadyExists.Error())
}

// =============================================================================
// Test: Apply Policy - Error Paths
// =============================================================================

func TestHandleApplyPolicyErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when service unavailable", func(t *testing.T) {
		logger := newSDNTestLogger()
		handler := NewSDNHandler(logger, nil)

		applyReq := &SDNApplyPolicyRequest{
			Name:        "test-policy",
			Description: "Test policy",
			Priority:    100,
		}

		payload, err := EncodePayload(applyReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		req := &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		applyReq := &SDNApplyPolicyRequest{
			Description: "Test policy",
		}

		payload, err := EncodePayload(applyReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("creates new policy successfully", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		applyReq := &SDNApplyPolicyRequest{
			Name:        "new-policy",
			Description: "A new policy",
			Priority:    100,
			Rules: []SDNPolicyRule{
				{
					Direction: "ingress",
					Action:    "allow",
					PortRange: "80",
					Protocol:  "tcp",
				},
			},
			Labels: map[string]string{"env": "test"},
		}

		payload, err := EncodePayload(applyReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var applyResp SDNApplyPolicyResponse
		err = DecodePayload(resp.Payload, &applyResp)
		require.NoError(t, err)

		assert.NotNil(t, applyResp.Policy)
		assert.Equal(t, "new-policy", applyResp.Policy.Name)
	})

	t.Run("updates existing policy successfully", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		// First, create a policy
		applyReq := &SDNApplyPolicyRequest{
			Name:        "update-policy",
			Description: "Original policy",
			Priority:    100,
		}

		payload, err := EncodePayload(applyReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, StatusOK, resp.Status)

		// Now update the policy
		updateReq := &SDNApplyPolicyRequest{
			Name:        "update-policy",
			Description: "Updated policy",
			Priority:    200,
		}

		payload, err = EncodePayload(updateReq)
		require.NoError(t, err)

		req = &Request{
			Opcode:  OpSDNApplyPolicy,
			Payload: payload,
		}

		resp = handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var applyResp SDNApplyPolicyResponse
		err = DecodePayload(resp.Payload, &applyResp)
		require.NoError(t, err)

		assert.Equal(t, "Updated policy", applyResp.Policy.Description)
		assert.Equal(t, 200, applyResp.Policy.Priority)
	})
}

// =============================================================================
// Test: List Policies - Error Paths
// =============================================================================

func TestHandleListPoliciesErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when service unavailable", func(t *testing.T) {
		logger := newSDNTestLogger()
		handler := NewSDNHandler(logger, nil)

		listReq := &SDNListPoliciesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		req := &Request{
			Opcode:  OpSDNListPolicies,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("applies default limit", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		// Create some policies first
		for i := 0; i < 5; i++ {
			applyReq := &SDNApplyPolicyRequest{
				Name:     "policy-" + string(rune('A'+i)),
				Priority: i * 10,
			}
			payload, _ := EncodePayload(applyReq)
			req := &Request{
				Opcode:  OpSDNApplyPolicy,
				Payload: payload,
			}
			handler.HandleRequest(ctx, req)
		}

		listReq := &SDNListPoliciesRequest{
			Limit: 0, // Should default
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("applies max limit", func(t *testing.T) {
		handler, _ := createTestSDNHandler()

		listReq := &SDNListPoliciesRequest{
			Limit: 5000, // Should be capped to max
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpSDNListPolicies,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})
}
