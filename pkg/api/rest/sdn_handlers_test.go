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

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock SDN Service
// =============================================================================

type mockSDNService struct {
	bridges map[string]*ovs.Bridge
	ports   map[string]*ovs.Port
	flows   map[string][]*ovs.Flow

	createBridgeErr error
	deleteBridgeErr error
	getBridgeErr    error
	listBridgesErr  error
	setFailModeErr  error
	setProtocolsErr error

	addPortErr       error
	deletePortErr    error
	getPortErr       error
	listPortsErr     error
	setPortVLANErr   error
	setPortTrunksErr error

	addFlowErr        error
	deleteFlowErr     error
	listFlowsErr      error
	deleteAllFlowsErr error
}

func newMockSDNService() *mockSDNService {
	return &mockSDNService{
		bridges: make(map[string]*ovs.Bridge),
		ports:   make(map[string]*ovs.Port),
		flows:   make(map[string][]*ovs.Flow),
	}
}

func (m *mockSDNService) CreateBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	if m.createBridgeErr != nil {
		return nil, m.createBridgeErr
	}
	if _, exists := m.bridges[name]; exists {
		return nil, ovs.ErrBridgeExists
	}
	bridge := &ovs.Bridge{
		UUID:         "bridge-" + name,
		Name:         name,
		DatapathType: "system",
		Ports:        []string{},
		ExternalIDs:  make(map[string]string),
		OtherConfig:  make(map[string]string),
		Status:       map[string]string{"state": "up"},
	}
	m.bridges[name] = bridge
	return bridge, nil
}

func (m *mockSDNService) DeleteBridge(ctx context.Context, name string) error {
	if m.deleteBridgeErr != nil {
		return m.deleteBridgeErr
	}
	if _, exists := m.bridges[name]; !exists {
		return ovs.ErrBridgeNotFound
	}
	delete(m.bridges, name)
	return nil
}

func (m *mockSDNService) GetBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	if m.getBridgeErr != nil {
		return nil, m.getBridgeErr
	}
	bridge, exists := m.bridges[name]
	if !exists {
		return nil, ovs.ErrBridgeNotFound
	}
	return bridge, nil
}

func (m *mockSDNService) ListBridges(ctx context.Context) ([]*ovs.Bridge, error) {
	if m.listBridgesErr != nil {
		return nil, m.listBridgesErr
	}
	result := make([]*ovs.Bridge, 0, len(m.bridges))
	for _, bridge := range m.bridges {
		result = append(result, bridge)
	}
	return result, nil
}

func (m *mockSDNService) SetBridgeFailMode(ctx context.Context, name, failMode string) error {
	if m.setFailModeErr != nil {
		return m.setFailModeErr
	}
	bridge, exists := m.bridges[name]
	if !exists {
		return ovs.ErrBridgeNotFound
	}
	bridge.FailMode = failMode
	return nil
}

func (m *mockSDNService) SetBridgeProtocols(ctx context.Context, name string, protocols []string) error {
	if m.setProtocolsErr != nil {
		return m.setProtocolsErr
	}
	bridge, exists := m.bridges[name]
	if !exists {
		return ovs.ErrBridgeNotFound
	}
	bridge.FlowProtocols = protocols
	return nil
}

func (m *mockSDNService) AddPort(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
	if m.addPortErr != nil {
		return nil, m.addPortErr
	}
	if _, exists := m.bridges[bridgeName]; !exists {
		return nil, ovs.ErrBridgeNotFound
	}
	if _, exists := m.ports[portName]; exists {
		return nil, ovs.ErrPortExists
	}
	port := &ovs.Port{
		UUID:        "port-" + portName,
		Name:        portName,
		ExternalIDs: make(map[string]string),
		OtherConfig: make(map[string]string),
	}
	m.ports[portName] = port
	m.bridges[bridgeName].Ports = append(m.bridges[bridgeName].Ports, portName)
	return port, nil
}

func (m *mockSDNService) DeletePort(ctx context.Context, bridgeName, portName string) error {
	if m.deletePortErr != nil {
		return m.deletePortErr
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
	if m.getPortErr != nil {
		return nil, m.getPortErr
	}
	port, exists := m.ports[name]
	if !exists {
		return nil, ovs.ErrPortNotFound
	}
	return port, nil
}

func (m *mockSDNService) ListPorts(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
	if m.listPortsErr != nil {
		return nil, m.listPortsErr
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
	if m.setPortVLANErr != nil {
		return m.setPortVLANErr
	}
	port, exists := m.ports[portName]
	if !exists {
		return ovs.ErrPortNotFound
	}
	port.Tag = tag
	return nil
}

func (m *mockSDNService) SetPortTrunks(ctx context.Context, portName string, trunks []int64) error {
	if m.setPortTrunksErr != nil {
		return m.setPortTrunksErr
	}
	port, exists := m.ports[portName]
	if !exists {
		return ovs.ErrPortNotFound
	}
	port.Trunks = trunks
	return nil
}

func (m *mockSDNService) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	if m.addFlowErr != nil {
		return m.addFlowErr
	}
	if _, exists := m.bridges[bridgeName]; !exists {
		return ovs.ErrBridgeNotFound
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

func (m *mockSDNService) DeleteFlow(ctx context.Context, bridgeName string, match string) error {
	if m.deleteFlowErr != nil {
		return m.deleteFlowErr
	}
	if _, exists := m.bridges[bridgeName]; !exists {
		return ovs.ErrBridgeNotFound
	}
	return nil
}

func (m *mockSDNService) ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
	if m.listFlowsErr != nil {
		return nil, m.listFlowsErr
	}
	if _, exists := m.bridges[bridgeName]; !exists {
		return nil, ovs.ErrBridgeNotFound
	}
	flows := m.flows[bridgeName]
	if flows == nil {
		flows = []*ovs.Flow{}
	}
	return flows, nil
}

func (m *mockSDNService) DeleteAllFlows(ctx context.Context, bridgeName string) error {
	if m.deleteAllFlowsErr != nil {
		return m.deleteAllFlowsErr
	}
	if _, exists := m.bridges[bridgeName]; !exists {
		return ovs.ErrBridgeNotFound
	}
	m.flows[bridgeName] = []*ovs.Flow{}
	return nil
}

// Helper methods for test setup
func (m *mockSDNService) addTestBridge(name string) {
	m.bridges[name] = &ovs.Bridge{
		UUID:         "bridge-" + name,
		Name:         name,
		DatapathType: "system",
		Ports:        []string{},
		ExternalIDs:  make(map[string]string),
		OtherConfig:  make(map[string]string),
		Status:       map[string]string{"state": "up"},
	}
}

func (m *mockSDNService) addTestPort(bridgeName, portName string) {
	m.ports[portName] = &ovs.Port{
		UUID:        "port-" + portName,
		Name:        portName,
		ExternalIDs: make(map[string]string),
		OtherConfig: make(map[string]string),
	}
	if bridge, exists := m.bridges[bridgeName]; exists {
		bridge.Ports = append(bridge.Ports, portName)
	}
}

func (m *mockSDNService) addTestFlow(bridgeName string, flow *ovs.Flow) {
	m.flows[bridgeName] = append(m.flows[bridgeName], flow)
}

// =============================================================================
// Test Helpers
// =============================================================================

func setupSDNTestHandler(svc *mockSDNService) (*SDNHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewSDNHandlers(svc, logger)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

func decodeSDNResponse(t *testing.T, body *bytes.Buffer, v interface{}) {
	t.Helper()
	err := json.NewDecoder(body).Decode(v)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestSDNHandlerErrors(t *testing.T) {
	t.Run("ErrSDNServiceNotAvailable", func(t *testing.T) {
		err := ErrSDNServiceNotAvailable{}
		assert.Equal(t, "SDN service not available", err.Error())
	})

	t.Run("ErrInvalidBridgeID with empty ID", func(t *testing.T) {
		err := ErrInvalidBridgeID{}
		assert.Equal(t, "bridge ID is required", err.Error())
	})

	t.Run("ErrInvalidBridgeID with ID", func(t *testing.T) {
		err := ErrInvalidBridgeID{ID: "bad-id"}
		assert.Equal(t, "invalid bridge ID: bad-id", err.Error())
	})

	t.Run("ErrInvalidPortID with empty ID", func(t *testing.T) {
		err := ErrInvalidPortID{}
		assert.Equal(t, "port ID is required", err.Error())
	})

	t.Run("ErrInvalidPortID with ID", func(t *testing.T) {
		err := ErrInvalidPortID{ID: "bad-port"}
		assert.Equal(t, "invalid port ID: bad-port", err.Error())
	})

	t.Run("ErrInvalidFlowID with empty ID", func(t *testing.T) {
		err := ErrInvalidFlowID{}
		assert.Equal(t, "flow ID is required", err.Error())
	})

	t.Run("ErrInvalidFlowID with ID", func(t *testing.T) {
		err := ErrInvalidFlowID{ID: "bad-flow"}
		assert.Equal(t, "invalid flow ID: bad-flow", err.Error())
	})

	t.Run("ErrInvalidSDNPolicyID with empty ID", func(t *testing.T) {
		err := ErrInvalidSDNPolicyID{}
		assert.Equal(t, "policy ID is required", err.Error())
	})

	t.Run("ErrInvalidSDNPolicyID with ID", func(t *testing.T) {
		err := ErrInvalidSDNPolicyID{ID: "bad-policy"}
		assert.Equal(t, "invalid policy ID: bad-policy", err.Error())
	})

	t.Run("ErrSDNOperationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrSDNOperationFailed{Operation: "create_bridge", Cause: cause}
		assert.Equal(t, "SDN operation create_bridge failed: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrBridgeNotFound", func(t *testing.T) {
		err := ErrBridgeNotFound{ID: "br0"}
		assert.Equal(t, "bridge not found: br0", err.Error())
	})

	t.Run("ErrPortNotFound", func(t *testing.T) {
		err := ErrPortNotFound{ID: "eth0"}
		assert.Equal(t, "port not found: eth0", err.Error())
	})

	t.Run("ErrFlowNotFound", func(t *testing.T) {
		err := ErrFlowNotFound{ID: "flow-1"}
		assert.Equal(t, "flow not found: flow-1", err.Error())
	})

	t.Run("ErrSDNPolicyNotFound", func(t *testing.T) {
		err := ErrSDNPolicyNotFound{ID: "policy-1"}
		assert.Equal(t, "policy not found: policy-1", err.Error())
	})

	t.Run("ErrBridgeAlreadyExists", func(t *testing.T) {
		err := ErrBridgeAlreadyExists{Name: "br0"}
		assert.Equal(t, "bridge already exists: br0", err.Error())
	})

	t.Run("ErrPolicyAlreadyExists", func(t *testing.T) {
		err := ErrPolicyAlreadyExists{Name: "test-policy"}
		assert.Equal(t, "policy already exists: test-policy", err.Error())
	})
}

// =============================================================================
// Bridge Handler Tests
// =============================================================================

func TestCreateBridge(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		reqBody := CreateBridgeRequest{
			Name:     "br-test",
			FailMode: "secure",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp BridgeResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "br-test", resp.Name)
		assert.Equal(t, "secure", resp.FailMode)
	})

	t.Run("with protocols", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		reqBody := CreateBridgeRequest{
			Name:      "br-test",
			Protocols: []string{"OpenFlow10", "OpenFlow13"},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("missing name", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		reqBody := CreateBridgeRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid json", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := CreateBridgeRequest{Name: "br-test"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("bridge already exists", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		reqBody := CreateBridgeRequest{Name: "br-test"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusConflict, w.Code)
	})

	t.Run("create bridge error", func(t *testing.T) {
		svc := newMockSDNService()
		svc.createBridgeErr = errors.New("internal error")
		_, router := setupSDNTestHandler(svc)

		reqBody := CreateBridgeRequest{Name: "br-test"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestListBridges(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test1")
		svc.addTestBridge("br-test2")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp BridgeListResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, 2, resp.Count)
	})

	t.Run("empty list", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp BridgeListResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, 0, resp.Count)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("list bridges error", func(t *testing.T) {
		svc := newMockSDNService()
		svc.listBridgesErr = errors.New("internal error")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestGetBridge(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp BridgeResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "br-test", resp.Name)
	})

	t.Run("not found", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestDeleteBridge(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br-test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SDNActionResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "delete", resp.Action)
	})

	t.Run("not found", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br-test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// =============================================================================
// Port Handler Tests
// =============================================================================

func TestAddPort(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		reqBody := AddPortRequest{
			Name: "eth0",
			VLAN: 100,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/ports", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp PortResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "eth0", resp.Name)
	})

	t.Run("with trunk VLANs", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		reqBody := AddPortRequest{
			Name:   "eth0",
			Trunks: []int64{100, 200, 300},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/ports", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("missing name", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		reqBody := AddPortRequest{}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/ports", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bridge not found", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		reqBody := AddPortRequest{Name: "eth0"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/nonexistent/ports", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid json", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/ports", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := AddPortRequest{Name: "eth0"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/ports", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestListPorts(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		svc.addTestPort("br-test", "eth0")
		svc.addTestPort("br-test", "eth1")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test/ports", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PortListResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, 2, resp.Count)
	})

	t.Run("bridge not found", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/nonexistent/ports", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test/ports", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestRemovePort(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		svc.addTestPort("br-test", "eth0")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br-test/ports/eth0", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SDNActionResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "delete", resp.Action)
	})

	t.Run("port not found", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br-test/ports/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("bridge not found", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/nonexistent/ports/eth0", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br-test/ports/eth0", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// =============================================================================
// Flow Handler Tests
// =============================================================================

func TestAddFlow(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		reqBody := AddFlowRequest{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows?bridge_id=br-test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp FlowResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "br-test", resp.BridgeID)
		assert.Equal(t, 100, resp.Priority)
	})

	t.Run("missing bridge_id", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		reqBody := AddFlowRequest{
			Match:   "in_port=1",
			Actions: "output:2",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bridge not found", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		reqBody := AddFlowRequest{
			Match:   "in_port=1",
			Actions: "output:2",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows?bridge_id=nonexistent", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid json", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows?bridge_id=br-test", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := AddFlowRequest{
			Match:   "in_port=1",
			Actions: "output:2",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows?bridge_id=br-test", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestListFlows(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		svc.addTestFlow("br-test", &ovs.Flow{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
			Cookie:   "0x1",
		})
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/flows?bridge_id=br-test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp FlowListResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, 1, resp.Count)
	})

	t.Run("missing bridge_id", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/flows", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bridge not found", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/flows?bridge_id=nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/flows?bridge_id=br-test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestDeleteFlow(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/flows/flow-1?bridge_id=br-test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SDNActionResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "delete", resp.Action)
	})

	t.Run("missing bridge_id", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/flows/flow-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("bridge not found", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/flows/flow-1?bridge_id=nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/flows/flow-1?bridge_id=br-test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// =============================================================================
// Policy Handler Tests
// =============================================================================

func TestCreatePolicy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		reqBody := CreatePolicyRequest{
			Name:        "test-policy",
			Description: "Test network policy",
			Priority:    100,
			Rules: []PolicyRule{
				{
					Direction: "ingress",
					Protocol:  "tcp",
					PortRange: "80",
					Action:    "allow",
				},
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp PolicyResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "test-policy", resp.Name)
		assert.Equal(t, 100, resp.Priority)
		assert.Equal(t, "active", resp.Status)
	})

	t.Run("missing name", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		reqBody := CreatePolicyRequest{
			Description: "Test policy",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid json", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/policies", bytes.NewReader([]byte("invalid")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		reqBody := CreatePolicyRequest{Name: "test-policy"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/policies", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestListPolicies(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		handlers, router := setupSDNTestHandler(svc)

		// Add some policies directly
		now := time.Now().UTC()
		handlers.policies["policy-1"] = &PolicyResponse{
			ID:        "policy-1",
			Name:      "test-policy-1",
			Status:    "active",
			CreatedAt: now,
			UpdatedAt: now,
		}
		handlers.policies["policy-2"] = &PolicyResponse{
			ID:        "policy-2",
			Name:      "test-policy-2",
			Status:    "active",
			CreatedAt: now,
			UpdatedAt: now,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/policies", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SDNPolicyListResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, 2, resp.Count)
	})

	t.Run("empty list", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/policies", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SDNPolicyListResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, 0, resp.Count)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/policies", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestGetPolicy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		handlers, router := setupSDNTestHandler(svc)

		now := time.Now().UTC()
		handlers.policies["policy-1"] = &PolicyResponse{
			ID:        "policy-1",
			Name:      "test-policy",
			Status:    "active",
			CreatedAt: now,
			UpdatedAt: now,
		}

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/policies/policy-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp PolicyResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "test-policy", resp.Name)
	})

	t.Run("not found", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/policies/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/policies/policy-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestDeletePolicy(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		handlers, router := setupSDNTestHandler(svc)

		now := time.Now().UTC()
		handlers.policies["policy-1"] = &PolicyResponse{
			ID:        "policy-1",
			Name:      "test-policy",
			Status:    "active",
			CreatedAt: now,
			UpdatedAt: now,
		}

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/policies/policy-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SDNActionResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "delete", resp.Action)
	})

	t.Run("not found", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/policies/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/policies/policy-1", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// =============================================================================
// Topology Handler Tests
// =============================================================================

func TestGetTopology(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test1")
		svc.addTestBridge("br-test2")
		svc.addTestPort("br-test1", "eth0")
		svc.addTestPort("br-test1", "eth1")
		svc.addTestFlow("br-test1", &ovs.Flow{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
		})
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/topology", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TopologyResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, 2, resp.Statistics.TotalBridges)
	})

	t.Run("empty topology", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/topology", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp TopologyResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, 0, resp.Statistics.TotalBridges)
	})

	t.Run("service not available", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/topology", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("list bridges error", func(t *testing.T) {
		svc := newMockSDNService()
		svc.listBridgesErr = errors.New("internal error")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/topology", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestWriteSDNError(t *testing.T) {
	testCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"bridge not found", ovs.ErrBridgeNotFound, http.StatusNotFound},
		{"bridge exists", ovs.ErrBridgeExists, http.StatusConflict},
		{"port not found", ovs.ErrPortNotFound, http.StatusNotFound},
		{"port exists", ovs.ErrPortExists, http.StatusConflict},
		{"flow not found", ovs.ErrFlowNotFound, http.StatusNotFound},
		{"invalid flow", ovs.ErrInvalidFlow, http.StatusBadRequest},
		{"invalid bridge name", ovs.ErrInvalidBridgeName, http.StatusBadRequest},
		{"invalid port name", ovs.ErrInvalidPortName, http.StatusBadRequest},
		{"not connected", ovs.ErrNotConnected, http.StatusServiceUnavailable},
		{"connection failed", ovs.ErrConnectionFailed, http.StatusServiceUnavailable},
		{"operation timeout", ovs.ErrOperationTimeout, http.StatusGatewayTimeout},
		{"transaction failed", ovs.ErrTransactionFailed, http.StatusInternalServerError},
		{"unknown error", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newMockSDNService()
			handlers, _ := setupSDNTestHandler(svc)

			w := httptest.NewRecorder()
			handlers.writeSDNError(w, "test", tc.err)

			assert.Equal(t, tc.expectedStatus, w.Code)
		})
	}
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestNewSDNHandlers(t *testing.T) {
	t.Run("with logger", func(t *testing.T) {
		svc := newMockSDNService()
		logger := slog.Default()
		handlers := NewSDNHandlers(svc, logger)

		assert.NotNil(t, handlers)
		assert.NotNil(t, handlers.sdnService)
		assert.NotNil(t, handlers.logger)
		assert.NotNil(t, handlers.policies)
	})

	t.Run("without logger", func(t *testing.T) {
		svc := newMockSDNService()
		handlers := NewSDNHandlers(svc, nil)

		assert.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger)
	})

	t.Run("nil service", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, nil)

		assert.NotNil(t, handlers)
		assert.Nil(t, handlers.sdnService)
	})
}

func TestSetPolicyService(t *testing.T) {
	svc := newMockSDNService()
	handlers := NewSDNHandlers(svc, nil)

	assert.Nil(t, handlers.policyService)

	// Note: PolicyServiceInterface is defined but not implemented in mock
	handlers.SetPolicyService(nil)

	assert.Nil(t, handlers.policyService)
}

func TestSDNRegisterRoutes(t *testing.T) {
	svc := newMockSDNService()
	handlers := NewSDNHandlers(svc, nil)
	router := mux.NewRouter()

	handlers.RegisterRoutes(router)

	// Verify routes are registered by making requests
	testCases := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/sdn/bridges"},
		{http.MethodGet, "/api/v1/sdn/bridges"},
		{http.MethodGet, "/api/v1/sdn/bridges/br-test"},
		{http.MethodDelete, "/api/v1/sdn/bridges/br-test"},
		{http.MethodPost, "/api/v1/sdn/bridges/br-test/ports"},
		{http.MethodGet, "/api/v1/sdn/bridges/br-test/ports"},
		{http.MethodDelete, "/api/v1/sdn/bridges/br-test/ports/eth0"},
		{http.MethodPost, "/api/v1/sdn/flows"},
		{http.MethodGet, "/api/v1/sdn/flows"},
		{http.MethodDelete, "/api/v1/sdn/flows/flow-1"},
		{http.MethodPost, "/api/v1/sdn/policies"},
		{http.MethodGet, "/api/v1/sdn/policies"},
		{http.MethodGet, "/api/v1/sdn/policies/policy-1"},
		{http.MethodDelete, "/api/v1/sdn/policies/policy-1"},
		{http.MethodGet, "/api/v1/sdn/topology"},
	}

	for _, tc := range testCases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			match := &mux.RouteMatch{}
			req := httptest.NewRequest(tc.method, tc.path, nil)
			assert.True(t, router.Match(req, match), "Route should be registered: %s %s", tc.method, tc.path)
		})
	}
}

// =============================================================================
// Conversion Helper Tests
// =============================================================================

func TestOVSBridgeToResponse(t *testing.T) {
	svc := newMockSDNService()
	handlers := NewSDNHandlers(svc, nil)

	bridge := &ovs.Bridge{
		UUID:          "test-uuid",
		Name:          "br-test",
		DatapathType:  "system",
		FailMode:      "secure",
		FlowProtocols: []string{"OpenFlow13"},
		STP:           true,
		Ports:         []string{"eth0", "eth1"},
		ExternalIDs:   map[string]string{"key": "value"},
		OtherConfig:   map[string]string{"cfg": "val"},
		Status:        map[string]string{"state": "up"},
	}

	resp := handlers.ovsBridgeToResponse(bridge)

	assert.Equal(t, "test-uuid", resp.ID)
	assert.Equal(t, "br-test", resp.Name)
	assert.Equal(t, "system", resp.DatapathType)
	assert.Equal(t, "secure", resp.FailMode)
	assert.Equal(t, []string{"OpenFlow13"}, resp.Protocols)
	assert.True(t, resp.STP)
	assert.Equal(t, []string{"eth0", "eth1"}, resp.Ports)
	assert.Equal(t, "up", resp.Status)
}

func TestOVSBridgeToResponseWithoutStatus(t *testing.T) {
	svc := newMockSDNService()
	handlers := NewSDNHandlers(svc, nil)

	bridge := &ovs.Bridge{
		UUID: "test-uuid",
		Name: "br-test",
	}

	resp := handlers.ovsBridgeToResponse(bridge)

	assert.Equal(t, "up", resp.Status)
}

func TestOVSPortToResponse(t *testing.T) {
	svc := newMockSDNService()
	handlers := NewSDNHandlers(svc, nil)

	port := &ovs.Port{
		UUID:        "port-uuid",
		Name:        "eth0",
		Tag:         100,
		Trunks:      []int64{200, 300},
		MAC:         "00:11:22:33:44:55",
		ExternalIDs: map[string]string{"key": "value"},
		OtherConfig: map[string]string{"cfg": "val"},
	}

	resp := handlers.ovsPortToResponse(port, "bridge-uuid")

	assert.Equal(t, "port-uuid", resp.ID)
	assert.Equal(t, "eth0", resp.Name)
	assert.Equal(t, "bridge-uuid", resp.BridgeID)
	assert.Equal(t, int64(100), resp.VLAN)
	assert.Equal(t, []int64{200, 300}, resp.Trunks)
	assert.Equal(t, "00:11:22:33:44:55", resp.MACAddress)
	assert.Equal(t, "up", resp.Status)
}

func TestOVSFlowToResponse(t *testing.T) {
	svc := newMockSDNService()
	handlers := NewSDNHandlers(svc, nil)

	flow := &ovs.Flow{
		Table:       0,
		Priority:    100,
		Match:       "in_port=1",
		Actions:     "output:2",
		Cookie:      "0x1",
		PacketCount: 1000,
		ByteCount:   64000,
		Duration:    3600,
	}

	resp := handlers.ovsFlowToResponse(flow, "bridge-uuid")

	assert.Equal(t, "0x1", resp.ID)
	assert.Equal(t, "bridge-uuid", resp.BridgeID)
	assert.Equal(t, 0, resp.Table)
	assert.Equal(t, 100, resp.Priority)
	assert.Equal(t, "in_port=1", resp.Match)
	assert.Equal(t, "output:2", resp.Actions)
	assert.Equal(t, int64(1000), resp.PacketCount)
	assert.Equal(t, int64(64000), resp.ByteCount)
	assert.Equal(t, 3600, resp.Duration)
}

// =============================================================================
// Policy Already Exists Test
// =============================================================================

func TestCreatePolicyAlreadyExists(t *testing.T) {
	svc := newMockSDNService()
	handlers, router := setupSDNTestHandler(svc)

	// Add existing policy
	now := time.Now().UTC()
	handlers.policies["existing-policy"] = &PolicyResponse{
		ID:        "existing-policy",
		Name:      "test-policy",
		Status:    "active",
		CreatedAt: now,
		UpdatedAt: now,
	}

	// Try to create policy with same name
	reqBody := CreatePolicyRequest{
		Name: "test-policy",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/policies", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// =============================================================================
// Additional Error Path Tests
// =============================================================================

func TestBridgeFailModeError(t *testing.T) {
	svc := newMockSDNService()
	svc.setFailModeErr = errors.New("fail mode error")
	_, router := setupSDNTestHandler(svc)

	reqBody := CreateBridgeRequest{
		Name:     "br-test",
		FailMode: "secure",
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should still succeed, fail mode is optional
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestBridgeProtocolsError(t *testing.T) {
	svc := newMockSDNService()
	svc.setProtocolsErr = errors.New("protocols error")
	_, router := setupSDNTestHandler(svc)

	reqBody := CreateBridgeRequest{
		Name:      "br-test",
		Protocols: []string{"OpenFlow13"},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should still succeed, protocols are optional
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestPortVLANError(t *testing.T) {
	svc := newMockSDNService()
	svc.addTestBridge("br-test")
	svc.setPortVLANErr = errors.New("vlan error")
	_, router := setupSDNTestHandler(svc)

	reqBody := AddPortRequest{
		Name: "eth0",
		VLAN: 100,
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/ports", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should still succeed, VLAN setting is optional
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestPortTrunksError(t *testing.T) {
	svc := newMockSDNService()
	svc.addTestBridge("br-test")
	svc.setPortTrunksErr = errors.New("trunks error")
	_, router := setupSDNTestHandler(svc)

	reqBody := AddPortRequest{
		Name:   "eth0",
		Trunks: []int64{100, 200},
	}
	body, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/ports", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should still succeed, trunks setting is optional
	assert.Equal(t, http.StatusCreated, w.Code)
}

// =============================================================================
// Port State Tests
// =============================================================================

func TestGetPortState(t *testing.T) {
	t.Run("returns port state", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		svc.addTestPort("br-test", "eth0")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test/ports/eth0/state", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "br-test", resp["bridge_id"])
		assert.Equal(t, "up", resp["admin_state"])
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test/ports/eth0/state", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns error when GetPort fails", func(t *testing.T) {
		svc := newMockSDNService()
		svc.getPortErr = errors.New("port not found")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test/ports/missing/state", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.NotEqual(t, http.StatusOK, w.Code)
	})
}

func TestSetPortState(t *testing.T) {
	t.Run("sets port state", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		body, _ := json.Marshal(map[string]string{"admin_state": "down"})
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/bridges/br-test/ports/eth0/state", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "down", resp["admin_state"])
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		body, _ := json.Marshal(map[string]string{"admin_state": "up"})
		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/bridges/br-test/ports/eth0/state", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/bridges/br-test/ports/eth0/state", bytes.NewReader([]byte("bad")))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestGetPortStats(t *testing.T) {
	t.Run("returns port stats", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test/ports/eth0/stats", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp map[string]interface{}
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "br-test", resp["bridge_id"])
		assert.Equal(t, "eth0", resp["port_id"])
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test/ports/eth0/stats", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// =============================================================================
// Per-Bridge Flow Tests
// =============================================================================

func TestAddFlowForBridge(t *testing.T) {
	t.Run("adds flow for bridge", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		body, _ := json.Marshal(AddFlowRequest{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/flows", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		body, _ := json.Marshal(AddFlowRequest{Match: "in_port=1", Actions: "drop"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/flows", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/flows", bytes.NewReader([]byte("bad")))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error when AddFlow fails", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addFlowErr = errors.New("flow error")
		_, router := setupSDNTestHandler(svc)

		body, _ := json.Marshal(AddFlowRequest{Match: "in_port=1", Actions: "drop"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br-test/flows", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.NotEqual(t, http.StatusCreated, w.Code)
	})
}

func TestListFlowsForBridge(t *testing.T) {
	t.Run("lists flows for bridge", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		svc.addTestFlow("br-test", &ovs.Flow{
			Table:    0,
			Priority: 100,
			Match:    "in_port=1",
			Actions:  "output:2",
		})
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test/flows", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test/flows", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns error when ListFlows fails", func(t *testing.T) {
		svc := newMockSDNService()
		svc.listFlowsErr = errors.New("list error")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br-test/flows", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.NotEqual(t, http.StatusOK, w.Code)
	})
}

func TestDeleteFlowForBridge(t *testing.T) {
	t.Run("deletes flow for bridge", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		svc.addTestFlow("br-test", &ovs.Flow{Match: "in_port=1"})
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br-test/flows/in_port=1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br-test/flows/flow-1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns error when DeleteFlow fails", func(t *testing.T) {
		svc := newMockSDNService()
		svc.deleteFlowErr = errors.New("delete error")
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br-test/flows/flow-1", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.NotEqual(t, http.StatusOK, w.Code)
	})
}

// =============================================================================
// VLAN Handler Tests
// =============================================================================

func TestCreateVLAN(t *testing.T) {
	t.Run("creates VLAN", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		body, _ := json.Marshal(map[string]interface{}{
			"vlan_id":     100,
			"name":        "test-vlan",
			"description": "Test VLAN",
			"bridge_ids":  []string{"br-test"},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/vlans", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		body, _ := json.Marshal(map[string]interface{}{"vlan_id": 100})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/vlans", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns error for invalid body", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/vlans", bytes.NewReader([]byte("bad")))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestListVLANs(t *testing.T) {
	t.Run("lists VLANs", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/vlans", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/vlans", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestDeleteVLAN(t *testing.T) {
	t.Run("deletes VLAN", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/vlans/100", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("returns service unavailable when service not set", func(t *testing.T) {
		handlers := NewSDNHandlers(nil, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/vlans/100", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("returns error for invalid VLAN ID", func(t *testing.T) {
		svc := newMockSDNService()
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/vlans/abc", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}
