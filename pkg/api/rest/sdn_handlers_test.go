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

	// deletedCookies records every cookie DeleteFlowsByCookie removed.
	deletedCookies []uint64

	// createBridgeOpts records the options of every CreateBridgeWithOptions
	// call that passed validation.
	createBridgeOpts []*ovs.BridgeOptions

	createBridgeErr error
	deleteBridgeErr error
	getBridgeErr    error
	listBridgesErr  error

	addPortErr       error
	deletePortErr    error
	getPortErr       error
	listPortsErr     error
	setPortVLANErr   error
	setPortTrunksErr error
	setPortStateErr  error
	getInterfaceErr  error
	setPolicingErr   error
	setShapingErr    error

	// policing records every SetIngressPolicing call, keyed by port name,
	// as {rateBps, burstBits}.
	policing map[string][2]uint64
	// shaping records every SetEgressShaping call the same way.
	shaping map[string][2]uint64

	// interfaces holds the Open vSwitch interface rows GetInterface reads.
	interfaces map[string]*ovs.Interface
	// portStates records every SetPortState call, keyed by port name.
	portStates map[string]ovs.PortState

	addFlowErr        error
	deleteFlowErr     error
	listFlowsErr      error
	deleteAllFlowsErr error
}

func newMockSDNService() *mockSDNService {
	return &mockSDNService{
		bridges:    make(map[string]*ovs.Bridge),
		ports:      make(map[string]*ovs.Port),
		flows:      make(map[string][]*ovs.Flow),
		interfaces: make(map[string]*ovs.Interface),
		portStates: make(map[string]ovs.PortState),
		policing:   make(map[string][2]uint64),
		shaping:    make(map[string][2]uint64),
	}
}

// CreateBridgeWithOptions validates the options as the OVS client does and
// records them on the bridge row it creates.
func (m *mockSDNService) CreateBridgeWithOptions(ctx context.Context, name string, opts *ovs.BridgeOptions) (*ovs.Bridge, error) {
	if m.createBridgeErr != nil {
		return nil, m.createBridgeErr
	}
	var failMode string
	var protocols []string
	if opts != nil {
		failMode, protocols = opts.FailMode, opts.Protocols
	}
	if failMode != "" && failMode != "secure" && failMode != "standalone" {
		return nil, &ovs.ErrInvalidFailMode{FailMode: failMode}
	}
	validProtocols := map[string]bool{
		"OpenFlow10": true, "OpenFlow11": true, "OpenFlow12": true,
		"OpenFlow13": true, "OpenFlow14": true, "OpenFlow15": true,
	}
	for _, p := range protocols {
		if !validProtocols[p] {
			return nil, ovs.ErrInvalidProtocol
		}
	}
	m.createBridgeOpts = append(m.createBridgeOpts, opts)
	if _, exists := m.bridges[name]; exists {
		return nil, ovs.ErrBridgeExists
	}
	bridge := &ovs.Bridge{
		UUID:          "bridge-" + name,
		Name:          name,
		DatapathType:  "system",
		Ports:         []string{},
		ExternalIDs:   make(map[string]string),
		OtherConfig:   make(map[string]string),
		Status:        map[string]string{"state": "up"},
		FailMode:      failMode,
		FlowProtocols: protocols,
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

func (m *mockSDNService) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	m.portStates[portName] = state
	if m.setPortStateErr != nil {
		return m.setPortStateErr
	}
	iface, exists := m.interfaces[portName]
	if !exists {
		return ovs.ErrPortNotFound
	}
	iface.AdminState = string(state)
	return nil
}

func (m *mockSDNService) SetIngressPolicing(ctx context.Context, name string, rateBps, burstBits uint64) error {
	m.policing[name] = [2]uint64{rateBps, burstBits}
	return m.setPolicingErr
}

func (m *mockSDNService) SetEgressShaping(ctx context.Context, name string, rateBps, burstBits uint64) error {
	m.shaping[name] = [2]uint64{rateBps, burstBits}
	return m.setShapingErr
}

func (m *mockSDNService) GetInterface(ctx context.Context, name string) (*ovs.Interface, error) {
	if m.getInterfaceErr != nil {
		return nil, m.getInterfaceErr
	}
	iface, exists := m.interfaces[name]
	if !exists {
		return nil, ovs.ErrPortNotFound
	}
	return iface, nil
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

func (m *mockSDNService) DeleteFlowsByCookie(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error {
	if m.deleteFlowErr != nil {
		return m.deleteFlowErr
	}
	if _, exists := m.bridges[bridgeName]; !exists {
		return ovs.ErrBridgeNotFound
	}
	m.deletedCookies = append(m.deletedCookies, cookie)
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

	t.Run("ErrBridgeAlreadyExists", func(t *testing.T) {
		err := ErrBridgeAlreadyExists{Name: "br0"}
		assert.Equal(t, "bridge already exists: br0", err.Error())
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
		// The fail mode rides the create transaction itself.
		require.Len(t, svc.createBridgeOpts, 1)
		assert.Equal(t, "secure", svc.createBridgeOpts[0].FailMode)
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
		require.Len(t, svc.createBridgeOpts, 1)
		assert.Equal(t, []string{"OpenFlow10", "OpenFlow13"}, svc.createBridgeOpts[0].Protocols)
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

		// The ID is the cookie the flow was installed with, so a delete
		// or a listing names this flow and no other.
		require.Len(t, svc.flows["br-test"], 1)
		installed := svc.flows["br-test"][0].Cookie
		assert.Equal(t, "flow-"+installed, resp.ID)
		cookie, err := ovs.ParseFlowID(resp.ID)
		require.NoError(t, err)
		assert.Equal(t, ovs.APIFlowCookieOwner, cookie&(0xFFFF<<48))
	})

	t.Run("a requested cookie is the identity", func(t *testing.T) {
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		body, _ := json.Marshal(AddFlowRequest{Priority: 1, Actions: "drop", Cookie: "0x42"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows?bridge_id=br-test", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)
		var resp FlowResponse
		decodeSDNResponse(t, w.Body, &resp)
		assert.Equal(t, "flow-0x42", resp.ID)

		body, _ = json.Marshal(AddFlowRequest{Priority: 1, Actions: "drop", Cookie: "not-a-cookie"})
		req = httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows?bridge_id=br-test", bytes.NewReader(body))
		w = httptest.NewRecorder()
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code, "a cookie that does not parse is refused, not installed as 0")
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

	assert.Equal(t, "flow-0x1", resp.ID, "a listed flow's ID is its cookie, as add returns it")
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

// =============================================================================
// Additional Error Path Tests
// =============================================================================

func TestBridgeFailModeError(t *testing.T) {
	svc := newMockSDNService()
	_, router := setupSDNTestHandler(svc)

	body, err := json.Marshal(CreateBridgeRequest{Name: "br-test", FailMode: "bogus"})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// An invalid fail mode refuses the whole create: no bridge is left
	// behind in standalone mode.
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotContains(t, svc.bridges, "br-test")
}

func TestBridgeProtocolsError(t *testing.T) {
	svc := newMockSDNService()
	_, router := setupSDNTestHandler(svc)

	body, err := json.Marshal(CreateBridgeRequest{Name: "br-test", Protocols: []string{"OpenFlow99"}})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.NotContains(t, svc.bridges, "br-test")
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
		svc.addTestFlow("br-test", &ovs.Flow{Match: "in_port=1", Cookie: "0xa9f1000000000007"})
		_, router := setupSDNTestHandler(svc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br-test/flows/flow-0xa9f1000000000007", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, []uint64{0xa9f1000000000007}, svc.deletedCookies, "the delete is by the flow's own cookie")
	})

	t.Run("refuses an ID that names no flow", func(t *testing.T) {
		// "in_port=1" used to reach OVS as a match, and the encoder's
		// skipping turned less specific strings into "every flow" (#614).
		svc := newMockSDNService()
		svc.addTestBridge("br-test")
		_, router := setupSDNTestHandler(svc)

		for _, id := range []string{"in_port=1", "flow-0", "flow-to-delete"} {
			req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br-test/flows/"+id, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code, "id %q", id)
		}
		assert.Empty(t, svc.deletedCookies)
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
