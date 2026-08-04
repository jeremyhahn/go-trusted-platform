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

package switchapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"log/slog"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// mockSwitchService implements device.SwitchServiceProvider for testing.
type mockSwitchService struct {
	managers map[string]switchmgmt.Manager
}

func (m *mockSwitchService) Manager(name string) (switchmgmt.Manager, error) {
	mgr, ok := m.managers[name]
	if !ok {
		return nil, switchmgmt.ErrManagerNotFound{Name: name}
	}
	return mgr, nil
}

// mockManager implements switchmgmt.Manager for testing.
type mockManager struct {
	listPortsFunc     func(ctx context.Context) ([]*switchmgmt.PortStatus, error)
	getPortStatusFunc func(ctx context.Context, port string) (*switchmgmt.PortStatus, error)
	setPortVLANFunc   func(ctx context.Context, port string, vlanID uint16) error
	enablePortFunc    func(ctx context.Context, port string) error
	disablePortFunc   func(ctx context.Context, port string) error
	getPortVLANFunc   func(ctx context.Context, port string) (uint16, error)
}

func (m *mockManager) ListPorts(ctx context.Context) ([]*switchmgmt.PortStatus, error) {
	if m.listPortsFunc != nil {
		return m.listPortsFunc(ctx)
	}
	return nil, nil
}

func (m *mockManager) GetPortStatus(ctx context.Context, port string) (*switchmgmt.PortStatus, error) {
	if m.getPortStatusFunc != nil {
		return m.getPortStatusFunc(ctx, port)
	}
	return nil, nil
}

func (m *mockManager) SetPortVLAN(ctx context.Context, port string, vlanID uint16) error {
	if m.setPortVLANFunc != nil {
		return m.setPortVLANFunc(ctx, port, vlanID)
	}
	return nil
}

func (m *mockManager) GetPortVLAN(ctx context.Context, port string) (uint16, error) {
	if m.getPortVLANFunc != nil {
		return m.getPortVLANFunc(ctx, port)
	}
	return 0, nil
}

func (m *mockManager) EnablePort(ctx context.Context, port string) error {
	if m.enablePortFunc != nil {
		return m.enablePortFunc(ctx, port)
	}
	return nil
}

func (m *mockManager) DisablePort(ctx context.Context, port string) error {
	if m.disablePortFunc != nil {
		return m.disablePortFunc(ctx, port)
	}
	return nil
}

func (m *mockManager) Close() error {
	return nil
}

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, nil)
}

func newTestResponseWriter() response.HttpWriter {
	return response.NewResponseWriter(newTestLogger(), nil)
}

func newTestHandlers(svc *mockSwitchService) *Handlers {
	return NewHandlers(newTestLogger(), newTestResponseWriter(), svc)
}

func newTestRouter(handlers *Handlers) *mux.Router {
	r := mux.NewRouter()
	r.UseEncodedPath()
	r.HandleFunc("/api/v1/switches/{switch}/ports", handlers.ListPorts).Methods("GET")
	r.HandleFunc("/api/v1/switches/{switch}/ports/{port}", handlers.GetPortStatus).Methods("GET")
	r.HandleFunc("/api/v1/switches/{switch}/ports/{port}/vlan", handlers.SetPortVLAN).Methods("POST")
	r.HandleFunc("/api/v1/switches/{switch}/ports/{port}/enable", handlers.EnablePort).Methods("POST")
	r.HandleFunc("/api/v1/switches/{switch}/ports/{port}/disable", handlers.DisablePort).Methods("POST")
	return r
}

func TestListPorts_Success(t *testing.T) {
	mgr := &mockManager{
		listPortsFunc: func(ctx context.Context) ([]*switchmgmt.PortStatus, error) {
			return []*switchmgmt.PortStatus{
				{Port: "Eth1/1", Mode: switchmgmt.PortModeAccess, AccessVLAN: 100, Enabled: true, LinkUp: true},
				{Port: "Eth1/2", Mode: switchmgmt.PortModeTrunk, TrunkVLANs: []uint16{100, 200}, Enabled: true, LinkUp: false},
			}, nil
		},
	}

	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": mgr}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/switches/core-01/ports", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	var resp response.WebServiceResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
}

func TestListPorts_SwitchNotFound(t *testing.T) {
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/switches/nonexistent/ports", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestListPorts_ManagerError(t *testing.T) {
	mgr := &mockManager{
		listPortsFunc: func(ctx context.Context) ([]*switchmgmt.PortStatus, error) {
			return nil, switchmgmt.ErrSSHCommandFailed{Command: "show interface brief", Output: "timeout"}
		},
	}

	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": mgr}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/switches/core-01/ports", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestGetPortStatus_Success(t *testing.T) {
	mgr := &mockManager{
		getPortStatusFunc: func(ctx context.Context, port string) (*switchmgmt.PortStatus, error) {
			return &switchmgmt.PortStatus{
				Port:        "Eth1/3",
				Mode:        switchmgmt.PortModeAccess,
				AccessVLAN:  200,
				Enabled:     true,
				LinkUp:      true,
				Description: "server-01",
			}, nil
		},
	}

	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": mgr}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/switches/core-01/ports/Eth1%2F3", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
}

func TestGetPortStatus_PortNotFound(t *testing.T) {
	mgr := &mockManager{
		getPortStatusFunc: func(ctx context.Context, port string) (*switchmgmt.PortStatus, error) {
			return nil, switchmgmt.ErrPortNotFound{Port: port}
		},
	}

	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": mgr}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/switches/core-01/ports/Eth99%2F99", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestSetPortVLAN_Success(t *testing.T) {
	var capturedPort string
	var capturedVLAN uint16

	mgr := &mockManager{
		setPortVLANFunc: func(ctx context.Context, port string, vlanID uint16) error {
			capturedPort = port
			capturedVLAN = vlanID
			return nil
		},
	}

	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": mgr}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	body, _ := json.Marshal(setVLANRequest{VLANID: 200})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F3/vlan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Eth1/3", capturedPort)
	assert.Equal(t, uint16(200), capturedVLAN)
}

func TestSetPortVLAN_MissingVLANID(t *testing.T) {
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": &mockManager{}}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	body, _ := json.Marshal(setVLANRequest{VLANID: 0})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F3/vlan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSetPortVLAN_InvalidVLANID(t *testing.T) {
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": &mockManager{}}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	body, _ := json.Marshal(setVLANRequest{VLANID: 5000})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F3/vlan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSetPortVLAN_InvalidBody(t *testing.T) {
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": &mockManager{}}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F3/vlan",
		bytes.NewReader([]byte("invalid json")))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestSetPortVLAN_SwitchNotFound(t *testing.T) {
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	body, _ := json.Marshal(setVLANRequest{VLANID: 200})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/nonexistent/ports/Eth1%2F3/vlan", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestEnablePort_Success(t *testing.T) {
	var capturedPort string
	mgr := &mockManager{
		enablePortFunc: func(ctx context.Context, port string) error {
			capturedPort = port
			return nil
		},
	}

	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": mgr}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F3/enable", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Eth1/3", capturedPort)
}

func TestEnablePort_SwitchNotFound(t *testing.T) {
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/nonexistent/ports/Eth1%2F3/enable", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestEnablePort_OperationFails(t *testing.T) {
	mgr := &mockManager{
		enablePortFunc: func(ctx context.Context, port string) error {
			return switchmgmt.ErrSSHCommandFailed{Command: "no shutdown", Output: "error"}
		},
	}

	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": mgr}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F3/enable", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

func TestDisablePort_Success(t *testing.T) {
	var capturedPort string
	mgr := &mockManager{
		disablePortFunc: func(ctx context.Context, port string) error {
			capturedPort = port
			return nil
		},
	}

	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": mgr}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F3/disable", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Eth1/3", capturedPort)
}

func TestDisablePort_SwitchNotFound(t *testing.T) {
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/nonexistent/ports/Eth1%2F3/disable", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestDisablePort_OperationFails(t *testing.T) {
	mgr := &mockManager{
		disablePortFunc: func(ctx context.Context, port string) error {
			return switchmgmt.ErrSSHCommandFailed{Command: "shutdown", Output: "error"}
		},
	}

	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{"core-01": mgr}}
	handlers := newTestHandlers(svc)
	router := newTestRouter(handlers)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/switches/core-01/ports/Eth1%2F3/disable", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}
