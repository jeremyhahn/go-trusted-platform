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

package sdn

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	restapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// mockSDNService implements platformv1.SDNServiceServer for testing
type mockSDNService struct {
	platformv1.UnimplementedSDNServiceServer

	createBridgeFunc     func(ctx context.Context, req *platformv1.CreateBridgeRequest) (*platformv1.CreateBridgeResponse, error)
	deleteBridgeFunc     func(ctx context.Context, req *platformv1.DeleteBridgeRequest) (*platformv1.DeleteBridgeResponse, error)
	getBridgeFunc        func(ctx context.Context, req *platformv1.GetBridgeRequest) (*platformv1.GetBridgeResponse, error)
	listBridgesFunc      func(ctx context.Context, req *platformv1.ListBridgesRequest) (*platformv1.ListBridgesResponse, error)
	addPortFunc          func(ctx context.Context, req *platformv1.AddPortRequest) (*platformv1.AddPortResponse, error)
	deletePortFunc       func(ctx context.Context, req *platformv1.DeletePortRequest) (*platformv1.DeletePortResponse, error)
	getPortFunc          func(ctx context.Context, req *platformv1.GetPortRequest) (*platformv1.GetPortResponse, error)
	setPortStateFunc     func(ctx context.Context, req *platformv1.SetPortStateRequest) (*platformv1.SetPortStateResponse, error)
	addFlowFunc          func(ctx context.Context, req *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error)
	deleteFlowFunc       func(ctx context.Context, req *platformv1.DeleteFlowRequest) (*platformv1.DeleteFlowResponse, error)
	listFlowsFunc        func(ctx context.Context, req *platformv1.ListFlowsRequest) (*platformv1.ListFlowsResponse, error)
	createVLANFunc       func(ctx context.Context, req *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error)
	listVLANsFunc        func(ctx context.Context, req *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error)
	getPortStatsFunc     func(ctx context.Context, req *platformv1.GetPortStatsRequest) (*platformv1.GetPortStatsResponse, error)
	applyPolicyFunc      func(ctx context.Context, req *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error)
	authenticatePortFunc func(ctx context.Context, req *platformv1.AuthenticatePortRequest) (*platformv1.AuthenticatePortResponse, error)
	revokePortAuthFunc   func(ctx context.Context, req *platformv1.RevokePortAuthRequest) (*platformv1.RevokePortAuthResponse, error)
}

func (m *mockSDNService) CreateBridge(ctx context.Context, req *platformv1.CreateBridgeRequest) (*platformv1.CreateBridgeResponse, error) {
	if m.createBridgeFunc != nil {
		return m.createBridgeFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) DeleteBridge(ctx context.Context, req *platformv1.DeleteBridgeRequest) (*platformv1.DeleteBridgeResponse, error) {
	if m.deleteBridgeFunc != nil {
		return m.deleteBridgeFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) GetBridge(ctx context.Context, req *platformv1.GetBridgeRequest) (*platformv1.GetBridgeResponse, error) {
	if m.getBridgeFunc != nil {
		return m.getBridgeFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) ListBridges(ctx context.Context, req *platformv1.ListBridgesRequest) (*platformv1.ListBridgesResponse, error) {
	if m.listBridgesFunc != nil {
		return m.listBridgesFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) AddPort(ctx context.Context, req *platformv1.AddPortRequest) (*platformv1.AddPortResponse, error) {
	if m.addPortFunc != nil {
		return m.addPortFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) DeletePort(ctx context.Context, req *platformv1.DeletePortRequest) (*platformv1.DeletePortResponse, error) {
	if m.deletePortFunc != nil {
		return m.deletePortFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) AuthenticatePort(ctx context.Context, req *platformv1.AuthenticatePortRequest) (*platformv1.AuthenticatePortResponse, error) {
	if m.authenticatePortFunc != nil {
		return m.authenticatePortFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) RevokePortAuth(ctx context.Context, req *platformv1.RevokePortAuthRequest) (*platformv1.RevokePortAuthResponse, error) {
	if m.revokePortAuthFunc != nil {
		return m.revokePortAuthFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) GetPort(ctx context.Context, req *platformv1.GetPortRequest) (*platformv1.GetPortResponse, error) {
	if m.getPortFunc != nil {
		return m.getPortFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) SetPortState(ctx context.Context, req *platformv1.SetPortStateRequest) (*platformv1.SetPortStateResponse, error) {
	if m.setPortStateFunc != nil {
		return m.setPortStateFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) AddFlow(ctx context.Context, req *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error) {
	if m.addFlowFunc != nil {
		return m.addFlowFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) DeleteFlow(ctx context.Context, req *platformv1.DeleteFlowRequest) (*platformv1.DeleteFlowResponse, error) {
	if m.deleteFlowFunc != nil {
		return m.deleteFlowFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) ListFlows(ctx context.Context, req *platformv1.ListFlowsRequest) (*platformv1.ListFlowsResponse, error) {
	if m.listFlowsFunc != nil {
		return m.listFlowsFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) CreateVLAN(ctx context.Context, req *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error) {
	if m.createVLANFunc != nil {
		return m.createVLANFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) ListVLANs(ctx context.Context, req *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error) {
	if m.listVLANsFunc != nil {
		return m.listVLANsFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) GetPortStats(ctx context.Context, req *platformv1.GetPortStatsRequest) (*platformv1.GetPortStatsResponse, error) {
	if m.getPortStatsFunc != nil {
		return m.getPortStatsFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockSDNService) ApplyPolicy(ctx context.Context, req *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
	if m.applyPolicyFunc != nil {
		return m.applyPolicyFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

// mockResponseWriter implements response.HttpWriter for testing
type mockResponseWriter struct {
	lastStatus  int
	lastPayload interface{}
	lastError   error
}

func (m *mockResponseWriter) Write(w http.ResponseWriter, r *http.Request, status int, resp interface{}) {
	m.lastStatus = status
	jsonResp, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(jsonResp)
}

func (m *mockResponseWriter) WriteYaml(w http.ResponseWriter, status int, resp interface{}) {
	m.lastStatus = status
}

func (m *mockResponseWriter) WriteJson(w http.ResponseWriter, status int, resp interface{}) {
	m.lastStatus = status
	jsonResp, _ := json.Marshal(resp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(jsonResp)
}

func (m *mockResponseWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusOK
	m.lastPayload = payload
	resp := restwire.WebServiceResponse{Code: http.StatusOK, Success: true, Payload: payload}
	m.Write(w, r, http.StatusOK, resp)
}

func (m *mockResponseWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusCreated
	m.lastPayload = payload
	resp := restwire.WebServiceResponse{Code: http.StatusCreated, Success: true, Payload: payload}
	m.Write(w, r, http.StatusCreated, resp)
}

func (m *mockResponseWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastPayload = payload
	m.lastError = err
}

func (m *mockResponseWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusOK
	m.lastError = err
}

func (m *mockResponseWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusUnauthorized
	m.lastError = err
	resp := restwire.WebServiceResponse{Code: http.StatusUnauthorized, Success: false, Error: err.Error()}
	m.Write(w, r, http.StatusUnauthorized, resp)
}

func (m *mockResponseWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusBadRequest
	m.lastError = err
	resp := restwire.WebServiceResponse{Code: http.StatusBadRequest, Success: false, Error: err.Error()}
	m.Write(w, r, http.StatusBadRequest, resp)
}

func (m *mockResponseWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastError = err
	resp := restwire.WebServiceResponse{Code: http.StatusNotFound, Success: false, Error: err.Error()}
	m.Write(w, r, http.StatusNotFound, resp)
}

func (m *mockResponseWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.lastStatus = http.StatusForbidden
	m.lastError = err
	m.lastPayload = payload
}

func (m *mockResponseWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusInternalServerError
	m.lastError = err
	resp := restwire.WebServiceResponse{Code: http.StatusInternalServerError, Success: false, Error: err.Error()}
	m.Write(w, r, http.StatusInternalServerError, resp)
}

func (m *mockResponseWriter) Error503(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusServiceUnavailable
	m.lastError = err
	resp := restwire.WebServiceResponse{Code: http.StatusServiceUnavailable, Success: false, Error: err.Error()}
	m.Write(w, r, http.StatusServiceUnavailable, resp)
}

func createTestHandlers(mock *mockSDNService) (*SDNHandlers, *mockResponseWriter) {
	logger := logging.NewLogger(slog.LevelInfo, nil)
	respWriter := &mockResponseWriter{}
	handlers := NewSDNHandlers(logger, mock, respWriter)
	return handlers, respWriter
}

// Bridge Handler Tests

func TestCreateBridge_Success(t *testing.T) {
	mock := &mockSDNService{
		createBridgeFunc: func(ctx context.Context, req *platformv1.CreateBridgeRequest) (*platformv1.CreateBridgeResponse, error) {
			return &platformv1.CreateBridgeResponse{
				Status: &platformv1.Status{Success: true, Message: "bridge created"},
				Bridge: &platformv1.Bridge{
					Id:        "uuid-1",
					Config:    &platformv1.BridgeConfig{Name: req.Config.Name, Type: platformv1.BridgeType_BRIDGE_TYPE_OVS},
					Status:    platformv1.BridgeStatus_BRIDGE_STATUS_UP,
					CreatedAt: timestamppb.Now(),
					UpdatedAt: timestamppb.Now(),
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"name": "br0", "type": "ovs"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateBridge(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
	assert.NotNil(t, respWriter.lastPayload)
}

func TestCreateBridge_MissingName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"type": "ovs"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateBridge(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
	assert.IsType(t, ErrMissingBridgeName{}, respWriter.lastError)
}

func TestCreateBridge_InvalidJSON(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{invalid json}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateBridge(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestCreateBridge_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		createBridgeFunc: func(ctx context.Context, req *platformv1.CreateBridgeRequest) (*platformv1.CreateBridgeResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "bridge already exists")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"name": "br0", "type": "ovs"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateBridge(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestListBridges_Success(t *testing.T) {
	mock := &mockSDNService{
		listBridgesFunc: func(ctx context.Context, req *platformv1.ListBridgesRequest) (*platformv1.ListBridgesResponse, error) {
			return &platformv1.ListBridgesResponse{
				Bridges: []*platformv1.Bridge{
					{
						Id:        "uuid-1",
						Config:    &platformv1.BridgeConfig{Name: "br0", Type: platformv1.BridgeType_BRIDGE_TYPE_OVS},
						Status:    platformv1.BridgeStatus_BRIDGE_STATUS_UP,
						CreatedAt: timestamppb.Now(),
					},
					{
						Id:        "uuid-2",
						Config:    &platformv1.BridgeConfig{Name: "br1", Type: platformv1.BridgeType_BRIDGE_TYPE_OVS},
						Status:    platformv1.BridgeStatus_BRIDGE_STATUS_UP,
						CreatedAt: timestamppb.Now(),
					},
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges", nil)
	w := httptest.NewRecorder()

	handlers.ListBridges(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
	payload, ok := respWriter.lastPayload.(ListBridgesResponse)
	require.True(t, ok)
	assert.Len(t, payload.Bridges, 2)
}

func TestListBridges_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		listBridgesFunc: func(ctx context.Context, req *platformv1.ListBridgesRequest) (*platformv1.ListBridgesResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges", nil)
	w := httptest.NewRecorder()

	handlers.ListBridges(w, req)

	assert.Equal(t, http.StatusInternalServerError, respWriter.lastStatus)
}

func TestGetBridge_Success(t *testing.T) {
	mock := &mockSDNService{
		getBridgeFunc: func(ctx context.Context, req *platformv1.GetBridgeRequest) (*platformv1.GetBridgeResponse, error) {
			return &platformv1.GetBridgeResponse{
				Bridge: &platformv1.Bridge{
					Id:     "uuid-1",
					Config: &platformv1.BridgeConfig{Name: "br0", Type: platformv1.BridgeType_BRIDGE_TYPE_OVS},
					Status: platformv1.BridgeStatus_BRIDGE_STATUS_UP,
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br0", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	w := httptest.NewRecorder()

	handlers.GetBridge(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestGetBridge_MissingName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/", nil)
	w := httptest.NewRecorder()

	handlers.GetBridge(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestGetBridge_NotFound(t *testing.T) {
	mock := &mockSDNService{
		getBridgeFunc: func(ctx context.Context, req *platformv1.GetBridgeRequest) (*platformv1.GetBridgeResponse, error) {
			return nil, status.Error(codes.NotFound, "bridge not found")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "nonexistent"})
	w := httptest.NewRecorder()

	handlers.GetBridge(w, req)

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

func TestDeleteBridge_Success(t *testing.T) {
	mock := &mockSDNService{
		deleteBridgeFunc: func(ctx context.Context, req *platformv1.DeleteBridgeRequest) (*platformv1.DeleteBridgeResponse, error) {
			return &platformv1.DeleteBridgeResponse{
				Status: &platformv1.Status{Success: true, Message: "bridge deleted"},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br0", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	w := httptest.NewRecorder()

	handlers.DeleteBridge(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestDeleteBridge_MissingName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/", nil)
	w := httptest.NewRecorder()

	handlers.DeleteBridge(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestDeleteBridge_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		deleteBridgeFunc: func(ctx context.Context, req *platformv1.DeleteBridgeRequest) (*platformv1.DeleteBridgeResponse, error) {
			return nil, status.Error(codes.NotFound, "bridge not found")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br0", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	w := httptest.NewRecorder()

	handlers.DeleteBridge(w, req)

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

// Port Handler Tests

func TestAddPort_Success(t *testing.T) {
	mock := &mockSDNService{
		addPortFunc: func(ctx context.Context, req *platformv1.AddPortRequest) (*platformv1.AddPortResponse, error) {
			return &platformv1.AddPortResponse{
				Status: &platformv1.Status{Success: true, Message: "port added"},
				Port: &platformv1.Port{
					Id:        "uuid-1",
					BridgeId:  req.BridgeId,
					Config:    &platformv1.PortConfig{Name: req.Config.Name, Type: platformv1.PortType_PORT_TYPE_INTERNAL},
					Status:    platformv1.PortStatus_PORT_STATUS_UP,
					CreatedAt: timestamppb.Now(),
					UpdatedAt: timestamppb.Now(),
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"name": "port0", "type": "internal"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br0/ports", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddPort(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestAddPort_MissingBridgeName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"name": "port0"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges//ports", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddPort(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestAddPort_MissingPortName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"type": "internal"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br0/ports", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddPort(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestAddPort_InvalidJSON(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{invalid}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br0/ports", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddPort(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestAddPort_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		addPortFunc: func(ctx context.Context, req *platformv1.AddPortRequest) (*platformv1.AddPortResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "invalid port config")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"name": "port0", "type": "internal"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br0/ports", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddPort(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestDeletePort_Success(t *testing.T) {
	mock := &mockSDNService{
		deletePortFunc: func(ctx context.Context, req *platformv1.DeletePortRequest) (*platformv1.DeletePortResponse, error) {
			return &platformv1.DeletePortResponse{
				Status: &platformv1.Status{Success: true, Message: "port deleted"},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/port0", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	w := httptest.NewRecorder()

	handlers.DeletePort(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestDeletePort_MissingBridgeName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges//ports/port0", nil)
	req = mux.SetURLVars(req, map[string]string{"port": "port0"})
	w := httptest.NewRecorder()

	handlers.DeletePort(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestDeletePort_MissingPortName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	w := httptest.NewRecorder()

	handlers.DeletePort(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestDeletePort_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		deletePortFunc: func(ctx context.Context, req *platformv1.DeletePortRequest) (*platformv1.DeletePortResponse, error) {
			return nil, status.Error(codes.NotFound, "port not found")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/port0", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	w := httptest.NewRecorder()

	handlers.DeletePort(w, req)

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

func TestAuthenticatePort_Success(t *testing.T) {
	cert := []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n")
	authenticatedAt := timestamppb.Now()
	var got *platformv1.AuthenticatePortRequest
	mock := &mockSDNService{
		authenticatePortFunc: func(ctx context.Context, req *platformv1.AuthenticatePortRequest) (*platformv1.AuthenticatePortResponse, error) {
			got = req
			return &platformv1.AuthenticatePortResponse{
				Status: &platformv1.Status{Success: true},
				Auth: &platformv1.PortAuth{
					Authenticated:   true,
					CertificateCn:   "device-01",
					AuthenticatedAt: authenticatedAt,
					AuthorizedVlans: []uint32{10, 20},
				},
			}, nil
		},
	}
	handlers, respWriter := createTestHandlers(mock)

	body, err := json.Marshal(AuthenticatePortRequest{Certificate: cert, Format: "PEM"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br0/ports/port0/auth", bytes.NewReader(body))
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	w := httptest.NewRecorder()

	handlers.AuthenticatePort(w, req)

	require.Equal(t, http.StatusOK, respWriter.lastStatus)
	require.NotNil(t, got)
	assert.Equal(t, "br0", got.BridgeId)
	assert.Equal(t, "port0", got.PortId)
	assert.Equal(t, cert, got.Certificate)
	assert.Equal(t, "PEM", got.Format)

	resp, ok := respWriter.lastPayload.(PortAuthResponse)
	require.True(t, ok, "payload is %T", respWriter.lastPayload)
	assert.Equal(t, "br0", resp.BridgeID)
	assert.Equal(t, "port0", resp.PortID)
	assert.True(t, resp.Authenticated)
	assert.Equal(t, "device-01", resp.CertificateCN)
	assert.Equal(t, []uint32{10, 20}, resp.AuthorizedVLANs)
	require.NotNil(t, resp.AuthenticatedAt)
	assert.True(t, authenticatedAt.AsTime().Equal(*resp.AuthenticatedAt))
	assert.Nil(t, resp.ExpiresAt)
}

func TestAuthenticatePort_MissingPathParam(t *testing.T) {
	tests := []struct {
		name string
		vars map[string]string
	}{
		{name: "bridge", vars: map[string]string{"port": "port0"}},
		{name: "port", vars: map[string]string{"name": "br0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlers, respWriter := createTestHandlers(&mockSDNService{})

			req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br0/ports/port0/auth", bytes.NewReader([]byte(`{}`)))
			req = mux.SetURLVars(req, tt.vars)
			w := httptest.NewRecorder()

			handlers.AuthenticatePort(w, req)

			assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
		})
	}
}

func TestAuthenticatePort_InvalidBody(t *testing.T) {
	handlers, respWriter := createTestHandlers(&mockSDNService{})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br0/ports/port0/auth", bytes.NewReader([]byte(`{"certificate":"not base64!"}`)))
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	w := httptest.NewRecorder()

	handlers.AuthenticatePort(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
	assert.IsType(t, ErrInvalidRequestBody{}, respWriter.lastError)
}

func TestAuthenticatePort_PortNotFound(t *testing.T) {
	mock := &mockSDNService{
		authenticatePortFunc: func(ctx context.Context, req *platformv1.AuthenticatePortRequest) (*platformv1.AuthenticatePortResponse, error) {
			return nil, status.Error(codes.NotFound, "port not found")
		},
	}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/bridges/br0/ports/missing/auth", bytes.NewReader([]byte(`{"certificate":"TUlJQg=="}`)))
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "missing"})
	w := httptest.NewRecorder()

	handlers.AuthenticatePort(w, req)

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

func TestRevokePortAuth_Success(t *testing.T) {
	var got *platformv1.RevokePortAuthRequest
	mock := &mockSDNService{
		revokePortAuthFunc: func(ctx context.Context, req *platformv1.RevokePortAuthRequest) (*platformv1.RevokePortAuthResponse, error) {
			got = req
			return &platformv1.RevokePortAuthResponse{
				Status: &platformv1.Status{Success: true, Message: "port authentication revoked"},
			}, nil
		},
	}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/port0/auth", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	w := httptest.NewRecorder()

	handlers.RevokePortAuth(w, req)

	require.Equal(t, http.StatusOK, respWriter.lastStatus)
	require.NotNil(t, got)
	assert.Equal(t, "br0", got.BridgeId)
	assert.Equal(t, "port0", got.PortId)
	assert.Equal(t, SuccessResponse{Success: true, Message: "port authentication revoked"}, respWriter.lastPayload)
}

// The service refuses port authentication with FailedPrecondition while the
// switch does not enforce it (#304); REST answers 409, the platform's status
// for that class (#665), not 500.
func TestPortAuth_RefusalIsConflict(t *testing.T) {
	refusals := map[string]policy.ErrPortAuthNotEnforced{
		http.MethodPost:   {Operation: "AuthenticatePort"},
		http.MethodDelete: {Operation: "RevokePortAuth"},
	}
	mock := &mockSDNService{
		authenticatePortFunc: func(ctx context.Context, req *platformv1.AuthenticatePortRequest) (*platformv1.AuthenticatePortResponse, error) {
			return nil, refusals[http.MethodPost]
		},
		revokePortAuthFunc: func(ctx context.Context, req *platformv1.RevokePortAuthRequest) (*platformv1.RevokePortAuthResponse, error) {
			return nil, refusals[http.MethodDelete]
		},
	}
	handlers, respWriter := createTestHandlers(mock)
	body, err := json.Marshal(AuthenticatePortRequest{Certificate: []byte("self-signed"), Format: "PEM"})
	require.NoError(t, err)

	calls := map[string]func(http.ResponseWriter, *http.Request){
		http.MethodPost:   handlers.AuthenticatePort,
		http.MethodDelete: handlers.RevokePortAuth,
	}
	for method, handle := range calls {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/api/v1/sdn/bridges/br0/ports/port0/auth", bytes.NewReader(body))
			req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
			rec := httptest.NewRecorder()

			handle(rec, req)

			assert.Equal(t, http.StatusConflict, respWriter.lastStatus)
			var answer restwire.WebServiceResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &answer))
			assert.Equal(t, refusals[method].Error(), answer.Error, "the refusal's own message reaches the caller")
		})
	}
}

func TestRevokePortAuth_MissingPathParam(t *testing.T) {
	tests := []struct {
		name string
		vars map[string]string
	}{
		{name: "bridge", vars: map[string]string{"port": "port0"}},
		{name: "port", vars: map[string]string{"name": "br0"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handlers, respWriter := createTestHandlers(&mockSDNService{})

			req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/port0/auth", nil)
			req = mux.SetURLVars(req, tt.vars)
			w := httptest.NewRecorder()

			handlers.RevokePortAuth(w, req)

			assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
		})
	}
}

func TestRevokePortAuth_PortNotFound(t *testing.T) {
	mock := &mockSDNService{
		revokePortAuthFunc: func(ctx context.Context, req *platformv1.RevokePortAuthRequest) (*platformv1.RevokePortAuthResponse, error) {
			return nil, status.Error(codes.NotFound, "port not found")
		},
	}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/bridges/br0/ports/missing/auth", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "missing"})
	w := httptest.NewRecorder()

	handlers.RevokePortAuth(w, req)

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

func TestGetPortState_Success(t *testing.T) {
	mock := &mockSDNService{
		getPortFunc: func(ctx context.Context, req *platformv1.GetPortRequest) (*platformv1.GetPortResponse, error) {
			return &platformv1.GetPortResponse{
				Port: &platformv1.Port{
					Id:       "uuid-1",
					BridgeId: req.BridgeId,
					Config:   &platformv1.PortConfig{Name: req.PortId},
					Status:   platformv1.PortStatus_PORT_STATUS_UP,
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br0/ports/port0/state", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	w := httptest.NewRecorder()

	handlers.GetPortState(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestGetPortState_MissingBridgeName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges//ports/port0/state", nil)
	req = mux.SetURLVars(req, map[string]string{"port": "port0"})
	w := httptest.NewRecorder()

	handlers.GetPortState(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestGetPortState_MissingPortName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br0/ports//state", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	w := httptest.NewRecorder()

	handlers.GetPortState(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestGetPortState_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		getPortFunc: func(ctx context.Context, req *platformv1.GetPortRequest) (*platformv1.GetPortResponse, error) {
			return nil, status.Error(codes.NotFound, "port not found")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br0/ports/port0/state", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	w := httptest.NewRecorder()

	handlers.GetPortState(w, req)

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

func TestGetPortState_NilPort(t *testing.T) {
	mock := &mockSDNService{
		getPortFunc: func(ctx context.Context, req *platformv1.GetPortRequest) (*platformv1.GetPortResponse, error) {
			return &platformv1.GetPortResponse{
				Port: nil,
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br0/ports/port0/state", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	w := httptest.NewRecorder()

	handlers.GetPortState(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
	payload, ok := respWriter.lastPayload.(PortStateResponse)
	require.True(t, ok)
	assert.Equal(t, "unknown", payload.AdminState)
}

// putPortState sends body to the set-state handler for port0 on br0.
func putPortState(handlers *SDNHandlers, body string) {
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/bridges/br0/ports/port0/state", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	req.Header.Set("Content-Type", "application/json")
	handlers.SetPortState(httptest.NewRecorder(), req)
}

func TestSetPortState_Success(t *testing.T) {
	var got *platformv1.SetPortStateRequest
	mock := &mockSDNService{
		setPortStateFunc: func(_ context.Context, req *platformv1.SetPortStateRequest) (*platformv1.SetPortStateResponse, error) {
			got = req
			return &platformv1.SetPortStateResponse{
				Port: &platformv1.Port{Status: platformv1.PortStatus_PORT_STATUS_DOWN},
			}, nil
		},
	}
	handlers, respWriter := createTestHandlers(mock)

	putPortState(handlers, `{"admin_state": "DOWN", "ingress_rate": 10000000, "ingress_burst": 1000000,
		"egress_rate": 20000000, "egress_burst": 2000000}`)

	require.Equal(t, http.StatusOK, respWriter.lastStatus)
	require.NotNil(t, got, "the handler answered without calling the SDN service")
	assert.Equal(t, "br0", got.GetBridgeId())
	assert.Equal(t, "port0", got.GetPortId())
	assert.Equal(t, "down", got.GetAdminState())
	assert.Equal(t, uint64(10_000_000), got.GetIngressRate())
	assert.Equal(t, uint64(1_000_000), got.GetIngressBurst())
	assert.Equal(t, uint64(20_000_000), got.GetEgressRate())
	assert.Equal(t, uint64(2_000_000), got.GetEgressBurst())
	assert.Equal(t, PortStateResponse{BridgeID: "br0", PortID: "port0", AdminState: "down"}, respWriter.lastPayload)
}

func TestSetPortState_ServiceError(t *testing.T) {
	mock := &mockSDNService{
		setPortStateFunc: func(context.Context, *platformv1.SetPortStateRequest) (*platformv1.SetPortStateResponse, error) {
			return nil, status.Error(codes.NotFound, "port not found")
		},
	}
	handlers, respWriter := createTestHandlers(mock)

	putPortState(handlers, `{"admin_state": "up"}`)

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

func TestSetPortState_InvalidState(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"admin_state": "invalid"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/bridges/br0/ports/port0/state", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.SetPortState(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestSetPortState_MissingBridgeName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"admin_state": "up"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/bridges//ports/port0/state", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"port": "port0"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.SetPortState(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestSetPortState_MissingPortName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"admin_state": "up"}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/bridges/br0/ports//state", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.SetPortState(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestSetPortState_InvalidJSON(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{invalid}`
	req := httptest.NewRequest(http.MethodPut, "/api/v1/sdn/bridges/br0/ports/port0/state", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.SetPortState(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

// Flow Handler Tests

func TestAddFlow_Success(t *testing.T) {
	mock := &mockSDNService{
		addFlowFunc: func(ctx context.Context, req *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error) {
			return &platformv1.AddFlowResponse{
				Status: &platformv1.Status{Success: true, Message: "flow added"},
				Flow: &platformv1.Flow{
					Id:        "flow-1",
					Config:    req.Config,
					CreatedAt: timestamppb.Now(),
					Stats: &platformv1.FlowStats{
						PacketCount:     100,
						ByteCount:       10000,
						DurationSeconds: 60,
					},
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"bridge_id": "br0", "priority": 100, "match": {"in_port": "1"}, "actions": [{"type": "output", "port": "2"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddFlow(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestAddFlow_MissingBridgeID(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"priority": 100}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddFlow(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestAddFlow_InvalidJSON(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{invalid}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddFlow(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestAddFlow_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		addFlowFunc: func(ctx context.Context, req *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "invalid flow")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"bridge_id": "br0", "priority": 100}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddFlow(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestAddFlow_WithNilMatch(t *testing.T) {
	mock := &mockSDNService{
		addFlowFunc: func(ctx context.Context, req *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error) {
			return &platformv1.AddFlowResponse{
				Status: &platformv1.Status{Success: true, Message: "flow added"},
				Flow: &platformv1.Flow{
					Id:        "flow-1",
					Config:    req.Config,
					CreatedAt: timestamppb.Now(),
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"bridge_id": "br0", "priority": 100}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddFlow(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestAddFlow_WithNilActions(t *testing.T) {
	mock := &mockSDNService{
		addFlowFunc: func(ctx context.Context, req *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error) {
			return &platformv1.AddFlowResponse{
				Status: &platformv1.Status{Success: true, Message: "flow added"},
				Flow: &platformv1.Flow{
					Id:        "flow-1",
					Config:    req.Config,
					CreatedAt: timestamppb.Now(),
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"bridge_id": "br0", "priority": 100, "match": {"in_port": "1"}}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.AddFlow(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestDeleteFlow_Success(t *testing.T) {
	mock := &mockSDNService{
		deleteFlowFunc: func(ctx context.Context, req *platformv1.DeleteFlowRequest) (*platformv1.DeleteFlowResponse, error) {
			return &platformv1.DeleteFlowResponse{
				Status: &platformv1.Status{Success: true, Message: "flow deleted"},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"bridge_id": "br0", "flow_id": "flow-1"}`
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.DeleteFlow(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestDeleteFlow_MissingBridgeID(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"flow_id": "flow-1"}`
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.DeleteFlow(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestDeleteFlow_MissingFlowID(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"bridge_id": "br0"}`
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.DeleteFlow(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestDeleteFlow_InvalidJSON(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{invalid}`
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.DeleteFlow(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestDeleteFlow_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		deleteFlowFunc: func(ctx context.Context, req *platformv1.DeleteFlowRequest) (*platformv1.DeleteFlowResponse, error) {
			return nil, status.Error(codes.NotFound, "flow not found")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"bridge_id": "br0", "flow_id": "flow-1"}`
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/sdn/flows", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.DeleteFlow(w, req)

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

func TestListFlows_Success(t *testing.T) {
	mock := &mockSDNService{
		listFlowsFunc: func(ctx context.Context, req *platformv1.ListFlowsRequest) (*platformv1.ListFlowsResponse, error) {
			return &platformv1.ListFlowsResponse{
				Flows: []*platformv1.Flow{
					{
						Id:     "flow-1",
						Config: &platformv1.FlowConfig{BridgeId: req.BridgeId, Priority: 100},
					},
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/flows?bridge_id=br0", nil)
	w := httptest.NewRecorder()

	handlers.ListFlows(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestListFlows_MissingBridgeID(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/flows", nil)
	w := httptest.NewRecorder()

	handlers.ListFlows(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestListFlows_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		listFlowsFunc: func(ctx context.Context, req *platformv1.ListFlowsRequest) (*platformv1.ListFlowsResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/flows?bridge_id=br0", nil)
	w := httptest.NewRecorder()

	handlers.ListFlows(w, req)

	assert.Equal(t, http.StatusInternalServerError, respWriter.lastStatus)
}

// Policy Handler Tests

func TestApplyPolicy_Success(t *testing.T) {
	var got *platformv1.ApplyPolicyRequest
	mock := &mockSDNService{
		applyPolicyFunc: func(_ context.Context, req *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
			got = req
			return &platformv1.ApplyPolicyResponse{Policy: &platformv1.Policy{
				Id:     "p1",
				Config: req.GetConfig(),
				Status: platformv1.PolicyStatus_POLICY_STATUS_ACTIVE,
			}}, nil
		},
	}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"id": "p1", "name": "web", "type": "qos",
		"rules": [{"rule_id": "r1", "vlan_id": 20, "action": "rate-limit", "action_value": "1mbit"}]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/policies", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.ApplyPolicy(w, req)

	require.Equal(t, http.StatusCreated, respWriter.lastStatus)
	require.NotNil(t, got)
	assert.Equal(t, "p1", got.GetPolicyId())
	assert.Equal(t, "web", got.GetConfig().GetName())
	assert.Equal(t, platformv1.PolicyType_POLICY_TYPE_QOS, got.GetConfig().GetType())
	assert.Equal(t, uint32(20), got.GetConfig().GetRules()[0].GetMatch().GetVlanId())
	assert.Equal(t, platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT, got.GetConfig().GetRules()[0].GetAction())

	policy, ok := respWriter.lastPayload.(restapi.PolicyResponse)
	require.True(t, ok, "payload = %T", respWriter.lastPayload)
	assert.Equal(t, "p1", policy.ID)
	assert.Equal(t, "qos", policy.Type)
	assert.Equal(t, "active", policy.Status)
}

func TestApplyPolicy_UnknownEnumNameIsBadRequest(t *testing.T) {
	mock := &mockSDNService{
		applyPolicyFunc: func(context.Context, *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
			t.Fatal("a policy with an unknown type reached the service")
			return nil, nil
		},
	}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/policies", bytes.NewBufferString(`{"name": "web", "type": "bogus"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.ApplyPolicy(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestApplyPolicy_ServiceRefusalIsBadRequest(t *testing.T) {
	mock := &mockSDNService{
		applyPolicyFunc: func(context.Context, *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "policy name is required")
		},
	}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/policies", bytes.NewBufferString(`{"description": "test"}`))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.ApplyPolicy(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestApplyPolicy_InvalidJSON(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{invalid}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/policies", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.ApplyPolicy(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestListPolicies_Success(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/policies", nil)
	w := httptest.NewRecorder()

	handlers.ListPolicies(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestGetPolicy_NotFound(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/policies/nonexistent", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "nonexistent"})
	w := httptest.NewRecorder()

	handlers.GetPolicy(w, req)

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

func TestGetPolicy_MissingID(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/policies/", nil)
	w := httptest.NewRecorder()

	handlers.GetPolicy(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

// VLAN Handler Tests

func TestCreateVLAN_Success(t *testing.T) {
	mock := &mockSDNService{
		createVLANFunc: func(ctx context.Context, req *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error) {
			return &platformv1.CreateVLANResponse{
				Status: &platformv1.Status{Success: true, Message: "VLAN created"},
				Vlan: &platformv1.VLAN{
					Id:        "vlan-1",
					Config:    req.Config,
					CreatedAt: timestamppb.Now(),
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"vlan_id": 100, "name": "test-vlan", "bridge_id": "br0", "ports": ["port0"]}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/vlans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateVLAN(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestCreateVLAN_MissingBridgeID(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"vlan_id": 100, "name": "test-vlan"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/vlans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateVLAN(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestCreateVLAN_InvalidVLANID(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"vlan_id": 5000, "bridge_id": "br0"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/vlans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateVLAN(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestCreateVLAN_ZeroVLANID(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{"vlan_id": 0, "bridge_id": "br0"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/vlans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateVLAN(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestCreateVLAN_InvalidJSON(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	body := `{invalid}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/vlans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateVLAN(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestCreateVLAN_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		createVLANFunc: func(ctx context.Context, req *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error) {
			return nil, status.Error(codes.AlreadyExists, "VLAN already exists")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	body := `{"vlan_id": 100, "name": "test-vlan", "bridge_id": "br0"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/sdn/vlans", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handlers.CreateVLAN(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestListVLANs_Success(t *testing.T) {
	mock := &mockSDNService{
		listVLANsFunc: func(ctx context.Context, req *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error) {
			return &platformv1.ListVLANsResponse{
				Vlans: []*platformv1.VLAN{
					{
						Id: "vlan-1",
						Config: &platformv1.VLANConfig{
							VlanId:   100,
							Name:     "test-vlan",
							BridgeId: req.BridgeId,
						},
					},
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)
	w := httptest.NewRecorder()

	handlers.ListVLANs(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
}

func TestListVLANs_MissingBridgeID(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/vlans", nil)
	w := httptest.NewRecorder()

	handlers.ListVLANs(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestListVLANs_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		listVLANsFunc: func(ctx context.Context, req *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error) {
			return nil, status.Error(codes.Internal, "internal error")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/vlans?bridge_id=br0", nil)
	w := httptest.NewRecorder()

	handlers.ListVLANs(w, req)

	assert.Equal(t, http.StatusInternalServerError, respWriter.lastStatus)
}

// Port Stats Handler Tests

func TestGetPortStats_Success(t *testing.T) {
	mock := &mockSDNService{
		getPortStatsFunc: func(ctx context.Context, req *platformv1.GetPortStatsRequest) (*platformv1.GetPortStatsResponse, error) {
			return &platformv1.GetPortStatsResponse{
				Stats: &platformv1.PortStats{
					PacketsReceived: 1000,
					PacketsSent:     800,
					BytesReceived:   100000,
					BytesSent:       80000,
					Errors:          5,
					Dropped:         10,
				},
			}, nil
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br0/ports/port0/stats", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	w := httptest.NewRecorder()

	handlers.GetPortStats(w, req)

	assert.Equal(t, http.StatusOK, respWriter.lastStatus)
	payload, ok := respWriter.lastPayload.(PortStatsResponse)
	require.True(t, ok)
	assert.Equal(t, uint64(1000), payload.PacketsReceived)
	assert.Equal(t, uint64(800), payload.PacketsSent)
}

func TestGetPortStats_MissingBridgeName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges//ports/port0/stats", nil)
	req = mux.SetURLVars(req, map[string]string{"port": "port0"})
	w := httptest.NewRecorder()

	handlers.GetPortStats(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestGetPortStats_MissingPortName(t *testing.T) {
	mock := &mockSDNService{}
	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br0/ports//stats", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	w := httptest.NewRecorder()

	handlers.GetPortStats(w, req)

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestGetPortStats_GRPCError(t *testing.T) {
	mock := &mockSDNService{
		getPortStatsFunc: func(ctx context.Context, req *platformv1.GetPortStatsRequest) (*platformv1.GetPortStatsResponse, error) {
			return nil, status.Error(codes.NotFound, "port not found")
		},
	}

	handlers, respWriter := createTestHandlers(mock)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br0/ports/port0/stats", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0", "port": "port0"})
	w := httptest.NewRecorder()

	handlers.GetPortStats(w, req)

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

// Helper Function Tests

func TestParseBridgeType(t *testing.T) {
	handlers := &SDNHandlers{}

	tests := []struct {
		input    string
		expected platformv1.BridgeType
	}{
		{"ovs", platformv1.BridgeType_BRIDGE_TYPE_OVS},
		{"linux", platformv1.BridgeType_BRIDGE_TYPE_LINUX},
		{"vxlan", platformv1.BridgeType_BRIDGE_TYPE_VXLAN},
		{"unknown", platformv1.BridgeType_BRIDGE_TYPE_OVS},
		{"", platformv1.BridgeType_BRIDGE_TYPE_OVS},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := handlers.parseBridgeType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBridgeTypeToString(t *testing.T) {
	handlers := &SDNHandlers{}

	tests := []struct {
		input    platformv1.BridgeType
		expected string
	}{
		{platformv1.BridgeType_BRIDGE_TYPE_OVS, "ovs"},
		{platformv1.BridgeType_BRIDGE_TYPE_LINUX, "linux"},
		{platformv1.BridgeType_BRIDGE_TYPE_VXLAN, "vxlan"},
		{platformv1.BridgeType_BRIDGE_TYPE_UNSPECIFIED, "unknown"},
		{platformv1.BridgeType(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := handlers.bridgeTypeToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBridgeStatusToString(t *testing.T) {
	handlers := &SDNHandlers{}

	tests := []struct {
		input    platformv1.BridgeStatus
		expected string
	}{
		{platformv1.BridgeStatus_BRIDGE_STATUS_UP, "up"},
		{platformv1.BridgeStatus_BRIDGE_STATUS_DOWN, "down"},
		{platformv1.BridgeStatus_BRIDGE_STATUS_ERROR, "error"},
		{platformv1.BridgeStatus_BRIDGE_STATUS_UNSPECIFIED, "unknown"},
		{platformv1.BridgeStatus(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := handlers.bridgeStatusToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParsePortType(t *testing.T) {
	handlers := &SDNHandlers{}

	tests := []struct {
		input    string
		expected platformv1.PortType
	}{
		{"internal", platformv1.PortType_PORT_TYPE_INTERNAL},
		{"physical", platformv1.PortType_PORT_TYPE_PHYSICAL},
		{"tap", platformv1.PortType_PORT_TYPE_TAP},
		{"veth", platformv1.PortType_PORT_TYPE_VETH},
		{"vxlan", platformv1.PortType_PORT_TYPE_VXLAN},
		{"gre", platformv1.PortType_PORT_TYPE_GRE},
		{"unknown", platformv1.PortType_PORT_TYPE_INTERNAL},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := handlers.parsePortType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPortTypeToString(t *testing.T) {
	handlers := &SDNHandlers{}

	tests := []struct {
		input    platformv1.PortType
		expected string
	}{
		{platformv1.PortType_PORT_TYPE_INTERNAL, "internal"},
		{platformv1.PortType_PORT_TYPE_PHYSICAL, "physical"},
		{platformv1.PortType_PORT_TYPE_TAP, "tap"},
		{platformv1.PortType_PORT_TYPE_VETH, "veth"},
		{platformv1.PortType_PORT_TYPE_VXLAN, "vxlan"},
		{platformv1.PortType_PORT_TYPE_GRE, "gre"},
		{platformv1.PortType_PORT_TYPE_UNSPECIFIED, "unknown"},
		{platformv1.PortType(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := handlers.portTypeToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPortStatusToString(t *testing.T) {
	handlers := &SDNHandlers{}

	tests := []struct {
		input    platformv1.PortStatus
		expected string
	}{
		{platformv1.PortStatus_PORT_STATUS_UP, "up"},
		{platformv1.PortStatus_PORT_STATUS_DOWN, "down"},
		{platformv1.PortStatus_PORT_STATUS_BLOCKED, "blocked"},
		{platformv1.PortStatus_PORT_STATUS_LEARNING, "learning"},
		{platformv1.PortStatus_PORT_STATUS_FORWARDING, "forwarding"},
		{platformv1.PortStatus_PORT_STATUS_UNSPECIFIED, "unknown"},
		{platformv1.PortStatus(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := handlers.portStatusToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseFlowTable(t *testing.T) {
	handlers := &SDNHandlers{}

	tests := []struct {
		input    uint32
		expected platformv1.FlowTable
	}{
		{0, platformv1.FlowTable_FLOW_TABLE_0},
		{1, platformv1.FlowTable_FLOW_TABLE_1},
		{2, platformv1.FlowTable_FLOW_TABLE_2},
		{3, platformv1.FlowTable_FLOW_TABLE_3},
		{255, platformv1.FlowTable_FLOW_TABLE_DROP},
		{100, platformv1.FlowTable_FLOW_TABLE_0},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := handlers.parseFlowTable(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseFlowActionType(t *testing.T) {
	handlers := &SDNHandlers{}

	tests := []struct {
		input    string
		expected platformv1.FlowActionType
	}{
		{"output", platformv1.FlowActionType_FLOW_ACTION_OUTPUT},
		{"drop", platformv1.FlowActionType_FLOW_ACTION_DROP},
		{"set_vlan", platformv1.FlowActionType_FLOW_ACTION_SET_VLAN},
		{"strip_vlan", platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN},
		{"set_field", platformv1.FlowActionType_FLOW_ACTION_SET_FIELD},
		{"goto_table", platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE},
		{"controller", platformv1.FlowActionType_FLOW_ACTION_CONTROLLER},
		{"unknown", platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := handlers.parseFlowActionType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestFlowActionTypeToString(t *testing.T) {
	handlers := &SDNHandlers{}

	tests := []struct {
		input    platformv1.FlowActionType
		expected string
	}{
		{platformv1.FlowActionType_FLOW_ACTION_OUTPUT, "output"},
		{platformv1.FlowActionType_FLOW_ACTION_DROP, "drop"},
		{platformv1.FlowActionType_FLOW_ACTION_SET_VLAN, "set_vlan"},
		{platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN, "strip_vlan"},
		{platformv1.FlowActionType_FLOW_ACTION_SET_FIELD, "set_field"},
		{platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE, "goto_table"},
		{platformv1.FlowActionType_FLOW_ACTION_CONTROLLER, "controller"},
		{platformv1.FlowActionType_FLOW_ACTION_UNSPECIFIED, "unknown"},
		{platformv1.FlowActionType(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := handlers.flowActionTypeToString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Response conversion tests

func TestBridgeToResponse_NilBridge(t *testing.T) {
	handlers := &SDNHandlers{}

	result := handlers.bridgeToResponse(nil)

	assert.Equal(t, BridgeResponse{}, result)
}

func TestBridgeToResponse_NilConfig(t *testing.T) {
	handlers := &SDNHandlers{}

	bridge := &platformv1.Bridge{
		Id:     "test-id",
		Status: platformv1.BridgeStatus_BRIDGE_STATUS_UP,
	}

	result := handlers.bridgeToResponse(bridge)

	assert.Equal(t, "test-id", result.ID)
	assert.Equal(t, "up", result.Status)
	assert.Empty(t, result.Name)
}

func TestPortToResponse_NilPort(t *testing.T) {
	handlers := &SDNHandlers{}

	result := handlers.portToResponse(nil)

	assert.Equal(t, PortResponse{}, result)
}

func TestPortToResponse_NilConfig(t *testing.T) {
	handlers := &SDNHandlers{}

	port := &platformv1.Port{
		Id:       "test-id",
		BridgeId: "br0",
		Status:   platformv1.PortStatus_PORT_STATUS_UP,
	}

	result := handlers.portToResponse(port)

	assert.Equal(t, "test-id", result.ID)
	assert.Equal(t, "br0", result.BridgeID)
	assert.Equal(t, "up", result.Status)
	assert.Empty(t, result.Name)
}

func TestFlowToResponse_NilFlow(t *testing.T) {
	handlers := &SDNHandlers{}

	result := handlers.flowToResponse(nil)

	assert.Equal(t, FlowResponse{}, result)
}

func TestFlowToResponse_NilConfig(t *testing.T) {
	handlers := &SDNHandlers{}

	flow := &platformv1.Flow{
		Id: "test-id",
	}

	result := handlers.flowToResponse(flow)

	assert.Equal(t, "test-id", result.ID)
	assert.Empty(t, result.BridgeID)
}

func TestVlanToResponse_NilVlan(t *testing.T) {
	handlers := &SDNHandlers{}

	result := handlers.vlanToResponse(nil)

	assert.Equal(t, VLANResponse{}, result)
}

func TestVlanToResponse_NilConfig(t *testing.T) {
	handlers := &SDNHandlers{}

	vlan := &platformv1.VLAN{
		Id: "test-id",
	}

	result := handlers.vlanToResponse(vlan)

	assert.Equal(t, "test-id", result.ID)
	assert.Empty(t, result.Name)
}

// gRPC error handling tests

func TestHandleGRPCError_NonGRPCError(t *testing.T) {
	handlers, respWriter := createTestHandlers(&mockSDNService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handlers.handleGRPCError(w, req, errors.New("regular error"))

	assert.Equal(t, http.StatusInternalServerError, respWriter.lastStatus)
}

func TestHandleGRPCError_NotFound(t *testing.T) {
	handlers, respWriter := createTestHandlers(&mockSDNService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handlers.handleGRPCError(w, req, status.Error(codes.NotFound, "not found"))

	assert.Equal(t, http.StatusNotFound, respWriter.lastStatus)
}

func TestHandleGRPCError_InvalidArgument(t *testing.T) {
	handlers, respWriter := createTestHandlers(&mockSDNService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handlers.handleGRPCError(w, req, status.Error(codes.InvalidArgument, "invalid"))

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestHandleGRPCError_PermissionDenied(t *testing.T) {
	handlers, respWriter := createTestHandlers(&mockSDNService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handlers.handleGRPCError(w, req, status.Error(codes.PermissionDenied, "denied"))

	assert.Equal(t, http.StatusUnauthorized, respWriter.lastStatus)
}

func TestHandleGRPCError_Unauthenticated(t *testing.T) {
	handlers, respWriter := createTestHandlers(&mockSDNService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handlers.handleGRPCError(w, req, status.Error(codes.Unauthenticated, "unauthenticated"))

	assert.Equal(t, http.StatusUnauthorized, respWriter.lastStatus)
}

func TestHandleGRPCError_AlreadyExists(t *testing.T) {
	handlers, respWriter := createTestHandlers(&mockSDNService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handlers.handleGRPCError(w, req, status.Error(codes.AlreadyExists, "exists"))

	assert.Equal(t, http.StatusBadRequest, respWriter.lastStatus)
}

func TestHandleGRPCError_Internal(t *testing.T) {
	handlers, respWriter := createTestHandlers(&mockSDNService{})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	handlers.handleGRPCError(w, req, status.Error(codes.Internal, "internal"))

	assert.Equal(t, http.StatusInternalServerError, respWriter.lastStatus)
}

// Flow conversion tests

func TestFlowMatchToProto_NilMatch(t *testing.T) {
	handlers := &SDNHandlers{}

	result := handlers.flowMatchToProto(nil)

	assert.Nil(t, result)
}

func TestProtoToFlowMatch_NilMatch(t *testing.T) {
	handlers := &SDNHandlers{}

	result := handlers.protoToFlowMatch(nil)

	assert.Nil(t, result)
}

func TestFlowActionsToProto_NilActions(t *testing.T) {
	handlers := &SDNHandlers{}

	result := handlers.flowActionsToProto(nil)

	assert.Nil(t, result)
}

func TestProtoToFlowActions_NilActions(t *testing.T) {
	handlers := &SDNHandlers{}

	result := handlers.protoToFlowActions(nil)

	assert.Nil(t, result)
}

func TestFlowActionsToProto_WithActions(t *testing.T) {
	handlers := &SDNHandlers{}

	actions := []*FlowAction{
		{Type: "output", Port: "1"},
		{Type: "drop"},
	}

	result := handlers.flowActionsToProto(actions)

	assert.Len(t, result, 2)
	assert.Equal(t, platformv1.FlowActionType_FLOW_ACTION_OUTPUT, result[0].Type)
	assert.Equal(t, "1", result[0].Port)
}

func TestProtoToFlowActions_WithActions(t *testing.T) {
	handlers := &SDNHandlers{}

	actions := []*platformv1.FlowAction{
		{Type: platformv1.FlowActionType_FLOW_ACTION_OUTPUT, Port: "1"},
		{Type: platformv1.FlowActionType_FLOW_ACTION_DROP},
	}

	result := handlers.protoToFlowActions(actions)

	assert.Len(t, result, 2)
	assert.Equal(t, "output", result[0].Type)
	assert.Equal(t, "1", result[0].Port)
}

// timeFromTimestamp tests

func TestTimeFromTimestamp_NilTimestamp(t *testing.T) {
	// The function uses an interface, so we can test with nil directly via function behavior
	// The handlers should handle nil timestamps gracefully
	handlers, _ := createTestHandlers(&mockSDNService{
		getBridgeFunc: func(ctx context.Context, req *platformv1.GetBridgeRequest) (*platformv1.GetBridgeResponse, error) {
			return &platformv1.GetBridgeResponse{
				Bridge: &platformv1.Bridge{
					Id:        "test-id",
					Config:    &platformv1.BridgeConfig{Name: "br0"},
					Status:    platformv1.BridgeStatus_BRIDGE_STATUS_UP,
					CreatedAt: nil,
					UpdatedAt: nil,
				},
			}, nil
		},
	})

	req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/bridges/br0", nil)
	req = mux.SetURLVars(req, map[string]string{"name": "br0"})
	w := httptest.NewRecorder()

	handlers.GetBridge(w, req)

	// Should not panic
	assert.Equal(t, http.StatusOK, w.Code)
}
