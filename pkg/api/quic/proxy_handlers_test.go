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

package quic

import (
	"context"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeProxyQUICService is a configurable ProxyServiceInterface test double.
type fakeProxyQUICService struct {
	err error

	createRouteResp *platformv1.CreateProxyRouteResponse
	getRouteResp    *platformv1.GetProxyRouteResponse
	updateRouteResp *platformv1.UpdateProxyRouteResponse
	deleteRouteResp *platformv1.DeleteProxyRouteResponse
	listRoutesResp  *platformv1.ListProxyRoutesResponse
	createPoolResp  *platformv1.CreateProxyPoolResponse
	getPoolResp     *platformv1.GetProxyPoolResponse
	updatePoolResp  *platformv1.UpdateProxyPoolResponse
	deletePoolResp  *platformv1.DeleteProxyPoolResponse
	listPoolsResp   *platformv1.ListProxyPoolsResponse
	configResp      *platformv1.GetProxyConfigResponse
	statusResp      *platformv1.GetProxyStatusResponse
	reloadResp      *platformv1.ReloadProxyConfigResponse
	matrixResp      *platformv1.GetProxyZoneMatrixResponse

	lastRouteID string
	lastPoolID  string
}

func (f *fakeProxyQUICService) CreateRoute(ctx context.Context, req *platformv1.CreateProxyRouteRequest) (*platformv1.CreateProxyRouteResponse, error) {
	return f.createRouteResp, f.err
}

func (f *fakeProxyQUICService) GetRoute(ctx context.Context, req *platformv1.GetProxyRouteRequest) (*platformv1.GetProxyRouteResponse, error) {
	f.lastRouteID = req.GetId()
	return f.getRouteResp, f.err
}

func (f *fakeProxyQUICService) UpdateRoute(ctx context.Context, req *platformv1.UpdateProxyRouteRequest) (*platformv1.UpdateProxyRouteResponse, error) {
	return f.updateRouteResp, f.err
}

func (f *fakeProxyQUICService) DeleteRoute(ctx context.Context, req *platformv1.DeleteProxyRouteRequest) (*platformv1.DeleteProxyRouteResponse, error) {
	f.lastRouteID = req.GetId()
	return f.deleteRouteResp, f.err
}

func (f *fakeProxyQUICService) ListRoutes(ctx context.Context, req *platformv1.ListProxyRoutesRequest) (*platformv1.ListProxyRoutesResponse, error) {
	return f.listRoutesResp, f.err
}

func (f *fakeProxyQUICService) CreatePool(ctx context.Context, req *platformv1.CreateProxyPoolRequest) (*platformv1.CreateProxyPoolResponse, error) {
	return f.createPoolResp, f.err
}

func (f *fakeProxyQUICService) GetPool(ctx context.Context, req *platformv1.GetProxyPoolRequest) (*platformv1.GetProxyPoolResponse, error) {
	f.lastPoolID = req.GetId()
	return f.getPoolResp, f.err
}

func (f *fakeProxyQUICService) UpdatePool(ctx context.Context, req *platformv1.UpdateProxyPoolRequest) (*platformv1.UpdateProxyPoolResponse, error) {
	return f.updatePoolResp, f.err
}

func (f *fakeProxyQUICService) DeletePool(ctx context.Context, req *platformv1.DeleteProxyPoolRequest) (*platformv1.DeleteProxyPoolResponse, error) {
	f.lastPoolID = req.GetId()
	return f.deletePoolResp, f.err
}

func (f *fakeProxyQUICService) ListPools(ctx context.Context, req *platformv1.ListProxyPoolsRequest) (*platformv1.ListProxyPoolsResponse, error) {
	return f.listPoolsResp, f.err
}

func (f *fakeProxyQUICService) GetProxyConfig(ctx context.Context, req *platformv1.GetProxyConfigRequest) (*platformv1.GetProxyConfigResponse, error) {
	return f.configResp, f.err
}

func (f *fakeProxyQUICService) GetProxyStatus(ctx context.Context, req *platformv1.GetProxyStatusRequest) (*platformv1.GetProxyStatusResponse, error) {
	return f.statusResp, f.err
}

func (f *fakeProxyQUICService) ReloadProxyConfig(ctx context.Context, req *platformv1.ReloadProxyConfigRequest) (*platformv1.ReloadProxyConfigResponse, error) {
	return f.reloadResp, f.err
}

func (f *fakeProxyQUICService) GetZoneMatrix(ctx context.Context, req *platformv1.GetProxyZoneMatrixRequest) (*platformv1.GetProxyZoneMatrixResponse, error) {
	return f.matrixResp, f.err
}

// proxySubRequest builds a proxy sub-request as the gateway category
// dispatcher would deliver it (sub-opcode in Opcode, body in Payload).
func proxySubRequest(t *testing.T, sub byte, msg interface{}) *Request {
	t.Helper()
	var payload []byte
	if msg != nil {
		encoded, err := EncodePayload(msg)
		if err != nil {
			t.Fatalf("EncodePayload: %v", err)
		}
		payload = encoded
	}
	return &Request{Opcode: sub, Payload: payload}
}

func TestProxyHandler_RouteLifecycle(t *testing.T) {
	fake := &fakeProxyQUICService{
		createRouteResp: &platformv1.CreateProxyRouteResponse{
			Route:   &platformv1.ProxyRoute{Id: "web", PoolId: "pool-1", PathPrefix: "/"},
			Version: 2,
		},
		getRouteResp: &platformv1.GetProxyRouteResponse{
			Route: &platformv1.ProxyRoute{Id: "web", PoolId: "pool-1"},
		},
		updateRouteResp: &platformv1.UpdateProxyRouteResponse{
			Route:   &platformv1.ProxyRoute{Id: "web", PoolId: "pool-2"},
			Version: 3,
		},
		deleteRouteResp: &platformv1.DeleteProxyRouteResponse{Version: 4},
		listRoutesResp: &platformv1.ListProxyRoutesResponse{
			Routes:  []*platformv1.ProxyRoute{{Id: "web"}},
			Version: 4,
		},
	}
	h := NewProxyHandler(nil, fake)
	ctx := context.Background()

	// Create
	resp := h.HandleRequest(ctx, proxySubRequest(t, ProxySubRouteCreate, &platformv1.CreateProxyRouteRequest{
		Route: &platformv1.ProxyRoute{Id: "web", PoolId: "pool-1", PathPrefix: "/"},
	}))
	if resp.Status != StatusOK {
		t.Fatalf("create status = 0x%02x payload %s", resp.Status, resp.Payload)
	}
	var created platformv1.CreateProxyRouteResponse
	if err := DecodePayload(resp.Payload, &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	if created.GetRoute().GetId() != "web" || created.GetVersion() != 2 {
		t.Errorf("create = %v v%d, want web v2", created.GetRoute().GetId(), created.GetVersion())
	}

	// Get
	resp = h.HandleRequest(ctx, proxySubRequest(t, ProxySubRouteGet, &platformv1.GetProxyRouteRequest{Id: "web"}))
	if resp.Status != StatusOK {
		t.Fatalf("get status = 0x%02x payload %s", resp.Status, resp.Payload)
	}
	if fake.lastRouteID != "web" {
		t.Errorf("service received route id %q, want web", fake.lastRouteID)
	}

	// Update
	resp = h.HandleRequest(ctx, proxySubRequest(t, ProxySubRouteUpdate, &platformv1.UpdateProxyRouteRequest{
		Id:    "web",
		Route: &platformv1.ProxyRoute{Id: "web", PoolId: "pool-2", PathPrefix: "/"},
	}))
	if resp.Status != StatusOK {
		t.Fatalf("update status = 0x%02x payload %s", resp.Status, resp.Payload)
	}

	// Delete
	resp = h.HandleRequest(ctx, proxySubRequest(t, ProxySubRouteDelete, &platformv1.DeleteProxyRouteRequest{Id: "web"}))
	if resp.Status != StatusOK {
		t.Fatalf("delete status = 0x%02x payload %s", resp.Status, resp.Payload)
	}

	// List
	resp = h.HandleRequest(ctx, proxySubRequest(t, ProxySubRouteList, &platformv1.ListProxyRoutesRequest{}))
	if resp.Status != StatusOK {
		t.Fatalf("list status = 0x%02x payload %s", resp.Status, resp.Payload)
	}
	var list platformv1.ListProxyRoutesResponse
	if err := DecodePayload(resp.Payload, &list); err != nil {
		t.Fatalf("decode list response: %v", err)
	}
	if len(list.GetRoutes()) != 1 || list.GetVersion() != 4 {
		t.Errorf("list = (%d routes, v%d), want (1, v4)", len(list.GetRoutes()), list.GetVersion())
	}
}

func TestProxyHandler_PoolLifecycle(t *testing.T) {
	fake := &fakeProxyQUICService{
		createPoolResp: &platformv1.CreateProxyPoolResponse{
			Pool:    &platformv1.ProxyPool{Id: "pool-1"},
			Version: 1,
		},
		getPoolResp: &platformv1.GetProxyPoolResponse{
			Pool: &platformv1.ProxyPool{Id: "pool-1"},
		},
		updatePoolResp: &platformv1.UpdateProxyPoolResponse{
			Pool:    &platformv1.ProxyPool{Id: "pool-1"},
			Version: 2,
		},
		deletePoolResp: &platformv1.DeleteProxyPoolResponse{Version: 3},
		listPoolsResp: &platformv1.ListProxyPoolsResponse{
			Pools:   []*platformv1.ProxyPool{{Id: "pool-1"}},
			Version: 3,
		},
	}
	h := NewProxyHandler(nil, fake)
	ctx := context.Background()

	for _, tc := range []struct {
		name string
		sub  byte
		msg  interface{}
	}{
		{"create", ProxySubPoolCreate, &platformv1.CreateProxyPoolRequest{Pool: &platformv1.ProxyPool{Id: "pool-1"}}},
		{"get", ProxySubPoolGet, &platformv1.GetProxyPoolRequest{Id: "pool-1"}},
		{"update", ProxySubPoolUpdate, &platformv1.UpdateProxyPoolRequest{Id: "pool-1", Pool: &platformv1.ProxyPool{Id: "pool-1"}}},
		{"delete", ProxySubPoolDelete, &platformv1.DeleteProxyPoolRequest{Id: "pool-1"}},
		{"list", ProxySubPoolList, &platformv1.ListProxyPoolsRequest{}},
	} {
		resp := h.HandleRequest(ctx, proxySubRequest(t, tc.sub, tc.msg))
		if resp.Status != StatusOK {
			t.Errorf("%s status = 0x%02x payload %s", tc.name, resp.Status, resp.Payload)
		}
	}
	if fake.lastPoolID != "pool-1" {
		t.Errorf("service received pool id %q, want pool-1", fake.lastPoolID)
	}
}

func TestProxyHandler_ConfigStatusReloadMatrix(t *testing.T) {
	fake := &fakeProxyQUICService{
		configResp: &platformv1.GetProxyConfigResponse{Version: 5},
		statusResp: &platformv1.GetProxyStatusResponse{Version: 5, RouteCount: 1, PoolCount: 2},
		reloadResp: &platformv1.ReloadProxyConfigResponse{Version: 6},
		matrixResp: &platformv1.GetProxyZoneMatrixResponse{
			Zones: []string{"public", "trusted"},
			Pairs: []*platformv1.ProxyZonePair{{From: "trusted", To: "public"}},
		},
	}
	h := NewProxyHandler(nil, fake)
	ctx := context.Background()

	resp := h.HandleRequest(ctx, proxySubRequest(t, ProxySubConfigGet, &platformv1.GetProxyConfigRequest{}))
	if resp.Status != StatusOK {
		t.Fatalf("config status = 0x%02x payload %s", resp.Status, resp.Payload)
	}
	var cfg platformv1.GetProxyConfigResponse
	if err := DecodePayload(resp.Payload, &cfg); err != nil {
		t.Fatalf("decode config: %v", err)
	}
	if cfg.GetVersion() != 5 {
		t.Errorf("config version = %d, want 5", cfg.GetVersion())
	}

	resp = h.HandleRequest(ctx, proxySubRequest(t, ProxySubStatusGet, &platformv1.GetProxyStatusRequest{}))
	if resp.Status != StatusOK {
		t.Fatalf("status status = 0x%02x payload %s", resp.Status, resp.Payload)
	}
	var st platformv1.GetProxyStatusResponse
	if err := DecodePayload(resp.Payload, &st); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if st.GetPoolCount() != 2 {
		t.Errorf("pool count = %d, want 2", st.GetPoolCount())
	}

	resp = h.HandleRequest(ctx, proxySubRequest(t, ProxySubReload, &platformv1.ReloadProxyConfigRequest{}))
	if resp.Status != StatusOK {
		t.Fatalf("reload status = 0x%02x payload %s", resp.Status, resp.Payload)
	}

	resp = h.HandleRequest(ctx, proxySubRequest(t, ProxySubZoneMatrix, &platformv1.GetProxyZoneMatrixRequest{}))
	if resp.Status != StatusOK {
		t.Fatalf("matrix status = 0x%02x payload %s", resp.Status, resp.Payload)
	}
	var matrix platformv1.GetProxyZoneMatrixResponse
	if err := DecodePayload(resp.Payload, &matrix); err != nil {
		t.Fatalf("decode matrix: %v", err)
	}
	if len(matrix.GetZones()) != 2 || len(matrix.GetPairs()) != 1 {
		t.Errorf("matrix = (%d zones, %d pairs), want (2, 1)", len(matrix.GetZones()), len(matrix.GetPairs()))
	}
}

func TestProxyHandler_ErrorStatusMapping(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		err        error
		wantStatus byte
	}{
		{"not found", status.Error(codes.NotFound, "route not found"), StatusNotFound},
		{"already exists", status.Error(codes.AlreadyExists, "route exists"), StatusAlreadyExists},
		{"invalid argument", status.Error(codes.InvalidArgument, "bad route"), StatusInvalidArgument},
		{"failed precondition", status.Error(codes.FailedPrecondition, "pool in use"), StatusInvalidRequest},
		{"unavailable", status.Error(codes.Unavailable, "zone service missing"), StatusUnavailable},
		{"internal", status.Error(codes.Internal, "boom"), StatusInternalError},
		{"unmapped code", status.Error(codes.DataLoss, "weird"), StatusInternalError},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewProxyHandler(nil, &fakeProxyQUICService{err: tc.err})
			resp := h.HandleRequest(ctx, proxySubRequest(t, ProxySubRouteGet, &platformv1.GetProxyRouteRequest{Id: "x"}))
			if resp.Status != tc.wantStatus {
				t.Errorf("status = 0x%02x, want 0x%02x", resp.Status, tc.wantStatus)
			}
		})
	}
}

func TestProxyHandler_NilServiceAndRequestGuards(t *testing.T) {
	ctx := context.Background()

	// Nil service yields Unavailable for a valid sub-opcode.
	h := NewProxyHandler(nil, nil)
	resp := h.HandleRequest(ctx, proxySubRequest(t, ProxySubRouteList, &platformv1.ListProxyRoutesRequest{}))
	if resp.Status != StatusUnavailable {
		t.Errorf("nil service status = 0x%02x, want StatusUnavailable", resp.Status)
	}

	// Nil request is rejected.
	resp = h.HandleRequest(ctx, nil)
	if resp.Status != StatusInvalidRequest {
		t.Errorf("nil request status = 0x%02x, want StatusInvalidRequest", resp.Status)
	}

	// Unknown sub-opcode is NotImplemented.
	resp = h.HandleRequest(ctx, &Request{Opcode: 0xEE})
	if resp.Status != StatusNotImplemented {
		t.Errorf("unknown sub-opcode status = 0x%02x, want StatusNotImplemented", resp.Status)
	}
}

func TestProxyHandler_DecodeFailure(t *testing.T) {
	h := NewProxyHandler(nil, &fakeProxyQUICService{})
	resp := h.HandleRequest(context.Background(), &Request{
		Opcode:  ProxySubRouteGet,
		Payload: []byte{0xFF, 0x00, 0x01}, // not a valid codec payload
	})
	if resp.Status != StatusInvalidRequest {
		t.Errorf("decode failure status = 0x%02x payload %s, want StatusInvalidRequest", resp.Status, resp.Payload)
	}
}

func TestIsProxySubOpcode(t *testing.T) {
	for sub := ProxySubRouteCreate; sub <= ProxySubZoneMatrix; sub++ {
		if !IsProxySubOpcode(sub) {
			t.Errorf("IsProxySubOpcode(0x%02x) = false, want true", sub)
		}
	}
	// Gateway's own sub-opcodes must not be claimed by the proxy range.
	for _, sub := range []byte{OpGatewayStatus, OpGatewayListNetworkZones, OpGatewayAssignNetworkZone, 0x2E, 0xFF} {
		if IsProxySubOpcode(sub) {
			t.Errorf("IsProxySubOpcode(0x%02x) = true, want false", sub)
		}
	}
}
