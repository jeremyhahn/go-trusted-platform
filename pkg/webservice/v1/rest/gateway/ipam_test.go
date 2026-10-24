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

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// mockIPAMGatewayService implements the IPAM RPCs of
// platformv1.GatewayServiceServer for the REST IPAM router tests.
type mockIPAMGatewayService struct {
	platformv1.UnimplementedGatewayServiceServer

	createPoolFunc func(ctx context.Context, req *platformv1.CreateIPAMPoolRequest) (*platformv1.CreateIPAMPoolResponse, error)
	getPoolFunc    func(ctx context.Context, req *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error)
	updatePoolFunc func(ctx context.Context, req *platformv1.UpdateIPAMPoolRequest) (*platformv1.UpdateIPAMPoolResponse, error)
	deletePoolFunc func(ctx context.Context, req *platformv1.DeleteIPAMPoolRequest) (*platformv1.DeleteIPAMPoolResponse, error)
	listPoolsFunc  func(ctx context.Context, req *platformv1.ListIPAMPoolsRequest) (*platformv1.ListIPAMPoolsResponse, error)
	allocateFunc   func(ctx context.Context, req *platformv1.AllocateIPRequest) (*platformv1.AllocateIPResponse, error)
	releaseFunc    func(ctx context.Context, req *platformv1.ReleaseIPRequest) (*platformv1.ReleaseIPResponse, error)
	listAllocsFunc func(ctx context.Context, req *platformv1.ListAllocationsRequest) (*platformv1.ListAllocationsResponse, error)
}

func (m *mockIPAMGatewayService) CreateIPAMPool(ctx context.Context, req *platformv1.CreateIPAMPoolRequest) (*platformv1.CreateIPAMPoolResponse, error) {
	if m.createPoolFunc != nil {
		return m.createPoolFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIPAMGatewayService) GetIPAMPool(ctx context.Context, req *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error) {
	if m.getPoolFunc != nil {
		return m.getPoolFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIPAMGatewayService) UpdateIPAMPool(ctx context.Context, req *platformv1.UpdateIPAMPoolRequest) (*platformv1.UpdateIPAMPoolResponse, error) {
	if m.updatePoolFunc != nil {
		return m.updatePoolFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIPAMGatewayService) DeleteIPAMPool(ctx context.Context, req *platformv1.DeleteIPAMPoolRequest) (*platformv1.DeleteIPAMPoolResponse, error) {
	if m.deletePoolFunc != nil {
		return m.deletePoolFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIPAMGatewayService) ListIPAMPools(ctx context.Context, req *platformv1.ListIPAMPoolsRequest) (*platformv1.ListIPAMPoolsResponse, error) {
	if m.listPoolsFunc != nil {
		return m.listPoolsFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIPAMGatewayService) AllocateIP(ctx context.Context, req *platformv1.AllocateIPRequest) (*platformv1.AllocateIPResponse, error) {
	if m.allocateFunc != nil {
		return m.allocateFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIPAMGatewayService) ReleaseIP(ctx context.Context, req *platformv1.ReleaseIPRequest) (*platformv1.ReleaseIPResponse, error) {
	if m.releaseFunc != nil {
		return m.releaseFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func (m *mockIPAMGatewayService) ListAllocations(ctx context.Context, req *platformv1.ListAllocationsRequest) (*platformv1.ListAllocationsResponse, error) {
	if m.listAllocsFunc != nil {
		return m.listAllocsFunc(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not implemented")
}

func newIPAMTestRouter(t *testing.T, svc platformv1.GatewayServiceServer) *mux.Router {
	t.Helper()
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	writer := response.NewResponseWriter(logger, nil)
	mr := mux.NewRouter()
	NewIPAMRouter(logger, svc, writer).RegisterRoutes(mr)
	return mr
}

type ipamEnvelope struct {
	Code    int             `json:"code"`
	Error   string          `json:"error"`
	Success bool            `json:"success"`
	Payload json.RawMessage `json:"payload"`
}

func decodeIPAMEnvelope(t *testing.T, rec *httptest.ResponseRecorder) ipamEnvelope {
	t.Helper()
	var env ipamEnvelope
	if err := json.NewDecoder(rec.Body).Decode(&env); err != nil {
		t.Fatalf("decode envelope: %v (body=%s)", err, rec.Body.String())
	}
	return env
}

func testPoolProto(id string) *platformv1.IPAMPool {
	return &platformv1.IPAMPool{
		Id:        id,
		Name:      id,
		Cidr:      "10.0.0.0/24",
		Gateway:   "10.0.0.1",
		Zone:      "control-plane",
		Total:     254,
		Allocated: 3,
		Available: 251,
		CreatedAt: timestamppb.Now(),
		UpdatedAt: timestamppb.Now(),
	}
}

func TestIPAMRoutes_ListPools(t *testing.T) {
	var gotZone string
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		listPoolsFunc: func(_ context.Context, req *platformv1.ListIPAMPoolsRequest) (*platformv1.ListIPAMPoolsResponse, error) {
			gotZone = req.GetZone()
			return &platformv1.ListIPAMPoolsResponse{
				Pools: []*platformv1.IPAMPool{testPoolProto("prod-v4")},
			}, nil
		},
	})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sdn/gateway/ipam/pools?zone=control-plane", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if gotZone != "control-plane" {
		t.Fatalf("zone filter = %q, want control-plane", gotZone)
	}

	env := decodeIPAMEnvelope(t, rec)
	var payload IPAMPoolListResponse
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Count != 1 || len(payload.Pools) != 1 {
		t.Fatalf("pools = %+v, want one pool", payload)
	}
	p := payload.Pools[0]
	if p.ID != "prod-v4" || p.CIDR != "10.0.0.0/24" || p.Total != 254 || p.Available != 251 {
		t.Fatalf("pool fields wrong: %+v", p)
	}
}

func TestIPAMRoutes_CreatePool(t *testing.T) {
	var gotReq *platformv1.CreateIPAMPoolRequest
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		createPoolFunc: func(_ context.Context, req *platformv1.CreateIPAMPoolRequest) (*platformv1.CreateIPAMPoolResponse, error) {
			gotReq = req
			return &platformv1.CreateIPAMPoolResponse{Pool: testPoolProto(req.GetName())}, nil
		},
	})

	body := bytes.NewBufferString(`{"name":"prod-v4","cidr":"10.0.0.0/24","gateway":"10.0.0.1","zone":"control-plane"}`)
	req := httptest.NewRequest(http.MethodPost, "/sdn/gateway/ipam/pools", body)
	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if gotReq.GetName() != "prod-v4" || gotReq.GetCidr() != "10.0.0.0/24" || gotReq.GetZone() != "control-plane" {
		t.Fatalf("request not converted: %+v", gotReq)
	}
}

func TestIPAMRoutes_UpdateAndDeletePoolByID(t *testing.T) {
	var updatedID, deletedID string
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		getPoolFunc: func(_ context.Context, req *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error) {
			return &platformv1.GetIPAMPoolResponse{Pool: testPoolProto(req.GetId())}, nil
		},
		updatePoolFunc: func(_ context.Context, req *platformv1.UpdateIPAMPoolRequest) (*platformv1.UpdateIPAMPoolResponse, error) {
			updatedID = req.GetId()
			return &platformv1.UpdateIPAMPoolResponse{Pool: testPoolProto(req.GetId())}, nil
		},
		deletePoolFunc: func(_ context.Context, req *platformv1.DeleteIPAMPoolRequest) (*platformv1.DeleteIPAMPoolResponse, error) {
			deletedID = req.GetId()
			return &platformv1.DeleteIPAMPoolResponse{}, nil
		},
	})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/sdn/gateway/ipam/pools/prod-v4", bytes.NewBufferString(`{"name":"renamed"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("update status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if updatedID != "prod-v4" {
		t.Fatalf("updated id = %q, want prod-v4", updatedID)
	}

	rec = httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/sdn/gateway/ipam/pools/prod-v4", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("delete status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if deletedID != "prod-v4" {
		t.Fatalf("deleted id = %q, want prod-v4", deletedID)
	}
}

func TestIPAMRoutes_UpdatePoolPreservesOmittedFields(t *testing.T) {
	// The gRPC UpdateIPAMPool applies zone/description/lease/inactivity
	// unconditionally, so the REST wrapper must merge from the current
	// pool: a body carrying only {name} must not clear anything else.
	existing := testPoolProto("prod-v4")
	existing.Description = "production IPv4"
	existing.DefaultLeaseDurationNanos = 86400e9
	existing.InactivityTimeoutNanos = 3600e9

	var gotUpdate *platformv1.UpdateIPAMPoolRequest
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		getPoolFunc: func(_ context.Context, req *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error) {
			return &platformv1.GetIPAMPoolResponse{Pool: existing}, nil
		},
		updatePoolFunc: func(_ context.Context, req *platformv1.UpdateIPAMPoolRequest) (*platformv1.UpdateIPAMPoolResponse, error) {
			gotUpdate = req
			return &platformv1.UpdateIPAMPoolResponse{Pool: existing}, nil
		},
	})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/sdn/gateway/ipam/pools/prod-v4", bytes.NewBufferString(`{"name":"renamed"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if gotUpdate.GetName() != "renamed" {
		t.Fatalf("name = %q, want renamed", gotUpdate.GetName())
	}
	if gotUpdate.GetZone() != "control-plane" ||
		gotUpdate.GetDescription() != "production IPv4" ||
		gotUpdate.GetGateway() != "10.0.0.1" ||
		gotUpdate.GetDefaultLeaseDurationNanos() != 86400e9 ||
		gotUpdate.GetInactivityTimeoutNanos() != 3600e9 {
		t.Fatalf("omitted fields were not preserved: %+v", gotUpdate)
	}
}

func TestIPAMRoutes_Allocations(t *testing.T) {
	var gotPoolID, releasedIP string
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		listAllocsFunc: func(_ context.Context, req *platformv1.ListAllocationsRequest) (*platformv1.ListAllocationsResponse, error) {
			gotPoolID = req.GetPoolId()
			return &platformv1.ListAllocationsResponse{
				Allocations: []*platformv1.IPAllocation{
					{Ip: "10.0.0.10", PoolId: req.GetPoolId(), Hostname: "node-03", Status: "active", AllocatedAt: timestamppb.Now()},
				},
			}, nil
		},
		allocateFunc: func(_ context.Context, req *platformv1.AllocateIPRequest) (*platformv1.AllocateIPResponse, error) {
			return &platformv1.AllocateIPResponse{
				Allocation: &platformv1.IPAllocation{Ip: "10.0.0.11", PoolId: req.GetPoolId()},
			}, nil
		},
		releaseFunc: func(_ context.Context, req *platformv1.ReleaseIPRequest) (*platformv1.ReleaseIPResponse, error) {
			releasedIP = req.GetIp()
			return &platformv1.ReleaseIPResponse{}, nil
		},
	})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sdn/gateway/ipam/allocations?pool_id=prod-v4", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("list status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if gotPoolID != "prod-v4" {
		t.Fatalf("pool_id filter = %q, want prod-v4", gotPoolID)
	}
	env := decodeIPAMEnvelope(t, rec)
	var payload IPAllocationListResponse
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload.Count != 1 || payload.Allocations[0].IP != "10.0.0.10" || payload.Allocations[0].Status != "active" {
		t.Fatalf("allocations wrong: %+v", payload)
	}

	rec = httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sdn/gateway/ipam/allocations", bytes.NewBufferString(`{"pool_id":"prod-v4","hostname":"node-04"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("allocate status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/sdn/gateway/ipam/allocations/10.0.0.11", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("release status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if releasedIP != "10.0.0.11" {
		t.Fatalf("released ip = %q, want 10.0.0.11", releasedIP)
	}
}

func TestIPAMRoutes_ErrorMapping(t *testing.T) {
	cases := []struct {
		name string
		code codes.Code
		want int
	}{
		{"unavailable maps 503", codes.Unavailable, http.StatusServiceUnavailable},
		{"already exists maps 409", codes.AlreadyExists, http.StatusConflict},
		{"not found maps 404", codes.NotFound, http.StatusNotFound},
		{"invalid argument maps 400", codes.InvalidArgument, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
				listPoolsFunc: func(_ context.Context, _ *platformv1.ListIPAMPoolsRequest) (*platformv1.ListIPAMPoolsResponse, error) {
					return nil, status.Error(tc.code, "ipam backend says no")
				},
			})
			rec := httptest.NewRecorder()
			mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sdn/gateway/ipam/pools", nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestIPAMRoutes_NilServerAnswers503(t *testing.T) {
	mr := newIPAMTestRouter(t, nil)

	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/sdn/gateway/ipam/pools"},
		{http.MethodGet, "/sdn/gateway/ipam/pools"},
		{http.MethodGet, "/sdn/gateway/ipam/pools/prod-v4"},
		{http.MethodPut, "/sdn/gateway/ipam/pools/prod-v4"},
		{http.MethodDelete, "/sdn/gateway/ipam/pools/prod-v4"},
		{http.MethodPost, "/sdn/gateway/ipam/allocations"},
		{http.MethodGet, "/sdn/gateway/ipam/allocations"},
		{http.MethodDelete, "/sdn/gateway/ipam/allocations/10.0.0.11"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mr.ServeHTTP(rec, httptest.NewRequest(route.method, route.path, bytes.NewBufferString(`{}`)))
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("status = %d, want 503 (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

func TestIPAMRoutes_InvalidBodyAnswers400(t *testing.T) {
	// The empty mock answers every RPC with Unimplemented, so a body that
	// reached the service would surface as something other than 400.
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{})

	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/sdn/gateway/ipam/pools"},
		{http.MethodPut, "/sdn/gateway/ipam/pools/prod-v4"},
		{http.MethodPost, "/sdn/gateway/ipam/allocations"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mr.ServeHTTP(rec, httptest.NewRequest(route.method, route.path, bytes.NewBufferString("{not json")))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestIPAMRoutes_ActionResponsesMatchDaemonShape pins the promise both REST
// references make — that the webservice and the daemon REST stack serve "the
// same object shapes". The list endpoints always did; the pool-delete and
// allocation-release endpoints originally returned a bare {"id"} / {"ip"}
// while the daemon returned its GatewayActionResponse envelope, so a client
// written against the documented contract broke on exactly those two.
//
// It asserts by decoding the webservice payload into the DAEMON's own struct
// rather than into the local mirror: a test against the local type would keep
// passing if the two drifted apart again, which is the bug this covers.
func TestIPAMRoutes_ActionResponsesMatchDaemonShape(t *testing.T) {
	svc := &mockIPAMGatewayService{
		deletePoolFunc: func(_ context.Context, _ *platformv1.DeleteIPAMPoolRequest) (*platformv1.DeleteIPAMPoolResponse, error) {
			return &platformv1.DeleteIPAMPoolResponse{}, nil
		},
		releaseFunc: func(_ context.Context, _ *platformv1.ReleaseIPRequest) (*platformv1.ReleaseIPResponse, error) {
			return &platformv1.ReleaseIPResponse{}, nil
		},
	}
	mr := newIPAMTestRouter(t, svc)

	for _, tc := range []struct {
		name         string
		path         string
		resourceID   string
		resourceType string
		action       string
	}{
		{"delete pool", "/sdn/gateway/ipam/pools/prod-v4", "prod-v4", "ipam_pool", "delete"},
		{"release ip", "/sdn/gateway/ipam/allocations/10.0.0.11", "10.0.0.11", "ip_allocation", "release"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			mr.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, tc.path, nil))
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
			}

			var daemonShaped rest.GatewayActionResponse
			if err := json.Unmarshal(decodeIPAMEnvelope(t, rec).Payload, &daemonShaped); err != nil {
				t.Fatalf("payload does not decode into the daemon's GatewayActionResponse: %v", err)
			}
			if daemonShaped.ResourceID != tc.resourceID {
				t.Errorf("resource_id = %q, want %q", daemonShaped.ResourceID, tc.resourceID)
			}
			if daemonShaped.ResourceType != tc.resourceType {
				t.Errorf("resource_type = %q, want %q", daemonShaped.ResourceType, tc.resourceType)
			}
			if daemonShaped.Action != tc.action {
				t.Errorf("action = %q, want %q", daemonShaped.Action, tc.action)
			}
			if !daemonShaped.Success {
				t.Error("success = false, want true")
			}
			if daemonShaped.Message == "" {
				t.Error("message is empty; the daemon stack always sets one")
			}
		})
	}
}

func TestIPAMRoutes_CreatePoolCarriesWindow(t *testing.T) {
	var gotReq *platformv1.CreateIPAMPoolRequest
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		createPoolFunc: func(_ context.Context, req *platformv1.CreateIPAMPoolRequest) (*platformv1.CreateIPAMPoolResponse, error) {
			gotReq = req
			p := testPoolProto(req.GetName())
			p.Reserved = req.GetReserved()
			p.RangeStart = req.GetRangeStart()
			p.RangeEnd = req.GetRangeEnd()
			return &platformv1.CreateIPAMPoolResponse{Pool: p}, nil
		},
	})

	body := bytes.NewBufferString(`{"name":"provisioning","cidr":"192.0.2.0/24","gateway":"192.0.2.1",` +
		`"reserved":["192.0.2.1/32"],"range_start":"192.0.2.50","range_end":"192.0.2.254"}`)
	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sdn/gateway/ipam/pools", body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	if len(gotReq.GetReserved()) != 1 || gotReq.GetRangeStart() != "192.0.2.50" || gotReq.GetRangeEnd() != "192.0.2.254" {
		t.Fatalf("window not converted: %+v", gotReq)
	}
	var pool IPAMPoolResponse
	if err := json.Unmarshal(decodeIPAMEnvelope(t, rec).Payload, &pool); err != nil {
		t.Fatalf("decode pool: %v", err)
	}
	if pool.RangeStart != "192.0.2.50" || pool.Reserved[0] != "192.0.2.1/32" {
		t.Fatalf("window not in response: %+v", pool)
	}
}

func TestIPAMRoutes_UpdatePoolWindow(t *testing.T) {
	existing := testPoolProto("provisioning")
	existing.Reserved = []string{"10.0.0.1/32"}
	existing.RangeStart = "10.0.0.50"
	existing.RangeEnd = "10.0.0.254"

	var gotUpdate *platformv1.UpdateIPAMPoolRequest
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		getPoolFunc: func(_ context.Context, _ *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error) {
			return &platformv1.GetIPAMPoolResponse{Pool: existing}, nil
		},
		updatePoolFunc: func(_ context.Context, req *platformv1.UpdateIPAMPoolRequest) (*platformv1.UpdateIPAMPoolResponse, error) {
			gotUpdate = req
			return &platformv1.UpdateIPAMPoolResponse{Pool: existing}, nil
		},
	})
	put := func(body string) {
		t.Helper()
		rec := httptest.NewRecorder()
		mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/sdn/gateway/ipam/pools/provisioning", bytes.NewBufferString(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
		}
	}

	// No window field: the window is left alone.
	put(`{"name":"renamed"}`)
	if gotUpdate.GetUpdateWindow() {
		t.Fatalf("a body without window fields must not replace the window: %+v", gotUpdate)
	}

	// One window field: the others keep the pool's values.
	put(`{"range_start":"10.0.0.100"}`)
	if !gotUpdate.GetUpdateWindow() || gotUpdate.GetRangeStart() != "10.0.0.100" ||
		gotUpdate.GetRangeEnd() != "10.0.0.254" || len(gotUpdate.GetReserved()) != 1 {
		t.Fatalf("window not merged: %+v", gotUpdate)
	}

	// Empty values clear the window.
	put(`{"reserved":[],"range_start":"","range_end":""}`)
	if !gotUpdate.GetUpdateWindow() || len(gotUpdate.GetReserved()) != 0 ||
		gotUpdate.GetRangeStart() != "" || gotUpdate.GetRangeEnd() != "" {
		t.Fatalf("window not cleared: %+v", gotUpdate)
	}
}

func TestDerefString(t *testing.T) {
	s := "x"
	if derefString(&s) != "x" || derefString(nil) != "" {
		t.Fatal("derefString")
	}
}

func TestIPAMRoutes_GetPool(t *testing.T) {
	var gotID string
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		getPoolFunc: func(_ context.Context, req *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error) {
			gotID = req.GetId()
			if req.GetId() != "prod-v4" {
				return nil, status.Error(codes.NotFound, "pool not found")
			}
			return &platformv1.GetIPAMPoolResponse{Pool: testPoolProto("prod-v4")}, nil
		},
	})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sdn/gateway/ipam/pools/prod-v4", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if gotID != "prod-v4" {
		t.Fatalf("pool id = %q, want prod-v4", gotID)
	}
	var pool IPAMPoolResponse
	if err := json.Unmarshal(decodeIPAMEnvelope(t, rec).Payload, &pool); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if pool.ID != "prod-v4" || pool.CIDR != "10.0.0.0/24" || pool.Available != 251 {
		t.Fatalf("pool wrong: %+v", pool)
	}

	rec = httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/sdn/gateway/ipam/pools/missing", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("missing pool status = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}
}

// failingIPAMService answers every IPAM RPC with err.
func failingIPAMService(err error) *mockIPAMGatewayService {
	return &mockIPAMGatewayService{
		createPoolFunc: func(context.Context, *platformv1.CreateIPAMPoolRequest) (*platformv1.CreateIPAMPoolResponse, error) {
			return nil, err
		},
		getPoolFunc: func(context.Context, *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error) {
			return nil, err
		},
		updatePoolFunc: func(context.Context, *platformv1.UpdateIPAMPoolRequest) (*platformv1.UpdateIPAMPoolResponse, error) {
			return nil, err
		},
		deletePoolFunc: func(context.Context, *platformv1.DeleteIPAMPoolRequest) (*platformv1.DeleteIPAMPoolResponse, error) {
			return nil, err
		},
		allocateFunc: func(context.Context, *platformv1.AllocateIPRequest) (*platformv1.AllocateIPResponse, error) {
			return nil, err
		},
		releaseFunc: func(context.Context, *platformv1.ReleaseIPRequest) (*platformv1.ReleaseIPResponse, error) {
			return nil, err
		},
		listAllocsFunc: func(context.Context, *platformv1.ListAllocationsRequest) (*platformv1.ListAllocationsResponse, error) {
			return nil, err
		},
	}
}

func TestIPAMRoutes_ServiceErrorsReachTheCaller(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		body   string
		code   codes.Code
		want   int
	}{
		{"create pool conflict", http.MethodPost, "/sdn/gateway/ipam/pools", `{"id":"prod-v4","cidr":"10.0.0.0/24"}`, codes.AlreadyExists, http.StatusConflict},
		{"update unknown pool", http.MethodPut, "/sdn/gateway/ipam/pools/missing", `{"name":"renamed"}`, codes.NotFound, http.StatusNotFound},
		{"delete unknown pool", http.MethodDelete, "/sdn/gateway/ipam/pools/missing", "", codes.NotFound, http.StatusNotFound},
		{"allocate from exhausted pool", http.MethodPost, "/sdn/gateway/ipam/allocations", `{"pool_id":"prod-v4"}`, codes.ResourceExhausted, http.StatusTooManyRequests},
		{"list allocations unavailable", http.MethodGet, "/sdn/gateway/ipam/allocations", "", codes.Unavailable, http.StatusServiceUnavailable},
		{"release unknown ip", http.MethodDelete, "/sdn/gateway/ipam/allocations/10.0.0.99", "", codes.NotFound, http.StatusNotFound},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mr := newIPAMTestRouter(t, failingIPAMService(status.Error(tc.code, "ipam backend says no")))
			rec := httptest.NewRecorder()
			mr.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, bytes.NewBufferString(tc.body)))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (body=%s)", rec.Code, tc.want, rec.Body.String())
			}
			if env := decodeIPAMEnvelope(t, rec); env.Success {
				t.Fatalf("envelope reports success for a failed call: %+v", env)
			}
		})
	}
}

func TestIPAMRoutes_UpdatePoolRejectedByService(t *testing.T) {
	// The merge read succeeds; the update itself is refused, and that
	// refusal is what the caller sees.
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		getPoolFunc: func(context.Context, *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error) {
			return &platformv1.GetIPAMPoolResponse{Pool: testPoolProto("prod-v4")}, nil
		},
		updatePoolFunc: func(context.Context, *platformv1.UpdateIPAMPoolRequest) (*platformv1.UpdateIPAMPoolResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "gateway outside the pool CIDR")
		},
	})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/sdn/gateway/ipam/pools/prod-v4", bytes.NewBufferString(`{"gateway":"192.0.2.1"}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestIPAMRoutes_UpdatePoolAppliesEveryProvidedField(t *testing.T) {
	var gotUpdate *platformv1.UpdateIPAMPoolRequest
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		getPoolFunc: func(context.Context, *platformv1.GetIPAMPoolRequest) (*platformv1.GetIPAMPoolResponse, error) {
			return &platformv1.GetIPAMPoolResponse{Pool: testPoolProto("prod-v4")}, nil
		},
		updatePoolFunc: func(_ context.Context, req *platformv1.UpdateIPAMPoolRequest) (*platformv1.UpdateIPAMPoolResponse, error) {
			gotUpdate = req
			return &platformv1.UpdateIPAMPoolResponse{Pool: testPoolProto("prod-v4")}, nil
		},
	})

	body := `{"gateway":"10.0.0.254","zone":"edge","description":"edge IPv4",` +
		`"default_lease_duration_nanos":7200000000000,"inactivity_timeout_nanos":600000000000}`
	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/sdn/gateway/ipam/pools/prod-v4", bytes.NewBufferString(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if gotUpdate.GetName() != "prod-v4" {
		t.Fatalf("omitted name was not preserved: %q", gotUpdate.GetName())
	}
	if gotUpdate.GetGateway() != "10.0.0.254" ||
		gotUpdate.GetZone() != "edge" ||
		gotUpdate.GetDescription() != "edge IPv4" ||
		gotUpdate.GetDefaultLeaseDurationNanos() != 7200e9 ||
		gotUpdate.GetInactivityTimeoutNanos() != 600e9 {
		t.Fatalf("provided fields were not applied: %+v", gotUpdate)
	}
	if gotUpdate.GetUpdateWindow() {
		t.Fatal("a body without window fields must not replace the window")
	}
}

func TestIPAMRoutes_AllocateReportsLeaseTimes(t *testing.T) {
	allocatedAt := timestamppb.Now()
	expiresAt := timestamppb.New(allocatedAt.AsTime().Add(86400e9))
	mr := newIPAMTestRouter(t, &mockIPAMGatewayService{
		allocateFunc: func(_ context.Context, req *platformv1.AllocateIPRequest) (*platformv1.AllocateIPResponse, error) {
			return &platformv1.AllocateIPResponse{Allocation: &platformv1.IPAllocation{
				Ip: "10.0.0.12", PoolId: req.GetPoolId(), DeviceId: req.GetDeviceId(), Status: "active",
				AllocatedAt: allocatedAt, ExpiresAt: expiresAt,
			}}, nil
		},
	})

	rec := httptest.NewRecorder()
	mr.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sdn/gateway/ipam/allocations", bytes.NewBufferString(`{"pool_id":"prod-v4","device_id":"dev-7"}`)))
	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 (body=%s)", rec.Code, rec.Body.String())
	}
	var alloc IPAllocationResponse
	if err := json.Unmarshal(decodeIPAMEnvelope(t, rec).Payload, &alloc); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if alloc.IP != "10.0.0.12" || alloc.PoolID != "prod-v4" || alloc.DeviceID != "dev-7" {
		t.Fatalf("allocation wrong: %+v", alloc)
	}
	if alloc.AllocatedAt == nil || !alloc.AllocatedAt.Equal(allocatedAt.AsTime()) {
		t.Fatalf("allocated_at = %v, want %v", alloc.AllocatedAt, allocatedAt.AsTime())
	}
	if alloc.ExpiresAt == nil || !alloc.ExpiresAt.Equal(expiresAt.AsTime()) {
		t.Fatalf("expires_at = %v, want %v", alloc.ExpiresAt, expiresAt.AsTime())
	}
}
