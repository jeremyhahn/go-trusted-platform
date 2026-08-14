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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// fakeProxyBackend is a configurable ProxyServiceBackend test double.
type fakeProxyBackend struct {
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

	lastUpdateRouteID string
	lastUpdatePoolID  string
	lastDeletedID     string
	lastCreateRoute   *platformv1.ProxyRoute
}

func (f *fakeProxyBackend) CreateRoute(ctx context.Context, req *platformv1.CreateProxyRouteRequest) (*platformv1.CreateProxyRouteResponse, error) {
	f.lastCreateRoute = req.GetRoute()
	return f.createRouteResp, f.err
}

func (f *fakeProxyBackend) GetRoute(ctx context.Context, req *platformv1.GetProxyRouteRequest) (*platformv1.GetProxyRouteResponse, error) {
	return f.getRouteResp, f.err
}

func (f *fakeProxyBackend) UpdateRoute(ctx context.Context, req *platformv1.UpdateProxyRouteRequest) (*platformv1.UpdateProxyRouteResponse, error) {
	f.lastUpdateRouteID = req.GetId()
	return f.updateRouteResp, f.err
}

func (f *fakeProxyBackend) DeleteRoute(ctx context.Context, req *platformv1.DeleteProxyRouteRequest) (*platformv1.DeleteProxyRouteResponse, error) {
	f.lastDeletedID = req.GetId()
	return f.deleteRouteResp, f.err
}

func (f *fakeProxyBackend) ListRoutes(ctx context.Context, req *platformv1.ListProxyRoutesRequest) (*platformv1.ListProxyRoutesResponse, error) {
	return f.listRoutesResp, f.err
}

func (f *fakeProxyBackend) CreatePool(ctx context.Context, req *platformv1.CreateProxyPoolRequest) (*platformv1.CreateProxyPoolResponse, error) {
	return f.createPoolResp, f.err
}

func (f *fakeProxyBackend) GetPool(ctx context.Context, req *platformv1.GetProxyPoolRequest) (*platformv1.GetProxyPoolResponse, error) {
	return f.getPoolResp, f.err
}

func (f *fakeProxyBackend) UpdatePool(ctx context.Context, req *platformv1.UpdateProxyPoolRequest) (*platformv1.UpdateProxyPoolResponse, error) {
	f.lastUpdatePoolID = req.GetId()
	return f.updatePoolResp, f.err
}

func (f *fakeProxyBackend) DeletePool(ctx context.Context, req *platformv1.DeleteProxyPoolRequest) (*platformv1.DeleteProxyPoolResponse, error) {
	f.lastDeletedID = req.GetId()
	return f.deletePoolResp, f.err
}

func (f *fakeProxyBackend) ListPools(ctx context.Context, req *platformv1.ListProxyPoolsRequest) (*platformv1.ListProxyPoolsResponse, error) {
	return f.listPoolsResp, f.err
}

func (f *fakeProxyBackend) GetProxyConfig(ctx context.Context, req *platformv1.GetProxyConfigRequest) (*platformv1.GetProxyConfigResponse, error) {
	return f.configResp, f.err
}

func (f *fakeProxyBackend) GetProxyStatus(ctx context.Context, req *platformv1.GetProxyStatusRequest) (*platformv1.GetProxyStatusResponse, error) {
	return f.statusResp, f.err
}

func (f *fakeProxyBackend) ReloadProxyConfig(ctx context.Context, req *platformv1.ReloadProxyConfigRequest) (*platformv1.ReloadProxyConfigResponse, error) {
	return f.reloadResp, f.err
}

func (f *fakeProxyBackend) GetZoneMatrix(ctx context.Context, req *platformv1.GetProxyZoneMatrixRequest) (*platformv1.GetProxyZoneMatrixResponse, error) {
	return f.matrixResp, f.err
}

// newProxyTestRouter builds a mux router with the proxy routes registered
// over the given backend.
func newProxyTestRouter(backend ProxyServiceBackend) *mux.Router {
	router := mux.NewRouter()
	NewProxyHandlers(backend, nil).RegisterRoutes(router)
	return router
}

// doProxyRequest performs an HTTP request against the test router.
// A non-nil body proto message is protojson-encoded.
func doProxyRequest(t *testing.T, router *mux.Router, method, path string, body proto.Message) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := protojson.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, reader)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// decodeProxyResponse protojson-decodes the recorded body into msg.
func decodeProxyResponse(t *testing.T, rec *httptest.ResponseRecorder, msg proto.Message) {
	t.Helper()
	opts := protojson.UnmarshalOptions{DiscardUnknown: true}
	if err := opts.Unmarshal(rec.Body.Bytes(), msg); err != nil {
		t.Fatalf("decode response %q: %v", rec.Body.String(), err)
	}
}

func TestProxyRESTHandlers_CreateRoute(t *testing.T) {
	fake := &fakeProxyBackend{
		createRouteResp: &platformv1.CreateProxyRouteResponse{
			Route:   &platformv1.ProxyRoute{Id: "web", PoolId: "pool-1", PathPrefix: "/"},
			Version: 2,
		},
	}
	router := newProxyTestRouter(fake)

	rec := doProxyRequest(t, router, http.MethodPost, "/api/v1/proxy/routes", &platformv1.CreateProxyRouteRequest{
		Route: &platformv1.ProxyRoute{Id: "web", PoolId: "pool-1", PathPrefix: "/",
			Auth: &platformv1.ProxyAuthRequirements{Mode: "public"}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("code = %d body %s, want 201", rec.Code, rec.Body.String())
	}
	var resp platformv1.CreateProxyRouteResponse
	decodeProxyResponse(t, rec, &resp)
	if resp.GetRoute().GetId() != "web" || resp.GetVersion() != 2 {
		t.Errorf("response = %v v%d, want web v2", resp.GetRoute().GetId(), resp.GetVersion())
	}
	if fake.lastCreateRoute.GetAuth().GetMode() != "public" {
		t.Errorf("backend received auth mode %q, want public", fake.lastCreateRoute.GetAuth().GetMode())
	}
}

func TestProxyRESTHandlers_CreateRoute_BadBody(t *testing.T) {
	router := newProxyTestRouter(&fakeProxyBackend{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/proxy/routes", bytes.NewReader([]byte("{not json")))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("code = %d, want 400", rec.Code)
	}
	var envelope map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &envelope); err != nil {
		t.Fatalf("error envelope not JSON: %v", err)
	}
	if envelope["error"] == "" {
		t.Error("error envelope missing error field")
	}
}

func TestProxyRESTHandlers_GetRoute(t *testing.T) {
	fake := &fakeProxyBackend{
		getRouteResp: &platformv1.GetProxyRouteResponse{
			Route: &platformv1.ProxyRoute{Id: "web", PoolId: "pool-1"},
		},
	}
	router := newProxyTestRouter(fake)

	rec := doProxyRequest(t, router, http.MethodGet, "/api/v1/proxy/routes/web", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body %s, want 200", rec.Code, rec.Body.String())
	}
	var resp platformv1.GetProxyRouteResponse
	decodeProxyResponse(t, rec, &resp)
	if resp.GetRoute().GetPoolId() != "pool-1" {
		t.Errorf("pool id = %q, want pool-1", resp.GetRoute().GetPoolId())
	}
}

func TestProxyRESTHandlers_GetRoute_NotFound(t *testing.T) {
	fake := &fakeProxyBackend{err: status.Error(codes.NotFound, "proxy route not found: ghost")}
	router := newProxyTestRouter(fake)

	rec := doProxyRequest(t, router, http.MethodGet, "/api/v1/proxy/routes/ghost", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("code = %d, want 404", rec.Code)
	}
}

func TestProxyRESTHandlers_UpdateRoute_IDFromURL(t *testing.T) {
	fake := &fakeProxyBackend{
		updateRouteResp: &platformv1.UpdateProxyRouteResponse{
			Route:   &platformv1.ProxyRoute{Id: "web"},
			Version: 3,
		},
	}
	router := newProxyTestRouter(fake)

	rec := doProxyRequest(t, router, http.MethodPut, "/api/v1/proxy/routes/web", &platformv1.UpdateProxyRouteRequest{
		Route: &platformv1.ProxyRoute{PoolId: "pool-2", PathPrefix: "/"},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d body %s, want 200", rec.Code, rec.Body.String())
	}
	if fake.lastUpdateRouteID != "web" {
		t.Errorf("backend received id %q, want web (from URL)", fake.lastUpdateRouteID)
	}
}

func TestProxyRESTHandlers_DeleteRoute(t *testing.T) {
	fake := &fakeProxyBackend{deleteRouteResp: &platformv1.DeleteProxyRouteResponse{Version: 4}}
	router := newProxyTestRouter(fake)

	rec := doProxyRequest(t, router, http.MethodDelete, "/api/v1/proxy/routes/web", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	if fake.lastDeletedID != "web" {
		t.Errorf("backend received id %q, want web", fake.lastDeletedID)
	}
	var resp platformv1.DeleteProxyRouteResponse
	decodeProxyResponse(t, rec, &resp)
	if resp.GetVersion() != 4 {
		t.Errorf("version = %d, want 4", resp.GetVersion())
	}
}

func TestProxyRESTHandlers_ListRoutes(t *testing.T) {
	fake := &fakeProxyBackend{
		listRoutesResp: &platformv1.ListProxyRoutesResponse{
			Routes:  []*platformv1.ProxyRoute{{Id: "a"}, {Id: "b"}},
			Version: 7,
		},
	}
	router := newProxyTestRouter(fake)

	rec := doProxyRequest(t, router, http.MethodGet, "/api/v1/proxy/routes", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, want 200", rec.Code)
	}
	var resp platformv1.ListProxyRoutesResponse
	decodeProxyResponse(t, rec, &resp)
	if len(resp.GetRoutes()) != 2 || resp.GetVersion() != 7 {
		t.Errorf("list = (%d, v%d), want (2, v7)", len(resp.GetRoutes()), resp.GetVersion())
	}
}

func TestProxyRESTHandlers_PoolLifecycle(t *testing.T) {
	fake := &fakeProxyBackend{
		createPoolResp: &platformv1.CreateProxyPoolResponse{Pool: &platformv1.ProxyPool{Id: "pool-1"}, Version: 1},
		getPoolResp:    &platformv1.GetProxyPoolResponse{Pool: &platformv1.ProxyPool{Id: "pool-1"}},
		updatePoolResp: &platformv1.UpdateProxyPoolResponse{Pool: &platformv1.ProxyPool{Id: "pool-1"}, Version: 2},
		deletePoolResp: &platformv1.DeleteProxyPoolResponse{Version: 3},
		listPoolsResp:  &platformv1.ListProxyPoolsResponse{Pools: []*platformv1.ProxyPool{{Id: "pool-1"}}, Version: 3},
	}
	router := newProxyTestRouter(fake)

	rec := doProxyRequest(t, router, http.MethodPost, "/api/v1/proxy/pools", &platformv1.CreateProxyPoolRequest{
		Pool: &platformv1.ProxyPool{Id: "pool-1", Backends: []*platformv1.ProxyBackend{{Url: "https://b:8443"}}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create code = %d body %s, want 201", rec.Code, rec.Body.String())
	}

	if rec := doProxyRequest(t, router, http.MethodGet, "/api/v1/proxy/pools/pool-1", nil); rec.Code != http.StatusOK {
		t.Fatalf("get code = %d, want 200", rec.Code)
	}
	if rec := doProxyRequest(t, router, http.MethodPut, "/api/v1/proxy/pools/pool-1", &platformv1.UpdateProxyPoolRequest{
		Pool: &platformv1.ProxyPool{Backends: []*platformv1.ProxyBackend{{Url: "https://b:8443"}}},
	}); rec.Code != http.StatusOK {
		t.Fatalf("update code = %d, want 200", rec.Code)
	}
	if fake.lastUpdatePoolID != "pool-1" {
		t.Errorf("backend received pool id %q, want pool-1 (from URL)", fake.lastUpdatePoolID)
	}
	if rec := doProxyRequest(t, router, http.MethodDelete, "/api/v1/proxy/pools/pool-1", nil); rec.Code != http.StatusOK {
		t.Fatalf("delete code = %d, want 200", rec.Code)
	}
	if rec := doProxyRequest(t, router, http.MethodGet, "/api/v1/proxy/pools", nil); rec.Code != http.StatusOK {
		t.Fatalf("list code = %d, want 200", rec.Code)
	}
}

func TestProxyRESTHandlers_PoolConflictErrors(t *testing.T) {
	router := newProxyTestRouter(&fakeProxyBackend{err: status.Error(codes.AlreadyExists, "proxy pool already exists: pool-1")})
	rec := doProxyRequest(t, router, http.MethodPost, "/api/v1/proxy/pools", &platformv1.CreateProxyPoolRequest{
		Pool: &platformv1.ProxyPool{Id: "pool-1"},
	})
	if rec.Code != http.StatusConflict {
		t.Fatalf("exists code = %d, want 409", rec.Code)
	}

	router = newProxyTestRouter(&fakeProxyBackend{err: status.Error(codes.FailedPrecondition, "proxy pool in use: pool-1")})
	rec = doProxyRequest(t, router, http.MethodDelete, "/api/v1/proxy/pools/pool-1", nil)
	if rec.Code != http.StatusConflict {
		t.Fatalf("in-use code = %d, want 409", rec.Code)
	}
}

func TestProxyRESTHandlers_ConfigStatusReloadMatrix(t *testing.T) {
	fake := &fakeProxyBackend{
		configResp: &platformv1.GetProxyConfigResponse{Version: 5},
		statusResp: &platformv1.GetProxyStatusResponse{Version: 5, RouteCount: 2},
		reloadResp: &platformv1.ReloadProxyConfigResponse{Version: 6},
		matrixResp: &platformv1.GetProxyZoneMatrixResponse{Zones: []string{"public"}},
	}
	router := newProxyTestRouter(fake)

	rec := doProxyRequest(t, router, http.MethodGet, "/api/v1/proxy/config", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("config code = %d, want 200", rec.Code)
	}
	var cfg platformv1.GetProxyConfigResponse
	decodeProxyResponse(t, rec, &cfg)
	if cfg.GetVersion() != 5 {
		t.Errorf("config version = %d, want 5", cfg.GetVersion())
	}

	rec = doProxyRequest(t, router, http.MethodGet, "/api/v1/proxy/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status code = %d, want 200", rec.Code)
	}
	var st platformv1.GetProxyStatusResponse
	decodeProxyResponse(t, rec, &st)
	if st.GetRouteCount() != 2 {
		t.Errorf("route count = %d, want 2", st.GetRouteCount())
	}

	rec = doProxyRequest(t, router, http.MethodPost, "/api/v1/proxy/reload", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("reload code = %d, want 200", rec.Code)
	}
	var reload platformv1.ReloadProxyConfigResponse
	decodeProxyResponse(t, rec, &reload)
	if reload.GetVersion() != 6 {
		t.Errorf("reload version = %d, want 6", reload.GetVersion())
	}

	rec = doProxyRequest(t, router, http.MethodGet, "/api/v1/proxy/zone-matrix", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("matrix code = %d, want 200", rec.Code)
	}
}

func TestProxyRESTHandlers_ZoneMatrixUnavailable(t *testing.T) {
	router := newProxyTestRouter(&fakeProxyBackend{err: status.Error(codes.Unavailable, "no zone service")})
	rec := doProxyRequest(t, router, http.MethodGet, "/api/v1/proxy/zone-matrix", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code = %d, want 503", rec.Code)
	}
}

func TestProxyRESTHandlers_NilService(t *testing.T) {
	router := newProxyTestRouter(nil)
	paths := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/proxy/routes"},
		{http.MethodGet, "/api/v1/proxy/routes"},
		{http.MethodGet, "/api/v1/proxy/routes/x"},
		{http.MethodPut, "/api/v1/proxy/routes/x"},
		{http.MethodDelete, "/api/v1/proxy/routes/x"},
		{http.MethodPost, "/api/v1/proxy/pools"},
		{http.MethodGet, "/api/v1/proxy/pools"},
		{http.MethodGet, "/api/v1/proxy/pools/x"},
		{http.MethodPut, "/api/v1/proxy/pools/x"},
		{http.MethodDelete, "/api/v1/proxy/pools/x"},
		{http.MethodGet, "/api/v1/proxy/config"},
		{http.MethodGet, "/api/v1/proxy/status"},
		{http.MethodPost, "/api/v1/proxy/reload"},
		{http.MethodGet, "/api/v1/proxy/zone-matrix"},
	}
	for _, p := range paths {
		rec := doProxyRequest(t, router, p.method, p.path, nil)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s code = %d, want 503", p.method, p.path, rec.Code)
		}
	}
}

func TestProxyRESTHandlers_InternalError(t *testing.T) {
	router := newProxyTestRouter(&fakeProxyBackend{err: status.Error(codes.Internal, "boom")})
	rec := doProxyRequest(t, router, http.MethodGet, "/api/v1/proxy/status", nil)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("code = %d, want 500", rec.Code)
	}
}
