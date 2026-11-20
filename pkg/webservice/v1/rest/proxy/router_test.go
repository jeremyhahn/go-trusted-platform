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

package proxy

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fakeProxyServer records the last request of each call and serves a small
// in-memory route and pool store.
type fakeProxyServer struct {
	platformv1.UnimplementedProxyServiceServer
	mu      sync.Mutex
	calls   []string
	routes  map[string]*platformv1.ProxyRoute
	pools   map[string]*platformv1.ProxyPool
	version uint64
	lastUpd *platformv1.UpdateProxyRouteRequest
	lastPU  *platformv1.UpdateProxyPoolRequest
}

func newFake() *fakeProxyServer {
	return &fakeProxyServer{
		routes: map[string]*platformv1.ProxyRoute{},
		pools:  map[string]*platformv1.ProxyPool{},
	}
}

func (f *fakeProxyServer) record(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, name)
	f.version++
}

func (f *fakeProxyServer) CreateRoute(_ context.Context, req *platformv1.CreateProxyRouteRequest) (*platformv1.CreateProxyRouteResponse, error) {
	f.record("CreateRoute")
	if req.GetRoute().GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "route id is required")
	}
	f.routes[req.GetRoute().GetId()] = req.GetRoute()
	return &platformv1.CreateProxyRouteResponse{Route: req.GetRoute(), Version: f.version}, nil
}

func (f *fakeProxyServer) GetRoute(_ context.Context, req *platformv1.GetProxyRouteRequest) (*platformv1.GetProxyRouteResponse, error) {
	f.record("GetRoute")
	r, ok := f.routes[req.GetId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "proxy route %q not found", req.GetId())
	}
	return &platformv1.GetProxyRouteResponse{Route: r}, nil
}

func (f *fakeProxyServer) UpdateRoute(_ context.Context, req *platformv1.UpdateProxyRouteRequest) (*platformv1.UpdateProxyRouteResponse, error) {
	f.record("UpdateRoute")
	f.lastUpd = req
	return &platformv1.UpdateProxyRouteResponse{Route: req.GetRoute(), Version: f.version}, nil
}

func (f *fakeProxyServer) DeleteRoute(_ context.Context, req *platformv1.DeleteProxyRouteRequest) (*platformv1.DeleteProxyRouteResponse, error) {
	f.record("DeleteRoute:" + req.GetId())
	return &platformv1.DeleteProxyRouteResponse{Version: f.version}, nil
}

func (f *fakeProxyServer) ListRoutes(context.Context, *platformv1.ListProxyRoutesRequest) (*platformv1.ListProxyRoutesResponse, error) {
	f.record("ListRoutes")
	out := &platformv1.ListProxyRoutesResponse{Version: f.version}
	for _, r := range f.routes {
		out.Routes = append(out.Routes, r)
	}
	return out, nil
}

func (f *fakeProxyServer) CreatePool(_ context.Context, req *platformv1.CreateProxyPoolRequest) (*platformv1.CreateProxyPoolResponse, error) {
	f.record("CreatePool")
	f.pools[req.GetPool().GetId()] = req.GetPool()
	return &platformv1.CreateProxyPoolResponse{Pool: req.GetPool(), Version: f.version}, nil
}

func (f *fakeProxyServer) GetPool(_ context.Context, req *platformv1.GetProxyPoolRequest) (*platformv1.GetProxyPoolResponse, error) {
	f.record("GetPool")
	p, ok := f.pools[req.GetId()]
	if !ok {
		return nil, status.Errorf(codes.NotFound, "proxy pool %q not found", req.GetId())
	}
	return &platformv1.GetProxyPoolResponse{Pool: p}, nil
}

func (f *fakeProxyServer) UpdatePool(_ context.Context, req *platformv1.UpdateProxyPoolRequest) (*platformv1.UpdateProxyPoolResponse, error) {
	f.record("UpdatePool")
	f.lastPU = req
	return &platformv1.UpdateProxyPoolResponse{Pool: req.GetPool(), Version: f.version}, nil
}

func (f *fakeProxyServer) DeletePool(_ context.Context, req *platformv1.DeleteProxyPoolRequest) (*platformv1.DeleteProxyPoolResponse, error) {
	f.record("DeletePool:" + req.GetId())
	return nil, status.Errorf(codes.FailedPrecondition, "proxy pool %q is in use", req.GetId())
}

func (f *fakeProxyServer) ListPools(context.Context, *platformv1.ListProxyPoolsRequest) (*platformv1.ListProxyPoolsResponse, error) {
	f.record("ListPools")
	return &platformv1.ListProxyPoolsResponse{Version: f.version}, nil
}

func (f *fakeProxyServer) GetProxyConfig(context.Context, *platformv1.GetProxyConfigRequest) (*platformv1.GetProxyConfigResponse, error) {
	f.record("GetProxyConfig")
	return &platformv1.GetProxyConfigResponse{Version: f.version}, nil
}

func (f *fakeProxyServer) ReloadProxyConfig(context.Context, *platformv1.ReloadProxyConfigRequest) (*platformv1.ReloadProxyConfigResponse, error) {
	f.record("ReloadProxyConfig")
	return &platformv1.ReloadProxyConfigResponse{Version: f.version}, nil
}

func (f *fakeProxyServer) GetProxyStatus(context.Context, *platformv1.GetProxyStatusRequest) (*platformv1.GetProxyStatusResponse, error) {
	f.record("GetProxyStatus")
	return &platformv1.GetProxyStatusResponse{Version: f.version, RouteCount: uint32(len(f.routes))}, nil
}

func (f *fakeProxyServer) GetZoneMatrix(context.Context, *platformv1.GetProxyZoneMatrixRequest) (*platformv1.GetProxyZoneMatrixResponse, error) {
	f.record("GetZoneMatrix")
	return &platformv1.GetProxyZoneMatrixResponse{Zones: []string{"dmz", "lan"}}, nil
}

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, nil)
}

func newMux(server platformv1.ProxyServiceServer) *mux.Router {
	router := mux.NewRouter()
	NewProxyRouter(newTestLogger(), server, response.NewResponseWriter(newTestLogger(), nil)).
		RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	return router
}

func do(t *testing.T, h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestProxyRouter_EveryOperationReachesItsRPC(t *testing.T) {
	fake := newFake()
	h := newMux(fake)

	steps := []struct {
		method, path, body string
		want               int
		contains           string
	}{
		{http.MethodPost, "/api/v1/proxy/pools", `{"id":"p1","backends":[{"url":"https://10.0.0.1:8443","weight":1}]}`, http.StatusOK, `"p1"`},
		{http.MethodGet, "/api/v1/proxy/pools/p1", "", http.StatusOK, `https://10.0.0.1:8443`},
		{http.MethodPut, "/api/v1/proxy/pools/p1", `{"backends":[{"url":"https://10.0.0.2:8443"}]}`, http.StatusOK, `10.0.0.2`},
		{http.MethodGet, "/api/v1/proxy/pools", "", http.StatusOK, `"version"`},
		{http.MethodPost, "/api/v1/proxy/routes", `{"id":"r1","hosts":["a.test"],"pathPrefix":"/a","poolId":"p1","auth":{"mode":"mtls"}}`, http.StatusOK, `"r1"`},
		{http.MethodGet, "/api/v1/proxy/routes/r1", "", http.StatusOK, `"/a"`},
		{http.MethodPut, "/api/v1/proxy/routes/r1", `{"pathPrefix":"/b"}`, http.StatusOK, `"/b"`},
		{http.MethodGet, "/api/v1/proxy/routes", "", http.StatusOK, `"r1"`},
		{http.MethodDelete, "/api/v1/proxy/routes/r1", "", http.StatusOK, `"version"`},
		{http.MethodDelete, "/api/v1/proxy/pools/p1", "", http.StatusConflict, `in use`},
		{http.MethodGet, "/api/v1/proxy/config", "", http.StatusOK, `"version"`},
		{http.MethodPost, "/api/v1/proxy/config/reload", "", http.StatusOK, `"version"`},
		{http.MethodGet, "/api/v1/proxy/status", "", http.StatusOK, `"routeCount"`},
		{http.MethodGet, "/api/v1/proxy/zone-matrix", "", http.StatusOK, `"dmz"`},
	}
	for _, s := range steps {
		rec := do(t, h, s.method, s.path, s.body)
		if rec.Code != s.want {
			t.Fatalf("%s %s: status %d, want %d; body %s", s.method, s.path, rec.Code, s.want, rec.Body.String())
		}
		if !strings.Contains(rec.Body.String(), s.contains) {
			t.Fatalf("%s %s: body %s lacks %s", s.method, s.path, rec.Body.String(), s.contains)
		}
	}

	want := []string{
		"CreatePool", "GetPool", "UpdatePool", "ListPools",
		"CreateRoute", "GetRoute", "UpdateRoute", "ListRoutes", "DeleteRoute:r1",
		"DeletePool:p1", "GetProxyConfig", "ReloadProxyConfig", "GetProxyStatus", "GetZoneMatrix",
	}
	if strings.Join(fake.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("calls %v, want %v", fake.calls, want)
	}
	if fake.lastUpd.GetId() != "r1" || fake.lastUpd.GetRoute().GetPathPrefix() != "/b" {
		t.Fatalf("UpdateRoute got %v, want id r1 from the path", fake.lastUpd)
	}
	if fake.lastPU.GetId() != "p1" {
		t.Fatalf("UpdatePool got id %q, want p1 from the path", fake.lastPU.GetId())
	}
}

func TestProxyRouter_MapsServiceErrors(t *testing.T) {
	h := newMux(newFake())
	if rec := do(t, h, http.MethodGet, "/api/v1/proxy/routes/missing", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing route: status %d, want 404", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/v1/proxy/routes", `{"hosts":["a"]}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("route without id: status %d, want 400", rec.Code)
	}
	if rec := do(t, h, http.MethodPost, "/api/v1/proxy/routes", `{not json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad JSON: status %d, want 400", rec.Code)
	}
}

func TestProxyRouter_NilServerIsUnavailable(t *testing.T) {
	h := newMux(nil)
	rec := do(t, h, http.MethodGet, "/api/v1/proxy/status", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("nil server: status %d, want 503", rec.Code)
	}
}
