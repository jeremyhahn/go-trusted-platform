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

// Tests for the ProxyService read routes on the webservice (#2061 slice 1):
// each read reaches its ProxyServiceServer method with the request the route
// builds, answers protojson (camelCase, 64-bit fields as strings), maps the
// service refusals to their HTTP status, needs proxy:read, and no write
// route is served yet.

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingServer records the last request it was handed and answers a
// canned response (or err).
type recordingServer struct {
	platformv1.UnimplementedProxyServiceServer
	err   error
	last  proto.Message
	calls int
}

func (s *recordingServer) record(req proto.Message) {
	s.last = req
	s.calls++
}

func cannedRoute() *platformv1.ProxyRoute {
	return &platformv1.ProxyRoute{
		Id:         "web",
		Hosts:      []string{"app.example"},
		PathPrefix: "/app",
		PoolId:     "pool-1",
		Auth:       &platformv1.ProxyAuthRequirements{Mode: "mtls", AttestationMaxAgeNanos: 5000000000},
	}
}

func cannedPool() *platformv1.ProxyPool {
	return &platformv1.ProxyPool{
		Id:                   "pool-1",
		Backends:             []*platformv1.ProxyBackend{{Url: "http://10.0.0.1:8080", Weight: 2}},
		MaxIdleConnsPerHost:  4,
		IdleConnTimeoutNanos: 9000000000,
	}
}

func (s *recordingServer) ListRoutes(_ context.Context, req *platformv1.ListProxyRoutesRequest) (*platformv1.ListProxyRoutesResponse, error) {
	s.record(req)
	return &platformv1.ListProxyRoutesResponse{Routes: []*platformv1.ProxyRoute{cannedRoute()}, Version: 7}, s.err
}

func (s *recordingServer) GetRoute(_ context.Context, req *platformv1.GetProxyRouteRequest) (*platformv1.GetProxyRouteResponse, error) {
	s.record(req)
	return &platformv1.GetProxyRouteResponse{Route: cannedRoute()}, s.err
}

func (s *recordingServer) ListPools(_ context.Context, req *platformv1.ListProxyPoolsRequest) (*platformv1.ListProxyPoolsResponse, error) {
	s.record(req)
	return &platformv1.ListProxyPoolsResponse{Pools: []*platformv1.ProxyPool{cannedPool()}, Version: 7}, s.err
}

func (s *recordingServer) GetPool(_ context.Context, req *platformv1.GetProxyPoolRequest) (*platformv1.GetProxyPoolResponse, error) {
	s.record(req)
	return &platformv1.GetProxyPoolResponse{Pool: cannedPool()}, s.err
}

func (s *recordingServer) GetProxyConfig(_ context.Context, req *platformv1.GetProxyConfigRequest) (*platformv1.GetProxyConfigResponse, error) {
	s.record(req)
	return &platformv1.GetProxyConfigResponse{
		Routes:  []*platformv1.ProxyRoute{cannedRoute()},
		Pools:   []*platformv1.ProxyPool{cannedPool()},
		Version: 7,
	}, s.err
}

func (s *recordingServer) GetProxyStatus(_ context.Context, req *platformv1.GetProxyStatusRequest) (*platformv1.GetProxyStatusResponse, error) {
	s.record(req)
	return &platformv1.GetProxyStatusResponse{Version: 7, RouteCount: 2, PoolCount: 1, UpdatedAt: 1700000000}, s.err
}

func (s *recordingServer) GetZoneMatrix(_ context.Context, req *platformv1.GetProxyZoneMatrixRequest) (*platformv1.GetProxyZoneMatrixResponse, error) {
	s.record(req)
	return &platformv1.GetProxyZoneMatrixResponse{
		Zones: []string{"management", "tenant"},
		Pairs: []*platformv1.ProxyZonePair{{From: "management", To: "tenant", Services: []string{"https"}}},
	}, s.err
}

// Every write method records too, so a write route served by mistake shows
// up as a call.
func (s *recordingServer) CreateRoute(_ context.Context, req *platformv1.CreateProxyRouteRequest) (*platformv1.CreateProxyRouteResponse, error) {
	s.record(req)
	return &platformv1.CreateProxyRouteResponse{}, s.err
}

func (s *recordingServer) UpdateRoute(_ context.Context, req *platformv1.UpdateProxyRouteRequest) (*platformv1.UpdateProxyRouteResponse, error) {
	s.record(req)
	return &platformv1.UpdateProxyRouteResponse{}, s.err
}

func (s *recordingServer) DeletePool(_ context.Context, req *platformv1.DeleteProxyPoolRequest) (*platformv1.DeleteProxyPoolResponse, error) {
	s.record(req)
	return &platformv1.DeleteProxyPoolResponse{}, s.err
}

func (s *recordingServer) ReloadProxyConfig(_ context.Context, req *platformv1.ReloadProxyConfigRequest) (*platformv1.ReloadProxyConfigResponse, error) {
	s.record(req)
	return &platformv1.ReloadProxyConfigResponse{}, s.err
}

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, nil)
}

func newTestRouter(server platformv1.ProxyServiceServer) *Router {
	return NewRouter(newTestLogger(), server, response.NewResponseWriter(newTestLogger(), nil))
}

// mountRouter mounts the proxy routes under /api/v1, as the webservice does.
func mountRouter(server platformv1.ProxyServiceServer) *mux.Router {
	router := mux.NewRouter()
	newTestRouter(server).RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	return router
}

// envelope is the webservice response envelope.
type envelope struct {
	Code    int             `json:"code"`
	Success bool            `json:"success"`
	Error   string          `json:"error"`
	Payload json.RawMessage `json:"payload"`
}

func serve(router *mux.Router, verb, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(verb, path, strings.NewReader("")))
	return rec
}

// proxyProbe is one read route: the request it must hand the service and
// the protojson fragments its payload must carry.
type proxyProbe struct {
	name     string
	path     string
	want     proto.Message
	contains []string
}

var proxyProbes = []proxyProbe{
	{
		name: "list routes", path: "/api/v1/proxy/routes",
		want:     &platformv1.ListProxyRoutesRequest{},
		contains: []string{`"pathPrefix":"/app"`, `"poolId":"pool-1"`, `"version":"7"`, `"attestationMaxAgeNanos":"5000000000"`},
	},
	{
		name: "get route", path: "/api/v1/proxy/routes/web",
		want:     &platformv1.GetProxyRouteRequest{Id: "web"},
		contains: []string{`"route":`, `"pathPrefix":"/app"`},
	},
	{
		name: "list pools", path: "/api/v1/proxy/pools",
		want:     &platformv1.ListProxyPoolsRequest{},
		contains: []string{`"maxIdleConnsPerHost":4`, `"idleConnTimeoutNanos":"9000000000"`, `"version":"7"`},
	},
	{
		name: "get pool", path: "/api/v1/proxy/pools/pool-1",
		want:     &platformv1.GetProxyPoolRequest{Id: "pool-1"},
		contains: []string{`"pool":`, `"weight":2`},
	},
	{
		name: "config", path: "/api/v1/proxy/config",
		want:     &platformv1.GetProxyConfigRequest{},
		contains: []string{`"routes":`, `"pools":`, `"version":"7"`},
	},
	{
		name: "status", path: "/api/v1/proxy/status",
		want:     &platformv1.GetProxyStatusRequest{},
		contains: []string{`"routeCount":2`, `"poolCount":1`, `"version":"7"`, `"updatedAt":"1700000000"`},
	},
	{
		name: "zone matrix", path: "/api/v1/proxy/zone-matrix",
		want:     &platformv1.GetProxyZoneMatrixRequest{},
		contains: []string{`"zones":["management","tenant"]`, `"from":"management"`},
	},
}

// TestProxyRouterServesEveryReadOperation: each of the seven ProxyService
// reads is a GET that reaches its method, with {id} passed through, and
// answers 200 with the protojson payload.
func TestProxyRouterServesEveryReadOperation(t *testing.T) {
	for _, probe := range proxyProbes {
		t.Run(probe.name, func(t *testing.T) {
			server := &recordingServer{}
			rec := serve(mountRouter(server), http.MethodGet, probe.path)
			if rec.Code != http.StatusOK {
				t.Fatalf("code = %d, want 200, body %s", rec.Code, rec.Body)
			}
			var body envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %s: %v", rec.Body, err)
			}
			if !body.Success {
				t.Fatalf("envelope = %+v", body)
			}
			if !proto.Equal(server.last, probe.want) {
				t.Fatalf("service got %v, want %v", server.last, probe.want)
			}
			payload := strings.ReplaceAll(string(body.Payload), " ", "")
			for _, fragment := range probe.contains {
				if !strings.Contains(payload, fragment) {
					t.Errorf("payload %s does not carry %s", payload, fragment)
				}
			}
		})
	}
}

// TestProxyRouterMapsServiceRefusals: a gRPC refusal from the service
// becomes its HTTP status.
func TestProxyRouterMapsServiceRefusals(t *testing.T) {
	refusals := map[codes.Code]int{
		codes.NotFound:         http.StatusNotFound,
		codes.Unavailable:      http.StatusServiceUnavailable,
		codes.PermissionDenied: http.StatusForbidden,
		codes.InvalidArgument:  http.StatusBadRequest,
	}
	for code, want := range refusals {
		for _, probe := range proxyProbes {
			server := &recordingServer{err: status.Error(code, "refused")}
			rec := serve(mountRouter(server), http.MethodGet, probe.path)
			if rec.Code != want {
				t.Errorf("%s refused with %s: code = %d, want %d", probe.name, code, rec.Code, want)
			}
		}
	}
}

// TestProxyRouterWithoutAServiceIsUnavailable: with no ProxyServiceServer
// every route answers 503.
func TestProxyRouterWithoutAServiceIsUnavailable(t *testing.T) {
	for _, probe := range proxyProbes {
		rec := serve(mountRouter(nil), http.MethodGet, probe.path)
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("%s: code = %d, want 503", probe.name, rec.Code)
		}
	}
}

// grantingAuthorizer grants one scope and refuses every other with 403.
type grantingAuthorizer struct {
	granted string
}

func (a grantingAuthorizer) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scope != a.granted {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// TestProxyRouterRequiresProxyRead: every read route needs proxy:read; any
// other scope is refused before the service is called.
func TestProxyRouterRequiresProxyRead(t *testing.T) {
	for _, probe := range proxyProbes {
		for _, granted := range []string{"proxy:read", "proxy:write", "proxy:delete"} {
			server := &recordingServer{}
			proxyRouter := newTestRouter(server)
			proxyRouter.SetScopeAuthorizer(grantingAuthorizer{granted: granted})
			router := mux.NewRouter()
			proxyRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

			rec := serve(router, http.MethodGet, probe.path)
			if granted == "proxy:read" {
				if rec.Code != http.StatusOK {
					t.Errorf("%s with %s: code = %d, want 200", probe.name, granted, rec.Code)
				}
				continue
			}
			if rec.Code != http.StatusForbidden || server.last != nil {
				t.Errorf("%s with %s: code = %d, service called = %v; want 403 and no call",
					probe.name, granted, rec.Code, server.last != nil)
			}
		}
	}
}

// TestProxyRouterHasNoWriteRoutes: the writes come in the next slice; none
// is served now and the service sees no call.
func TestProxyRouterHasNoWriteRoutes(t *testing.T) {
	writes := []struct{ verb, path string }{
		{http.MethodPost, "/api/v1/proxy/routes"},
		{http.MethodPut, "/api/v1/proxy/routes/x"},
		{http.MethodDelete, "/api/v1/proxy/routes/x"},
		{http.MethodPost, "/api/v1/proxy/pools"},
		{http.MethodPut, "/api/v1/proxy/pools/x"},
		{http.MethodDelete, "/api/v1/proxy/pools/x"},
		{http.MethodPost, "/api/v1/proxy/reload"},
	}
	for _, write := range writes {
		server := &recordingServer{}
		rec := serve(mountRouter(server), write.verb, write.path)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s %s: code = %d, want 404 or 405", write.verb, write.path, rec.Code)
		}
		if server.calls != 0 {
			t.Errorf("%s %s: service saw %d calls, want none", write.verb, write.path, server.calls)
		}
	}
}
