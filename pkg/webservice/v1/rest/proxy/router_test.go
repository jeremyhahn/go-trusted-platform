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

// Tests for the ProxyService routes on the webservice (#2061 slices 1 and
// 2): each of the fourteen operations reaches its ProxyServiceServer method
// with the request the route builds (the write bodies decoded as the daemon
// REST decodes them, the URL id winning on updates), answers protojson
// (camelCase, 64-bit fields as strings), maps the service refusals to their
// HTTP status, refuses a body that does not decode, and needs its own scope:
// proxy:read for the reads, proxy:write for the creates, updates and reload,
// proxy:delete for the deletes.

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

// The write methods record the request and answer a canned response at
// config version 8.
func (s *recordingServer) CreateRoute(_ context.Context, req *platformv1.CreateProxyRouteRequest) (*platformv1.CreateProxyRouteResponse, error) {
	s.record(req)
	return &platformv1.CreateProxyRouteResponse{Route: cannedRoute(), Version: 8}, s.err
}

func (s *recordingServer) UpdateRoute(_ context.Context, req *platformv1.UpdateProxyRouteRequest) (*platformv1.UpdateProxyRouteResponse, error) {
	s.record(req)
	return &platformv1.UpdateProxyRouteResponse{Route: cannedRoute(), Version: 8}, s.err
}

func (s *recordingServer) DeleteRoute(_ context.Context, req *platformv1.DeleteProxyRouteRequest) (*platformv1.DeleteProxyRouteResponse, error) {
	s.record(req)
	return &platformv1.DeleteProxyRouteResponse{Version: 8}, s.err
}

func (s *recordingServer) CreatePool(_ context.Context, req *platformv1.CreateProxyPoolRequest) (*platformv1.CreateProxyPoolResponse, error) {
	s.record(req)
	return &platformv1.CreateProxyPoolResponse{Pool: cannedPool(), Version: 8}, s.err
}

func (s *recordingServer) UpdatePool(_ context.Context, req *platformv1.UpdateProxyPoolRequest) (*platformv1.UpdateProxyPoolResponse, error) {
	s.record(req)
	return &platformv1.UpdateProxyPoolResponse{Pool: cannedPool(), Version: 8}, s.err
}

func (s *recordingServer) DeletePool(_ context.Context, req *platformv1.DeleteProxyPoolRequest) (*platformv1.DeleteProxyPoolResponse, error) {
	s.record(req)
	return &platformv1.DeleteProxyPoolResponse{Version: 8}, s.err
}

func (s *recordingServer) ReloadProxyConfig(_ context.Context, req *platformv1.ReloadProxyConfigRequest) (*platformv1.ReloadProxyConfigResponse, error) {
	s.record(req)
	return &platformv1.ReloadProxyConfigResponse{Version: 8}, s.err
}

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, nil)
}

func newTestRouter(server platformv1.ProxyServiceServer) *Router {
	return NewRouter(newTestLogger(), server, response.NewResponseWriter(newTestLogger(), nil))
}

// mountRouter mounts the proxy routes under /api/v1, as the webservice does,
// behind an authorizer that grants every scope; the scope checks are covered
// by the grantingAuthorizer tests and the no-authorizer test.
func mountRouter(server platformv1.ProxyServiceServer) *mux.Router {
	proxyRouter := newTestRouter(server)
	proxyRouter.SetScopeAuthorizer(allowAllAuthorizer{})
	router := mux.NewRouter()
	proxyRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
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

func serveBody(router *mux.Router, verb, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(verb, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(rec, req)
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
	for _, probe := range proxyWriteProbes {
		rec := serveBody(mountRouter(nil), probe.verb, probe.path, probe.body)
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

// proxyWriteProbe is one write route: the body it sends, the scope it needs,
// the request it must hand the service and the status it answers.
// allowAllAuthorizer grants every scope, so the tests that drive the
// handlers through mountRouter pass the scope gate; the scope checks
// themselves are covered by the grantingAuthorizer tests.
type allowAllAuthorizer struct{}

func (allowAllAuthorizer) RequireScope(string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler { return next }
}

type proxyWriteProbe struct {
	name  string
	verb  string
	path  string
	body  string
	scope string
	want  proto.Message
	code  int
}

var proxyWriteProbes = []proxyWriteProbe{
	{
		name: "create route", verb: http.MethodPost, path: "/api/v1/proxy/routes",
		body:  `{"route":{"id":"web","pathPrefix":"/app","poolId":"pool-1"}}`,
		scope: "proxy:write",
		want:  &platformv1.CreateProxyRouteRequest{Route: &platformv1.ProxyRoute{Id: "web", PathPrefix: "/app", PoolId: "pool-1"}},
		code:  http.StatusCreated,
	},
	{
		name: "update route", verb: http.MethodPut, path: "/api/v1/proxy/routes/web",
		body:  `{"id":"ignored","route":{"id":"other","pathPrefix":"/app","poolId":"pool-1"}}`,
		scope: "proxy:write",
		want:  &platformv1.UpdateProxyRouteRequest{Id: "web", Route: &platformv1.ProxyRoute{Id: "other", PathPrefix: "/app", PoolId: "pool-1"}},
		code:  http.StatusOK,
	},
	{
		name: "delete route", verb: http.MethodDelete, path: "/api/v1/proxy/routes/web",
		scope: "proxy:delete",
		want:  &platformv1.DeleteProxyRouteRequest{Id: "web"},
		code:  http.StatusOK,
	},
	{
		name: "create pool", verb: http.MethodPost, path: "/api/v1/proxy/pools",
		body:  `{"pool":{"id":"pool-1","balancer":"round-robin"}}`,
		scope: "proxy:write",
		want:  &platformv1.CreateProxyPoolRequest{Pool: &platformv1.ProxyPool{Id: "pool-1", Balancer: "round-robin"}},
		code:  http.StatusCreated,
	},
	{
		name: "update pool", verb: http.MethodPut, path: "/api/v1/proxy/pools/pool-1",
		body:  `{"pool":{"id":"pool-1","balancer":"least-conn"}}`,
		scope: "proxy:write",
		want:  &platformv1.UpdateProxyPoolRequest{Id: "pool-1", Pool: &platformv1.ProxyPool{Id: "pool-1", Balancer: "least-conn"}},
		code:  http.StatusOK,
	},
	{
		name: "delete pool", verb: http.MethodDelete, path: "/api/v1/proxy/pools/pool-1",
		scope: "proxy:delete",
		want:  &platformv1.DeleteProxyPoolRequest{Id: "pool-1"},
		code:  http.StatusOK,
	},
	{
		name: "reload", verb: http.MethodPost, path: "/api/v1/proxy/reload",
		scope: "proxy:write",
		want:  &platformv1.ReloadProxyConfigRequest{},
		code:  http.StatusOK,
	},
}

// TestProxyRouterServesEveryWriteOperation: each of the seven ProxyService
// writes reaches its method with the decoded body and the URL id, and
// answers its status with the protojson payload.
func TestProxyRouterServesEveryWriteOperation(t *testing.T) {
	for _, probe := range proxyWriteProbes {
		t.Run(probe.name, func(t *testing.T) {
			server := &recordingServer{}
			rec := serveBody(mountRouter(server), probe.verb, probe.path, probe.body)
			if rec.Code != probe.code {
				t.Fatalf("code = %d, want %d, body %s", rec.Code, probe.code, rec.Body)
			}
			var body envelope
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("decode %s: %v", rec.Body, err)
			}
			if !body.Success {
				t.Fatalf("envelope = %+v", body)
			}
			if server.calls != 1 || !proto.Equal(server.last, probe.want) {
				t.Fatalf("service got %v (%d calls), want %v", server.last, server.calls, probe.want)
			}
			payload := strings.ReplaceAll(string(body.Payload), " ", "")
			if !strings.Contains(payload, `"version":"8"`) {
				t.Errorf("payload %s does not carry the version", payload)
			}
		})
	}
}

// TestProxyRouterMapsWriteRefusals: a gRPC refusal from a write becomes its
// HTTP status.
func TestProxyRouterMapsWriteRefusals(t *testing.T) {
	refusals := map[codes.Code]int{
		codes.NotFound:           http.StatusNotFound,
		codes.InvalidArgument:    http.StatusBadRequest,
		codes.AlreadyExists:      http.StatusConflict,
		codes.FailedPrecondition: http.StatusConflict,
		codes.Unavailable:        http.StatusServiceUnavailable,
	}
	for code, want := range refusals {
		for _, probe := range proxyWriteProbes {
			server := &recordingServer{err: status.Error(code, "refused")}
			rec := serveBody(mountRouter(server), probe.verb, probe.path, probe.body)
			if rec.Code != want {
				t.Errorf("%s refused with %s: code = %d, want %d", probe.name, code, rec.Code, want)
			}
		}
	}
}

// TestProxyRouterRefusesBadWriteBodies: a create or update body that does
// not decode answers 400 before the service is called.
func TestProxyRouterRefusesBadWriteBodies(t *testing.T) {
	writes := []struct{ verb, path string }{
		{http.MethodPost, "/api/v1/proxy/routes"},
		{http.MethodPut, "/api/v1/proxy/routes/web"},
		{http.MethodPost, "/api/v1/proxy/pools"},
		{http.MethodPut, "/api/v1/proxy/pools/pool-1"},
	}
	for _, write := range writes {
		server := &recordingServer{}
		rec := serveBody(mountRouter(server), write.verb, write.path, `{not json`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%s %s: code = %d, want 400", write.verb, write.path, rec.Code)
		}
		if server.calls != 0 {
			t.Errorf("%s %s: service saw %d calls, want none", write.verb, write.path, server.calls)
		}
	}
}

// TestProxyRouterRequiresEachWriteScope: each write passes with its own
// scope (proxy:write, or proxy:delete for the deletes) and is refused 403
// before the service is called under either other proxy scope.
func TestProxyRouterRequiresEachWriteScope(t *testing.T) {
	for _, probe := range proxyWriteProbes {
		for _, granted := range []string{"proxy:read", "proxy:write", "proxy:delete"} {
			server := &recordingServer{}
			proxyRouter := newTestRouter(server)
			proxyRouter.SetScopeAuthorizer(grantingAuthorizer{granted: granted})
			router := mux.NewRouter()
			proxyRouter.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

			rec := serveBody(router, probe.verb, probe.path, probe.body)
			if granted == probe.scope {
				if rec.Code != probe.code || server.calls != 1 {
					t.Errorf("%s with %s: code = %d, calls = %d; want %d and one call",
						probe.name, granted, rec.Code, server.calls, probe.code)
				}
				continue
			}
			if rec.Code != http.StatusForbidden || server.calls != 0 {
				t.Errorf("%s with %s: code = %d, calls = %d; want 403 and no call",
					probe.name, granted, rec.Code, server.calls)
			}
		}
	}
}

// TestProxyRouterRefusesWritesWithoutAScopeAuthorizer pins the fail-closed
// branch: with no ScopeAuthorizer (the legacy JWT handler) every write answers
// 403 before the service is called; the reads are covered by
// TestProxyRouterRefusesEveryReadWithoutAScopeAuthorizer (#2160 Codex).
func TestProxyRouterRefusesWritesWithoutAScopeAuthorizer(t *testing.T) {
	unscoped := func(server *recordingServer) *mux.Router {
		router := mux.NewRouter()
		newTestRouter(server).RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
		return router
	}
	for _, probe := range proxyWriteProbes {
		server := &recordingServer{}
		rec := serveBody(unscoped(server), probe.verb, probe.path, probe.body)
		if rec.Code != http.StatusForbidden || server.calls != 0 {
			t.Errorf("%s without an authorizer: code = %d, calls = %d; want 403 and no call",
				probe.name, rec.Code, server.calls)
		}
	}
}

// TestProxyRouterRefusesEveryReadWithoutAScopeAuthorizer pins the legacy JWT
// case: with no ScopeAuthorizer set, a role-only session carries no scopes,
// so every read answers 403 before the service (#1990, #2157 Codex).
func TestProxyRouterRefusesEveryReadWithoutAScopeAuthorizer(t *testing.T) {
	for _, probe := range proxyProbes {
		server := &recordingServer{}
		router := mux.NewRouter()
		newTestRouter(server).RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())

		rec := serve(router, http.MethodGet, probe.path)
		if rec.Code != http.StatusForbidden {
			t.Errorf("%s: code = %d, want 403", probe.name, rec.Code)
		}
		if server.calls != 0 {
			t.Errorf("%s: service saw %d calls, want none", probe.name, server.calls)
		}
	}
}

// TestProxyRouterAddressesSlashIDs round-trips a route and a pool whose ids
// contain a slash: the URL carries it percent-encoded and the service sees the
// decoded id (#2160 Codex).
func TestProxyRouterAddressesSlashIDs(t *testing.T) {
	route := &platformv1.ProxyRoute{Id: "a/b", PathPrefix: "/app", PoolId: "pool-1"}
	routeBody := `{"route":{"id":"a/b","pathPrefix":"/app","poolId":"pool-1"}}`
	pool := &platformv1.ProxyPool{Id: "p/1", Balancer: "round-robin"}
	poolBody := `{"pool":{"id":"p/1","balancer":"round-robin"}}`
	cases := []struct {
		name string
		verb string
		path string
		body string
		code int
		want proto.Message
	}{
		{"create route", http.MethodPost, "/api/v1/proxy/routes", routeBody, http.StatusCreated,
			&platformv1.CreateProxyRouteRequest{Route: route}},
		{"get route", http.MethodGet, "/api/v1/proxy/routes/a%2Fb", "", http.StatusOK,
			&platformv1.GetProxyRouteRequest{Id: "a/b"}},
		{"update route", http.MethodPut, "/api/v1/proxy/routes/a%2Fb", routeBody, http.StatusOK,
			&platformv1.UpdateProxyRouteRequest{Id: "a/b", Route: route}},
		{"delete route", http.MethodDelete, "/api/v1/proxy/routes/a%2Fb", "", http.StatusOK,
			&platformv1.DeleteProxyRouteRequest{Id: "a/b"}},
		{"create pool", http.MethodPost, "/api/v1/proxy/pools", poolBody, http.StatusCreated,
			&platformv1.CreateProxyPoolRequest{Pool: pool}},
		{"get pool", http.MethodGet, "/api/v1/proxy/pools/p%2F1", "", http.StatusOK,
			&platformv1.GetProxyPoolRequest{Id: "p/1"}},
		{"update pool", http.MethodPut, "/api/v1/proxy/pools/p%2F1", poolBody, http.StatusOK,
			&platformv1.UpdateProxyPoolRequest{Id: "p/1", Pool: pool}},
		{"delete pool", http.MethodDelete, "/api/v1/proxy/pools/p%2F1", "", http.StatusOK,
			&platformv1.DeleteProxyPoolRequest{Id: "p/1"}},
		{"get plain route", http.MethodGet, "/api/v1/proxy/routes/web", "", http.StatusOK,
			&platformv1.GetProxyRouteRequest{Id: "web"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := &recordingServer{}
			rec := serveBody(mountRouter(server), tc.verb, tc.path, tc.body)
			if rec.Code != tc.code {
				t.Fatalf("code = %d, want %d (body %s)", rec.Code, tc.code, rec.Body.String())
			}
			if !proto.Equal(server.last, tc.want) {
				t.Errorf("service saw %v, want %v", server.last, tc.want)
			}
		})
	}
}

// TestProxyRouterPassesEncodedSlashIDs pins that route and pool IDs holding a
// slash, which the SDK sends as a%2Fb, reach the service decoded (#2157 Codex).
func TestProxyRouterPassesEncodedSlashIDs(t *testing.T) {
	cases := []struct {
		path string
		want proto.Message
	}{
		{"/api/v1/proxy/routes/web", &platformv1.GetProxyRouteRequest{Id: "web"}},
		{"/api/v1/proxy/routes/a%2Fb", &platformv1.GetProxyRouteRequest{Id: "a/b"}},
		{"/api/v1/proxy/pools/pool-1", &platformv1.GetProxyPoolRequest{Id: "pool-1"}},
		{"/api/v1/proxy/pools/a%2Fb", &platformv1.GetProxyPoolRequest{Id: "a/b"}},
	}
	for _, tc := range cases {
		server := &recordingServer{}
		rec := serve(mountRouter(server), http.MethodGet, tc.path)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: code = %d, want 200", tc.path, rec.Code)
			continue
		}
		if !proto.Equal(server.last, tc.want) {
			t.Errorf("%s: service got %v, want %v", tc.path, server.last, tc.want)
		}
	}
}
