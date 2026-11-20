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

package cluster

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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// recordingServer is a platformv1.ClusterServiceServer that records the last
// RPC it served and answers err when one is set.
type recordingServer struct {
	platformv1.UnimplementedClusterServiceServer

	last string
	err  error
}

// GetStatus records the call and returns a three-node cluster.
func (s *recordingServer) GetStatus(_ context.Context, _ *platformv1.GetClusterStatusRequest) (*platformv1.GetClusterStatusResponse, error) {
	s.last = "GetStatus"
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.GetClusterStatusResponse{
		Cluster: &platformv1.ClusterInfo{Id: "c1", LeaderId: "n1", TotalNodes: 3},
	}, nil
}

// ListNodes records the call.
func (s *recordingServer) ListNodes(_ context.Context, _ *platformv1.ListClusterNodesRequest) (*platformv1.ListClusterNodesResponse, error) {
	s.last = "ListNodes"
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.ListClusterNodesResponse{}, nil
}

// Bootstrap records the call.
func (s *recordingServer) Bootstrap(_ context.Context, _ *platformv1.BootstrapClusterRequest) (*platformv1.BootstrapClusterResponse, error) {
	s.last = "Bootstrap"
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.BootstrapClusterResponse{}, nil
}

// Join records the call.
func (s *recordingServer) Join(_ context.Context, _ *platformv1.JoinClusterRequest) (*platformv1.JoinClusterResponse, error) {
	s.last = "Join"
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.JoinClusterResponse{}, nil
}

// Leave records the call.
func (s *recordingServer) Leave(_ context.Context, _ *platformv1.LeaveClusterRequest) (*platformv1.LeaveClusterResponse, error) {
	s.last = "Leave"
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.LeaveClusterResponse{}, nil
}

// newTestLogger builds a quiet logger for the router.
func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelError, nil)
}

// envelope is the response writer's JSON envelope.
type envelope struct {
	Code    int             `json:"code"`
	Success bool            `json:"success"`
	Error   string          `json:"error"`
	Payload json.RawMessage `json:"payload"`
}

// mount mounts the cluster routes under /api/v1.
func mount(server platformv1.ClusterServiceServer, authorizer middleware.ScopeAuthorizer) *mux.Router {
	router := mux.NewRouter()
	r := NewClusterRouter(newTestLogger(), server, response.NewResponseWriter(newTestLogger(), nil))
	if authorizer != nil {
		r.SetScopeAuthorizer(authorizer)
	}
	r.RegisterRoutes(router.PathPrefix("/api/v1").Subrouter())
	return router
}

// grantingAuthorizer grants exactly one scope and refuses every other.
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

// clusterProbes are the five routes with the scope and RPC behind each
// (scopes from pkg/api/grpc/method_permissions.go).
var clusterProbes = []struct {
	name, verb, path, body, scope, rpc string
}{
	{"status", http.MethodGet, "/api/v1/cluster/status", "", "cluster:read", "GetStatus"},
	{"nodes", http.MethodGet, "/api/v1/cluster/nodes", "", "cluster:read", "ListNodes"},
	{"bootstrap", http.MethodPost, "/api/v1/cluster/bootstrap", "{}", "cluster:write", "Bootstrap"},
	{"join", http.MethodPost, "/api/v1/cluster/join", `{"seedAddresses":["10.0.0.1:7946"]}`, "cluster:write", "Join"},
	{"leave", http.MethodPost, "/api/v1/cluster/leave", "{}", "cluster:write", "Leave"},
}

// serve sends one request to router and returns the recorder.
func serve(router http.Handler, verb, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(verb, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	router.ServeHTTP(rec, req)
	return rec
}

// decode reads the response envelope.
func decode(t *testing.T, rec *httptest.ResponseRecorder) envelope {
	t.Helper()
	var body envelope
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode %s: %v", rec.Body, err)
	}
	return body
}

func TestClusterRouterServesEveryOperation(t *testing.T) {
	for _, probe := range clusterProbes {
		t.Run(probe.name, func(t *testing.T) {
			server := &recordingServer{}
			rec := serve(mount(server, nil), probe.verb, probe.path, probe.body)
			if rec.Code != http.StatusOK {
				t.Fatalf("code = %d, body %s", rec.Code, rec.Body)
			}
			if body := decode(t, rec); !body.Success {
				t.Fatalf("envelope = %+v", body)
			}
			if server.last != probe.rpc {
				t.Fatalf("rpc = %q, want %q", server.last, probe.rpc)
			}
		})
	}
}

func TestClusterRouterRequiresEachRouteScope(t *testing.T) {
	for _, probe := range clusterProbes {
		for _, granted := range []string{"cluster:read", "cluster:write"} {
			t.Run(probe.name+"/"+granted, func(t *testing.T) {
				server := &recordingServer{}
				rec := serve(mount(server, grantingAuthorizer{granted: granted}), probe.verb, probe.path, probe.body)
				if granted == probe.scope {
					if rec.Code != http.StatusOK || server.last != probe.rpc {
						t.Fatalf("code = %d rpc = %q, want 200 and %q", rec.Code, server.last, probe.rpc)
					}
					return
				}
				if rec.Code != http.StatusForbidden {
					t.Fatalf("code = %d, want 403", rec.Code)
				}
				if server.last != "" {
					t.Fatalf("rpc %q reached without scope %s", server.last, probe.scope)
				}
			})
		}
	}
}

func TestClusterRouterWritesCamelCase(t *testing.T) {
	rec := serve(mount(&recordingServer{}, nil), http.MethodGet, "/api/v1/cluster/status", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("code = %d, body %s", rec.Code, rec.Body)
	}
	payload := string(decode(t, rec).Payload)
	for _, want := range []string{`"leaderId"`, `"totalNodes"`} {
		if !strings.Contains(payload, want) {
			t.Fatalf("payload %s lacks %s", payload, want)
		}
	}
	if strings.Contains(payload, `"leader_id"`) {
		t.Fatalf("payload %s is snake_case", payload)
	}
}

func TestClusterRouterMapsUnavailableTo503(t *testing.T) {
	for _, probe := range clusterProbes {
		t.Run(probe.name, func(t *testing.T) {
			server := &recordingServer{err: status.Error(codes.Unavailable, "cluster: not configured")}
			rec := serve(mount(server, nil), probe.verb, probe.path, probe.body)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("code = %d, want 503, body %s", rec.Code, rec.Body)
			}
			body := decode(t, rec)
			if body.Success || body.Error == "" {
				t.Fatalf("envelope = %+v", body)
			}
		})
	}
}

func TestClusterRouterWithoutAServerIs503(t *testing.T) {
	router := mount(nil, nil)
	for _, probe := range clusterProbes {
		t.Run(probe.name, func(t *testing.T) {
			rec := serve(router, probe.verb, probe.path, probe.body)
			if rec.Code != http.StatusServiceUnavailable {
				t.Fatalf("code = %d, want 503, body %s", rec.Code, rec.Body)
			}
		})
	}
}
