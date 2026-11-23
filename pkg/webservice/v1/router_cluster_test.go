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

package v1

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// countingClusterServer counts the cluster calls that reach it and answers
// each with err when it is set.
type countingClusterServer struct {
	platformv1.UnimplementedClusterServiceServer
	status    int
	nodes     int
	bootstrap int
	join      int
	leave     int
	err       error
}

func (s *countingClusterServer) Bootstrap(context.Context, *platformv1.BootstrapClusterRequest) (*platformv1.BootstrapClusterResponse, error) {
	s.bootstrap++
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.BootstrapClusterResponse{}, nil
}

func (s *countingClusterServer) Join(context.Context, *platformv1.JoinClusterRequest) (*platformv1.JoinClusterResponse, error) {
	s.join++
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.JoinClusterResponse{}, nil
}

func (s *countingClusterServer) GetStatus(context.Context, *platformv1.GetClusterStatusRequest) (*platformv1.GetClusterStatusResponse, error) {
	s.status++
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.GetClusterStatusResponse{}, nil
}

func (s *countingClusterServer) ListNodes(context.Context, *platformv1.ListClusterNodesRequest) (*platformv1.ListClusterNodesResponse, error) {
	s.nodes++
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.ListClusterNodesResponse{}, nil
}

func (s *countingClusterServer) Leave(context.Context, *platformv1.LeaveClusterRequest) (*platformv1.LeaveClusterResponse, error) {
	s.leave++
	if s.err != nil {
		return nil, s.err
	}
	return &platformv1.LeaveClusterResponse{}, nil
}

// serveCluster sends one request through the console router built on a
// registry holding srv and the given token handler.
func serveCluster(t *testing.T, srv *countingClusterServer, auth jwt.TokenHandler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	registry := &testHandlerRegistry{tokenHandler: auth, clusterService: srv}
	var req *http.Request
	if body == "" {
		req = httptest.NewRequest(method, target, nil)
	} else {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	newGatedTestRouter(t, registry).ServeHTTP(recorder, req)
	return recorder
}

func clusterAdmin() jwt.TokenHandler {
	return &allScopesSessionAuth{sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}}
}

// TestClusterRoutes_StatusOnTheConsole pins the round-3 finding on #2180:
// the web app's cluster hook reaches GetStatus through the console listener.
func TestClusterRoutes_StatusOnTheConsole(t *testing.T) {
	srv := &countingClusterServer{}
	rec := serveCluster(t, srv, clusterAdmin(), http.MethodGet, "/api/v1/cluster/status", "")
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, srv.status)
}

func TestClusterRoutes_NodesOnTheConsole(t *testing.T) {
	srv := &countingClusterServer{}
	rec := serveCluster(t, srv, clusterAdmin(), http.MethodGet, "/api/v1/cluster/nodes", "")
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, srv.nodes)
}

func TestClusterRoutes_LeaveOnTheConsole(t *testing.T) {
	srv := &countingClusterServer{}
	rec := serveCluster(t, srv, clusterAdmin(), http.MethodPost, "/api/v1/cluster/leave", "{}")
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, srv.leave)
}

// TestClusterRoutes_UnavailableIs503 maps the gRPC Unavailable code to 503
// with a JSON error body, as the daemon listener does.
func TestClusterRoutes_UnavailableIs503(t *testing.T) {
	srv := &countingClusterServer{err: status.Error(codes.Unavailable, "no cluster coordinator")}
	rec := serveCluster(t, srv, clusterAdmin(), http.MethodGet, "/api/v1/cluster/status", "")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Contains(t, body["error"], "no cluster coordinator")
}

// TestClusterRoutes_AreGated refuses an anonymous caller (401) and a
// non-admin session (403) before any cluster call.
func TestClusterRoutes_AreGated(t *testing.T) {
	srv := &countingClusterServer{}
	rec := serveCluster(t, srv, &anonymousAuth{}, http.MethodGet, "/api/v1/cluster/status", "")
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	rec = serveCluster(t, srv, &sessionAuth{roles: []string{"user"}, tenantID: "system"}, http.MethodPost, "/api/v1/cluster/leave", "{}")
	assert.Equal(t, http.StatusForbidden, rec.Code)

	assert.Zero(t, srv.status+srv.nodes+srv.leave)
}

// TestClusterRoutes_BootstrapAndJoinOnTheConsole pins the round-2 finding on
// #2180: Bootstrap and Join reach their servers through the console listener.
func TestClusterRoutes_BootstrapAndJoinOnTheConsole(t *testing.T) {
	srv := &countingClusterServer{}
	rec := serveCluster(t, srv, clusterAdmin(), http.MethodPost, "/api/v1/cluster/bootstrap", "{}")
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, srv.bootstrap)

	rec = serveCluster(t, srv, clusterAdmin(), http.MethodPost, "/api/v1/cluster/join", "{}")
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, 1, srv.join)
}

// clusterRoute is one console cluster route, the scope it needs and the
// counter of the server call it reaches.
type clusterRoute struct {
	name, method, target, body, scope string
	count                             func(*countingClusterServer) int
}

func clusterRoutesUnderTest() []clusterRoute {
	return []clusterRoute{
		{"status", http.MethodGet, "/api/v1/cluster/status", "", "cluster:read", func(s *countingClusterServer) int { return s.status }},
		{"nodes", http.MethodGet, "/api/v1/cluster/nodes", "", "cluster:read", func(s *countingClusterServer) int { return s.nodes }},
		{"bootstrap", http.MethodPost, "/api/v1/cluster/bootstrap", "{}", "cluster:write", func(s *countingClusterServer) int { return s.bootstrap }},
		{"join", http.MethodPost, "/api/v1/cluster/join", "{}", "cluster:write", func(s *countingClusterServer) int { return s.join }},
		{"leave", http.MethodPost, "/api/v1/cluster/leave", "{}", "cluster:write", func(s *countingClusterServer) int { return s.leave }},
	}
}

// clusterGrant is the set of scopes an admin session holds in
// TestClusterRoutes_ScopeEnforced.
type clusterGrant map[string]bool

func (g clusterGrant) list() []string {
	out := []string{}
	for scope, ok := range g {
		if ok {
			out = append(out, scope)
		}
	}
	return out
}

// TestClusterRoutes_ScopeEnforced pins the round-2 finding on #2180: every
// console cluster route checks its own scope, and a refused route reaches no
// server.
func TestClusterRoutes_ScopeEnforced(t *testing.T) {
	grants := []struct {
		name   string
		scopes clusterGrant
	}{
		{"no scope", clusterGrant{}},
		{"cluster:read only", clusterGrant{"cluster:read": true}},
		{"cluster:write only", clusterGrant{"cluster:write": true}},
		{"cluster:read and cluster:write", clusterGrant{"cluster:read": true, "cluster:write": true}},
	}
	for _, g := range grants {
		for _, route := range clusterRoutesUnderTest() {
			t.Run(g.name+"/"+route.name, func(t *testing.T) {
				srv := &countingClusterServer{}
				auth := &scopedSessionAuth{
					sessionAuth: sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"},
					scopes:      g.scopes.list(),
				}
				rec := serveCluster(t, srv, auth, route.method, route.target, route.body)
				if g.scopes[route.scope] {
					assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
					assert.Equal(t, 1, route.count(srv))
				} else {
					assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
					assert.Zero(t, route.count(srv))
				}
				assert.Equal(t, route.count(srv), srv.status+srv.nodes+srv.bootstrap+srv.join+srv.leave)
			})
		}
	}

	t.Run("admin under a token handler with no ScopeAuthorizer is refused", func(t *testing.T) {
		for _, route := range clusterRoutesUnderTest() {
			srv := &countingClusterServer{}
			auth := &sessionAuth{roles: []string{common.ROLE_ADMIN}, tenantID: "system"}
			rec := serveCluster(t, srv, auth, route.method, route.target, route.body)
			assert.Equal(t, http.StatusForbidden, rec.Code, route.name)
			assert.Zero(t, srv.status+srv.nodes+srv.bootstrap+srv.join+srv.leave, route.name)
		}
	})
}
