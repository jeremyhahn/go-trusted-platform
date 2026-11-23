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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestNewSDNRouter(t *testing.T) {
	logger := newTestLogger()
	router := NewSDNRouter(logger, &scriptedSDNServer{}, response.NewResponseWriter(logger, nil))

	require.NotNil(t, router)
	require.NotNil(t, router.handlers)
}

// TestRegisterRoutes: every SDN route, zones included, is mounted.
func TestRegisterRoutes(t *testing.T) {
	router := newTestRouter(&scriptedSDNServer{})
	routes := append([]struct{ method, target string }{
		{http.MethodPost, "/api/v1/sdn/zones"},
		{http.MethodGet, "/api/v1/sdn/zones"},
		{http.MethodPut, "/api/v1/sdn/zones/lab"},
		{http.MethodDelete, "/api/v1/sdn/zones/lab"},
	}, everyRoute...)

	for _, route := range routes {
		t.Run(route.method+" "+route.target, func(t *testing.T) {
			var match mux.RouteMatch
			assert.True(t, router.Match(httptest.NewRequest(route.method, route.target, nil), &match))
		})
	}
}

// sdnScopeGrant is a scope authorizer that admits only its granted scope.
type sdnScopeGrant struct{ granted string }

func (g sdnScopeGrant) RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if scope != g.granted {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// countingSDNServer counts the delete calls that reach the service.
type countingSDNServer struct {
	scriptedSDNServer
	deletes int
}

func (s *countingSDNServer) DeletePolicy(_ context.Context, _ *platformv1.DeletePolicyRequest) (*platformv1.DeletePolicyResponse, error) {
	s.deletes++
	return &platformv1.DeletePolicyResponse{}, nil
}

func (s *countingSDNServer) DeleteVLAN(_ context.Context, _ *platformv1.DeleteVLANRequest) (*platformv1.DeleteVLANResponse, error) {
	s.deletes++
	return &platformv1.DeleteVLANResponse{}, nil
}

func scopedSDNRoot(server platformv1.SDNServiceServer, authorizer middleware.ScopeAuthorizer) *mux.Router {
	logger := newTestLogger()
	r := NewSDNRouter(logger, server, response.NewResponseWriter(logger, nil))
	r.SetScopeAuthorizer(authorizer)
	root := mux.NewRouter()
	r.RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())
	return root
}

// The REST policy and VLAN deletes need the sdn:delete scope, as the
// daemon's gRPC methods do (#1951 (a)).
func TestSDNRouter_DeleteRoutesNeedDeleteScope(t *testing.T) {
	deleteScope := grpcapi.ScopeForMethod("/platform.v1.SDNService/DeletePolicy")
	require.NotEmpty(t, deleteScope)
	require.Equal(t, deleteScope, grpcapi.ScopeForMethod("/platform.v1.SDNService/DeleteVLAN"))

	targets := []string{"/api/v1/sdn/policies/p1", "/api/v1/sdn/vlans/100?bridge_id=b1"}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			denied := &countingSDNServer{}
			rec := httptest.NewRecorder()
			scopedSDNRoot(denied, sdnScopeGrant{granted: "sdn:read"}).
				ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, target, nil))
			assert.Equal(t, http.StatusForbidden, rec.Code)
			assert.Zero(t, denied.deletes, "a request without the scope must not reach the service")

			allowed := &countingSDNServer{}
			rec = httptest.NewRecorder()
			scopedSDNRoot(allowed, sdnScopeGrant{granted: deleteScope}).
				ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, target, nil))
			assert.NotEqual(t, http.StatusForbidden, rec.Code)
			assert.Equal(t, 1, allowed.deletes)
		})
	}
}
