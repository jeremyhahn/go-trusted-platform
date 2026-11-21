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

// Package proxy serves the ProxyService on the webservice (/api/v1/proxy),
// the REST surface the web SDK calls (#2061). It answers from the same
// in-process ProxyServiceServer the gRPC, daemon REST, QUIC and MCP
// transports use, on the paths the daemon REST serves.
package proxy

import (
	"net/http"
	"net/url"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// basePath is where the proxy routes are mounted under /api/v1.
const basePath = "/proxy"

// scopeRead is the IAM scope every proxy read needs, as on gRPC
// (pkg/api/iam/method_permissions.go).
const scopeRead = "proxy:read"

// Router serves the ProxyService reads over REST.
type Router struct {
	logger          *logging.Logger
	server          platformv1.ProxyServiceServer
	respWriter      response.HttpWriter
	scopeAuthorizer middleware.ScopeAuthorizer
	router.WebServiceRouter
}

// NewRouter returns a Router answering from server; a nil server answers
// every route 503.
func NewRouter(
	logger *logging.Logger,
	server platformv1.ProxyServiceServer,
	respWriter response.HttpWriter,
) *Router {
	return &Router{logger: logger, server: server, respWriter: respWriter}
}

// SetScopeAuthorizer sets the authorizer that enforces each route's scope.
// Without one every route answers 403.
func (r *Router) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// RegisterRoutes mounts the proxy read routes on parent.
func (r *Router) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	// Route and pool IDs may contain slashes (the SDK sends a%2Fb): match on
	// the encoded path and decode {id} in the handler, as the switch router does.
	sr.UseEncodedPath()
	sr.Handle("/routes", r.requireScope(scopeRead, r.listRoutes)).Methods(http.MethodGet)
	sr.Handle("/routes/{id}", r.requireScope(scopeRead, r.getRoute)).Methods(http.MethodGet)
	sr.Handle("/pools", r.requireScope(scopeRead, r.listPools)).Methods(http.MethodGet)
	sr.Handle("/pools/{id}", r.requireScope(scopeRead, r.getPool)).Methods(http.MethodGet)
	sr.Handle("/config", r.requireScope(scopeRead, r.getConfig)).Methods(http.MethodGet)
	sr.Handle("/status", r.requireScope(scopeRead, r.getStatus)).Methods(http.MethodGet)
	sr.Handle("/zone-matrix", r.requireScope(scopeRead, r.getZoneMatrix)).Methods(http.MethodGet)
	// The writes (route and pool create/update/delete, reload) come in the
	// next slice of #2061, behind proxy:write and proxy:delete.
}

// requireScope wraps handler in the scope check. Without an authorizer (the
// legacy JWT handler) the route fails closed with 403, since a role-only
// session carries no scopes (#1990, #2157 Codex), as scopeRouteGuard does.
func (r *Router) requireScope(scope string, handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		})
	}
	return r.scopeAuthorizer.RequireScope(scope)(handler)
}

// ensure answers 503 when no ProxyServiceServer is wired.
func (r *Router) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "proxy"})
		return false
	}
	return true
}

// pathID returns the URL-decoded {id} of an encoded-path route, so a%2Fb
// reaches the service as a/b.
func pathID(req *http.Request) (string, error) {
	return url.PathUnescape(mux.Vars(req)["id"])
}

func (r *Router) listRoutes(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListRoutes(req.Context(), &platformv1.ListProxyRoutesRequest{})
	r.write(w, req, resp, err)
}

func (r *Router) getRoute(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	id, err := pathID(req)
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.GetRoute(req.Context(), &platformv1.GetProxyRouteRequest{Id: id})
	r.write(w, req, resp, err)
}

func (r *Router) listPools(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListPools(req.Context(), &platformv1.ListProxyPoolsRequest{})
	r.write(w, req, resp, err)
}

func (r *Router) getPool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	id, err := pathID(req)
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.GetPool(req.Context(), &platformv1.GetProxyPoolRequest{Id: id})
	r.write(w, req, resp, err)
}

func (r *Router) getConfig(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetProxyConfig(req.Context(), &platformv1.GetProxyConfigRequest{})
	r.write(w, req, resp, err)
}

func (r *Router) getStatus(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetProxyStatus(req.Context(), &platformv1.GetProxyStatusRequest{})
	r.write(w, req, resp, err)
}

func (r *Router) getZoneMatrix(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetZoneMatrix(req.Context(), &platformv1.GetProxyZoneMatrixRequest{})
	r.write(w, req, resp, err)
}

// write answers resp with 200, or the HTTP status of the service refusal.
func (r *Router) write(w http.ResponseWriter, req *http.Request, resp proto.Message, err error) {
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}
