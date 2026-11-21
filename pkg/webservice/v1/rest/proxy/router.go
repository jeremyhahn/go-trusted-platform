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
// the REST surface the web SDK calls (#2061): all fourteen operations, the
// seven reads and the seven writes. It answers from the same in-process
// ProxyServiceServer the gRPC, daemon REST, QUIC and MCP transports use, on
// the paths and with the body shapes the daemon REST serves.
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

// The IAM scopes the proxy routes need, as on gRPC
// (pkg/api/grpc/method_permissions.go): reads need proxy:read; creates,
// updates and reload need proxy:write; deletes need proxy:delete.
const (
	scopeRead   = "proxy:read"
	scopeWrite  = "proxy:write"
	scopeDelete = "proxy:delete"
)

// Router serves every ProxyService operation over REST.
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
func (r *Router) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// RegisterRoutes mounts the proxy routes on parent. Route and pool ids may
// contain slashes: clients send them percent-encoded (a%2Fb), the subrouter
// matches the encoded path and the handlers decode the id with pathID.
func (r *Router) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.UseEncodedPath()
	sr.Handle("/routes", r.requireScope(scopeRead, r.listRoutes)).Methods(http.MethodGet)
	sr.Handle("/routes", r.requireScope(scopeWrite, r.createRoute)).Methods(http.MethodPost)
	sr.Handle("/routes/{id}", r.requireScope(scopeRead, r.getRoute)).Methods(http.MethodGet)
	sr.Handle("/routes/{id}", r.requireScope(scopeWrite, r.updateRoute)).Methods(http.MethodPut)
	sr.Handle("/routes/{id}", r.requireScope(scopeDelete, r.deleteRoute)).Methods(http.MethodDelete)
	sr.Handle("/pools", r.requireScope(scopeRead, r.listPools)).Methods(http.MethodGet)
	sr.Handle("/pools", r.requireScope(scopeWrite, r.createPool)).Methods(http.MethodPost)
	sr.Handle("/pools/{id}", r.requireScope(scopeRead, r.getPool)).Methods(http.MethodGet)
	sr.Handle("/pools/{id}", r.requireScope(scopeWrite, r.updatePool)).Methods(http.MethodPut)
	sr.Handle("/pools/{id}", r.requireScope(scopeDelete, r.deletePool)).Methods(http.MethodDelete)
	sr.Handle("/config", r.requireScope(scopeRead, r.getConfig)).Methods(http.MethodGet)
	sr.Handle("/status", r.requireScope(scopeRead, r.getStatus)).Methods(http.MethodGet)
	sr.Handle("/reload", r.requireScope(scopeWrite, r.reloadConfig)).Methods(http.MethodPost)
	sr.Handle("/zone-matrix", r.requireScope(scopeRead, r.getZoneMatrix)).Methods(http.MethodGet)
}

// requireScope wraps handler in the scope check when an authorizer is set.
// Without one (the legacy JWT handler is no ScopeAuthorizer) the reads stay
// on the admin role gate alone, but every write and delete fails closed with
// 403, as scopeRouteGuard does for the app service routes (#1990, #2160
// Codex).
func (r *Router) requireScope(scope string, handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		if scope == scopeRead {
			return handler
		}
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		})
	}
	return r.scopeAuthorizer.RequireScope(scope)(handler)
}

// pathID returns the {id} route variable decoded: the subrouter matches the
// encoded path, so an id containing a slash arrives as a%2Fb. A value that
// does not decode is returned raw, as the switch router's decodeVar does.
func pathID(req *http.Request) string {
	raw := mux.Vars(req)["id"]
	id, err := url.PathUnescape(raw)
	if err != nil {
		return raw
	}
	return id
}

// ensure answers 503 when no ProxyServiceServer is wired.
func (r *Router) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "proxy"})
		return false
	}
	return true
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
	resp, err := r.server.GetRoute(req.Context(), &platformv1.GetProxyRouteRequest{Id: pathID(req)})
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
	resp, err := r.server.GetPool(req.Context(), &platformv1.GetProxyPoolRequest{Id: pathID(req)})
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

// decode reads the request body into msg; a body that does not decode is
// answered 400 and decode reports false.
func (r *Router) decode(w http.ResponseWriter, req *http.Request, msg proto.Message) bool {
	if err := protorest.DecodeRequest(req, msg); err != nil {
		r.respWriter.Error400(w, req, err)
		return false
	}
	return true
}

// writeCreated answers resp with 201, or the HTTP status of the service
// refusal.
func (r *Router) writeCreated(w http.ResponseWriter, req *http.Request, resp proto.Message, err error) {
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, req, r.respWriter, http.StatusCreated, resp)
}

// createRoute decodes {"route":{...}}, as the daemon REST does.
func (r *Router) createRoute(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.CreateProxyRouteRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.CreateRoute(req.Context(), in)
	r.writeCreated(w, req, resp, err)
}

// updateRoute decodes {"route":{...}}; the URL id is the request id.
func (r *Router) updateRoute(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.UpdateProxyRouteRequest{}
	if !r.decode(w, req, in) {
		return
	}
	in.Id = pathID(req)
	resp, err := r.server.UpdateRoute(req.Context(), in)
	r.write(w, req, resp, err)
}

func (r *Router) deleteRoute(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.DeleteRoute(req.Context(), &platformv1.DeleteProxyRouteRequest{Id: pathID(req)})
	r.write(w, req, resp, err)
}

// createPool decodes {"pool":{...}}, as the daemon REST does.
func (r *Router) createPool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.CreateProxyPoolRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.CreatePool(req.Context(), in)
	r.writeCreated(w, req, resp, err)
}

// updatePool decodes {"pool":{...}}; the URL id is the request id.
func (r *Router) updatePool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.UpdateProxyPoolRequest{}
	if !r.decode(w, req, in) {
		return
	}
	in.Id = pathID(req)
	resp, err := r.server.UpdatePool(req.Context(), in)
	r.write(w, req, resp, err)
}

func (r *Router) deletePool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.DeletePool(req.Context(), &platformv1.DeleteProxyPoolRequest{Id: pathID(req)})
	r.write(w, req, resp, err)
}

// reloadConfig ignores the request body.
func (r *Router) reloadConfig(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ReloadProxyConfig(req.Context(), &platformv1.ReloadProxyConfigRequest{})
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
