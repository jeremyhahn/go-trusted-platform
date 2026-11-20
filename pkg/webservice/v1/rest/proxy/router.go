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

// Package proxy implements REST endpoints under /api/v1/proxy. The routes are
// a thin binding over the same in-process ProxyServiceServer that backs gRPC,
// QUIC and MCP, so the web console edits the one route and pool store every
// syncing gatewayd reads.
package proxy

import (
	"net/http"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// basePath is the REST prefix for reverse-proxy endpoints.
const basePath = "/proxy"

// maxBodyBytes bounds a route or pool document.
const maxBodyBytes = 1 << 20

// ProxyRouter wires REST endpoints onto a ProxyServiceServer.
type ProxyRouter struct {
	logger     *logging.Logger
	server     platformv1.ProxyServiceServer
	respWriter response.HttpWriter
	router.WebServiceRouter
}

// NewProxyRouter creates a new reverse-proxy REST router.
func NewProxyRouter(
	logger *logging.Logger,
	server platformv1.ProxyServiceServer,
	respWriter response.HttpWriter,
) *ProxyRouter {
	return &ProxyRouter{logger: logger, server: server, respWriter: respWriter}
}

// RegisterRoutes mounts the reverse-proxy routes.
//
//	GET    /api/v1/proxy/routes        - ListRoutes
//	POST   /api/v1/proxy/routes        - CreateRoute (body: ProxyRoute)
//	GET    /api/v1/proxy/routes/{id}   - GetRoute
//	PUT    /api/v1/proxy/routes/{id}   - UpdateRoute (body: ProxyRoute)
//	DELETE /api/v1/proxy/routes/{id}   - DeleteRoute
//	GET    /api/v1/proxy/pools         - ListPools
//	POST   /api/v1/proxy/pools         - CreatePool (body: ProxyPool)
//	GET    /api/v1/proxy/pools/{id}    - GetPool
//	PUT    /api/v1/proxy/pools/{id}    - UpdatePool (body: ProxyPool)
//	DELETE /api/v1/proxy/pools/{id}    - DeletePool
//	GET    /api/v1/proxy/config        - GetProxyConfig
//	POST   /api/v1/proxy/config/reload - ReloadProxyConfig
//	GET    /api/v1/proxy/status        - GetProxyStatus
//	GET    /api/v1/proxy/zone-matrix   - GetZoneMatrix
func (r *ProxyRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("/routes", r.listRoutes).Methods(http.MethodGet)
	sr.HandleFunc("/routes", r.createRoute).Methods(http.MethodPost)
	sr.HandleFunc("/routes/{id}", r.getRoute).Methods(http.MethodGet)
	sr.HandleFunc("/routes/{id}", r.updateRoute).Methods(http.MethodPut)
	sr.HandleFunc("/routes/{id}", r.deleteRoute).Methods(http.MethodDelete)
	sr.HandleFunc("/pools", r.listPools).Methods(http.MethodGet)
	sr.HandleFunc("/pools", r.createPool).Methods(http.MethodPost)
	sr.HandleFunc("/pools/{id}", r.getPool).Methods(http.MethodGet)
	sr.HandleFunc("/pools/{id}", r.updatePool).Methods(http.MethodPut)
	sr.HandleFunc("/pools/{id}", r.deletePool).Methods(http.MethodDelete)
	sr.HandleFunc("/config", r.getConfig).Methods(http.MethodGet)
	sr.HandleFunc("/config/reload", r.reloadConfig).Methods(http.MethodPost)
	sr.HandleFunc("/status", r.getStatus).Methods(http.MethodGet)
	sr.HandleFunc("/zone-matrix", r.getZoneMatrix).Methods(http.MethodGet)
}

// ensure reports whether the backing service is configured, writing a 503
// when it is not.
func (r *ProxyRouter) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "proxy"})
		return false
	}
	return true
}

// write sends resp or err.
func (r *ProxyRouter) write(w http.ResponseWriter, req *http.Request, resp proto.Message, err error) {
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

// decode reads a protojson body into msg, writing a 400 on failure. The body is bounded at maxBodyBytes.
func (r *ProxyRouter) decode(w http.ResponseWriter, req *http.Request, msg proto.Message) bool {
	req.Body = http.MaxBytesReader(w, req.Body, maxBodyBytes)
	if err := protorest.DecodeRequest(req, msg); err != nil {
		r.respWriter.Error400(w, req, err)
		return false
	}
	return true
}

func (r *ProxyRouter) listRoutes(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListRoutes(req.Context(), &platformv1.ListProxyRoutesRequest{})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) createRoute(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	route := &platformv1.ProxyRoute{}
	if !r.decode(w, req, route) {
		return
	}
	resp, err := r.server.CreateRoute(req.Context(), &platformv1.CreateProxyRouteRequest{Route: route})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) getRoute(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetRoute(req.Context(), &platformv1.GetProxyRouteRequest{Id: mux.Vars(req)["id"]})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) updateRoute(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	route := &platformv1.ProxyRoute{}
	if !r.decode(w, req, route) {
		return
	}
	resp, err := r.server.UpdateRoute(req.Context(), &platformv1.UpdateProxyRouteRequest{
		Id:    mux.Vars(req)["id"],
		Route: route,
	})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) deleteRoute(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.DeleteRoute(req.Context(), &platformv1.DeleteProxyRouteRequest{Id: mux.Vars(req)["id"]})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) listPools(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListPools(req.Context(), &platformv1.ListProxyPoolsRequest{})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) createPool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pool := &platformv1.ProxyPool{}
	if !r.decode(w, req, pool) {
		return
	}
	resp, err := r.server.CreatePool(req.Context(), &platformv1.CreateProxyPoolRequest{Pool: pool})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) getPool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetPool(req.Context(), &platformv1.GetProxyPoolRequest{Id: mux.Vars(req)["id"]})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) updatePool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pool := &platformv1.ProxyPool{}
	if !r.decode(w, req, pool) {
		return
	}
	resp, err := r.server.UpdatePool(req.Context(), &platformv1.UpdateProxyPoolRequest{
		Id:   mux.Vars(req)["id"],
		Pool: pool,
	})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) deletePool(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.DeletePool(req.Context(), &platformv1.DeleteProxyPoolRequest{Id: mux.Vars(req)["id"]})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) getConfig(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetProxyConfig(req.Context(), &platformv1.GetProxyConfigRequest{})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) reloadConfig(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ReloadProxyConfig(req.Context(), &platformv1.ReloadProxyConfigRequest{})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) getStatus(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetProxyStatus(req.Context(), &platformv1.GetProxyStatusRequest{})
	r.write(w, req, resp, err)
}

func (r *ProxyRouter) getZoneMatrix(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetZoneMatrix(req.Context(), &platformv1.GetProxyZoneMatrixRequest{})
	r.write(w, req, resp, err)
}
