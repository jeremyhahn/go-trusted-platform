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

// Package cluster serves the platform ClusterService over REST under
// /api/v1/cluster. Messages go out through protojson (camelCase), as every
// other protorest router does, so the console reads the same field names as
// the SDK. A node without a cluster service answers 503 on every route.
package cluster

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/protobuf/proto"
)

// basePath is the REST prefix for cluster endpoints.
const basePath = "/cluster"

// Scopes from pkg/api/grpc/method_permissions.go.
const (
	scopeRead  = "cluster:read"
	scopeWrite = "cluster:write"
)

// ClusterRouter wires REST endpoints onto a ClusterServiceServer.
type ClusterRouter struct {
	logger          *logging.Logger
	server          platformv1.ClusterServiceServer
	respWriter      response.HttpWriter
	scopeAuthorizer middleware.ScopeAuthorizer
	router.WebServiceRouter
}

// NewClusterRouter creates a new cluster REST router. A nil server is
// allowed: every route then answers 503.
func NewClusterRouter(
	logger *logging.Logger,
	server platformv1.ClusterServiceServer,
	respWriter response.HttpWriter,
) *ClusterRouter {
	return &ClusterRouter{logger: logger, server: server, respWriter: respWriter}
}

// SetScopeAuthorizer supplies the scope check every route takes on top of the
// admin gate. Nil leaves the routes on the role gate alone, which is the case
// under the legacy JWT handler: its sessions carry roles, not scopes.
func (r *ClusterRouter) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// RegisterRoutes mounts the cluster routes.
//
//	GET  /api/v1/cluster/status    - GetStatus (cluster:read)
//	GET  /api/v1/cluster/nodes     - ListNodes (cluster:read)
//	POST /api/v1/cluster/bootstrap - Bootstrap (cluster:write, body: BootstrapClusterRequest)
//	POST /api/v1/cluster/join      - Join (cluster:write, body: JoinClusterRequest)
//	POST /api/v1/cluster/leave     - Leave (cluster:write, body: LeaveClusterRequest)
func (r *ClusterRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.Handle("/status", r.requireScope(scopeRead, r.getStatus)).Methods(http.MethodGet)
	sr.Handle("/nodes", r.requireScope(scopeRead, r.listNodes)).Methods(http.MethodGet)
	sr.Handle("/bootstrap", r.requireScope(scopeWrite, r.bootstrap)).Methods(http.MethodPost)
	sr.Handle("/join", r.requireScope(scopeWrite, r.join)).Methods(http.MethodPost)
	sr.Handle("/leave", r.requireScope(scopeWrite, r.leave)).Methods(http.MethodPost)
}

// requireScope wraps handler in the scope check when one is configured.
func (r *ClusterRouter) requireScope(scope string, handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		return handler
	}
	return r.scopeAuthorizer.RequireScope(scope)(handler)
}

// ensure reports whether the backing service is configured, writing a 503
// when it is not.
func (r *ClusterRouter) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "cluster"})
		return false
	}
	return true
}

// decode reads the JSON body into in, answering 400 when it does not parse.
func (r *ClusterRouter) decode(w http.ResponseWriter, req *http.Request, in proto.Message) bool {
	if err := protorest.DecodeRequest(req, in); err != nil {
		r.respWriter.Error400(w, req, err)
		return false
	}
	return true
}

// write answers resp, or the mapped status of err.
func (r *ClusterRouter) write(w http.ResponseWriter, req *http.Request, resp proto.Message, err error) {
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

// getStatus handles GET /api/v1/cluster/status.
func (r *ClusterRouter) getStatus(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetStatus(req.Context(), &platformv1.GetClusterStatusRequest{})
	r.write(w, req, resp, err)
}

// listNodes handles GET /api/v1/cluster/nodes.
func (r *ClusterRouter) listNodes(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListNodes(req.Context(), &platformv1.ListClusterNodesRequest{})
	r.write(w, req, resp, err)
}

// bootstrap handles POST /api/v1/cluster/bootstrap.
func (r *ClusterRouter) bootstrap(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.BootstrapClusterRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.Bootstrap(req.Context(), in)
	r.write(w, req, resp, err)
}

// join handles POST /api/v1/cluster/join.
func (r *ClusterRouter) join(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.JoinClusterRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.Join(req.Context(), in)
	r.write(w, req, resp, err)
}

// leave handles POST /api/v1/cluster/leave.
func (r *ClusterRouter) leave(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.LeaveClusterRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.Leave(req.Context(), in)
	r.write(w, req, resp, err)
}
