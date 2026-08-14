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

// Package ntp implements REST endpoints under /api/v1/ntp. The routes are a
// thin binding over the same in-process NTPServiceServer that backs gRPC,
// QUIC, MCP, and the Unix socket, so every transport reports one clock.
package ntp

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// basePath is the REST prefix for time-synchronization endpoints.
const basePath = "/ntp"

// NTPRouter wires REST endpoints onto an NTPServiceServer.
type NTPRouter struct {
	logger     *logging.Logger
	server     platformv1.NTPServiceServer
	respWriter response.HttpWriter
	router.WebServiceRouter
}

// NewNTPRouter creates a new time-synchronization REST router.
func NewNTPRouter(
	logger *logging.Logger,
	server platformv1.NTPServiceServer,
	respWriter response.HttpWriter,
) *NTPRouter {
	return &NTPRouter{logger: logger, server: server, respWriter: respWriter}
}

// RegisterRoutes mounts the time-synchronization routes.
//
//	GET  /api/v1/ntp/status   - GetStatus
//	GET  /api/v1/ntp/sources  - ListSources
//	POST /api/v1/ntp/step     - Step (operator recovery, ntp:write)
func (r *NTPRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("/status", r.getStatus).Methods(http.MethodGet)
	sr.HandleFunc("/sources", r.listSources).Methods(http.MethodGet)
	sr.HandleFunc("/step", r.step).Methods(http.MethodPost)
}

// ensure reports whether the backing service is configured, writing a 503
// when the node has no `ntp:` section.
func (r *NTPRouter) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "ntp"})
		return false
	}
	return true
}

// getStatus handles GET /api/v1/ntp/status.
func (r *NTPRouter) getStatus(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetStatus(req.Context(), &platformv1.GetNTPStatusRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

// listSources handles GET /api/v1/ntp/sources.
func (r *NTPRouter) listSources(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListSources(req.Context(), &platformv1.ListNTPSourcesRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

// step handles POST /api/v1/ntp/step. The handler returns 409 Conflict when
// no source is reachable: protorest maps the service's FailedPrecondition
// status onto that code, so a step request that cannot be satisfied is
// rejected rather than silently moving the clock on stale data.
func (r *NTPRouter) step(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.Step(req.Context(), &platformv1.StepNTPClockRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}
