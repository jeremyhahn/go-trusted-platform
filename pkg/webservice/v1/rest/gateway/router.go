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

// Package gateway implements REST endpoints under /api/v1/gateway.
package gateway

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const basePath = "/gateway"

// GatewayRouter wires REST endpoints onto a GatewayServiceServer.
type GatewayRouter struct {
	logger     *logging.Logger
	server     platformv1.GatewayServiceServer
	respWriter response.HttpWriter
	router.WebServiceRouter
}

// NewGatewayRouter creates a router.
func NewGatewayRouter(
	logger *logging.Logger,
	server platformv1.GatewayServiceServer,
	respWriter response.HttpWriter,
) *GatewayRouter {
	return &GatewayRouter{logger: logger, server: server, respWriter: respWriter}
}

// RegisterRoutes mounts gateway routes.
//
//	GET    /api/v1/gateway/status                   - GetGatewayStatus
//	POST   /api/v1/gateway/mode                     - SetGatewayMode
//	GET    /api/v1/gateway/bgp/status               - GetBGPStatus
//	GET    /api/v1/gateway/bgp/peers                - ListBGPPeers
//	GET    /api/v1/gateway/bgp/prefixes             - ListAnnouncedPrefixes
//	POST   /api/v1/gateway/bgp/prefixes             - AnnouncePrefix
//	DELETE /api/v1/gateway/bgp/prefixes             - WithdrawPrefix (?prefix=)
//	GET    /api/v1/gateway/ipam/pools               - ListIPAMPools
//	GET    /api/v1/gateway/ipam/allocations         - ListAllocations
//	POST   /api/v1/gateway/ipam/allocations         - AllocateIP
//	DELETE /api/v1/gateway/ipam/allocations         - ReleaseIP (?ip=)
func (r *GatewayRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("/status", r.getStatus).Methods("GET")
	sr.HandleFunc("/mode", r.setMode).Methods("POST")
	sr.HandleFunc("/bgp/status", r.getBGPStatus).Methods("GET")
	sr.HandleFunc("/bgp/peers", r.listBGPPeers).Methods("GET")
	sr.HandleFunc("/bgp/prefixes", r.listAnnouncedPrefixes).Methods("GET")
	sr.HandleFunc("/bgp/prefixes", r.announcePrefix).Methods("POST")
	sr.HandleFunc("/bgp/prefixes", r.withdrawPrefix).Methods("DELETE")
	sr.HandleFunc("/ipam/pools", r.listIPAMPools).Methods("GET")
	sr.HandleFunc("/ipam/allocations", r.listAllocations).Methods("GET")
	sr.HandleFunc("/ipam/allocations", r.allocateIP).Methods("POST")
	sr.HandleFunc("/ipam/allocations", r.releaseIP).Methods("DELETE")
}

func (r *GatewayRouter) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "gateway"})
		return false
	}
	return true
}

func (r *GatewayRouter) getStatus(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetGatewayStatus(req.Context(), &platformv1.GetGatewayStatusRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) setMode(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.SetGatewayModeRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.SetGatewayMode(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) getBGPStatus(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetBGPStatus(req.Context(), &platformv1.GetBGPStatusRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) listBGPPeers(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListBGPPeers(req.Context(), &platformv1.ListBGPPeersRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) listAnnouncedPrefixes(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListAnnouncedPrefixes(req.Context(), &platformv1.ListAnnouncedPrefixesRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) announcePrefix(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.AnnouncePrefixRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.AnnouncePrefix(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, req, r.respWriter, http.StatusCreated, resp)
}

func (r *GatewayRouter) withdrawPrefix(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	prefix := req.URL.Query().Get("prefix")
	resp, err := r.server.WithdrawPrefix(req.Context(), &platformv1.WithdrawPrefixRequest{Prefix: prefix})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) listIPAMPools(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListIPAMPools(req.Context(), &platformv1.ListIPAMPoolsRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) listAllocations(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListAllocations(req.Context(), &platformv1.ListAllocationsRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) allocateIP(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.AllocateIPRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.AllocateIP(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, req, r.respWriter, http.StatusCreated, resp)
}

func (r *GatewayRouter) releaseIP(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	ip := req.URL.Query().Get("ip")
	resp, err := r.server.ReleaseIP(req.Context(), &platformv1.ReleaseIPRequest{Ip: ip})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}
