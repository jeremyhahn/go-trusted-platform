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
	"strconv"

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
//	GET    /api/v1/gateway/ipam/allocations         - ListAllocations (?poolId=)
//	POST   /api/v1/gateway/ipam/allocations         - AllocateIP
//	DELETE /api/v1/gateway/ipam/allocations         - ReleaseIP (?ip=)
//	GET    /api/v1/gateway/lb/vips                  - ListVIPs
//	GET    /api/v1/gateway/lb/vips/{protocol}/{address}/{port} - GetVIP
//	GET    /api/v1/gateway/lb/status                - GetLBStatus
//	POST   /api/v1/gateway/perf/flows               - GetPerfFlows (installs temporary flows; admin)
//	GET    /api/v1/gateway/perf/datapath            - GetPerfDatapath (?bridge=)
//	GET    /api/v1/gateway/perf/conntrack           - GetPerfConntrack (?zone=)
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
	// Load-balancer reads. AddVIP, RemoveVIP and SetVIPBackends come in the
	// next slice (#2052).
	sr.HandleFunc("/lb/vips", r.listVIPs).Methods("GET")
	sr.HandleFunc("/lb/vips/{protocol}/{address}/{port}", r.getVIP).Methods("GET")
	sr.HandleFunc("/lb/status", r.getLBStatus).Methods("GET")
	// GetPerfFlows installs and removes temporary flows in OpenFlow table
	// 250, so it is a POST (a write), never a GET.
	sr.HandleFunc("/perf/flows", r.getPerfFlows).Methods("POST")
	// The datapath and conntrack counters are only read, so both are GETs.
	sr.HandleFunc("/perf/datapath", r.getPerfDatapath).Methods("GET")
	sr.HandleFunc("/perf/conntrack", r.getPerfConntrack).Methods("GET")
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

func (r *GatewayRouter) listVIPs(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListVIPs(req.Context(), &platformv1.ListVIPsRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) getVIP(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	vars := mux.Vars(req)
	port, err := strconv.ParseUint(vars["port"], 10, 16)
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.GetVIP(req.Context(), &platformv1.GetVIPRequest{
		Protocol: vars["protocol"],
		Address:  vars["address"],
		Port:     uint32(port),
	})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) getLBStatus(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetLBStatus(req.Context(), &platformv1.GetLBStatusRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

// getPerfFlows runs one flow-programming benchmark. The service validates
// the count (InvalidArgument maps to 400) and removes the flows it installs.
func (r *GatewayRouter) getPerfFlows(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.GetPerfFlowsRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.GetPerfFlows(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

// getPerfDatapath reads the datapath counters of ?bridge= (empty: the
// default bridge).
func (r *GatewayRouter) getPerfDatapath(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetPerfDatapath(req.Context(), &platformv1.GetPerfDatapathRequest{
		Bridge: req.URL.Query().Get("bridge"),
	})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

// getPerfConntrack summarizes the conntrack table for ?zone= (absent:
// every zone). A zone that is not a uint32 answers 400.
func (r *GatewayRouter) getPerfConntrack(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.GetPerfConntrackRequest{}
	if z := req.URL.Query().Get("zone"); z != "" {
		v, err := strconv.ParseUint(z, 10, 32)
		if err != nil {
			r.respWriter.Error400(w, req, err)
			return
		}
		zone := uint32(v)
		pbReq.Zone = &zone
	}
	resp, err := r.server.GetPerfConntrack(req.Context(), pbReq)
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
	// The pool filter arrives as ?poolId= (JS SDK) or ?pool_id= (the proto
	// field name, as the IPAM router reads it); empty lists every pool.
	q := req.URL.Query()
	poolID := q.Get("poolId")
	if poolID == "" {
		poolID = q.Get("pool_id")
	}
	resp, err := r.server.ListAllocations(req.Context(), &platformv1.ListAllocationsRequest{PoolId: poolID})
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
