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

package gateway

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// sdnBasePath is where the daemon transport serves the load balancer, NAT64
// and performance routes (pkg/api/rest/gateway_{lb,nat64,perf}_handlers.go).
// The web service serves them at the same paths so one SDK path reaches
// either server.
const sdnBasePath = "/sdn/gateway"

// registerLBRoutes mounts the load balancer, NAT64 and performance routes.
//
//	POST   /api/v1/sdn/gateway/lb/vips                                     - AddVIP
//	GET    /api/v1/sdn/gateway/lb/vips                                     - ListVIPs
//	GET    /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}         - GetVIP
//	DELETE /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}         - RemoveVIP
//	PUT    /api/v1/sdn/gateway/lb/vips/{protocol}/{address}/{port}/backends - SetVIPBackends
//	GET    /api/v1/sdn/gateway/lb/status                                   - GetLBStatus
//	GET    /api/v1/sdn/gateway/nat64/status                                - GetNAT64Status
//	POST   /api/v1/sdn/gateway/perf/flows                                  - GetPerfFlows
//	GET    /api/v1/sdn/gateway/perf/datapath                               - GetPerfDatapath (?bridge=)
//	GET    /api/v1/sdn/gateway/perf/conntrack                              - GetPerfConntrack (?zone=)
func (r *GatewayRouter) registerLBRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(sdnBasePath).Subrouter()
	sr.HandleFunc("/lb/vips", r.addVIP).Methods("POST")
	sr.HandleFunc("/lb/vips", r.listVIPs).Methods("GET")
	sr.HandleFunc("/lb/vips/{protocol}/{address}/{port}", r.getVIP).Methods("GET")
	sr.HandleFunc("/lb/vips/{protocol}/{address}/{port}", r.removeVIP).Methods("DELETE")
	sr.HandleFunc("/lb/vips/{protocol}/{address}/{port}/backends", r.setVIPBackends).Methods("PUT")
	sr.HandleFunc("/lb/status", r.getLBStatus).Methods("GET")
	sr.HandleFunc("/nat64/status", r.getNAT64Status).Methods("GET")
	sr.HandleFunc("/perf/flows", r.getPerfFlows).Methods("POST")
	sr.HandleFunc("/perf/datapath", r.getPerfDatapath).Methods("GET")
	sr.HandleFunc("/perf/conntrack", r.getPerfConntrack).Methods("GET")
}

// errInvalidVIPKey reports a VIP path whose port is not 1-65535.
type errInvalidVIPKey struct{ port string }

func (e errInvalidVIPKey) Error() string {
	return fmt.Sprintf("invalid VIP port %q: must be 1-65535", e.port)
}

// errInvalidZone reports a conntrack zone filter that is not a uint32.
type errInvalidZone struct{ zone string }

func (e errInvalidZone) Error() string {
	return fmt.Sprintf("invalid conntrack zone %q", e.zone)
}

// vipKey reads the {protocol}/{address}/{port} VIP key from the path.
func vipKey(req *http.Request) (protocol, address string, port uint32, err error) {
	vars := mux.Vars(req)
	p, perr := strconv.ParseUint(vars["port"], 10, 16)
	if perr != nil || p == 0 {
		return "", "", 0, errInvalidVIPKey{port: vars["port"]}
	}
	return vars["protocol"], vars["address"], uint32(p), nil
}

func (r *GatewayRouter) addVIP(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.AddVIPRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.AddVIP(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, req, r.respWriter, http.StatusCreated, resp)
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
	protocol, address, port, err := vipKey(req)
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.GetVIP(req.Context(), &platformv1.GetVIPRequest{
		Protocol: protocol, Address: address, Port: port,
	})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) removeVIP(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	protocol, address, port, err := vipKey(req)
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.RemoveVIP(req.Context(), &platformv1.RemoveVIPRequest{
		Protocol: protocol, Address: address, Port: port,
	})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *GatewayRouter) setVIPBackends(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	protocol, address, port, err := vipKey(req)
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	pbReq := &platformv1.SetVIPBackendsRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	// The path names the VIP; a key in the body cannot redirect the write.
	pbReq.Protocol, pbReq.Address, pbReq.Port = protocol, address, port
	resp, err := r.server.SetVIPBackends(req.Context(), pbReq)
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

func (r *GatewayRouter) getNAT64Status(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetNAT64Status(req.Context(), &platformv1.GetNAT64StatusRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

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

func (r *GatewayRouter) getPerfConntrack(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.GetPerfConntrackRequest{}
	if raw := req.URL.Query().Get("zone"); raw != "" {
		zone, err := strconv.ParseUint(raw, 10, 32)
		if err != nil {
			r.respWriter.Error400(w, req, errInvalidZone{zone: raw})
			return
		}
		z := uint32(zone)
		pbReq.Zone = &z
	}
	resp, err := r.server.GetPerfConntrack(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}
