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

// Package overlay implements REST endpoints under /api/v1/overlay.
package overlay

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

const basePath = "/overlay"

// OverlayRouter wires REST endpoints onto an OverlayServiceServer.
type OverlayRouter struct {
	logger     *logging.Logger
	server     platformv1.OverlayServiceServer
	respWriter response.HttpWriter
	router.WebServiceRouter
}

// NewOverlayRouter creates a new router.
func NewOverlayRouter(
	logger *logging.Logger,
	server platformv1.OverlayServiceServer,
	respWriter response.HttpWriter,
) *OverlayRouter {
	return &OverlayRouter{logger: logger, server: server, respWriter: respWriter}
}

// RegisterRoutes mounts overlay routes.
//
//	GET    /api/v1/overlay/status                       - GetOverlayStatus
//	GET    /api/v1/overlay/vteps                        - ListVTEPs
//	GET    /api/v1/overlay/vteps/{nodeId}               - GetVTEP
//	GET    /api/v1/overlay/vnis                         - ListVNIs
//	POST   /api/v1/overlay/vnis                         - CreateVNI
//	DELETE /api/v1/overlay/vnis/{vni:[0-9]+}            - DeleteVNI
//	GET    /api/v1/overlay/tunnels                      - ListTunnels
//	GET    /api/v1/overlay/tunnels/stats                - GetTunnelStats
//	GET    /api/v1/overlay/macs                         - ListRemoteMACs
//	DELETE /api/v1/overlay/macs                         - ForgetMAC (?mac=&vni=)
func (r *OverlayRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("/status", r.getStatus).Methods("GET")
	sr.HandleFunc("/vteps", r.listVTEPs).Methods("GET")
	sr.HandleFunc("/vteps/{nodeId}", r.getVTEP).Methods("GET")
	sr.HandleFunc("/vnis", r.listVNIs).Methods("GET")
	sr.HandleFunc("/vnis", r.createVNI).Methods("POST")
	sr.HandleFunc("/vnis/{vni:[0-9]+}", r.deleteVNI).Methods("DELETE")
	sr.HandleFunc("/tunnels", r.listTunnels).Methods("GET")
	sr.HandleFunc("/tunnels/stats", r.getTunnelStats).Methods("GET")
	sr.HandleFunc("/macs", r.listMACs).Methods("GET")
	sr.HandleFunc("/macs", r.forgetMAC).Methods("DELETE")
}

func (r *OverlayRouter) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "overlay"})
		return false
	}
	return true
}

func (r *OverlayRouter) getStatus(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetOverlayStatus(req.Context(), &platformv1.GetOverlayStatusRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *OverlayRouter) listVTEPs(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListVTEPs(req.Context(), &platformv1.ListVTEPsRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *OverlayRouter) getVTEP(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetVTEP(req.Context(), &platformv1.GetVTEPRequest{NodeId: mux.Vars(req)["nodeId"]})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *OverlayRouter) listVNIs(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListVNIs(req.Context(), &platformv1.ListVNIsRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *OverlayRouter) createVNI(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.CreateVNIRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.CreateVNI(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, req, r.respWriter, http.StatusCreated, resp)
}

func (r *OverlayRouter) deleteVNI(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	raw := mux.Vars(req)["vni"]
	v, err := strconv.ParseUint(raw, 10, 32)
	if err != nil {
		r.respWriter.Error400(w, req, &protorest.ErrInvalidQuery{Name: "vni", Value: raw, Cause: err})
		return
	}
	resp, err := r.server.DeleteVNI(req.Context(), &platformv1.DeleteVNIRequest{Vni: uint32(v)})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *OverlayRouter) listTunnels(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListTunnels(req.Context(), &platformv1.ListTunnelsRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *OverlayRouter) getTunnelStats(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	vni, err := protorest.QueryUint32(req, "vni")
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, srvErr := r.server.GetTunnelStats(req.Context(), &platformv1.GetTunnelStatsRequest{
		RemoteVtep: req.URL.Query().Get("remote_vtep"),
		Vni:        vni,
	})
	if srvErr != nil {
		protorest.WriteError(w, req, r.respWriter, srvErr)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *OverlayRouter) listMACs(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListRemoteMACs(req.Context(), &platformv1.ListRemoteMACsRequest{})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *OverlayRouter) forgetMAC(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	vni, err := protorest.QueryUint32(req, "vni")
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, srvErr := r.server.ForgetMAC(req.Context(), &platformv1.ForgetMACRequest{
		Mac: req.URL.Query().Get("mac"),
		Vni: vni,
	})
	if srvErr != nil {
		protorest.WriteError(w, req, r.respWriter, srvErr)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}
