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

package attestation

import (
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// AttestationServerRouter wires REST endpoints onto the in-process
// platformv1.AttestationServiceServer used by sdk/go/services/attestation.
// This is the production-grade router that delegates directly to the gRPC
// server implementation, and it is now the only attestation router. A second,
// handler-based AttestationRouter once lived in router.go for callers supplying
// a smaller AttestationService interface; nothing ever constructed it, and it
// was removed with its handlers in #268.
type AttestationServerRouter struct {
	logger     *logging.Logger
	server     platformv1.AttestationServiceServer
	respWriter response.HttpWriter
	router.WebServiceRouter
}

// NewAttestationServerRouter constructs a router from the supplied gRPC
// server implementation.
func NewAttestationServerRouter(
	logger *logging.Logger,
	server platformv1.AttestationServiceServer,
	respWriter response.HttpWriter,
) *AttestationServerRouter {
	return &AttestationServerRouter{
		logger:     logger,
		server:     server,
		respWriter: respWriter,
	}
}

// RegisterRoutes mounts attestation REST routes under /api/v1/attestation.
//
//	GET    /api/v1/attestation/manifests/{id}                  - GetManifest
//	GET    /api/v1/attestation/manifests                       - ListManifests
//	POST   /api/v1/attestation/manifests/build                 - BuildManifest
//	POST   /api/v1/attestation/manifests/verify                - VerifyManifest
//	DELETE /api/v1/attestation/manifests/{id}                  - DeleteManifest
//	POST   /api/v1/attestation/quote                           - GetAttestationQuote
//	POST   /api/v1/attestation/quote/verify                    - VerifyAttestationQuote
//	POST   /api/v1/attestation/host                            - CollectHostAttestation
//	POST   /api/v1/attestation/vm/{id}                         - CollectVMAttestation
//	POST   /api/v1/attestation/container/{id}                  - CollectContainerAttestation
func (r *AttestationServerRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix("/attestation").Subrouter()
	sr.HandleFunc("/manifests", r.listManifests).Methods("GET")
	sr.HandleFunc("/manifests/build", r.buildManifest).Methods("POST")
	sr.HandleFunc("/manifests/verify", r.verifyManifest).Methods("POST")
	sr.HandleFunc("/manifests/{id}", r.getManifest).Methods("GET")
	sr.HandleFunc("/manifests/{id}", r.deleteManifest).Methods("DELETE")
	sr.HandleFunc("/quote", r.getQuote).Methods("POST")
	sr.HandleFunc("/quote/verify", r.verifyQuote).Methods("POST")
	sr.HandleFunc("/host", r.collectHost).Methods("POST")
	sr.HandleFunc("/vm/{id}", r.collectVM).Methods("POST")
	sr.HandleFunc("/container/{id}", r.collectContainer).Methods("POST")
}

func (r *AttestationServerRouter) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "attestation"})
		return false
	}
	return true
}

func (r *AttestationServerRouter) getManifest(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetManifest(req.Context(), &platformv1.GetManifestRequest{Id: mux.Vars(req)["id"]})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *AttestationServerRouter) listManifests(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.ListManifestsRequest{}
	resp, err := r.server.ListManifests(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *AttestationServerRouter) buildManifest(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.BuildManifestRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.BuildManifest(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, req, r.respWriter, http.StatusCreated, resp)
}

func (r *AttestationServerRouter) verifyManifest(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.VerifyManifestRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.VerifyManifest(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *AttestationServerRouter) deleteManifest(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.DeleteManifest(req.Context(), &platformv1.DeleteManifestRequest{Id: mux.Vars(req)["id"]})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *AttestationServerRouter) getQuote(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.GetAttestationQuoteRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.GetAttestationQuote(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *AttestationServerRouter) verifyQuote(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.VerifyAttestationQuoteRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.VerifyAttestationQuote(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *AttestationServerRouter) collectHost(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.CollectHostAttestationRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.CollectHostAttestation(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *AttestationServerRouter) collectVM(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.CollectVMAttestationRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	pbReq.VmId = mux.Vars(req)["id"]
	resp, err := r.server.CollectVMAttestation(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}

func (r *AttestationServerRouter) collectContainer(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	pbReq := &platformv1.CollectContainerAttestationRequest{}
	if err := protorest.DecodeRequest(req, pbReq); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	pbReq.ContainerId = mux.Vars(req)["id"]
	resp, err := r.server.CollectContainerAttestation(req.Context(), pbReq)
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}
