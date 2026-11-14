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
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/channelbind"
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
//	POST   /api/v1/attestation/quote/verify                    - VerifyAttestationQuote
//	POST   /api/v1/attestation/vm/{id}                         - CollectVMAttestation
//	POST   /api/v1/attestation/container/{id}                  - CollectContainerAttestation
//
// The two QUOTE-PRODUCING routes (/quote, /host) are deliberately NOT
// mounted here: they are mounted exactly once by RegisterQuoteRoutes, on the
// bare router, with the caller gate and the operator chain. Mounting them
// here as well — on a parent that already carries the operator middleware —
// registered them first, and gorilla/mux dispatches to the first match, so
// every machine caller was answered 401 by the operator chain before the
// gate ever ran (#458, measured on the fleet).
func (r *AttestationServerRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix("/attestation").Subrouter()
	sr.HandleFunc("/manifests", r.listManifests).Methods("GET")
	sr.HandleFunc("/manifests/build", r.buildManifest).Methods("POST")
	sr.HandleFunc("/manifests/verify", r.verifyManifest).Methods("POST")
	sr.HandleFunc("/manifests/{id}", r.getManifest).Methods("GET")
	sr.HandleFunc("/manifests/{id}", r.deleteManifest).Methods("DELETE")
	sr.HandleFunc("/quote/verify", r.verifyQuote).Methods("POST")
	sr.HandleFunc("/vm/{id}", r.collectVM).Methods("POST")
	sr.HandleFunc("/container/{id}", r.collectContainer).Methods("POST")
}

// RegisterQuoteRoutes mounts the two routes that make this node's TPM
// produce a quote for the caller's nonce:
//
//	POST /api/v1/attestation/quote
//	POST /api/v1/attestation/host
//
// They are the routes the reporting collector dials (#226), so they carry
// two principals: an operator (the chain in `operator`, normally JWT plus
// the admin role) and an admitted machine caller (`gate`, the node's
// caller-admission policy). Mount them on the BARE router and pass the
// operator chain explicitly, because a chain applied by a gated subrouter
// would run before the machine path and answer 401 to every collector.
//
// With a nil gate the routes take only the operator chain; with a nil
// operator chain and a nil gate they are open. This is the ONLY place the
// two routes are mounted (see RegisterRoutes for why).
func (r *AttestationServerRouter) RegisterQuoteRoutes(parent *mux.Router, gate *CallerGate, operator func(http.Handler) http.Handler) {
	sr := parent.PathPrefix("/attestation").Subrouter()
	sr.Handle("/quote", gate.Wrap(http.HandlerFunc(r.getQuote), operator)).Methods("POST")
	sr.Handle("/host", gate.Wrap(http.HandlerFunc(r.collectHost), operator)).Methods("POST")
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
	limit, err := protorest.QueryUint32(req, "limit")
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	offset, err := protorest.QueryUint32(req, "offset")
	if err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	pbReq := &platformv1.ListManifestsRequest{
		HostId: req.URL.Query().Get("host_id"),
		Limit:  limit,
		Offset: offset,
	}
	for _, bound := range []struct {
		name string
		set  func(*timestamppb.Timestamp)
	}{
		{"start_time", func(ts *timestamppb.Timestamp) { pbReq.StartTime = ts }},
		{"end_time", func(ts *timestamppb.Timestamp) { pbReq.EndTime = ts }},
	} {
		raw := req.URL.Query().Get(bound.name)
		if raw == "" {
			continue
		}
		t, err := time.Parse(time.RFC3339Nano, raw)
		if err != nil {
			r.respWriter.Error400(w, req, fmt.Errorf("invalid %s: %w", bound.name, err))
			return
		}
		// The manifest filter keeps whole seconds: refuse a fractional
		// bound rather than truncate it into a different window.
		if t.Nanosecond() != 0 {
			r.respWriter.Error400(w, req, fmt.Errorf("invalid %s: fractional seconds are not supported", bound.name))
			return
		}
		bound.set(timestamppb.New(t))
	}
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
	// The node binds its quote to the connection this request arrived on
	// (#482), as collect-host does.
	ctx := channelbind.WithConnectionTLS(req.Context(), channelbind.TransportREST, req.TLS)
	resp, err := r.server.GetAttestationQuote(ctx, pbReq)
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
	// The node binds its quote to the connection this request arrived on
	// (#482), so the server needs that connection's TLS state; nil records a
	// plain-HTTP request, which it refuses.
	ctx := channelbind.WithConnectionTLS(req.Context(), channelbind.TransportREST, req.TLS)
	resp, err := r.server.CollectHostAttestation(ctx, pbReq)
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
