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

// Package ceremony implements REST endpoints under /api/v1/ceremony. The
// routes are a thin binding over the same in-process CeremonyServiceServer
// that backs gRPC and the daemon REST, so the web UI sees the one ceremony.
package ceremony

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-qrdb/pkg/auth"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// basePath is the REST prefix for the ceremony routes.
const basePath = "/ceremony"

// The scopes the routes require, the same ones the gRPC transport enforces
// (pkg/api/iam/method_permissions.go).
const (
	scopeInitialize         = "ceremony:initialize"
	scopeStatus             = "ceremony:status"
	scopeClaimCert          = "ceremony:claim_cert"
	scopeClaimShareBegin    = "ceremony:claim_share_begin"
	scopeClaimShareComplete = "ceremony:claim_share_complete"
	scopeSignCSR            = "ceremony:sign_csr"
)

// Router wires REST endpoints onto a CeremonyServiceServer.
type Router struct {
	logger          *logging.Logger
	server          platformv1.CeremonyServiceServer
	respWriter      response.HttpWriter
	scopeAuthorizer middleware.ScopeAuthorizer
	router.WebServiceRouter
}

// NewRouter creates a new ceremony REST router.
func NewRouter(
	logger *logging.Logger,
	server platformv1.CeremonyServiceServer,
	respWriter response.HttpWriter,
) *Router {
	return &Router{logger: logger, server: server, respWriter: respWriter}
}

// SetScopeAuthorizer supplies the scope check every route takes on top of the
// admin gate. Without one (the legacy JWT handler, whose sessions carry roles,
// not scopes) every route fails closed with 403 (#1990, #2158 Codex).
func (r *Router) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// RegisterRoutes mounts the ceremony routes, the same paths the daemon REST
// serves. Every answer, error or success, carries Cache-Control: no-store:
// Init returns the admin private key and ClaimShareComplete a Shamir share.
//
//	POST /api/v1/ceremony/init                 - Init (ceremony:initialize)
//	GET  /api/v1/ceremony/status               - Status (ceremony:status)
//	POST /api/v1/ceremony/claim-cert/begin     - ClaimCertBegin (ceremony:claim_cert)
//	POST /api/v1/ceremony/claim-cert/complete  - ClaimCertComplete (ceremony:claim_cert)
//	POST /api/v1/ceremony/claim-share/begin    - ClaimShareBegin (ceremony:claim_share_begin)
//	POST /api/v1/ceremony/claim-share/complete - ClaimShareComplete (ceremony:claim_share_complete)
//	POST /api/v1/ceremony/sign-csr             - SignCSR (ceremony:sign_csr)
func (r *Router) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.Handle("/init", r.route(scopeInitialize, r.initCeremony)).Methods(http.MethodPost)
	sr.Handle("/status", r.route(scopeStatus, r.status)).Methods(http.MethodGet)
	sr.Handle("/claim-cert/begin", r.route(scopeClaimCert, r.claimCertBegin)).Methods(http.MethodPost)
	sr.Handle("/claim-cert/complete", r.route(scopeClaimCert, r.claimCertComplete)).Methods(http.MethodPost)
	sr.Handle("/claim-share/begin", r.route(scopeClaimShareBegin, r.claimShareBegin)).Methods(http.MethodPost)
	sr.Handle("/claim-share/complete", r.route(scopeClaimShareComplete, r.claimShareComplete)).Methods(http.MethodPost)
	sr.Handle("/sign-csr", r.route(scopeSignCSR, r.signCSR)).Methods(http.MethodPost)
}

// route sets Cache-Control: no-store before anything answers, the scope
// check included, then runs handler behind the scope check, which refuses
// every request when no scope authorizer is set. It also puts the request's
// TLS state into the context, where the embedded ceremony service reads the
// client certificate that authenticates a share claim.
func (r *Router) route(scope string, handler http.HandlerFunc) http.Handler {
	scoped := r.requireScope(scope, handler)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if req.TLS != nil {
			req = req.WithContext(auth.WithTLSState(req.Context(), req.TLS))
		}
		scoped.ServeHTTP(w, req)
	})
}

// requireScope wraps handler in the scope check. With no authorizer
// configured the route fails closed: it answers 403 and never calls handler,
// as scopeRouteGuard.Require does (#1990, #2158 Codex).
func (r *Router) requireScope(scope string, handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		})
	}
	return r.scopeAuthorizer.RequireScope(scope)(handler)
}

// ensure reports whether the backing service is configured, writing a 503
// when it is not.
func (r *Router) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "ceremony"})
		return false
	}
	return true
}

// decode reads the request body into msg, writing a 400 when it is not
// valid JSON for msg or when the body cannot be read in full.
func (r *Router) decode(w http.ResponseWriter, req *http.Request, msg proto.Message) bool {
	if err := acceptWireEnums(req); err != nil {
		r.respWriter.Error400(w, req, &protorest.ErrReadBodyFailed{Cause: err})
		return false
	}
	if err := protorest.DecodeRequest(req, msg); err != nil {
		r.respWriter.Error400(w, req, err)
		return false
	}
	return true
}

// wireEnumPrefixes maps each request field that carries a ceremony enum to
// the prefix of its protojson value names.
var wireEnumPrefixes = map[string]string{
	"role":               "CEREMONY_OFFICER_ROLE_",
	"authenticator_type": "CEREMONY_AUTHENTICATOR_TYPE_",
	"authenticatorType":  "CEREMONY_AUTHENTICATOR_TYPE_",
}

// acceptWireEnums rewrites the Go SDK REST adapter's lowercase enum strings
// ("admin", "piv") to their protojson names (CEREMONY_OFFICER_ROLE_ADMIN,
// CEREMONY_AUTHENTICATOR_TYPE_PIV) so protojson decodes them. Values already
// in protojson form, numeric values and bodies that are not a JSON object
// pass through unchanged, so the web console is unaffected. A body that
// cannot be read in full is reported to the caller, never replaced by the
// partial bytes, so the request is refused rather than decoded from a
// truncated body.
func acceptWireEnums(req *http.Request) error {
	if req.Body == nil {
		return nil
	}
	raw, err := io.ReadAll(req.Body)
	_ = req.Body.Close()
	if err != nil {
		return err
	}
	req.Body = io.NopCloser(bytes.NewReader(raw))
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil
	}
	changed := false
	for key, prefix := range wireEnumPrefixes {
		value, ok := fields[key]
		if !ok {
			continue
		}
		var name string
		if json.Unmarshal(value, &name) != nil || name == "" || strings.HasPrefix(name, prefix) {
			continue
		}
		rewritten, err := json.Marshal(prefix + strings.ToUpper(name))
		if err != nil {
			continue
		}
		fields[key] = rewritten
		changed = true
	}
	if !changed {
		return nil
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	req.Body = io.NopCloser(bytes.NewReader(out))
	req.ContentLength = int64(len(out))
	return nil
}

// write answers 200 with resp, or the HTTP status matching err.
func (r *Router) write(w http.ResponseWriter, req *http.Request, resp proto.Message, err error) {
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	// The body carries the admin private key or a Shamir share, so it is
	// never handed to the logging response writer, which logs every body it
	// writes at debug level (#2158 Codex).
	payload, err := protorest.MarshalOptions.Marshal(resp)
	if err != nil {
		r.respWriter.Error500(w, req, err)
		return
	}
	body, err := json.Marshal(restwire.WebServiceResponse{
		Code:    http.StatusOK,
		Success: true,
		Payload: json.RawMessage(payload),
	})
	if err != nil {
		r.respWriter.Error500(w, req, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// initCeremony handles POST /api/v1/ceremony/init.
func (r *Router) initCeremony(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.CeremonyInitRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.Init(req.Context(), in)
	r.write(w, req, resp, err)
}

// status handles GET /api/v1/ceremony/status.
func (r *Router) status(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.Status(req.Context(), &platformv1.CeremonyStatusRequest{})
	r.write(w, req, resp, err)
}

// claimCertBegin handles POST /api/v1/ceremony/claim-cert/begin.
func (r *Router) claimCertBegin(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.CeremonyClaimCertBeginRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.ClaimCertBegin(req.Context(), in)
	r.write(w, req, resp, err)
}

// claimCertComplete handles POST /api/v1/ceremony/claim-cert/complete.
func (r *Router) claimCertComplete(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.CeremonyClaimCertCompleteRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.ClaimCertComplete(req.Context(), in)
	r.write(w, req, resp, err)
}

// claimShareBegin handles POST /api/v1/ceremony/claim-share/begin.
func (r *Router) claimShareBegin(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.CeremonyClaimShareBeginRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.ClaimShareBegin(req.Context(), in)
	r.write(w, req, resp, err)
}

// claimShareComplete handles POST /api/v1/ceremony/claim-share/complete.
func (r *Router) claimShareComplete(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.CeremonyClaimShareCompleteRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.ClaimShareComplete(req.Context(), in)
	r.write(w, req, resp, err)
}

// signCSR handles POST /api/v1/ceremony/sign-csr.
func (r *Router) signCSR(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	in := &platformv1.CeremonySignCSRRequest{}
	if !r.decode(w, req, in) {
		return
	}
	resp, err := r.server.SignCSR(req.Context(), in)
	r.write(w, req, resp, err)
}
