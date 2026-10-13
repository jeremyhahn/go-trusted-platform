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

// Package vpn implements REST endpoints under /api/v1/vpn. The routes are a
// thin binding over the same in-process VPNServiceServer that backs gRPC,
// QUIC, MCP, and the Unix socket, so every transport sees one enrolment and
// posture-policy store.
package vpn

import (
	"net/http"

	"github.com/gorilla/mux"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// basePath is the REST prefix for the VPN control plane.
const basePath = "/vpn"

// The scopes the routes require, the same ones the gRPC, QUIC and MCP
// transports enforce: peers are read and written, posture policies are
// administered.
const (
	scopeRead  = "vpn:read"
	scopeWrite = "vpn:write"
	scopeAdmin = "vpn:admin"
)

// ErrPolicyNameMismatch is returned when a set body names a policy other
// than the one in the path.
type ErrPolicyNameMismatch struct {
	Path string
	Body string
}

func (e *ErrPolicyNameMismatch) Error() string {
	return "vpn: body policy name " + e.Body + " does not match path name " + e.Path
}

// VPNRouter wires REST endpoints onto a VPNServiceServer.
type VPNRouter struct {
	logger          *logging.Logger
	server          platformv1.VPNServiceServer
	respWriter      response.HttpWriter
	scopeAuthorizer middleware.ScopeAuthorizer
	router.WebServiceRouter
}

// NewVPNRouter creates a new VPN control-plane REST router.
func NewVPNRouter(
	logger *logging.Logger,
	server platformv1.VPNServiceServer,
	respWriter response.HttpWriter,
) *VPNRouter {
	return &VPNRouter{logger: logger, server: server, respWriter: respWriter}
}

// SetScopeAuthorizer supplies the scope check every route takes on top of the
// admin gate. Nil leaves the routes on the role gate alone, which is the case
// under the legacy JWT handler: its sessions carry roles, not scopes.
func (r *VPNRouter) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// RegisterRoutes mounts the VPN routes. Item routes take the tenant in the
// tenant_id query parameter; list and status routes take their optional
// filter the same way.
//
//	POST   /api/v1/vpn/peers                   - EnrolPeer (vpn:write, body: VPNPeer)
//	GET    /api/v1/vpn/peers                   - ListPeers (vpn:read)
//	DELETE /api/v1/vpn/peers/{device_id}       - RevokePeer (vpn:write)
//	GET    /api/v1/vpn/status                  - GetStatus (vpn:read)
//	GET    /api/v1/vpn/posture-policies        - ListPosturePolicies (vpn:admin)
//	GET    /api/v1/vpn/posture-policies/{name} - GetPosturePolicy (vpn:admin)
//	PUT    /api/v1/vpn/posture-policies/{name} - SetPosturePolicy (vpn:admin, body: VPNPosturePolicy)
//	DELETE /api/v1/vpn/posture-policies/{name} - DeletePosturePolicy (vpn:admin)
func (r *VPNRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.Handle("/peers", r.requireScope(scopeWrite, r.enrolPeer)).Methods(http.MethodPost)
	sr.Handle("/peers", r.requireScope(scopeRead, r.listPeers)).Methods(http.MethodGet)
	sr.Handle("/peers/{device_id}", r.requireScope(scopeWrite, r.revokePeer)).Methods(http.MethodDelete)
	sr.Handle("/status", r.requireScope(scopeRead, r.getStatus)).Methods(http.MethodGet)
	sr.Handle("/posture-policies", r.requireScope(scopeAdmin, r.listPosturePolicies)).Methods(http.MethodGet)
	sr.Handle("/posture-policies/{name}", r.requireScope(scopeAdmin, r.getPosturePolicy)).Methods(http.MethodGet)
	sr.Handle("/posture-policies/{name}", r.requireScope(scopeAdmin, r.setPosturePolicy)).Methods(http.MethodPut)
	sr.Handle("/posture-policies/{name}", r.requireScope(scopeAdmin, r.deletePosturePolicy)).Methods(http.MethodDelete)
}

// requireScope wraps handler in the scope check when one is configured.
func (r *VPNRouter) requireScope(scope string, handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		return handler
	}
	return r.scopeAuthorizer.RequireScope(scope)(handler)
}

// ensure reports whether the backing service is configured, writing a 503
// when it is not.
func (r *VPNRouter) ensure(w http.ResponseWriter, req *http.Request) bool {
	if r.server == nil {
		protorest.WriteError(w, req, r.respWriter, &protorest.ErrServiceUnavailable{Service: "vpn"})
		return false
	}
	return true
}

// enrolPeer handles POST /api/v1/vpn/peers.
func (r *VPNRouter) enrolPeer(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	peer := &platformv1.VPNPeer{}
	if err := protorest.DecodeRequest(req, peer); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	resp, err := r.server.EnrolPeer(req.Context(), &platformv1.EnrolVPNPeerRequest{Peer: peer})
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, req, r.respWriter, http.StatusCreated, resp)
}

// listPeers handles GET /api/v1/vpn/peers.
func (r *VPNRouter) listPeers(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListPeers(req.Context(), &platformv1.ListVPNPeersRequest{
		TenantId: req.URL.Query().Get("tenant_id"),
	})
	r.write(w, req, resp, err)
}

// revokePeer handles DELETE /api/v1/vpn/peers/{device_id}.
func (r *VPNRouter) revokePeer(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.RevokePeer(req.Context(), &platformv1.RevokeVPNPeerRequest{
		TenantId: req.URL.Query().Get("tenant_id"),
		DeviceId: mux.Vars(req)["device_id"],
	})
	r.write(w, req, resp, err)
}

// getStatus handles GET /api/v1/vpn/status.
func (r *VPNRouter) getStatus(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetStatus(req.Context(), &platformv1.GetVPNStatusRequest{
		GatewayId: req.URL.Query().Get("gateway_id"),
	})
	r.write(w, req, resp, err)
}

// listPosturePolicies handles GET /api/v1/vpn/posture-policies.
func (r *VPNRouter) listPosturePolicies(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.ListPosturePolicies(req.Context(), &platformv1.ListVPNPosturePoliciesRequest{
		TenantId: req.URL.Query().Get("tenant_id"),
	})
	r.write(w, req, resp, err)
}

// getPosturePolicy handles GET /api/v1/vpn/posture-policies/{name}.
func (r *VPNRouter) getPosturePolicy(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.GetPosturePolicy(req.Context(), &platformv1.GetVPNPosturePolicyRequest{
		TenantId: req.URL.Query().Get("tenant_id"),
		Name:     mux.Vars(req)["name"],
	})
	r.write(w, req, resp, err)
}

// setPosturePolicy handles PUT /api/v1/vpn/posture-policies/{name}. The path
// names the policy; a body that names a different one is refused.
func (r *VPNRouter) setPosturePolicy(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	policy := &platformv1.VPNPosturePolicy{}
	if err := protorest.DecodeRequest(req, policy); err != nil {
		r.respWriter.Error400(w, req, err)
		return
	}
	name := mux.Vars(req)["name"]
	if policy.GetName() != "" && policy.GetName() != name {
		r.respWriter.Error400(w, req, &ErrPolicyNameMismatch{Path: name, Body: policy.GetName()})
		return
	}
	policy.Name = name
	resp, err := r.server.SetPosturePolicy(req.Context(), &platformv1.SetVPNPosturePolicyRequest{Policy: policy})
	r.write(w, req, resp, err)
}

// deletePosturePolicy handles DELETE /api/v1/vpn/posture-policies/{name}.
func (r *VPNRouter) deletePosturePolicy(w http.ResponseWriter, req *http.Request) {
	if !r.ensure(w, req) {
		return
	}
	resp, err := r.server.DeletePosturePolicy(req.Context(), &platformv1.DeleteVPNPosturePolicyRequest{
		TenantId: req.URL.Query().Get("tenant_id"),
		Name:     mux.Vars(req)["name"],
	})
	r.write(w, req, resp, err)
}

// write sends the service reply, or maps the service error to its HTTP
// status.
func (r *VPNRouter) write(w http.ResponseWriter, req *http.Request, resp proto.Message, err error) {
	if err != nil {
		protorest.WriteError(w, req, r.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, req, r.respWriter, resp)
}
