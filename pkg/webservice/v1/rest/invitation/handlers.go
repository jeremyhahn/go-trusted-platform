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

package invitation

import (
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Handlers serves /api/v1/invitations.
type Handlers struct {
	logger     *logging.Logger
	server     platformv1.InvitationServiceServer
	respWriter response.HttpWriter
}

// NewHandlers wires the supplied server.
func NewHandlers(
	logger *logging.Logger,
	server platformv1.InvitationServiceServer,
	respWriter response.HttpWriter,
) *Handlers {
	return &Handlers{logger: logger, server: server, respWriter: respWriter}
}

func (h *Handlers) ensure(w http.ResponseWriter, r *http.Request) bool {
	if h.server == nil {
		protorest.WriteError(w, r, h.respWriter, &protorest.ErrServiceUnavailable{Service: "invitation"})
		return false
	}
	return true
}

func (h *Handlers) parseID(w http.ResponseWriter, r *http.Request) (uint64, bool) {
	raw := mux.Vars(r)["id"]
	v, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		h.respWriter.Error400(w, r, &protorest.ErrInvalidQuery{Name: "id", Value: raw, Cause: err})
		return 0, false
	}
	return v, true
}

// resolveTenantID returns the tenant the request acts on, taken from the
// VERIFIED session the authenticating middleware published.
//
// It used to base64-decode the request's JWT payload without verifying it,
// falling back to a `jwt`/`token` cookie and then to a `tenant_id` query
// parameter (#171). On a route that authenticates, that decoder was a second
// verification path that could disagree with the guard; on this router, which
// did not authenticate at all until #165, it meant the tenant was whatever an
// anonymous caller wrote into a cookie. The decoder is deleted rather than
// corrected: a locally-correct copy is still a second path, and a second path
// drifts from the seam.
//
// The tenant middleware's context value is still honoured first, because it
// is populated from the same verified identity and is what a tenant-scoped
// mount supplies.
func resolveTenantID(r *http.Request) string {
	if id := tenant.GetTenantID(r.Context()); id != "" {
		return id
	}
	if session, ok := iammw.GetSessionFromContext(r.Context()); ok && session != nil {
		return session.TenantID()
	}
	return ""
}

// resolveUserID returns the inviter's user id from the VERIFIED session.
//
// This carried the same unverified decode as resolveTenantID, and the
// consequence was worse: the value is recorded as WHO ISSUED the invitation,
// so an anonymous caller chose not only the tenant but the name the record
// was created under. That makes the audit trail attacker-authored rather than
// merely attacker-triggered — it would attribute the invitation to a real,
// innocent user id with nothing to distinguish it from a genuine one.
//
// Returns 0 when the session carries no numeric user id, which the service
// treats as "unattributed" — the same as before, but now unattributed
// honestly rather than attributed falsely.
func resolveUserID(r *http.Request) uint64 {
	session, ok := iammw.GetSessionFromContext(r.Context())
	if !ok || session == nil {
		return 0
	}
	id, err := strconv.ParseUint(session.UserID(), 10, 64)
	if err != nil {
		return 0
	}
	return id
}

// ListInvitations handles GET /api/v1/invitations.
//
// The underlying gRPC service requires a tenant_id, and it comes from the
// verified session (resolveTenantID). The `tenant_id` query-parameter
// fallback this used to carry is gone with the decoders it accompanied: a
// caller-supplied tenant on a tenant-scoped read is the same defect in a
// different carrier, and since #165 the route requires an authenticated
// admin, so there is no credential-less caller left for it to serve.
func (h *Handlers) ListInvitations(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	tenantID := resolveTenantID(r)
	req := &platformv1.ListInvitationsRequest{TenantId: tenantID}
	resp, err := h.server.ListInvitations(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// CreateInvitation handles POST /api/v1/invitations.
func (h *Handlers) CreateInvitation(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.CreateInvitationRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	// Default tenant_id and inviter ID from the authenticated session
	// so the WebUI doesn't have to thread JWT claims into its form.
	if req.TenantId == "" {
		req.TenantId = resolveTenantID(r)
	}
	if req.InvitedById == 0 {
		req.InvitedById = resolveUserID(r)
	}
	resp, err := h.server.CreateInvitation(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccessStatus(w, r, h.respWriter, http.StatusCreated, resp)
}

// GetInvitation handles GET /api/v1/invitations/{id}.
func (h *Handlers) GetInvitation(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	id, ok := h.parseID(w, r)
	if !ok {
		return
	}
	resp, err := h.server.GetInvitation(r.Context(), &platformv1.GetInvitationRequest{InvitationId: id})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// DeleteInvitation handles DELETE /api/v1/invitations/{id}.
func (h *Handlers) DeleteInvitation(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	id, ok := h.parseID(w, r)
	if !ok {
		return
	}
	resp, err := h.server.DeleteInvitation(r.Context(), &platformv1.DeleteInvitationRequest{InvitationId: id})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// RevokeInvitation handles POST /api/v1/invitations/{id}/revoke.
func (h *Handlers) RevokeInvitation(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	id, ok := h.parseID(w, r)
	if !ok {
		return
	}
	req := &platformv1.RevokeInvitationRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	req.InvitationId = id
	resp, err := h.server.RevokeInvitation(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// GetInvitationByToken handles GET /api/v1/invitations/token/{token}.
func (h *Handlers) GetInvitationByToken(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	resp, err := h.server.GetInvitationByToken(r.Context(), &platformv1.GetInvitationByTokenRequest{Token: mux.Vars(r)["token"]})
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}

// AcceptInvitation handles POST /api/v1/invitations/accept.
func (h *Handlers) AcceptInvitation(w http.ResponseWriter, r *http.Request) {
	if !h.ensure(w, r) {
		return
	}
	req := &platformv1.AcceptInvitationRequest{}
	if err := protorest.DecodeRequest(r, req); err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}
	resp, err := h.server.AcceptInvitation(r.Context(), req)
	if err != nil {
		protorest.WriteError(w, r, h.respWriter, err)
		return
	}
	protorest.WriteSuccess(w, r, h.respWriter, resp)
}
