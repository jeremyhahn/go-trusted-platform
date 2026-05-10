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
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/internal/protorest"
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

// resolveTenantID extracts the tenant ID from the request in priority
// order: tenant middleware context, then JWT claims (Authorization
// header or `jwt`/`token` cookie), then the `tenant_id` query
// parameter. This lets the invitation REST endpoints work whether or
// not the tenant middleware has been mounted in front of them.
func resolveTenantID(r *http.Request) string {
	if id := tenant.GetTenantID(r.Context()); id != "" {
		return id
	}
	if id := tenantIDFromJWT(r); id != "" {
		return id
	}
	return r.URL.Query().Get("tenant_id")
}

// tenantIDFromJWT decodes (without verifying — verification happens in
// the auth middleware when mounted) the JWT token attached to r and
// returns its `tenant_id` claim, or the empty string if no usable token
// is present.
func tenantIDFromJWT(r *http.Request) string {
	token := bearerToken(r)
	if token == "" {
		if c, err := r.Cookie("jwt"); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		if c, err := r.Cookie("token"); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		return ""
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		// Try standard base64 with padding as a fallback for permissive
		// encoders.
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return ""
		}
	}
	var claims struct {
		TenantID string `json:"tenant_id"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return ""
	}
	return claims.TenantID
}

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if strings.HasPrefix(auth, prefix) {
		return strings.TrimPrefix(auth, prefix)
	}
	return ""
}

// resolveUserID returns the inviter's user_id from the JWT claims
// using the same lookup chain as resolveTenantID. Returns 0 when no
// usable token is present.
func resolveUserID(r *http.Request) uint64 {
	token := bearerToken(r)
	if token == "" {
		if c, err := r.Cookie("jwt"); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		if c, err := r.Cookie("token"); err == nil {
			token = c.Value
		}
	}
	if token == "" {
		return 0
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return 0
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		payload, err = base64.URLEncoding.DecodeString(parts[1])
		if err != nil {
			return 0
		}
	}
	var claims struct {
		UID    uint64 `json:"uid"`
		UserID string `json:"user_id"`
		Sub    string `json:"sub"`
	}
	if json.Unmarshal(payload, &claims) != nil {
		return 0
	}
	if claims.UID != 0 {
		return claims.UID
	}
	if claims.UserID != "" {
		if v, err := strconv.ParseUint(claims.UserID, 10, 64); err == nil {
			return v
		}
	}
	if claims.Sub != "" {
		if v, err := strconv.ParseUint(claims.Sub, 10, 64); err == nil {
			return v
		}
	}
	return 0
}

// ListInvitations handles GET /api/v1/invitations.
//
// The underlying gRPC service requires a tenant_id; resolve it first
// from the JWT-derived request context (populated by the tenant
// middleware when mounted), then fall back to decoding the JWT token
// directly out of the Authorization header / cookie, then to the
// `tenant_id` query parameter so admin/CLI callers without a session
// can still drive the endpoint.
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
