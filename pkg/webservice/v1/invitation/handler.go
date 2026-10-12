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
	"encoding/json"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// emailRegex is a simple email validation pattern.
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

// HandlerParams contains the dependencies for creating an invitation handler.
type HandlerParams struct {
	Logger            *logging.Logger
	InvitationService InvitationServicer
	ResponseWriter    response.HttpWriter
	BaseURL           string
}

// handler implements the RestHandler interface.
type handler struct {
	logger            *logging.Logger
	invitationService InvitationServicer
	responseWriter    response.HttpWriter
	baseURL           string
}

// NewHandler creates a new invitation handler with the given parameters.
func NewHandler(params HandlerParams) (RestHandler, error) {
	if params.Logger == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingLogger{}}
	}
	if params.InvitationService == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingInvitationService{}}
	}
	if params.ResponseWriter == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingResponseWriter{}}
	}

	return &handler{
		logger:            params.Logger,
		invitationService: params.InvitationService,
		responseWriter:    params.ResponseWriter,
		baseURL:           params.BaseURL,
	}, nil
}

// Create creates a new invitation for the tenant.
// POST /api/v1/invitations
func (h *handler) Create(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("invitation: create request received")

	// Get tenant context
	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("invitation: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	userID := tenant.GetUserID(ctx)
	if userID == 0 {
		h.logger.Debug("invitation: missing user ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing user context"})
		return
	}

	// Only tenant owner can create invitations
	if !tenant.IsTenantOwner(ctx) {
		h.logger.Debug("invitation: user is not tenant owner",
			slog.Uint64("user_id", userID),
			slog.String("tenant_id", tenantID))
		h.responseWriter.Error403(w, r, ErrNotTenantOwner{}, nil)
		return
	}

	// Parse request body
	var req CreateInvitationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("invitation: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Validate email
	if req.Email == "" {
		h.responseWriter.Error400(w, r, ErrMissingEmail{})
		return
	}
	if !emailRegex.MatchString(req.Email) {
		h.responseWriter.Error400(w, r, ErrInvalidEmail{Email: req.Email})
		return
	}

	// Validate role
	if req.Role == "" {
		h.responseWriter.Error400(w, r, ErrMissingRole{})
		return
	}
	if !IsValidRole(req.Role) {
		h.responseWriter.Error400(w, r, ErrInvalidRole{Role: req.Role})
		return
	}

	// Create invitation with optional expiry duration
	invitation, err := h.invitationService.Create(ctx, tenantID, req.Email, req.Role, userID, req.ExpiresIn)
	if err != nil {
		h.writeServiceError(w, r, "create", req.Email, err)
		return
	}

	h.logger.Info("invitation: created successfully",
		slog.Uint64("invitation_id", invitation.ID),
		slog.String("email", req.Email),
		slog.String("role", req.Role),
		slog.String("tenant_id", tenantID))

	// Return response with token and invite URL (only on create)
	resp := ToInvitationResponseWithURL(invitation, true, h.baseURL)
	h.responseWriter.Success201(w, r, resp)
}

// List lists all invitations for the current tenant.
// GET /api/v1/invitations
func (h *handler) List(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("invitation: list request received")

	// Get tenant context
	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("invitation: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	// Get invitations for tenant
	invitations, err := h.invitationService.ListByTenant(ctx, tenantID)
	if err != nil {
		h.logger.Errorf("invitation: failed to list invitations for tenant=%s: %v", tenantID, err)
		h.responseWriter.Error500(w, r, ErrServiceError{Operation: "list", Cause: err})
		return
	}

	h.logger.Debug("invitation: listed invitations",
		slog.String("tenant_id", tenantID),
		slog.Int("count", len(invitations)))

	resp := ToInvitationListResponse(invitations, h.baseURL)
	h.responseWriter.Success200(w, r, resp)
}

// GetByToken retrieves an invitation by its token.
// GET /api/v1/invitations/token/{token}
// This is a public endpoint for invitation lookup.
func (h *handler) GetByToken(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("invitation: get by token request received")

	// Extract token from URL
	vars := mux.Vars(r)
	tokenValue := vars["token"]
	if tokenValue == "" {
		h.responseWriter.Error400(w, r, ErrMissingToken{})
		return
	}

	// Get invitation by token
	invitation, err := h.invitationService.GetByToken(r.Context(), tokenValue)
	if err != nil {
		h.writeGetByTokenError(w, r, tokenValue, err)
		return
	}

	// Check invitation status
	if invitation.Status == entities.InvitationStatusRevoked {
		h.responseWriter.Error400(w, r, ErrInvitationRevoked{Token: tokenValue})
		return
	}
	if invitation.Status == entities.InvitationStatusAccepted {
		h.responseWriter.Error400(w, r, ErrInvitationAlreadyAccepted{Token: tokenValue})
		return
	}
	if invitation.IsExpired() {
		h.responseWriter.Error400(w, r, ErrInvitationExpired{Token: tokenValue})
		return
	}

	h.logger.Debug("invitation: retrieved by token",
		slog.Uint64("invitation_id", invitation.ID))

	// Do not include token in response for security
	resp := ToInvitationResponseWithURL(invitation, false, h.baseURL)
	h.responseWriter.Success200(w, r, resp)
}

// Get retrieves an invitation by its ID.
// GET /api/v1/invitations/{id}
func (h *handler) Get(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("invitation: get by id request received")

	// Get tenant context
	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("invitation: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	// Extract invitation ID from URL
	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.responseWriter.Error400(w, r, ErrMissingInvitationID{})
		return
	}

	invitationID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidInvitationID{ID: idStr})
		return
	}

	// Get the invitation
	invitation, err := h.invitationService.Get(ctx, invitationID)
	if err != nil {
		if err == datastore.ErrRecordNotFound {
			h.responseWriter.Error404(w, r, ErrInvitationNotFound{ID: invitationID})
			return
		}
		h.logger.Errorf("invitation: failed to get invitation id=%d: %v", invitationID, err)
		h.responseWriter.Error500(w, r, ErrServiceError{Operation: "get", Cause: err})
		return
	}

	// Verify the invitation belongs to this tenant
	if invitation.TenantID != tenantID {
		h.logger.Warnf("invitation: attempted to access invitation from different tenant: invitation_id=%d, invitation_tenant=%s, user_tenant=%s",
			invitationID, invitation.TenantID, tenantID)
		h.responseWriter.Error404(w, r, ErrInvitationNotFound{ID: invitationID})
		return
	}

	h.logger.Debug("invitation: retrieved by id",
		slog.Uint64("invitation_id", invitation.ID),
		slog.String("tenant_id", tenantID))

	// Do not include token in response for security
	resp := ToInvitationResponseWithURL(invitation, false, h.baseURL)
	h.responseWriter.Success200(w, r, resp)
}

// Revoke revokes an invitation.
// DELETE /api/v1/invitations/{id}
func (h *handler) Revoke(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("invitation: revoke request received")

	// Get tenant context
	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("invitation: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	userID := tenant.GetUserID(ctx)
	if userID == 0 {
		h.logger.Debug("invitation: missing user ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing user context"})
		return
	}

	// Only tenant owner can revoke invitations
	if !tenant.IsTenantOwner(ctx) {
		h.logger.Debug("invitation: user is not tenant owner",
			slog.Uint64("user_id", userID),
			slog.String("tenant_id", tenantID))
		h.responseWriter.Error403(w, r, ErrNotTenantOwner{}, nil)
		return
	}

	// Extract invitation ID from URL
	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.responseWriter.Error400(w, r, ErrMissingInvitationID{})
		return
	}

	invitationID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidInvitationID{ID: idStr})
		return
	}

	// Verify the invitation belongs to this tenant
	invitation, err := h.invitationService.Get(ctx, invitationID)
	if err != nil {
		if err == datastore.ErrRecordNotFound {
			h.responseWriter.Error404(w, r, ErrInvitationNotFound{ID: invitationID})
			return
		}
		h.logger.Errorf("invitation: failed to get invitation id=%d: %v", invitationID, err)
		h.responseWriter.Error500(w, r, ErrServiceError{Operation: "revoke", Cause: err})
		return
	}

	// Verify tenant ownership
	if invitation.TenantID != tenantID {
		h.logger.Warnf("invitation: attempted to revoke invitation from different tenant: invitation_id=%d, invitation_tenant=%s, user_tenant=%s",
			invitationID, invitation.TenantID, tenantID)
		h.responseWriter.Error404(w, r, ErrInvitationNotFound{ID: invitationID})
		return
	}

	// Check if invitation can be revoked
	if invitation.Status == entities.InvitationStatusRevoked {
		h.responseWriter.Write(w, r, http.StatusConflict, restwire.WebServiceResponse{
			Code:    http.StatusConflict,
			Error:   ErrInvitationAlreadyRevoked{ID: invitationID}.Error(),
			Success: false,
		})
		return
	}
	if invitation.Status == entities.InvitationStatusAccepted {
		h.responseWriter.Write(w, r, http.StatusConflict, restwire.WebServiceResponse{
			Code:    http.StatusConflict,
			Error:   ErrInvitationAlreadyAccepted{Token: ""}.Error(),
			Success: false,
		})
		return
	}

	// Revoke the invitation
	if err := h.invitationService.Revoke(ctx, invitationID); err != nil {
		h.logger.Errorf("invitation: failed to revoke invitation id=%d: %v", invitationID, err)
		h.responseWriter.Error500(w, r, ErrServiceError{Operation: "revoke", Cause: err})
		return
	}

	h.logger.Info("invitation: revoked successfully",
		slog.Uint64("invitation_id", invitationID),
		slog.String("tenant_id", tenantID),
		slog.Uint64("revoked_by", userID))

	h.responseWriter.Success200(w, r, RevokeResponse{
		Status:  "revoked",
		Message: "invitation has been revoked",
	})
}

// writeServiceError writes an appropriate error response for service-level errors.
func (h *handler) writeServiceError(w http.ResponseWriter, r *http.Request, operation, email string, err error) {
	h.logger.Errorf("invitation: failed to %s invitation for email=%s: %v", operation, email, err)

	switch e := err.(type) {
	case ErrDuplicateInvitation:
		h.responseWriter.Write(w, r, http.StatusConflict, restwire.WebServiceResponse{
			Code:    http.StatusConflict,
			Error:   e.Error(),
			Success: false,
		})
	case ErrEmailAlreadyRegistered:
		h.responseWriter.Write(w, r, http.StatusConflict, restwire.WebServiceResponse{
			Code:    http.StatusConflict,
			Error:   e.Error(),
			Success: false,
		})
	default:
		h.responseWriter.Error500(w, r, ErrServiceError{Operation: operation, Cause: err})
	}
}

// writeGetByTokenError writes an appropriate error response for GetByToken errors.
func (h *handler) writeGetByTokenError(w http.ResponseWriter, r *http.Request, token string, err error) {
	if err == datastore.ErrRecordNotFound {
		h.responseWriter.Error404(w, r, ErrInvitationNotFound{Token: token})
		return
	}
	h.logger.Errorf("invitation: failed to get invitation by token: %v", err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: "getByToken", Cause: err})
}
