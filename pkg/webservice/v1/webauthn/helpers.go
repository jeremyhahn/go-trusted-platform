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

package webauthn

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// validateInvitation enforces invitation preconditions before a
// registration ceremony starts. Returns false when an error has been
// written to w.
func (h *WebAuthnRestHandler) validateInvitation(w http.ResponseWriter, r *http.Request, token, username string) bool {
	if h.invitationService == nil {
		h.logger.Warn("invitation token provided but invitation service is not configured")
		h.responseWriter.Error500(w, r, ErrInvitationServiceNotConfigured)
		return false
	}
	invitation, err := h.invitationService.GetByToken(r.Context(), token)
	if err != nil {
		h.logger.Debug("invitation not found", slog.String("error", err.Error()))
		h.writeInvitationError(w, r, err)
		return false
	}
	if invitation.Email != username {
		h.logger.Warn("invitation email mismatch",
			slog.String("invitation_email", invitation.Email),
			slog.String("username", username),
		)
		h.responseWriter.Error400(w, r, ErrInvitationEmailMismatch)
		return false
	}
	if invitation.Status != entities.InvitationStatusPending {
		h.writeInvitationStatusError(w, r, invitation.Status)
		return false
	}
	if invitation.IsExpired() {
		h.responseWriter.Error400(w, r, ErrInvitationExpired)
		return false
	}
	return true
}

// orchestrateTenant attaches the freshly-registered user to a tenant.
// Returns the resolved tenantID (empty when no TenantUserService is
// wired or when the fallback path was used).
func (h *WebAuthnRestHandler) orchestrateTenant(r *http.Request, user *entities.User, invitationToken string) (string, error) {
	if h.tenantUserService == nil {
		h.logger.Debug("tenant user service not configured, saving user without tenant")
		return "", h.userService.Save(r.Context(), user)
	}
	if invitationToken != "" {
		h.logger.Debug("registering invited user",
			slog.String("email", user.Email),
			slog.String("invitation_token", invitationToken))
		result, err := h.tenantUserService.RegisterInvitedUser(r.Context(), user, invitationToken)
		if err != nil {
			return "", err
		}
		return resolveTenantID(user, result), nil
	}
	h.logger.Debug("registering new user with tenant creation", slog.String("email", user.Email))
	result, err := h.tenantUserService.RegisterNewUser(r.Context(), user)
	if err != nil {
		return "", err
	}
	return resolveTenantID(user, result), nil
}

// resolveTenantID copies the registered user back over the caller's
// reference and extracts the tenant ID when present.
func resolveTenantID(user *entities.User, result *service.RegisterResult) string {
	if result == nil {
		return ""
	}
	if result.User != nil {
		*user = *result.User
	}
	if result.Tenant != nil {
		return result.Tenant.ID
	}
	return ""
}

// issueToken prefers the tenant-aware token, falling back to the
// vanilla platform JWT when no tenant-bound issuer is wired.
func (h *WebAuthnRestHandler) issueToken(r *http.Request, user *entities.User) (string, error) {
	if h.tenantUserService != nil {
		token, err := h.tenantUserService.IssueToken(r.Context(), user)
		if err != nil {
			h.logger.Error(err, "failed to issue token via tenant user service")
		}
		if token != "" {
			return token, nil
		}
	}
	return h.jwtService.GenerateToken(user)
}

// writeConflictError writes a 409 Conflict response.
func (h *WebAuthnRestHandler) writeConflictError(w http.ResponseWriter, r *http.Request, err error) {
	h.responseWriter.Write(w, r, http.StatusConflict, response.WebServiceResponse{
		Code:    http.StatusConflict,
		Error:   err.Error(),
		Success: false,
		Payload: nil,
	})
}

// writeInvitationError maps invitation lookup errors to HTTP codes.
func (h *WebAuthnRestHandler) writeInvitationError(w http.ResponseWriter, r *http.Request, err error) {
	switch err.(type) {
	case service.ErrInvitationNotFound:
		h.responseWriter.Error404(w, r, err)
	case service.ErrInvitationExpired,
		service.ErrInvitationAlreadyAccepted,
		service.ErrInvitationRevoked,
		service.ErrInvalidInvitation:
		h.responseWriter.Error400(w, r, err)
	default:
		h.responseWriter.Error500(w, r, err)
	}
}

// writeInvitationStatusError maps an invitation's status enum to a 4xx.
func (h *WebAuthnRestHandler) writeInvitationStatusError(w http.ResponseWriter, r *http.Request, status entities.InvitationStatus) {
	switch status {
	case entities.InvitationStatusAccepted:
		h.responseWriter.Error400(w, r, ErrInvitationAlreadyAccepted)
	case entities.InvitationStatusRevoked:
		h.responseWriter.Error400(w, r, ErrInvitationRevoked)
	case entities.InvitationStatusExpired:
		h.responseWriter.Error400(w, r, ErrInvitationExpired)
	default:
		h.responseWriter.Error400(w, r, ErrInvalidInvitationStatus)
	}
}

// writeRegistrationError maps tenant orchestration errors to HTTP codes.
func (h *WebAuthnRestHandler) writeRegistrationError(w http.ResponseWriter, r *http.Request, err error) {
	switch err.(type) {
	case service.ErrUserAlreadyExists:
		h.writeConflictError(w, r, err)
	case service.ErrInvitationNotFound:
		h.responseWriter.Error404(w, r, err)
	case service.ErrInvitationExpired,
		service.ErrInvitationAlreadyAccepted,
		service.ErrInvitationRevoked,
		service.ErrInvalidInvitation:
		h.responseWriter.Error400(w, r, err)
	default:
		h.responseWriter.Error500(w, r, err)
	}
}

// isNotFoundError reports whether the supplied error indicates a
// missing record from either the platform datastore or the quicbaas
// adapter.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if err == datastore.ErrRecordNotFound {
		return true
	}
	var notFound quicbaas.ErrNotFound
	return errAs(err, &notFound)
}

// errAs is a wrapper around errors.As-like type matching that supports
// both the standard library protocol and direct value assertions so
// tests can pass concrete error values without an As method.
var errAs = func(err error, target interface{}) bool {
	type asError interface {
		As(interface{}) bool
	}
	if x, ok := err.(asError); ok {
		return x.As(target)
	}
	switch t := target.(type) {
	case *quicbaas.ErrNotFound:
		if e, ok := err.(quicbaas.ErrNotFound); ok {
			*t = e
			return true
		}
	}
	return false
}

// getUserIDAndEmail resolves the active user ID from the X-User-Id
// header, falling back to the username supplied in the request body.
func getUserIDAndEmail(r *http.Request) (uint64, string, error) {
	xuserID := r.Header.Get("X-User-Id")
	if xuserID == "" {
		var u LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			return 0, "", ErrInvalidUserIDHeader
		}
		return util.NewID([]byte(u.Email)), u.Email, nil
	}
	userID, err := strconv.ParseUint(xuserID, 10, 64)
	if err != nil {
		if err == strconv.ErrSyntax {
			return util.NewID([]byte(xuserID)), "", nil
		}
		return 0, "", err
	}
	return userID, "", nil
}

// decodeXUserIDHeader parses the base64url-encoded user ID supplied by
// the frontend at FinishRegistration time.
func decodeXUserIDHeader(r *http.Request) (uint64, error) {
	xuserID := r.Header.Get("X-User-Id")
	if xuserID == "" {
		return 0, ErrInvalidUserIDHeader
	}
	decoded, err := base64.RawURLEncoding.DecodeString(xuserID)
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(string(decoded), 10, 64)
}

// decodeFinishRegistrationBody parses the WebAuthn attestation response.
// The session-model FinishRegistrationRequest correlates the ceremony via
// its SessionID (carried in the request body); the username is supplied
// separately to the SDK through the *WebAuthnUser argument, so it is not
// stamped onto the request here.
func decodeFinishRegistrationBody(body io.Reader) (*quicbaassdk.FIDO2FinishRegistrationRequest, error) {
	var req quicbaassdk.FIDO2FinishRegistrationRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		return nil, ErrInvalidRequestBody
	}
	return &req, nil
}

// decodeFinishAuthenticationBody parses the WebAuthn assertion response
// and stamps the username so the SDK can route the ceremony correctly.
func decodeFinishAuthenticationBody(body io.Reader, username string) (*quicbaassdk.FIDO2FinishAuthenticationRequest, error) {
	var req quicbaassdk.FIDO2FinishAuthenticationRequest
	if err := json.NewDecoder(body).Decode(&req); err != nil {
		return nil, ErrInvalidRequestBody
	}
	req.Username = username
	return &req, nil
}
