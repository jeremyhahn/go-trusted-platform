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

// Package webauthn is a thin REST proxy that delegates the WebAuthn
// registration and login ceremonies to the canonical quicbaas SDK
// (Security().Auth().FIDO2()). The platform retains only the
// surfaces that are intrinsically platform-local: invitation token
// validation, tenant orchestration, JWT issuance, and HTTP binding.
// All ceremony state (challenge / session) lives in quicbaas.
package webauthn

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	sdktransport "github.com/jeremyhahn/go-quicbaas/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

// NewHandler constructs a SDK-backed WebAuthn REST handler.
func NewHandler(params ServiceParams) (RestHandler, error) {
	if params.FIDO2Client == nil {
		return nil, ErrSDKClientRequired
	}
	if params.TenantID == "" {
		return nil, ErrTenantIDRequired
	}
	if params.Config == nil || params.Config.RPID == "" || len(params.Config.RPOrigins) == 0 {
		return nil, ErrInvalidConfig
	}
	return &WebAuthnRestHandler{
		logger:              params.Logger,
		jwtService:          params.JWTService,
		userService:         params.UserService,
		registrationService: params.RegistrationService,
		tenantUserService:   params.TenantUserService,
		invitationService:   params.InvitationService,
		responseWriter:      params.ResponseWriter,
		fido2Client:         params.FIDO2Client,
		tenantID:            params.TenantID,
		config:              params.Config,
	}, nil
}

// fido2Context scopes the request context to the handler's ceremony
// tenant. The SDK FIDO2 service is tenant-scoped and the xkms wire
// structs carry no tenant field: on the embedded transport the tenant
// rides the context, and an unscoped call fails closed with the SDK's
// "tenant is required" error. Every SDK ceremony call goes through this.
func (h *WebAuthnRestHandler) fido2Context(r *http.Request) context.Context {
	return sdktransport.ContextWithTenant(r.Context(), h.tenantID)
}

// BeginRegistration validates the invitation (when supplied) and starts
// a WebAuthn registration ceremony via the SDK.
func (h *WebAuthnRestHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	var req BeginRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody)
		return
	}
	if req.Username == "" {
		h.responseWriter.Error400(w, r, ErrUsernameRequired)
		return
	}
	if req.InvitationToken != "" && !h.validateInvitation(w, r, req.InvitationToken, req.Username) {
		return
	}
	userID := util.NewID([]byte(req.Username))
	if _, err := h.userService.Get(r.Context(), userID); err == nil {
		h.writeConflictError(w, r, ErrUserAlreadyExists)
		return
	} else if !isNotFoundError(err) {
		h.responseWriter.Error400(w, r, err)
		return
	}
	options, err := h.fido2Client.BeginRegistration(h.fido2Context(r),
		&quicbaassdk.FIDO2BeginRegistrationRequest{Username: req.Username, DisplayName: req.Username})
	if err != nil {
		h.logger.Error(err, "sdk BeginRegistration failed")
		h.responseWriter.Error500(w, r, err)
		return
	}
	if err := h.registrationService.Create(r.Context(), &entities.Registration{
		ID: userID, Email: req.Username, InvitationToken: req.InvitationToken,
	}); err != nil {
		h.responseWriter.Error500(w, r, err)
		return
	}
	h.responseWriter.Write(w, r, http.StatusOK, options)
}

// FinishRegistration completes the ceremony, orchestrates tenant
// creation/join, persists the platform user, and returns a JWT.
func (h *WebAuthnRestHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	userID, err := decodeXUserIDHeader(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}
	registration, err := h.registrationService.Get(r.Context(), service.NewSession(), userID)
	if err != nil {
		h.responseWriter.Error404(w, r, err)
		return
	}
	finishReq, err := decodeFinishRegistrationBody(r.Body)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}
	credential, err := h.fido2Client.FinishRegistration(h.fido2Context(r), finishReq)
	if err != nil {
		h.logger.Error(err, "sdk FinishRegistration failed")
		h.responseWriter.Error400(w, r, err)
		return
	}
	h.logger.Debug("sdk FinishRegistration ok", slog.String("credential_id", credential.CredentialID))
	user := &entities.User{ID: userID, Email: registration.Email}
	if existing, err := h.userService.Get(r.Context(), userID); err == nil {
		user = existing
	} else if !isNotFoundError(err) {
		h.responseWriter.Error500(w, r, err)
		return
	}
	tenantID, err := h.orchestrateTenant(r, user, registration.InvitationToken)
	if err != nil {
		h.writeRegistrationError(w, r, err)
		return
	}
	if err := h.registrationService.Delete(r.Context(), service.NewSession(), userID); err != nil {
		h.responseWriter.Error500(w, r, err)
		return
	}
	token, err := h.issueToken(r, user)
	if err != nil {
		h.responseWriter.Error500(w, r, err)
		return
	}
	h.responseWriter.Success200(w, r, FinishRegistrationResponse{Token: token, TenantID: tenantID})
}

// BeginLogin starts a WebAuthn authentication ceremony via the SDK.
func (h *WebAuthnRestHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	userID, username, err := getUserIDAndEmail(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}
	user, err := h.userService.Get(r.Context(), userID)
	if err != nil {
		if isNotFoundError(err) {
			h.responseWriter.Error400(w, r, ErrInvalidUserID)
			return
		}
		h.responseWriter.Error400(w, r, err)
		return
	}
	if username == "" {
		username = user.Email
	}
	options, err := h.fido2Client.BeginAuthentication(h.fido2Context(r),
		&quicbaassdk.FIDO2BeginAuthenticationRequest{Username: username})
	if err != nil {
		h.logger.Error(err, "sdk BeginAuthentication failed")
		h.responseWriter.Error500(w, r, err)
		return
	}
	w.Header().Set("Access-Control-Expose-Headers", "X-User-ID")
	w.Header().Set("X-User-ID", strconv.FormatUint(userID, 10))
	h.responseWriter.Write(w, r, http.StatusOK, options)
}

// FinishLogin completes a WebAuthn login ceremony and returns a JWT.
func (h *WebAuthnRestHandler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	userID, _, err := getUserIDAndEmail(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}
	user, err := h.userService.Get(r.Context(), userID)
	if err != nil {
		h.responseWriter.Error404(w, r, err)
		return
	}
	finishReq, err := decodeFinishAuthenticationBody(r.Body, user.Email)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}
	session, err := h.fido2Client.FinishAuthentication(h.fido2Context(r), finishReq)
	if err != nil {
		h.logger.Error(err, "sdk FinishAuthentication failed")
		h.responseWriter.Error400(w, r, err)
		return
	}
	token := session.Token
	if token == "" {
		if token, err = h.issueToken(r, user); err != nil {
			h.responseWriter.Error500(w, r, err)
			return
		}
	}
	h.responseWriter.Success200(w, r, token)
}

// RegistrationStatus reports whether the X-User-Id (or POSTed
// username) corresponds to a registered platform user.
func (h *WebAuthnRestHandler) RegistrationStatus(w http.ResponseWriter, r *http.Request) {
	userID, _, err := getUserIDAndEmail(r)
	if err != nil {
		if err == ErrInvalidUserIDHeader {
			h.responseWriter.Write(w, r, http.StatusOK, "not_registered")
			return
		}
		h.responseWriter.Error400(w, r, err)
		return
	}
	if userID == 0 {
		h.responseWriter.Write(w, r, http.StatusOK, "not_registered")
		return
	}
	if _, err := h.userService.Get(r.Context(), userID); err != nil {
		h.responseWriter.Write(w, r, http.StatusOK, "not_registered")
		return
	}
	h.responseWriter.Write(w, r, http.StatusOK, "registered")
}

// Verify forwards to next; WebAuthn no longer keeps a session.
func (h *WebAuthnRestHandler) Verify(w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	next.ServeHTTP(w, r)
}

// RefreshToken rejects: refresh is owned by /jwt/refresh.
func (h *WebAuthnRestHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	h.responseWriter.Error400(w, r, ErrRefreshUnsupported)
}
