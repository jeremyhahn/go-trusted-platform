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
	"errors"
	"log/slog"
	"net/http"

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
	if params.LoginDriver == nil {
		return nil, ErrLoginDriverRequired
	}
	if params.TenantUserService == nil {
		return nil, ErrTenantUserServiceRequired
	}
	return &WebAuthnRestHandler{
		logger:              params.Logger,
		userService:         params.UserService,
		registrationService: params.RegistrationService,
		tenantUserService:   params.TenantUserService,
		invitationService:   params.InvitationService,
		responseWriter:      params.ResponseWriter,
		fido2Client:         params.FIDO2Client,
		loginDriver:         params.LoginDriver,
		tenantID:            params.TenantID,
		config:              params.Config,
		publicRegistration:  params.PublicRegistrationEnabled,
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
	if req.Email == "" {
		h.responseWriter.Error400(w, r, ErrEmailRequired)
		return
	}
	// The address becomes the user id, the tenant owner label and the IAM
	// identity, so it is checked here, before any of those is derived from
	// it, against the rule the IAM mirror applies (#643).
	if err := service.ValidateEmail(req.Email); err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}
	// The canonical registration flag (docs/08 §Registration model):
	// with self-service registration disabled — the invite-only default —
	// an uninvited registration is refused before any ceremony starts.
	// Invited registrations carry their token and proceed to validation.
	if req.InvitationToken == "" && !h.publicRegistration {
		h.responseWriter.Error403(w, r, ErrPublicRegistrationDisabled, nil)
		return
	}
	if req.InvitationToken != "" && !h.validateInvitation(w, r, req.InvitationToken, req.Email) {
		return
	}
	userID := util.NewID([]byte(req.Email))
	if _, err := h.userService.Get(r.Context(), userID); err == nil {
		h.writeConflictError(w, r, ErrUserAlreadyExists)
		return
	} else if !isNotFoundError(err) {
		h.responseWriter.Error400(w, r, err)
		return
	}
	options, err := h.fido2Client.BeginRegistration(h.fido2Context(r),
		&quicbaassdk.FIDO2BeginRegistrationRequest{Email: req.Email, DisplayName: req.Email})
	if err != nil {
		h.logger.Error(err, "sdk BeginRegistration failed")
		h.responseWriter.Error500(w, r, err)
		return
	}
	// The browser consumes the parsed CredentialCreation object (publicKey
	// at the top level). The SDK's user handle stays untouched — the
	// authenticator stores it and the SDK validates it at login — and the
	// pending registration is keyed by a digest of that handle, because
	// the handle (as publicKey.user.id) is the one identifier the browser
	// echoes back at finish time. The ceremony session is correlated
	// server-side via the registration record.
	creation, handle, err := parseCreationOptions(options.OptionsJSON)
	if err != nil {
		h.logger.Error(err, "sdk BeginRegistration returned unparseable options")
		h.responseWriter.Error500(w, r, err)
		return
	}
	if err := h.registrationService.Create(r.Context(), &entities.Registration{
		ID: util.NewID(handle), Email: req.Email, InvitationToken: req.InvitationToken,
	}); err != nil {
		h.responseWriter.Error500(w, r, err)
		return
	}
	// The ceremony state lives in the SDK; the platform stores none of
	// it. The SDK session ID rides the begin payload and the browser
	// echoes it back on finish via the X-Session-Id header.
	creation["session_id"] = options.SessionID
	h.responseWriter.Write(w, r, http.StatusOK, creation)
}

// FinishRegistration completes the ceremony, orchestrates tenant
// creation/join, persists the platform user, and returns a JWT.
func (h *WebAuthnRestHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	recordID, err := registrationKeyFromHeader(r)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}
	registration, err := h.registrationService.Get(r.Context(), service.NewSession(), recordID)
	if err != nil {
		h.responseWriter.Error404(w, r, err)
		return
	}
	// Re-check the CURRENT policy: a begin that predates a flip to
	// invite-only (or a stale uninvited pending record) must not finish
	// into a user and tenant. Invited records carry their token and
	// remain redeemable.
	if registration.InvitationToken == "" && !h.publicRegistration {
		h.responseWriter.Error403(w, r, ErrPublicRegistrationDisabled, nil)
		return
	}
	// The platform user identity is derived from the registered username,
	// never from the correlation key (which may be a handle digest).
	userID := util.NewID([]byte(registration.Email))
	finishReq, err := decodeFinishRegistrationBody(r.Body, r.Header.Get(sessionIDHeader))
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
	// Fail closed: an error-free response is not attestation — the SDK
	// reports the verification verdict on Success, and a nil response
	// proves nothing.
	if credential == nil || !credential.Success {
		h.logger.Error(ErrAuthenticationFailed, "sdk FinishRegistration rejected the attestation")
		h.responseWriter.Error400(w, r, ErrAuthenticationFailed)
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
	if err := h.registrationService.Delete(r.Context(), service.NewSession(), recordID); err != nil {
		h.responseWriter.Error500(w, r, err)
		return
	}
	token, err := h.issueToken(r, user)
	if errors.Is(err, ErrOperatingTenant) {
		h.responseWriter.Error403(w, r, err, nil)
		return
	}
	if err != nil {
		h.responseWriter.Error500(w, r, err)
		return
	}
	h.responseWriter.Success200(w, r, FinishRegistrationResponse{Token: token, TenantID: tenantID})
}

// BeginLogin opens a WebAuthn assertion ceremony on the unified login
// backbone.
//
// It is USERNAMELESS: the driver's FIDO2 binder sends no hint, which
// drives the backbone's discoverable-credential flow, and the credential
// the authenticator returns identifies the user. The platform therefore
// performs no lookup of its own before the ceremony — the lookup that
// used to fail here whenever the platform record was missing or keyed
// differently from the credential (#640), and the lookup that could never
// work for a public email domain.
func (h *WebAuthnRestHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	h.loginDriver.Begin(w, r, quicbaassdk.FactorTypeFIDO2)
}

// FinishLogin submits the browser's assertion to the unified backbone,
// which resolves the principal from the credential id and verifies the
// assertion's signature, relying-party id/origin and sign counter. The
// verdict is the backbone's; the session credential the client receives is
// then minted from the identity it resolved, because that is what this
// server's own inbound seam validates (login.SessionIssuer).
func (h *WebAuthnRestHandler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	h.loginDriver.Finish(w, r, quicbaassdk.FactorTypeFIDO2)
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
