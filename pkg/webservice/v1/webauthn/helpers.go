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
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
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
	if invitation.IsExpired(time.Now()) {
		h.responseWriter.Error400(w, r, ErrInvitationExpired)
		return false
	}
	// Refused here, before an account exists: a member of the operating
	// tenant could never sign in with this passkey, since a browser login
	// is refused when the workspace is the operating tenant (#662).
	if invitation.TenantID == h.tenantID {
		h.responseWriter.Error403(w, r, ErrOperatingTenant, nil)
		return false
	}
	return true
}

// orchestrateTenant attaches the freshly-registered user to a tenant: a new
// workspace, or the tenant an invitation names. Returns the resolved
// tenantID (empty when the service reports no tenant).
func (h *WebAuthnRestHandler) orchestrateTenant(r *http.Request, user *entities.User, invitationToken string) (string, error) {
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

// issueToken mints the registration session in the user's own workspace
// through the tenant user service. It fails closed with ErrOperatingTenant
// when the user has no tenant or sits in the operating tenant: a browser
// session never lands there (#662), and there is no unscoped fallback.
func (h *WebAuthnRestHandler) issueToken(r *http.Request, user *entities.User) (string, error) {
	if user.TenantID == "" || user.TenantID == h.tenantID {
		return "", ErrOperatingTenant
	}
	token, err := h.tenantUserService.IssueToken(r.Context(), user)
	if err != nil {
		h.logger.Error(err, "failed to issue token via tenant user service")
		return "", err
	}
	if token == "" {
		return "", ErrEmptyTenantToken
	}
	return token, nil
}

// writeConflictError writes a 409 Conflict response.
func (h *WebAuthnRestHandler) writeConflictError(w http.ResponseWriter, r *http.Request, err error) {
	h.responseWriter.Write(w, r, http.StatusConflict, restwire.WebServiceResponse{
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

// sessionIDHeader carries the SDK ceremony session ID issued in the
// begin payload back to the finish endpoints. The SDK validates the
// assertion or attestation against that session's challenge, so the
// header is a correlation hint, not a trust decision.
const sessionIDHeader = "X-Session-Id"

// isNotFoundError reports whether the supplied error indicates a
// missing record from the platform datastore, the kvstore DAO layer,
// or the quicbaas adapter — each speaks its own typed not-found error.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, datastore.ErrRecordNotFound) {
		return true
	}
	var kvNotFound kvstore.ErrNotFound
	if errors.As(err, &kvNotFound) {
		return true
	}
	var kvNotFoundByIndex kvstore.ErrNotFoundByIndex
	if errors.As(err, &kvNotFoundByIndex) {
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

// parseCreationOptions parses the SDK's marshaled CredentialCreation
// options and returns both the parsed object (carrying publicKey at the
// top level — the shape the console frontend consumes) and the SDK's
// WebAuthn user handle. The handle is left UNTOUCHED in the options: the
// authenticator stores it and returns it as the assertion userHandle,
// which the SDK validates against its own user record at login — the
// browser echoes it back as the X-User-Id header at finish time, and the
// handler correlates the pending registration by a digest of the handle.
func parseCreationOptions(optionsJSON string) (map[string]interface{}, []byte, error) {
	var options map[string]interface{}
	if err := json.Unmarshal([]byte(optionsJSON), &options); err != nil {
		return nil, nil, ErrInvalidRequestBody
	}
	publicKey, ok := options["publicKey"].(map[string]interface{})
	if !ok {
		return nil, nil, ErrInvalidRequestBody
	}
	user, ok := publicKey["user"].(map[string]interface{})
	if !ok {
		return nil, nil, ErrInvalidRequestBody
	}
	encoded, ok := user["id"].(string)
	if !ok || encoded == "" {
		return nil, nil, ErrInvalidRequestBody
	}
	handle, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, nil, ErrInvalidRequestBody
	}
	return options, handle, nil
}

// registrationKeyFromHeader resolves the pending-registration record key
// from the X-User-Id header: the browser echoes back publicKey.user.id —
// the SDK's opaque WebAuthn user handle, base64url-encoded — and the
// record key is the digest of the decoded handle bytes the handler stored
// at begin time. This is the ONLY finish-registration contract; the
// platform user id is recovered from the record's Email, never from the
// header.
func registrationKeyFromHeader(r *http.Request) (uint64, error) {
	xuserID := r.Header.Get("X-User-Id")
	if xuserID == "" {
		return 0, ErrInvalidUserIDHeader
	}
	decoded, err := base64.RawURLEncoding.DecodeString(xuserID)
	if err != nil {
		return 0, err
	}
	return util.NewID(decoded), nil
}

// maxCredentialBodyBytes caps the finish request bodies. WebAuthn
// credentials — attestation objects with full x5c chains included — run
// a few KB; 64KB leaves ample headroom while keeping the unauthenticated
// finish endpoints from buffering attacker-sized bodies.
const maxCredentialBodyBytes = 64 * 1024

// readCredentialBody buffers at most maxCredentialBodyBytes of valid
// JSON from an unauthenticated finish request.
func readCredentialBody(body io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(body, maxCredentialBodyBytes+1))
	if err != nil {
		return nil, ErrInvalidRequestBody
	}
	if len(raw) > maxCredentialBodyBytes {
		return nil, ErrRequestBodyTooLarge
	}
	if !json.Valid(raw) {
		return nil, ErrInvalidRequestBody
	}
	return raw, nil
}

// decodeFinishRegistrationBody wraps the RAW WebAuthn PublicKeyCredential
// attestation JSON the browser posts (navigator.credentials.create()
// output — the ONLY finish contract; no other client speaks these
// endpoints) with the ceremony session the handler persisted at begin
// time. A finish with no persisted session cannot be correlated and fails
// closed.
func decodeFinishRegistrationBody(body io.Reader, sessionID string) (*quicbaassdk.FIDO2FinishRegistrationRequest, error) {
	raw, err := readCredentialBody(body)
	if err != nil {
		return nil, err
	}
	if sessionID == "" {
		return nil, ErrCeremonySessionMissing
	}
	return &quicbaassdk.FIDO2FinishRegistrationRequest{
		SessionID:       sessionID,
		AttestationJSON: string(raw),
	}, nil
}
