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

package eab

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/eab"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/tenant"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// HandlerParams contains the dependencies for creating an EAB handler.
type HandlerParams struct {
	Logger         *logging.Logger
	EABService     EABServicer
	Delivery       DeliveryServicer
	ResponseWriter response.HttpWriter
}

// handler implements the RestHandler interface.
type handler struct {
	logger         *logging.Logger
	eabService     EABServicer
	delivery       DeliveryServicer
	responseWriter response.HttpWriter
}

// NewHandler creates a new EAB handler with the given parameters.
func NewHandler(params HandlerParams) (RestHandler, error) {
	if params.Logger == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingLogger{}}
	}
	if params.EABService == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingEABService{}}
	}
	if params.ResponseWriter == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingResponseWriter{}}
	}
	if params.Delivery == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingDelivery{}}
	}

	return &handler{
		logger:         params.Logger,
		eabService:     params.EABService,
		delivery:       params.Delivery,
		responseWriter: params.ResponseWriter,
	}, nil
}

// Create creates a new EAB credential.
// POST /api/v1/eab/credentials
func (h *handler) Create(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("eab: create credential request received")

	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("eab: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	userID := tenant.GetUserID(ctx)
	if userID == 0 {
		h.logger.Debug("eab: missing user ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing user context"})
		return
	}

	// Only tenant owner can create credentials
	if !tenant.IsTenantOwner(ctx) {
		h.logger.Debug("eab: user is not tenant owner",
			slog.Uint64("user_id", userID),
			slog.String("tenant_id", tenantID))
		h.responseWriter.Error403(w, r, ErrNotTenantOwner{}, nil)
		return
	}

	var req CreateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("eab: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.ProfileID == 0 {
		h.responseWriter.Error400(w, r, ErrMissingProfileID{})
		return
	}

	// Use tenant from context, allow override only if specified
	credTenantID := tenantID
	if req.TenantID != "" {
		credTenantID = req.TenantID
	}

	// Validate expires_in_seconds
	var expiresIn time.Duration
	if req.ExpiresInSeconds > 0 {
		expiresIn = time.Duration(req.ExpiresInSeconds) * time.Second
	} else if req.ExpiresInSeconds < 0 {
		h.responseWriter.Error400(w, r, ErrInvalidExpiresIn{Reason: "cannot be negative"})
		return
	}

	params := eab.GenerateParams{
		ProfileID: req.ProfileID,
		TenantID:  credTenantID,
		ExpiresIn: expiresIn,
	}

	credential, err := h.eabService.Generate(ctx, params)
	if err != nil {
		h.logger.Errorf("eab: failed to generate credential: %v", err)
		h.responseWriter.Error500(w, r, ErrServiceError{Operation: "create", Cause: err})
		return
	}

	h.logger.Info("eab: credential created successfully",
		slog.Uint64("credential_id", credential.ID),
		slog.String("key_id", credential.KeyID),
		slog.Uint64("profile_id", req.ProfileID),
		slog.String("tenant_id", credTenantID))

	resp := ToCredentialResponse(credential, true)
	h.responseWriter.Success201(w, r, resp)
}

// Get retrieves an EAB credential by its ID.
// GET /api/v1/eab/credentials/{id}
func (h *handler) Get(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("eab: get credential by id request received")

	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("eab: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.responseWriter.Error400(w, r, ErrMissingCredentialID{})
		return
	}

	credentialID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidCredentialID{ID: idStr})
		return
	}

	credential, err := h.eabService.Get(ctx, credentialID)
	if err != nil {
		h.writeGetError(w, r, credentialID, err)
		return
	}

	// Verify the credential belongs to this tenant
	if credential.TenantID != tenantID {
		h.logger.Warnf("eab: attempted to access credential from different tenant: credential_id=%d, credential_tenant=%s, user_tenant=%s",
			credentialID, credential.TenantID, tenantID)
		h.responseWriter.Error404(w, r, ErrCredentialNotFound{ID: credentialID})
		return
	}

	h.logger.Debug("eab: retrieved credential by id",
		slog.Uint64("credential_id", credential.ID),
		slog.String("tenant_id", tenantID))

	resp := ToCredentialResponse(credential, false)
	h.responseWriter.Success200(w, r, resp)
}

// GetByKeyID retrieves an EAB credential by its KeyID.
// GET /api/v1/eab/credentials/key/{key_id}
func (h *handler) GetByKeyID(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("eab: get credential by key_id request received")

	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("eab: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	vars := mux.Vars(r)
	keyID := vars["key_id"]
	if keyID == "" {
		h.responseWriter.Error400(w, r, ErrMissingKeyID{})
		return
	}

	credential, err := h.eabService.GetByKeyID(ctx, keyID)
	if err != nil {
		h.writeGetByKeyIDError(w, r, keyID, err)
		return
	}

	// Verify the credential belongs to this tenant
	if credential.TenantID != tenantID {
		h.logger.Warnf("eab: attempted to access credential from different tenant: key_id=%s, credential_tenant=%s, user_tenant=%s",
			keyID, credential.TenantID, tenantID)
		h.responseWriter.Error404(w, r, ErrCredentialNotFound{KeyID: keyID})
		return
	}

	h.logger.Debug("eab: retrieved credential by key_id",
		slog.String("key_id", keyID),
		slog.String("tenant_id", tenantID))

	resp := ToCredentialResponse(credential, false)
	h.responseWriter.Success200(w, r, resp)
}

// List lists all EAB credentials for a profile or tenant.
// GET /api/v1/eab/credentials?profile_id=X
func (h *handler) List(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("eab: list credentials request received")

	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("eab: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	var credentials []*eab.Credential
	var err error

	profileIDStr := r.URL.Query().Get("profile_id")
	if profileIDStr != "" {
		profileID, parseErr := strconv.ParseUint(profileIDStr, 10, 64)
		if parseErr != nil {
			h.responseWriter.Error400(w, r, ErrInvalidProfileID{ID: profileIDStr})
			return
		}

		credentials, err = h.eabService.ListByProfile(ctx, profileID)
		if err != nil {
			h.logger.Errorf("eab: failed to list credentials for profile_id=%d: %v", profileID, err)
			h.responseWriter.Error500(w, r, ErrServiceError{Operation: "list", Cause: err})
			return
		}

		// Filter credentials by tenant
		filtered := make([]*eab.Credential, 0, len(credentials))
		for _, cred := range credentials {
			if cred.TenantID == tenantID {
				filtered = append(filtered, cred)
			}
		}
		credentials = filtered

		h.logger.Debug("eab: listed credentials for profile",
			slog.Uint64("profile_id", profileID),
			slog.String("tenant_id", tenantID),
			slog.Int("count", len(credentials)))
	} else {
		credentials, err = h.eabService.ListByTenant(ctx, tenantID)
		if err != nil {
			h.logger.Errorf("eab: failed to list credentials for tenant_id=%s: %v", tenantID, err)
			h.responseWriter.Error500(w, r, ErrServiceError{Operation: "list", Cause: err})
			return
		}

		h.logger.Debug("eab: listed credentials for tenant",
			slog.String("tenant_id", tenantID),
			slog.Int("count", len(credentials)))
	}

	resp := ToCredentialListResponse(credentials)
	h.responseWriter.Success200(w, r, resp)
}

// Revoke revokes an EAB credential.
// POST /api/v1/eab/credentials/{id}/revoke
func (h *handler) Revoke(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("eab: revoke credential request received")

	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("eab: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	userID := tenant.GetUserID(ctx)
	if userID == 0 {
		h.logger.Debug("eab: missing user ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing user context"})
		return
	}

	// Only tenant owner can revoke credentials
	if !tenant.IsTenantOwner(ctx) {
		h.logger.Debug("eab: user is not tenant owner",
			slog.Uint64("user_id", userID),
			slog.String("tenant_id", tenantID))
		h.responseWriter.Error403(w, r, ErrNotTenantOwner{}, nil)
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.responseWriter.Error400(w, r, ErrMissingCredentialID{})
		return
	}

	credentialID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidCredentialID{ID: idStr})
		return
	}

	// Verify the credential exists and belongs to this tenant
	credential, err := h.eabService.Get(ctx, credentialID)
	if err != nil {
		h.writeGetError(w, r, credentialID, err)
		return
	}

	if credential.TenantID != tenantID {
		h.logger.Warnf("eab: attempted to revoke credential from different tenant: credential_id=%d, credential_tenant=%s, user_tenant=%s",
			credentialID, credential.TenantID, tenantID)
		h.responseWriter.Error404(w, r, ErrCredentialNotFound{ID: credentialID})
		return
	}

	// Check if credential is already revoked
	if credential.Status == eab.StatusRevoked {
		h.responseWriter.Write(w, r, http.StatusConflict, response.WebServiceResponse{
			Code:    http.StatusConflict,
			Error:   ErrCredentialAlreadyRevoked{ID: credentialID}.Error(),
			Success: false,
		})
		return
	}

	if err := h.eabService.Revoke(ctx, credentialID); err != nil {
		h.logger.Errorf("eab: failed to revoke credential id=%d: %v", credentialID, err)
		h.responseWriter.Error500(w, r, ErrServiceError{Operation: "revoke", Cause: err})
		return
	}

	h.logger.Info("eab: credential revoked successfully",
		slog.Uint64("credential_id", credentialID),
		slog.String("tenant_id", tenantID),
		slog.Uint64("revoked_by", userID))

	h.responseWriter.Success200(w, r, RevokeResponse{
		Status:  "revoked",
		Message: "credential has been revoked",
	})
}

// Validate validates an EAB credential.
// POST /api/v1/eab/credentials/validate
func (h *handler) Validate(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("eab: validate credential request received")

	ctx := r.Context()

	var req ValidateCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Debug("eab: failed to decode request body", slog.String("error", err.Error()))
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.KeyID == "" {
		h.responseWriter.Error400(w, r, ErrMissingKeyID{})
		return
	}
	if req.HMACKey == "" {
		h.responseWriter.Error400(w, r, ErrMissingHMACKey{})
		return
	}

	// Decode base64 HMAC key
	hmacKey, err := base64.RawURLEncoding.DecodeString(req.HMACKey)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidHMACKey{Reason: "invalid base64 encoding"})
		return
	}

	credential, err := h.eabService.Validate(ctx, req.KeyID, hmacKey)
	if err != nil {
		// For validation, we don't return 500 errors for expected validation failures
		var notFound eab.ErrCredentialNotFound
		var expired eab.ErrCredentialExpired
		var revoked eab.ErrCredentialRevoked
		var alreadyUsed eab.ErrCredentialAlreadyUsed
		var invalid eab.ErrInvalidCredential

		if errors.As(err, &notFound) || errors.As(err, &expired) ||
			errors.As(err, &revoked) || errors.As(err, &alreadyUsed) ||
			errors.As(err, &invalid) {
			h.logger.Debug("eab: credential validation failed",
				slog.String("key_id", req.KeyID),
				slog.String("error", err.Error()))
			h.responseWriter.Success200(w, r, ValidateCredentialResponse{
				Valid:      false,
				Credential: nil,
			})
			return
		}

		h.logger.Errorf("eab: failed to validate credential key_id=%s: %v", req.KeyID, err)
		h.responseWriter.Error500(w, r, ErrServiceError{Operation: "validate", Cause: err})
		return
	}

	h.logger.Debug("eab: credential validated successfully",
		slog.String("key_id", req.KeyID),
		slog.Uint64("credential_id", credential.ID))

	credResp := ToCredentialResponse(credential, false)
	h.responseWriter.Success200(w, r, ValidateCredentialResponse{
		Valid:      true,
		Credential: &credResp,
	})
}

// Delete deletes an EAB credential.
// DELETE /api/v1/eab/credentials/{id}
func (h *handler) Delete(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("eab: delete credential request received")

	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("eab: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	userID := tenant.GetUserID(ctx)
	if userID == 0 {
		h.logger.Debug("eab: missing user ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing user context"})
		return
	}

	// Only tenant owner can delete credentials
	if !tenant.IsTenantOwner(ctx) {
		h.logger.Debug("eab: user is not tenant owner",
			slog.Uint64("user_id", userID),
			slog.String("tenant_id", tenantID))
		h.responseWriter.Error403(w, r, ErrNotTenantOwner{}, nil)
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.responseWriter.Error400(w, r, ErrMissingCredentialID{})
		return
	}

	credentialID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidCredentialID{ID: idStr})
		return
	}

	// Verify the credential exists and belongs to this tenant
	credential, err := h.eabService.Get(ctx, credentialID)
	if err != nil {
		h.writeGetError(w, r, credentialID, err)
		return
	}

	if credential.TenantID != tenantID {
		h.logger.Warnf("eab: attempted to delete credential from different tenant: credential_id=%d, credential_tenant=%s, user_tenant=%s",
			credentialID, credential.TenantID, tenantID)
		h.responseWriter.Error404(w, r, ErrCredentialNotFound{ID: credentialID})
		return
	}

	if err := h.eabService.Delete(ctx, credentialID); err != nil {
		h.logger.Errorf("eab: failed to delete credential id=%d: %v", credentialID, err)
		h.responseWriter.Error500(w, r, ErrServiceError{Operation: "delete", Cause: err})
		return
	}

	h.logger.Info("eab: credential deleted successfully",
		slog.Uint64("credential_id", credentialID),
		slog.String("tenant_id", tenantID),
		slog.Uint64("deleted_by", userID))

	h.responseWriter.Success200(w, r, DeleteResponse{
		Status:  "deleted",
		Message: "credential has been deleted",
	})
}

// GetQRCode generates a QR code for credential delivery.
// GET /api/v1/eab/credentials/{id}/qr
func (h *handler) GetQRCode(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("eab: get QR code request received")

	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("eab: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.responseWriter.Error400(w, r, ErrMissingCredentialID{})
		return
	}

	credentialID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidCredentialID{ID: idStr})
		return
	}

	credential, err := h.eabService.Get(ctx, credentialID)
	if err != nil {
		h.writeGetError(w, r, credentialID, err)
		return
	}

	// Verify the credential belongs to this tenant
	if credential.TenantID != tenantID {
		h.logger.Warnf("eab: attempted to get QR code for credential from different tenant: credential_id=%d, credential_tenant=%s, user_tenant=%s",
			credentialID, credential.TenantID, tenantID)
		h.responseWriter.Error404(w, r, ErrCredentialNotFound{ID: credentialID})
		return
	}

	qrCode, err := h.delivery.ToQRCode(credential)
	if err != nil {
		h.logger.Errorf("eab: failed to generate QR code for credential id=%d: %v", credentialID, err)
		h.responseWriter.Error500(w, r, ErrQRCodeGenerationFailed{Cause: err})
		return
	}

	h.logger.Debug("eab: QR code generated successfully",
		slog.Uint64("credential_id", credentialID),
		slog.String("tenant_id", tenantID))

	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(qrCode)))
	w.WriteHeader(http.StatusOK)
	w.Write(qrCode)
}

// GetEnrollmentURL generates an enrollment URL.
// GET /api/v1/eab/credentials/{id}/url
func (h *handler) GetEnrollmentURL(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("eab: get enrollment URL request received")

	ctx := r.Context()
	tenantID := tenant.GetTenantID(ctx)
	if tenantID == "" {
		h.logger.Debug("eab: missing tenant ID in context")
		h.responseWriter.Error401(w, r, ErrUnauthorized{Reason: "missing tenant context"})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.responseWriter.Error400(w, r, ErrMissingCredentialID{})
		return
	}

	credentialID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidCredentialID{ID: idStr})
		return
	}

	credential, err := h.eabService.Get(ctx, credentialID)
	if err != nil {
		h.writeGetError(w, r, credentialID, err)
		return
	}

	// Verify the credential belongs to this tenant
	if credential.TenantID != tenantID {
		h.logger.Warnf("eab: attempted to get enrollment URL for credential from different tenant: credential_id=%d, credential_tenant=%s, user_tenant=%s",
			credentialID, credential.TenantID, tenantID)
		h.responseWriter.Error404(w, r, ErrCredentialNotFound{ID: credentialID})
		return
	}

	enrollmentURL, err := h.delivery.ToURL(credential)
	if err != nil {
		h.logger.Errorf("eab: failed to generate enrollment URL for credential id=%d: %v", credentialID, err)
		h.responseWriter.Error500(w, r, ErrURLGenerationFailed{Cause: err})
		return
	}

	h.logger.Debug("eab: enrollment URL generated successfully",
		slog.Uint64("credential_id", credentialID),
		slog.String("tenant_id", tenantID))

	h.responseWriter.Success200(w, r, EnrollmentURLResponse{
		URL: enrollmentURL,
	})
}

// writeGetError writes an appropriate error response for Get errors.
func (h *handler) writeGetError(w http.ResponseWriter, r *http.Request, id uint64, err error) {
	var notFound eab.ErrCredentialNotFound
	if errors.As(err, &notFound) {
		h.responseWriter.Error404(w, r, ErrCredentialNotFound{ID: id})
		return
	}
	h.logger.Errorf("eab: failed to get credential id=%d: %v", id, err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: "get", Cause: err})
}

// writeGetByKeyIDError writes an appropriate error response for GetByKeyID errors.
func (h *handler) writeGetByKeyIDError(w http.ResponseWriter, r *http.Request, keyID string, err error) {
	var notFound eab.ErrCredentialNotFound
	if errors.As(err, &notFound) {
		h.responseWriter.Error404(w, r, ErrCredentialNotFound{KeyID: keyID})
		return
	}
	h.logger.Errorf("eab: failed to get credential by key_id=%s: %v", keyID, err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: "getByKeyID", Cause: err})
}

// Ensure handler implements RestHandler interface.
var _ RestHandler = (*handler)(nil)
