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
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/jwt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// BeginRegistrationRequest represents the request body for beginning registration.
type BeginRegistrationRequest struct {
	Username        string `json:"username"`
	InvitationToken string `json:"invitation_token,omitempty" secret:"true"`
}

// FinishRegistrationResponse represents the response for completing registration.
type FinishRegistrationResponse struct {
	Token    string `json:"token" secret:"true"`
	TenantID string `json:"tenant_id"`
}

// LoginRequest represents the request body for login operations.
type LoginRequest struct {
	Email string `json:"username"`
}

type RestHandler interface {
	BeginRegistration(w http.ResponseWriter, r *http.Request)
	FinishRegistration(w http.ResponseWriter, r *http.Request)
	BeginLogin(w http.ResponseWriter, r *http.Request)
	FinishLogin(w http.ResponseWriter, r *http.Request)
	RegistrationStatus(w http.ResponseWriter, r *http.Request)
	middleware.AuthMiddleware
}

type Config struct {
	RPDisplayName string   `yaml:"display-name" json:"display_name" mapstructure:"display-name"`
	RPID          string   `yaml:"id" json:"id" mapstructure:"id"`
	RPOrigins     []string `yaml:"origins" json:"origins" mapstructure:"origins"`
}

// IsConfigured returns true if the WebAuthn configuration is present and
// contains the minimum required fields (RPID and at least one RPOrigin).
func IsConfigured(config *Config) bool {
	if config == nil {
		return false
	}
	return config.RPID != "" && len(config.RPOrigins) > 0
}

type ServiceParams struct {
	Config              *Config
	Debug               bool
	JWTService          *jwt.Service
	Logger              *logging.Logger
	RegistrationService service.RegistrationServicer
	ResponseWriter      response.HttpWriter
	SessionService      service.WebAuthnSessionServicer
	UserService         service.UserServicer
	TenantUserService   service.TenantUserServicer
	InvitationService   service.InvitationServicer
}

type WebAuthnRestHandler struct {
	logger              *logging.Logger
	jwtService          *jwt.Service
	userService         service.UserServicer
	registrationService service.RegistrationServicer
	tenantUserService   service.TenantUserServicer
	invitationService   service.InvitationServicer
	responseWriter      response.HttpWriter
	webAuthn            *webauthn.WebAuthn
	RestHandler
}

func NewHandler(params ServiceParams) (RestHandler, error) {
	var displayName, id string
	var origins []string
	if params.Config != nil {
		if params.Config.RPDisplayName != "" {
			displayName = params.Config.RPDisplayName
		}
		if params.Config.RPID != "" {
			id = params.Config.RPID
		}
		if len(params.Config.RPOrigins) > 0 {
			origins = params.Config.RPOrigins
		}
	}
	wconfig := &webauthn.Config{
		RPDisplayName: displayName,
		RPID:          id,
		RPOrigins:     origins,
		Debug:         params.Debug,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * 60,
				TimeoutUVD: time.Second * 60,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true,
				Timeout:    time.Second * 60,
				TimeoutUVD: time.Second * 60,
			},
		},
	}

	params.Logger.Debug("Webauthn configuration", slog.Any("config", wconfig))

	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		params.Logger.Error(err, "failed to create webauthn instance")
		return nil, err
	}
	return &WebAuthnRestHandler{
		logger:              params.Logger,
		jwtService:          params.JWTService,
		userService:         params.UserService,
		registrationService: params.RegistrationService,
		tenantUserService:   params.TenantUserService,
		invitationService:   params.InvitationService,
		responseWriter:      params.ResponseWriter,
		webAuthn:            webAuthn,
	}, nil
}

func (handler *WebAuthnRestHandler) BeginRegistration(w http.ResponseWriter, r *http.Request) {
	handler.logger.Debug("webauthn begin registration")

	var req BeginRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		handler.responseWriter.Error400(w, r, ErrInvalidRequestBody)
		return
	}

	if req.Username == "" {
		handler.responseWriter.Error400(w, r, ErrUsernameRequired)
		return
	}

	// If invitation token is provided, validate it exists
	if req.InvitationToken != "" {
		if handler.invitationService == nil {
			handler.logger.Warn("invitation token provided but invitation service is not configured")
			handler.responseWriter.Error500(w, r, ErrInvitationServiceNotConfigured)
			return
		}

		invitation, err := handler.invitationService.GetByToken(r.Context(), req.InvitationToken)
		if err != nil {
			handler.logger.Debug("invitation not found", slog.String("error", err.Error()))
			handler.writeInvitationError(w, r, err)
			return
		}

		// Verify invitation email matches the username
		if invitation.Email != req.Username {
			handler.logger.Warn("invitation email mismatch",
				slog.String("invitation_email", invitation.Email),
				slog.String("username", req.Username),
			)
			handler.responseWriter.Error400(w, r, ErrInvitationEmailMismatch)
			return
		}

		// Verify invitation is still valid
		if invitation.Status != entities.InvitationStatusPending {
			handler.writeInvitationStatusError(w, r, invitation.Status)
			return
		}

		if invitation.IsExpired() {
			handler.responseWriter.Error400(w, r, ErrInvitationExpired)
			return
		}
	}

	opts := make([]webauthn.RegistrationOption, 0)
	userID := util.NewID([]byte(req.Username))

	handler.logger.Debug("begin registration", slog.Uint64("userID", userID))

	_, err := handler.userService.Get(r.Context(), userID)
	if err == nil {
		handler.writeConflictError(w, r, ErrUserAlreadyExists)
		return
	}
	var notFound quicbaas.ErrNotFound
	if !isNotFoundError(err, &notFound) {
		handler.responseWriter.Error400(w, r, err)
		return
	}
	user := entities.NewUser(req.Username)

	options, session, err := handler.webAuthn.BeginRegistration(user, opts...)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	sessionJSON, err := json.Marshal(session)
	if err != nil {
		handler.responseWriter.Error500(w, r, err)
		return
	}

	registration := &entities.Registration{
		ID:              userID,
		Email:           user.Email,
		SessionData:     sessionJSON,
		InvitationToken: req.InvitationToken,
	}

	if err := handler.registrationService.Create(r.Context(), registration); err != nil {
		handler.responseWriter.Error500(w, r, err)
		return
	}

	handler.responseWriter.Write(w, r, http.StatusOK, options)
}

func (handler *WebAuthnRestHandler) FinishRegistration(w http.ResponseWriter, r *http.Request) {
	handler.logger.Debug("webauthn finish registration")

	xuserID := r.Header.Get("X-User-Id")
	if xuserID == "" {
		handler.responseWriter.Error400(w, r, ErrInvalidUserIDHeader)
		return
	}

	sUserID, err := base64.RawURLEncoding.DecodeString(xuserID)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	userID, err := strconv.ParseUint(string(sUserID), 10, 64)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	registration, err := handler.registrationService.Get(r.Context(), service.NewSession(), userID)
	if err != nil {
		handler.responseWriter.Error404(w, r, err)
		return
	}

	user := &entities.User{
		ID:          userID,
		Email:       registration.Email,
		SessionData: registration.SessionData,
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(user.SessionData, &sessionData); err != nil {
		handler.responseWriter.Error500(w, r, err)
		return
	}

	credential, err := handler.webAuthn.FinishRegistration(user, sessionData, r)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	existingUser, err := handler.userService.Get(r.Context(), userID)
	if err != nil {
		var notFound quicbaas.ErrNotFound
		if !isNotFoundError(err, &notFound) {
			handler.responseWriter.Error500(w, r, err)
			return
		}
	} else {
		user = existingUser
	}

	user.AddCredential(credential)

	// Orchestrate tenant creation based on invitation token
	var tenantID string

	if handler.tenantUserService != nil {
		if registration.InvitationToken != "" {
			// User has an invitation - join existing tenant
			handler.logger.Debug("registering invited user",
				slog.String("email", user.Email),
				slog.String("invitation_token", registration.InvitationToken),
			)

			result, err := handler.tenantUserService.RegisterInvitedUser(
				r.Context(),
				user,
				registration.InvitationToken,
			)
			if err != nil {
				handler.logger.Error(err, "failed to register invited user")
				handler.writeRegistrationError(w, r, err)
				return
			}
			user = result.User
			if result.Tenant != nil {
				tenantID = result.Tenant.ID
			}
		} else {
			// New user - create new tenant
			handler.logger.Debug("registering new user with tenant creation",
				slog.String("email", user.Email),
			)

			result, err := handler.tenantUserService.RegisterNewUser(
				r.Context(),
				user,
			)
			if err != nil {
				handler.logger.Error(err, "failed to register new user")
				handler.writeRegistrationError(w, r, err)
				return
			}
			user = result.User
			if result.Tenant != nil {
				tenantID = result.Tenant.ID
			}
		}
	} else {
		// Fallback: save user without tenant orchestration
		handler.logger.Debug("tenant user service not configured, saving user without tenant")
		if err := handler.userService.Save(r.Context(), user); err != nil {
			handler.responseWriter.Error500(w, r, err)
			return
		}
	}

	// Clean up registration
	if err := handler.registrationService.Delete(r.Context(), service.NewSession(), userID); err != nil {
		handler.responseWriter.Error500(w, r, err)
		return
	}

	// Generate JWT token with tenant claims
	var tokenString string
	if handler.tenantUserService != nil {
		tokenString, err = handler.tenantUserService.IssueToken(r.Context(), user)
		if err != nil {
			handler.logger.Error(err, "failed to issue token via tenant user service")
			// Fallback to standard JWT generation
			tokenString, err = handler.jwtService.GenerateToken(user)
			if err != nil {
				handler.responseWriter.Error500(w, r, err)
				return
			}
		}
	} else {
		tokenString, err = handler.jwtService.GenerateToken(user)
		if err != nil {
			handler.responseWriter.Error500(w, r, err)
			return
		}
	}

	// Return response with tenant_id
	resp := FinishRegistrationResponse{
		Token:    tokenString,
		TenantID: tenantID,
	}

	handler.responseWriter.Success200(w, r, resp)
}

func (handler *WebAuthnRestHandler) BeginLogin(w http.ResponseWriter, r *http.Request) {
	handler.logger.Debug("webauthn begin login")

	userID, err := getUserID(r)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	user, err := handler.userService.Get(r.Context(), userID)
	if err != nil {
		var notFound quicbaas.ErrNotFound
		if isNotFoundError(err, &notFound) {
			handler.responseWriter.Error400(w, r, ErrInvalidUserID)
			return
		}
		handler.responseWriter.Error400(w, r, err)
		return
	}

	options, session, err := handler.webAuthn.BeginLogin(user)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	sessionDataBytes, err := json.Marshal(session)
	if err != nil {
		handler.responseWriter.Error500(w, r, err)
		return
	}

	user.SessionData = sessionDataBytes

	if err := handler.userService.Save(r.Context(), user); err != nil {
		handler.responseWriter.Error500(w, r, err)
		return
	}

	w.Header().Set("Access-Control-Expose-Headers", "X-User-ID")
	w.Header().Set("X-User-ID", strconv.FormatUint(userID, 10))

	handler.responseWriter.Write(w, r, http.StatusOK, options)
}

func (handler *WebAuthnRestHandler) FinishLogin(w http.ResponseWriter, r *http.Request) {
	handler.logger.Debug("webauthn finish login")

	userID, err := getUserID(r)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	user, err := handler.userService.Get(r.Context(), userID)
	if err != nil {
		handler.responseWriter.Error404(w, r, err)
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(user.SessionData, &sessionData); err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	credential, err := handler.webAuthn.FinishLogin(user, sessionData, r)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	if credential.Authenticator.CloneWarning {
		handler.logger.Warn("rest/webauthn: credential.Authenticator.CloneWarning")
	}

	user.UpdateCredential(credential)

	if err := handler.userService.Save(r.Context(), user); err != nil {
		handler.responseWriter.Error500(w, r, err)
		return
	}

	// Generate JWT token with tenant claims if available
	var tokenString string
	if handler.tenantUserService != nil {
		tokenString, err = handler.tenantUserService.IssueToken(r.Context(), user)
		if err != nil {
			handler.logger.Error(err, "failed to issue token via tenant user service")
			// Fallback to standard JWT generation
			tokenString, err = handler.jwtService.GenerateToken(user)
			if err != nil {
				handler.responseWriter.Error500(w, r, err)
				return
			}
		}
	} else {
		tokenString, err = handler.jwtService.GenerateToken(user)
		if err != nil {
			handler.responseWriter.Error500(w, r, err)
			return
		}
	}

	handler.responseWriter.Success200(w, r, tokenString)
}

func (handler *WebAuthnRestHandler) Verify(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	userID, err := getUserID(r)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	user, err := handler.userService.Get(r.Context(), userID)
	if err != nil {
		handler.responseWriter.Error404(w, r, err)
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(user.SessionData, &sessionData); err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	if sessionData.Expires.Before(time.Now()) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	next.ServeHTTP(w, r)
}

func (handler *WebAuthnRestHandler) RegistrationStatus(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		if err == ErrInvalidUserIDHeader {
			handler.responseWriter.Write(w, r, http.StatusOK, "not_registered")
			return
		}
		handler.responseWriter.Error400(w, r, err)
		return
	}

	if userID == 0 {
		handler.responseWriter.Write(w, r, http.StatusOK, "not_registered")
		return
	}

	user, err := handler.userService.Get(r.Context(), userID)
	if err != nil {
		handler.responseWriter.Write(w, r, http.StatusOK, "not_registered")
		return
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal(user.SessionData, &sessionData); err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	if sessionData.Expires.Before(time.Now()) {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}

	handler.responseWriter.Write(w, r, http.StatusOK, "registered")
}

// writeConflictError writes a 409 Conflict response.
func (handler *WebAuthnRestHandler) writeConflictError(w http.ResponseWriter, r *http.Request, err error) {
	handler.responseWriter.Write(w, r, http.StatusConflict, response.WebServiceResponse{
		Code:    http.StatusConflict,
		Error:   err.Error(),
		Success: false,
		Payload: nil,
	})
}

// writeInvitationError maps invitation errors to appropriate HTTP status codes.
func (handler *WebAuthnRestHandler) writeInvitationError(w http.ResponseWriter, r *http.Request, err error) {
	switch err.(type) {
	case service.ErrInvitationNotFound:
		handler.responseWriter.Error404(w, r, err)
	case service.ErrInvitationExpired:
		handler.responseWriter.Error400(w, r, err)
	case service.ErrInvitationAlreadyAccepted:
		handler.responseWriter.Error400(w, r, err)
	case service.ErrInvitationRevoked:
		handler.responseWriter.Error400(w, r, err)
	case service.ErrInvalidInvitation:
		handler.responseWriter.Error400(w, r, err)
	default:
		handler.responseWriter.Error500(w, r, err)
	}
}

// writeInvitationStatusError writes an error response based on invitation status.
func (handler *WebAuthnRestHandler) writeInvitationStatusError(
	w http.ResponseWriter,
	r *http.Request,
	status entities.InvitationStatus,
) {
	switch status {
	case entities.InvitationStatusAccepted:
		handler.responseWriter.Error400(w, r, ErrInvitationAlreadyAccepted)
	case entities.InvitationStatusRevoked:
		handler.responseWriter.Error400(w, r, ErrInvitationRevoked)
	case entities.InvitationStatusExpired:
		handler.responseWriter.Error400(w, r, ErrInvitationExpired)
	default:
		handler.responseWriter.Error400(w, r, ErrInvalidInvitationStatus)
	}
}

// writeRegistrationError maps registration errors to appropriate HTTP status codes.
func (handler *WebAuthnRestHandler) writeRegistrationError(w http.ResponseWriter, r *http.Request, err error) {
	switch err.(type) {
	case service.ErrUserAlreadyExists:
		handler.writeConflictError(w, r, err)
	case service.ErrInvitationNotFound:
		handler.responseWriter.Error404(w, r, err)
	case service.ErrInvitationExpired:
		handler.responseWriter.Error400(w, r, err)
	case service.ErrInvitationAlreadyAccepted:
		handler.responseWriter.Error400(w, r, err)
	case service.ErrInvitationRevoked:
		handler.responseWriter.Error400(w, r, err)
	case service.ErrInvalidInvitation:
		handler.responseWriter.Error400(w, r, err)
	case service.ErrTenantCreationFailed:
		handler.responseWriter.Error500(w, r, err)
	case service.ErrUserSaveFailed:
		handler.responseWriter.Error500(w, r, err)
	default:
		handler.responseWriter.Error500(w, r, err)
	}
}

// isNotFoundError checks if the error is a not found error.
func isNotFoundError(err error, notFound *quicbaas.ErrNotFound) bool {
	if err == datastore.ErrRecordNotFound {
		return true
	}
	if notFound != nil {
		var dnf quicbaas.ErrNotFound
		if errAs(err, &dnf) {
			return true
		}
	}
	return false
}

// errAs is a wrapper for errors.As to enable testing.
var errAs = func(err error, target interface{}) bool {
	type asError interface {
		As(interface{}) bool
	}
	if x, ok := err.(asError); ok {
		return x.As(target)
	}
	// Try direct type assertion for simple cases
	switch t := target.(type) {
	case *quicbaas.ErrNotFound:
		if e, ok := err.(quicbaas.ErrNotFound); ok {
			*t = e
			return true
		}
	}
	return false
}

func getUserID(r *http.Request) (uint64, error) {
	xuserID := r.Header.Get("X-User-Id")
	if xuserID == "" {
		var u LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&u); err != nil {
			return 0, ErrInvalidUserIDHeader
		}
		return util.NewID([]byte(u.Email)), nil
	}

	userID, err := strconv.ParseUint(xuserID, 10, 64)
	if err != nil {
		if err == strconv.ErrSyntax {
			userID = util.NewID([]byte(xuserID))
		} else {
			return 0, err
		}
	}

	return userID, nil
}
