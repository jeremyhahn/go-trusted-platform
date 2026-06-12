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

package jwt

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

var (
	// ErrLoginUnavailable is returned when the unified quicbaas login
	// client is not wired. The locked architecture forbids minting a
	// platform-local JWT from an unauthenticated credential, so /login
	// fails closed instead of issuing an unverified token.
	ErrLoginUnavailable = errors.New("rest/jwt: unified login backend is not configured")

	// ErrLoginFailed is returned when the unified login ceremony resolves
	// no bearer (no identity authenticated).
	ErrLoginFailed = errors.New("rest/jwt: authentication failed")
)

type TokenHandler interface {
	middleware.JsonWebTokenMiddleware
}

type RestHandler struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	jwtService     *Service
	userService    service.UserServicer
	// loginClient routes /login through the quicbaas SDK unified login
	// ceremony (Security().Auth().BeginLogin/FinishLogin). When nil,
	// /login fails closed with ErrLoginUnavailable rather than minting an
	// unverified local JWT.
	loginClient UnifiedLoginClient
	TokenHandler
}

// Instantiate a new JsonWebTokenService
func NewRestHandler(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	jwtService *Service,
	userService service.UserServicer) (TokenHandler, error) {

	return &RestHandler{
		logger:         logger,
		responseWriter: responseWriter,
		jwtService:     jwtService,
		userService:    userService}, nil
}

// SetUnifiedLoginClient wires the quicbaas SDK unified login client so
// /login authenticates via BeginLogin/FinishLogin and returns the
// SDK-issued OIDC bearer. Wired by the handler registry at boot when the
// SDK AuthService is available.
func (handler *RestHandler) SetUnifiedLoginClient(client UnifiedLoginClient) {
	handler.loginClient = client
}

// Creates a new web service session from the parsed JWT
func (handler *RestHandler) CreateSession(
	w http.ResponseWriter,
	r *http.Request) (service.Session, error) {

	handler.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	_, claims, err := handler.jwtService.ParseToken(w, r)
	if err != nil {
		return nil, err
	}

	handler.logger.Debugf("rest/jwt: claims: %+v", claims)

	var requestedServiceID uint64

	params := mux.Vars(r)
	serviceIDParam := params["service_id"]

	if serviceIDParam != "" {
		// ignore errors here; may be a new system without any services
		// configured
		requestedServiceID, _ = strconv.ParseUint(serviceIDParam, 10, 64)
	}

	user, err := handler.userService.Get(r.Context(), claims.UserID)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return nil, err
	}

	return service.CreateSession(
		handler.logger,
		requestedServiceID,
		claims.Services,
		user), nil
}

// GenerateToken authenticates the caller through the quicbaas SDK unified
// login ceremony and returns the SDK-issued OIDC bearer.
//
// The locked architecture makes qrdb's LoginClient the single canonical
// login backbone and quicbaas's OIDC TokenService the SessionIssuer; the
// platform is a consumer, not an issuer. /login is a single-shot POST over
// the webserver's mTLS-capable connection, so it drives the mTLS factor:
// BeginLogin(mtls) opens the attempt and FinishLogin(mtls) lets the
// quicbaas server derive the lookup key from the verified peer certificate
// and mint the bearer. WebAuthn/FIDO2 and PIV use challenge round-trips and
// are handled by the dedicated /webauthn router.
//
// When no unified login client is wired the handler fails closed with
// ErrLoginUnavailable — it never fabricates an unverified local JWT.
func (handler *RestHandler) GenerateToken(w http.ResponseWriter, req *http.Request) {

	handler.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		req.URL.Path, req.Method, req.RemoteAddr, req.RequestURI)

	var userCred service.UserCredential
	if err := json.NewDecoder(req.Body).Decode(&userCred); err != nil {
		handler.responseWriter.Error400(w, req, err)
		return
	}

	if handler.loginClient == nil {
		handler.logger.Error(ErrLoginUnavailable, "unified login client not configured")
		handler.responseWriter.Error403(w, req, ErrLoginUnavailable, nil)
		return
	}

	ctx := req.Context()

	begin, err := handler.loginClient.BeginLogin(ctx, quicbaas.BeginLoginRequest{
		Type: quicbaas.FactorTypeMTLS,
		Hint: userCred.Email,
	})
	if err != nil {
		handler.logger.Error(err, "unified BeginLogin(mtls) failed")
		handler.responseWriter.Error401(w, req, err)
		return
	}

	finish, err := handler.loginClient.FinishLogin(ctx, quicbaas.FinishLoginRequest{
		SessionID: begin.SessionID,
		Type:      quicbaas.FactorTypeMTLS,
	})
	if err != nil {
		handler.logger.Error(err, "unified FinishLogin(mtls) failed")
		handler.responseWriter.Error401(w, req, err)
		return
	}

	if finish == nil || finish.Bearer == "" {
		handler.logger.Error(ErrLoginFailed, "unified FinishLogin returned no bearer")
		handler.responseWriter.Error401(w, req, ErrLoginFailed)
		return
	}

	handler.logger.Debug("rest/jwt: unified login issued OIDC bearer")

	handler.responseWriter.Success200(w, req, finish.Bearer)
}

// Exchange a JWT for a new token with a new expiration date
func (handler *RestHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {

	handler.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	token, claims, err := handler.jwtService.ParseToken(w, r)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	if !token.Valid {
		handler.responseWriter.Error401(w, r, ErrInvalidToken)
		return
	}

	handler.logger.Debugf("rest/jwt: claims: %+v", claims)

	user := &entities.User{
		ID: claims.UserID,
	}

	tokenString, err := handler.jwtService.GenerateToken(user)
	if err != nil {
		handler.responseWriter.Error500(w, r, err)
		return
	}

	handler.logger.Debugf("rest/jwt: refreshed token: %s", tokenString)

	handler.responseWriter.Success200(w, r, tokenString)
}

// Validates the raw JWT token to ensure it's not expired or contains invalid claims. This
// is used by the negroni middleware to enforce authenticated access to procted resources.
func (handler *RestHandler) Verify(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	handler.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	token, _, err := handler.jwtService.ParseToken(w, r)
	if err != nil {
		// Error response already sent
		return
	}

	if err := handler.jwtService.Verify(token); err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	next(w, r)
}
