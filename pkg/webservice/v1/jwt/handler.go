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
	"context"
	"errors"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	iamsdk "github.com/jeremyhahn/go-quicbaas/sdk/go/client/iam"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/login"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	iammw "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

var (
	// ErrLoginUnavailable is returned when the unified quicbaas login
	// client is not wired. The locked architecture forbids minting a
	// platform-local JWT from an unauthenticated credential, so /login
	// fails closed instead of issuing an unverified token.
	ErrLoginUnavailable = errors.New("rest/jwt: unified login backend is not configured")
)

type TokenHandler interface {
	middleware.JsonWebTokenMiddleware
}

type RestHandler struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	jwtService     *Service
	userService    service.UserServicer
	// loginDriver routes /login through the unified login ceremony. There
	// is one ceremony in the platform and it lives in
	// pkg/webservice/v1/login; this handler contributes only the route.
	// When nil, /login fails closed with ErrLoginUnavailable rather than
	// minting an unverified local JWT.
	loginDriver *login.Driver
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

// SetLoginDriver wires the unified login driver so /login authenticates
// through the canonical ceremony and returns the session it issued. Wired
// by the handler registry at boot when the SDK AuthService is available.
func (handler *RestHandler) SetLoginDriver(driver *login.Driver) {
	handler.loginDriver = driver
}

// Creates a new web service session from the parsed JWT
func (handler *RestHandler) CreateSession(
	w http.ResponseWriter,
	r *http.Request) (service.Session, error) {

	handler.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	_, claims, err := handler.jwtService.ParseToken(r)
	if err != nil {
		handler.responseWriter.Error401(w, r, err)
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

	user, err := handler.sessionUser(r.Context(), claims)
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

// GenerateToken authenticates the caller through the unified login
// ceremony and returns the session it issued.
//
// The locked architecture makes qrdb's LoginClient the single canonical
// login backbone and quicbaas's OIDC TokenService the SessionIssuer; the
// platform is a consumer, not an issuer. /login is a single-shot POST over
// the webserver's mTLS-capable connection, so it drives the mtls factor,
// whose possession proof is the handshake itself — there is no challenge
// to issue and the driver completes the ceremony in this one request.
// WebAuthn and PIV use challenge round trips and are served by their own
// routes against the same driver.
//
// When no driver is wired the handler fails closed with
// ErrLoginUnavailable — it never fabricates an unverified local JWT.
func (handler *RestHandler) GenerateToken(w http.ResponseWriter, req *http.Request) {

	handler.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		req.URL.Path, req.Method, req.RemoteAddr, req.RequestURI)

	if handler.loginDriver == nil {
		handler.logger.Error(ErrLoginUnavailable, "unified login driver not configured")
		handler.responseWriter.Error403(w, req, ErrLoginUnavailable, nil)
		return
	}

	handler.loginDriver.Begin(w, req, quicbaas.FactorTypeMTLS)
}

// Exchange a JWT for a new token with a new expiration date
func (handler *RestHandler) RefreshToken(w http.ResponseWriter, r *http.Request) {

	handler.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	token, claims, err := handler.jwtService.ParseToken(r)
	if err != nil {
		handler.responseWriter.Error400(w, r, err)
		return
	}

	// Run the SAME verification a protected route runs, not just
	// token.Valid. Verify additionally enforces the audience, so checking
	// only the signature let a token this signer produced for a different
	// audience — one every protected route rejects — be exchanged here for
	// a fresh, correctly-audienced platform token. Refresh must not be a
	// laundering step for a token that cannot be used directly.
	if err := handler.jwtService.Verify(token); err != nil {
		handler.logger.Debugf("rest/jwt: refresh rejected: %v", err)
		handler.responseWriter.Error401(w, r, ErrInvalidToken)
		return
	}

	handler.logger.Debugf("rest/jwt: claims: %+v", claims)

	// Re-read the user and mint from THAT, not from the presented token's
	// claims. GenerateToken derives tenant_id, email and roles from the
	// user it is handed, so the two obvious shortcuts are both wrong:
	//
	//   - a bare {ID} stub (what this did) drops the caller's roles and
	//     falls back to tenant "default" — harmless while nothing enforced
	//     those claims, but now that the IAM routes are gated on the roles
	//     claim it would lock an admin out on their first refresh; and
	//   - copying the old token's claims forward lets someone whose admin
	//     role or tenant was revoked keep rolling the revoked privilege
	//     forward indefinitely, refreshing before each expiry.
	//
	// The store is the authority on current authorization, so a refresh
	// picks up a revocation and fails closed when the user is gone.
	user, err := handler.sessionUser(r.Context(), claims)
	if err != nil {
		handler.logger.Error(err, "rest/jwt: refresh could not resolve the user")
		handler.responseWriter.Error401(w, r, ErrInvalidToken)
		return
	}

	tokenString, err := handler.jwtService.GenerateToken(user)
	if err != nil {
		handler.responseWriter.Error500(w, r, err)
		return
	}

	handler.logger.Debugf("rest/jwt: refreshed token: %s", tokenString)

	handler.responseWriter.Success200(w, r, tokenString)
}

// Logout signs the caller's session out server-side (#215).
//
// Logout used to be a browser-only affair: the console deleted its cookie
// and the token stayed valid until it expired, so any copy of it kept
// working after the user signed out. Logout now revokes the presented
// token, so every route, /login/refresh and the RPC transports refuse it
// from then on, and also expires the session cookies for a client that
// cannot clear them itself.
//
// Signing out twice succeeds: the session is gone either way. A request
// that presents no verifiable token is 401 and revokes nothing.
func (handler *RestHandler) Logout(w http.ResponseWriter, r *http.Request) {

	handler.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	token, _, err := handler.jwtService.ParseToken(r)
	if err != nil {
		handler.responseWriter.Error401(w, r, err)
		return
	}
	if err := handler.jwtService.Revoke(token); err != nil && !errors.Is(err, ErrTokenRevoked) {
		handler.logger.Debugf("rest/jwt: logout rejected: %v", err)
		handler.responseWriter.Error401(w, r, ErrInvalidToken)
		return
	}

	for _, name := range []string{"jwt", "token"} {
		http.SetCookie(w, &http.Cookie{
			Name:     name,
			Value:    "",
			Path:     "/",
			MaxAge:   -1,
			Secure:   true,
			SameSite: http.SameSiteStrictMode,
		})
	}
	handler.responseWriter.Success200(w, r, nil)
}

// Validates the raw JWT token to ensure it's not expired or contains invalid claims. This
// is used by the negroni middleware to enforce authenticated access to procted resources.
//
// On success the verified claims are published into the request context as
// an iam.IAMSession, so the RBAC route guards downstream (iam.SessionGuard —
// RequireRoles / RequireTenant) decide against the same token this method
// just verified. Verification happens exactly once, here; the guards never
// re-parse a token.
func (handler *RestHandler) Verify(
	w http.ResponseWriter, r *http.Request, next http.HandlerFunc) {

	handler.logger.Debugf("url: %s, method: %s, remoteAddress: %s, requestUri: %s",
		r.URL.Path, r.Method, r.RemoteAddr, r.RequestURI)

	token, claims, err := handler.jwtService.ParseToken(r)
	if err != nil {
		// A request carrying no token, or one this signer did not
		// produce, is unauthenticated. It must be TOLD so: this used to
		// return silently on the assumption that ParseToken had already
		// written a response, which it never did, so every such request
		// got an empty 200 while the protected handler was correctly
		// skipped.
		handler.logger.Debugf("rest/jwt: verify rejected: %v", err)
		handler.responseWriter.Error401(w, r, err)
		return
	}

	if err := handler.jwtService.Verify(token); err != nil {
		// A signed-out session is unauthenticated, not a bad request:
		// the console answers a 401 by sending the user to sign in.
		if errors.Is(err, ErrTokenRevoked) {
			handler.responseWriter.Error401(w, r, err)
			return
		}
		handler.responseWriter.Error400(w, r, err)
		return
	}

	next(w, r.WithContext(iammw.SetSessionInContext(r.Context(), sessionFromClaims(claims))))
}

// sessionFromClaims projects verified platform-JWT claims onto the IAM
// session shape the route guards consume. The platform user store is
// separate from the QuicBaaS IAM user store, so there is no IAM user record
// to wrap — the token's own verified claims ARE the authority, exactly as
// they are for the broker platform-token path.
func sessionFromClaims(claims *TokenClaims) iammw.IAMSession {
	if claims == nil {
		return nil
	}
	return iammw.NewIAMSession(&iamsdk.User{
		ID:       claims.UserIDStr,
		TenantID: claims.TenantID,
		Email:    claims.Email,
		Roles:    claims.Roles,
	})
}

// sessionUser resolves the user a verified token names (#642). There are
// two token shapes and they name their principal differently:
//
//   - a platform-issued token carries the platform user id in "uid";
//   - a backbone-issued session (IssueSession, the unified login driver)
//     carries no "uid" — only the backbone's subject, which is the key
//     registration stores the user under and the same key the FIDO2
//     binder resolved the session's workspace with.
//
// Refusing the second shape (what this did) meant every account that
// signed in through the backbone was saved but never retrievable from its
// session: refresh and /session both failed. The store stays the authority
// either way, so a user who is gone fails closed, and a backbone subject
// that resolves to a user outside the session's tenant is refused rather
// than handed that user's record.
func (handler *RestHandler) sessionUser(ctx context.Context, claims *TokenClaims) (*entities.User, error) {
	if claims.UID != "" {
		userID, err := claims.PlatformUserID()
		if err != nil {
			return nil, err
		}
		return handler.userService.Get(ctx, userID)
	}
	if claims.Subject == "" {
		return nil, ErrInvalidUserClaim
	}
	user, err := handler.userService.GetByEmail(ctx, claims.Subject)
	if err != nil {
		return nil, err
	}
	if user == nil || user.TenantID == "" || user.TenantID != claims.TenantID {
		return nil, ErrInvalidUserClaim
	}
	return user, nil
}
