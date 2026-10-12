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
	"crypto"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// XKMSSigner provides access to crypto.Signer instances for key attributes.
// This interface is satisfied by both xkms.Backend and platform.XKMS.
type XKMSSigner interface {
	Signer(ctx context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, error)
}

var (
	ErrAuthorizationHeaderRequired = errors.New("jwt/service: authorization header required")
	ErrInvalidToken                = errors.New("jwt/service: invalid token")
	ErrInvalidUserClaim            = errors.New("jwt/service: invalid user id claim")
	ErrInvalidEmailClaim           = errors.New("jwt/service: invalid email claim")
)

type TokenClaims struct {
	Services []uint64 `json:"svcs"`
	// UID is the PLATFORM user-store key as a decimal string. User ids are
	// xxhash64 values, almost all above 2^53, so a JSON number would reach
	// every schemaless decoder (MapClaims, the console's JSON.parse) as a
	// float64 naming a different user (#642). It is empty in a
	// backbone-issued session (see IssueSession); read it with
	// PlatformUserID.
	UID string `json:"uid,omitempty"`
	// UserIDStr is the session principal under the standard "user_id"
	// claim: the platform user id in a platform-issued token, the
	// backbone's subject in a backbone-issued session.
	UserIDStr string `json:"user_id"`
	// Email is exposed under the standard "email" claim so the frontend
	// AuthContext can populate the user object after a successful login.
	Email string `json:"email,omitempty"`
	// TenantID surfaces the active tenant in the standard "tenant_id"
	// claim consumed by the frontend.
	TenantID string `json:"tenant_id,omitempty"`
	// IsTenantOwner mirrors the tenant ownership flag the frontend uses
	// to gate admin-only UI.
	IsTenantOwner bool `json:"is_tenant_owner,omitempty"`
	// Roles is the list of role names the frontend uses for UI
	// authorisation; the omitempty keeps tokens compact when no roles
	// have been assigned yet.
	Roles []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// PlatformUserID returns the platform user-store key carried in the "uid"
// claim. A token without one (a backbone-issued session) or with anything
// but a decimal uint64 returns ErrInvalidUserClaim, so a route that
// re-reads the platform user fails closed instead of resolving user 0.
func (claims *TokenClaims) PlatformUserID() (uint64, error) {
	if claims.UID == "" {
		return 0, ErrInvalidUserClaim
	}
	id, err := strconv.ParseUint(claims.UID, 10, 64)
	if err != nil {
		return 0, ErrInvalidUserClaim
	}
	return id, nil
}

type ServiceParams struct {
	Audience   string
	Expiration int
	Issuer     string
	KeyAttrs   *xkmssdk.KeyAttributes
	XKMS       XKMSSigner
}

type Service struct {
	params        ServiceParams
	signer        crypto.Signer
	signingMethod jwt.SigningMethod
}

func NewService(ctx context.Context, params ServiceParams) (*Service, error) {
	// Use go-xkms's SigningMethodSigner for crypto.Signer support
	signingMethod, err := xkmssdk.NewJWTSigningMethodSigner(params.KeyAttrs)
	if err != nil {
		return nil, err
	}
	signer, err := params.XKMS.Signer(ctx, params.KeyAttrs)
	if err != nil {
		return nil, err
	}
	return &Service{
		params:        params,
		signer:        signer,
		signingMethod: signingMethod,
	}, nil
}

func (service *Service) GenerateToken(user *entities.User) (string, error) {
	now := time.Now()
	// Surface the user's tenant in the standard "tenant_id" claim so the
	// WebUI's AuthContext can pick up the active tenant and unlock IAM
	// pages (the dashboard's IAM screens fail with "No tenant ID
	// available" otherwise). Default to "default" when the user record
	// lacks a tenant assignment so single-tenant deployments still
	// function.
	tenantID := user.TenantID
	if tenantID == "" {
		tenantID = "default"
	}
	// Surface the user's role names in the "roles" claim so the WebUI's
	// per-route authorization gates can decide what to show without an
	// extra /me round-trip. The platform-service flow grants "admin" to
	// the first user in a fresh tenant, so a newly-registered user's
	// JWT carries that role from the first request.
	roles := make([]string, 0, len(user.Roles))
	for _, r := range user.Roles {
		if r != nil && r.Name != "" {
			roles = append(roles, r.Name)
		}
	}
	token := jwt.NewWithClaims(service.signingMethod, TokenClaims{
		UID:           strconv.FormatUint(user.ID, 10),
		UserIDStr:     strconv.FormatUint(user.ID, 10),
		Email:         user.Email,
		TenantID:      tenantID,
		IsTenantOwner: user.IsTenantOwner,
		Roles:         roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:  strconv.FormatUint(user.ID, 10),
			Audience: jwt.ClaimStrings{service.params.Audience},
			Issuer:   service.params.Issuer,
			IssuedAt: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(
				now.Add(time.Minute * time.Duration(service.params.Expiration))),
			NotBefore: jwt.NewNumericDate(now),
		},
	})
	return token.SignedString(service.signer)
}

// ParseToken extracts and verifies the platform JWT a request carries.
//
// Two carriers are accepted, because the platform has two first-class
// clients and they credential differently:
//
//   - `Authorization: Bearer <jwt>` — platformctl, scripts, service callers.
//   - the `jwt` (or `token`) cookie — the console, whose SDK client is
//     configured with `credentials: "include"` and sends no Authorization
//     header. The cookie is set `Secure` + `SameSite=Strict`, which is what
//     keeps a cross-site request from riding it.
//
// The cookie is NOT a new credential channel: the IAM REST handlers
// already read it to resolve the tenant, but did so with an *unverified*
// base64 decode of the payload. Verifying it here means the same cookie is
// now checked cryptographically before any handler or route guard runs.
//
// ParseToken reports failures to its CALLER and writes nothing itself. It
// used to take an http.ResponseWriter it never touched, and Verify trusted
// that to mean the error response had already been sent — so an
// unparseable token produced an empty 200 instead of a 401. The parameter
// is gone so no caller can make that assumption again.
func (service *Service) ParseToken(
	r *http.Request) (*jwt.Token, *TokenClaims, error) {

	tokenString := requestToken(r)
	if tokenString == "" {
		return nil, nil, ErrAuthorizationHeaderRequired
	}

	token, err := service.ParseTokenString(tokenString)
	if err != nil {
		return nil, nil, err
	}

	claims, ok := token.Claims.(*TokenClaims)
	if !ok {
		return nil, nil, ErrInvalidToken
	}

	return token, claims, nil
}

// requestToken returns the raw JWT a request carries, or "" when it
// carries none. The Authorization header wins over a cookie so an explicit
// credential is never shadowed by an ambient one.
//
// The "Bearer " scheme is REQUIRED, not optional. Accepting a bare token
// let this function and the resource handlers disagree about which
// credential a request presented: they recognise only Bearer, so a caller
// could authenticate with a valid raw-header token for their own tenant
// while the handlers, seeing no Bearer, fell through to a cookie naming
// somebody else's. One credential, recognised the same way everywhere.
func requestToken(r *http.Request) string {
	const scheme = "Bearer "
	if header := r.Header.Get("Authorization"); strings.HasPrefix(header, scheme) {
		// TrimPrefix, not a slice: an Authorization header shorter than
		// the scheme used to panic here.
		if token := strings.TrimSpace(strings.TrimPrefix(header, scheme)); token != "" {
			return token
		}
	}
	for _, name := range []string{"jwt", "token"} {
		if cookie, err := r.Cookie(name); err == nil && cookie.Value != "" {
			return cookie.Value
		}
	}
	return ""
}

func (service *Service) ParseTokenString(tokenString string) (*jwt.Token, error) {
	parser := jwt.NewParser()
	claims := &TokenClaims{}
	token, err := parser.ParseWithClaims(tokenString, claims, service.KeyFunc)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (service *Service) KeyFunc(token *jwt.Token) (interface{}, error) {
	return service.signer.Public(), nil
}

func (service *Service) PublicKey() crypto.PublicKey {
	return service.signer.Public()
}

func (service *Service) Verify(token *jwt.Token) error {
	if !token.Valid {
		return ErrInvalidToken
	}
	opts := jwt.WithAudience(service.params.Audience)
	return jwt.NewValidator(opts).Validate(token.Claims)
}

// VerifyToken parses and validates a token string. Returns true when the
// token is valid (signature checks out and claims pass validation),
// false otherwise. Satisfies the daemon's PlatformJWTVerifier interface
// so gRPC/QUIC/MCP transports can accept platform-issued JWTs.
func (service *Service) VerifyToken(tokenString string) (bool, error) {
	if service == nil {
		return false, ErrInvalidToken
	}
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	tokenString = strings.TrimSpace(tokenString)
	if tokenString == "" {
		return false, ErrInvalidToken
	}
	token, err := service.ParseTokenString(tokenString)
	if err != nil {
		return false, err
	}
	if err := service.Verify(token); err != nil {
		return false, err
	}
	return true, nil
}
