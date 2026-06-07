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
	"crypto"
	"errors"
	"fmt"
	"log"
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
	Signer(attrs *xkmssdk.KeyAttributes) (crypto.Signer, error)
}

var (
	ErrAuthorizationHeaderRequired = errors.New("jwt/service: authorization header required")
	ErrInvalidToken                = errors.New("jwt/service: invalid token")
	ErrInvalidUserClaim            = errors.New("jwt/service: invalid user id claim")
	ErrInvalidEmailClaim           = errors.New("jwt/service: invalid email claim")
)

type TokenClaims struct {
	Organizations []uint64 `json:"orgs"`
	Services      []uint64 `json:"svcs"`
	UserID        uint64   `json:"uid"`
	// UserIDStr mirrors UserID as a decimal string under the standard
	// "user_id" claim so JS/TS consumers (and any other library that
	// expects a string identifier) can read it without dealing with
	// JSON-number precision loss on uint64.
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

func NewService(params ServiceParams) (*Service, error) {
	// Debug: log the password type to trace the issue
	var pwType string
	if params.KeyAttrs.Password != nil {
		pwType = fmt.Sprintf("%T", params.KeyAttrs.Password)
	} else {
		pwType = "nil"
	}
	log.Printf("jwt.NewService: KeyAttrs.CN=%s, Password type=%s, PlatformPolicy=%v",
		params.KeyAttrs.CN, pwType, params.KeyAttrs.PlatformPolicy)

	// Use go-xkms's SigningMethodSigner for crypto.Signer support
	signingMethod, err := xkmssdk.NewJWTSigningMethodSigner(params.KeyAttrs)
	if err != nil {
		return nil, err
	}
	signer, err := params.XKMS.Signer(params.KeyAttrs)
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
		UserID:        user.ID,
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

func (service *Service) ParseToken(
	w http.ResponseWriter, r *http.Request) (*jwt.Token, *TokenClaims, error) {

	tokenString := r.Header.Get("Authorization")
	if tokenString == "" {
		return nil, nil, ErrAuthorizationHeaderRequired
	}
	tokenString = tokenString[len("Bearer "):]

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
