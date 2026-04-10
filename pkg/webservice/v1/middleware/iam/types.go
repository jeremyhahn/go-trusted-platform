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

// Package iam provides IAM-aware authentication and authorization middleware
// that integrates with QuicBaaS's IAM services.
package iam

import (
	"context"
	"time"

	iampb "github.com/jeremyhahn/go-quicbaas/api/proto/iam"
)

// ContextKey is a typed key for context values to avoid collisions.
type ContextKey string

const (
	// SessionContextKey is the context key for storing IAM sessions.
	SessionContextKey ContextKey = "iam_session"

	// TenantIDHeader is the HTTP header for tenant identification.
	TenantIDHeader = "X-Tenant-ID"

	// AuthorizationHeader is the standard HTTP authorization header.
	AuthorizationHeader = "Authorization"

	// BearerPrefix is the prefix for Bearer token authentication.
	BearerPrefix = "Bearer "

	// PolicyContextHeader is the HTTP header for additional policy context.
	PolicyContextHeader = "X-Policy-Context"
)

// IAMSession represents an authenticated session with IAM user details.
type IAMSession interface {
	// User returns the underlying IAM user.
	User() *iampb.User

	// TenantID returns the tenant identifier.
	TenantID() string

	// UserID returns the user identifier.
	UserID() string

	// Email returns the user's email address.
	Email() string

	// Name returns the user's display name.
	Name() string

	// Roles returns the user's assigned roles.
	Roles() []string

	// Groups returns the user's group memberships.
	Groups() []string

	// HasRole checks if the user has a specific role.
	HasRole(role string) bool

	// HasGroup checks if the user is a member of a specific group.
	HasGroup(group string) bool

	// HasAnyRole checks if the user has any of the specified roles.
	HasAnyRole(roles ...string) bool

	// HasAllRoles checks if the user has all of the specified roles.
	HasAllRoles(roles ...string) bool

	// IsMFAVerified returns whether MFA has been verified for this session.
	IsMFAVerified() bool

	// MFATimestamp returns when MFA was last verified.
	MFATimestamp() time.Time

	// Attributes returns the user's custom attributes.
	Attributes() map[string]string

	// GetAttribute returns a specific attribute value.
	GetAttribute(key string) (string, bool)

	// ToSubject converts the session to a PEP Subject for authorization checks.
	ToSubject() *iampb.Subject

	// IsAttestationVerified returns whether TPM attestation was verified.
	IsAttestationVerified() bool

	// AttestationTime returns when attestation was verified.
	AttestationTime() time.Time

	// DeviceID returns the device identifier from the IDevID certificate.
	DeviceID() string
}

// IAMServiceClient defines the interface for IAM service operations.
type IAMServiceClient interface {
	// GetUser retrieves a user by tenant and user ID.
	GetUser(ctx context.Context, req *iampb.GetUserRequest) (*iampb.User, error)

	// ListUsers lists users with optional filters.
	ListUsers(ctx context.Context, req *iampb.ListUsersRequest) (*iampb.ListUsersResponse, error)
}

// PEPServiceClient defines the interface for Policy Enforcement Point operations.
type PEPServiceClient interface {
	// Check performs an authorization check.
	Check(ctx context.Context, req *iampb.CheckRequest) (*iampb.CheckResponse, error)

	// CheckBatch performs batch authorization checks.
	CheckBatch(ctx context.Context, req *iampb.CheckBatchRequest) (*iampb.CheckBatchResponse, error)
}

// MFAServiceClient defines the interface for MFA service operations.
type MFAServiceClient interface {
	// GetStatus retrieves the MFA status for a user.
	GetStatus(ctx context.Context, req *iampb.GetMFAStatusRequest) (*iampb.GetMFAStatusResponse, error)

	// VerifyCode verifies an MFA code.
	VerifyCode(ctx context.Context, req *iampb.VerifyMFACodeRequest) (*iampb.VerifyMFACodeResponse, error)
}

// SessionServiceClient defines the interface for session service operations.
type SessionServiceClient interface {
	// GetSession retrieves a session by ID.
	GetSession(ctx context.Context, req *iampb.GetSessionRequest) (*iampb.Session, error)

	// RevokeSession revokes a session.
	RevokeSession(ctx context.Context, req *iampb.RevokeSessionRequest) (*iampb.RevokeSessionResponse, error)
}

// JWTClaims represents the claims extracted from a JWT token.
type JWTClaims struct {
	// Subject is the user identifier (sub claim).
	Subject string

	// TenantID is the tenant identifier.
	TenantID string

	// Email is the user's email address.
	Email string

	// Name is the user's display name.
	Name string

	// Roles are the user's assigned roles.
	Roles []string

	// Groups are the user's group memberships.
	Groups []string

	// Audience is the intended audience (aud claim).
	Audience []string

	// Issuer is the token issuer (iss claim).
	Issuer string

	// IssuedAt is when the token was issued (iat claim).
	IssuedAt time.Time

	// ExpiresAt is when the token expires (exp claim).
	ExpiresAt time.Time

	// NotBefore is when the token becomes valid (nbf claim).
	NotBefore time.Time

	// MFAVerified indicates if MFA was verified during authentication.
	MFAVerified bool

	// MFATimestamp is when MFA was verified.
	MFATimestamp time.Time

	// SessionID is the associated session identifier.
	SessionID string

	// Custom holds any additional custom claims.
	Custom map[string]any
}

// AuthConfig holds configuration for the authentication middleware.
type AuthConfig struct {
	// RequireTLS requires TLS connections when true.
	RequireTLS bool

	// RequireMTLS requires mutual TLS (client certificates) when true.
	RequireMTLS bool

	// RequireJWT requires JWT token authentication when true.
	RequireJWT bool

	// ExtractTenantFromCert extracts tenant ID from certificate when true.
	ExtractTenantFromCert bool

	// TenantCertField specifies which certificate field contains the tenant ID.
	// Valid values: "cn", "ou", "o", "san_email", "san_dns"
	TenantCertField string

	// DefaultTenantID is used when no tenant can be extracted.
	DefaultTenantID string

	// TPM Attestation Settings
	// RequireTPMAttestation requires valid TPM attestation for authentication.
	RequireTPMAttestation bool

	// ValidateIDevID validates IDevID certificates per TCG specifications.
	ValidateIDevID bool

	// ValidateIAK validates IAK certificates per TCG specifications.
	ValidateIAK bool
}

// JWTConfig holds configuration for JWT token validation.
type JWTConfig struct {
	// SigningKey is the key used to validate JWT signatures (for symmetric algorithms).
	SigningKey []byte

	// PublicKey is the public key for asymmetric JWT validation.
	PublicKey any

	// Issuer is the expected token issuer.
	Issuer string

	// Audience is the expected token audience.
	Audience []string

	// ClockSkew allows for clock drift between servers.
	ClockSkew time.Duration

	// RequireMFA requires MFA verification claim in tokens.
	RequireMFA bool

	// RefreshTokenTTL is the lifetime for refresh tokens.
	RefreshTokenTTL time.Duration

	// AccessTokenTTL is the lifetime for access tokens.
	AccessTokenTTL time.Duration
}

// AuthzConfig holds configuration for the authorization middleware.
type AuthzConfig struct {
	// DefaultDeny denies access when no policy matches (default true).
	DefaultDeny bool

	// CacheDecisions enables caching of authorization decisions.
	CacheDecisions bool

	// CacheTTL is how long to cache authorization decisions.
	CacheTTL time.Duration

	// RequireMFA requires MFA verification for authorization.
	RequireMFA bool

	// MFAGracePeriod is how long after MFA verification before re-verification is required.
	MFAGracePeriod time.Duration
}

// HTTPMethodToAction maps HTTP methods to authorization actions.
var HTTPMethodToAction = map[string]string{
	"GET":     "read",
	"HEAD":    "read",
	"OPTIONS": "read",
	"POST":    "create",
	"PUT":     "update",
	"PATCH":   "update",
	"DELETE":  "delete",
}

// GetSessionFromContext retrieves the IAM session from the request context.
func GetSessionFromContext(ctx context.Context) (IAMSession, bool) {
	session, ok := ctx.Value(SessionContextKey).(IAMSession)
	return session, ok
}

// SetSessionInContext stores the IAM session in the request context.
func SetSessionInContext(ctx context.Context, session IAMSession) context.Context {
	return context.WithValue(ctx, SessionContextKey, session)
}
