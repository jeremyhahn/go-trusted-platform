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

package daemon

import (
	"context"
	"strings"
	"time"

	"github.com/jeremyhahn/go-quicbaas/pkg/iam/dpop"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// PlatformTokenConfig configures the broker platform-token validator shared
// across the gRPC, QUIC, and MCP inbound transports. It is the daemon-layer
// projection of the platform's webservice JWT.PlatformToken block, mirroring
// the HTTP path so every transport validates the same QuicBaaS OIDC tokens
// (JWKS-by-kid + aud + exp + DPoP where applicable) and enforces scp -> RBAC +
// tenant_id -> RLS via the AuthorizedContext.
//
// When Enabled is false (the zero value) the daemon retains its legacy
// per-transport validators, so the cutover is purely additive.
type PlatformTokenConfig struct {
	// Enabled turns on broker platform-token validation for the gRPC, QUIC,
	// and MCP inbound paths.
	Enabled bool

	// Issuer is the single trusted broker token issuer (iss must equal this).
	Issuer string

	// JWKSURL is the broker JWKS endpoint fetched and cached by kid.
	JWKSURL string

	// Audience is this platform service's resource identifier. The token aud
	// must contain it. Defaults to "api://platform" when empty.
	Audience string

	// AllowBearer accepts a non-sender-constrained bearer token when no DPoP
	// proof is presented. When false, every claims-path request that does not
	// present a DPoP proof is rejected. QUIC always validates as bearer (no
	// DPoP frame) and is therefore subject to this gate.
	AllowBearer bool

	// CacheTTL bounds JWKS key caching. Defaults to one hour when zero.
	CacheTTL time.Duration
}

// DefaultPlatformAudience is the resource identifier the platform claims when no
// audience is configured.
const DefaultPlatformAudience = "api://platform"

// platformTokenValidator wraps a QuicBaaS platformtoken.Validator and adapts it
// to every transport's auth seam. It implements the optional claims interfaces
// the gRPC interceptor (grpccreds.ClaimsTokenValidator), the QUIC middleware
// (quic.ClaimsTokenValidator), and the MCP authorization checker
// (mcp.ClaimsAuthManager) type-assert for, and additionally satisfies the
// legacy mcp.AuthManager / mcp.AuthorizationService interfaces so it can be
// installed directly on those config fields.
//
// It is safe for concurrent use: the underlying validator and replay cache are
// concurrency-safe and the adapter holds no mutable per-request state.
type platformTokenValidator struct {
	validator   *platformtoken.Validator
	allowBearer bool
	replayCache dpop.ReplayCache
	logger      *logging.Logger
}

// newPlatformTokenValidator builds the shared validator from PlatformTokenConfig.
// It returns a typed error when a required field is missing so callers fail
// closed rather than installing an unsafe validator.
func newPlatformTokenValidator(cfg PlatformTokenConfig, logger *logging.Logger) (*platformTokenValidator, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, ErrPlatformTokenConfig{Field: "issuer", Reason: "broker token issuer is required"}
	}
	if strings.TrimSpace(cfg.JWKSURL) == "" {
		return nil, ErrPlatformTokenConfig{Field: "jwks-url", Reason: "broker JWKS URL is required"}
	}

	audience := strings.TrimSpace(cfg.Audience)
	if audience == "" {
		audience = DefaultPlatformAudience
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = time.Hour
	}

	validator, err := platformtoken.NewValidator(platformtoken.Options{
		Issuer:   cfg.Issuer,
		Audience: audience,
		JWKSURL:  cfg.JWKSURL,
		CacheTTL: cacheTTL,
	})
	if err != nil {
		return nil, err
	}

	return &platformTokenValidator{
		validator:   validator,
		allowBearer: cfg.AllowBearer,
		replayCache: dpop.NewMemoryReplayCache(dpop.SystemClock{}),
		logger:      logger,
	}, nil
}

// AuthorizeToken validates the bearer token (binding the DPoP proof when a
// non-empty proof is supplied) and projects the validated claims into an
// AuthorizedContext (scp -> RBAC, tenant_id -> RLS). It implements the claims
// interface every transport type-asserts for.
//
// When a DPoP proof is supplied the token must carry a cnf.jkt binding and the
// proof is verified against it (RFC 9449). When no proof is supplied the call
// succeeds only if AllowBearer is set, mirroring the HTTP path's policy.
func (v *platformTokenValidator) AuthorizeToken(ctx context.Context, token, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	var (
		claims *platformtoken.Claims
		err    error
	)
	if strings.TrimSpace(dpopProof) != "" {
		claims, err = v.validator.ValidateWithDPoP(ctx, token, dpopProof, htm, htu, v.replayCache)
	} else {
		if !v.allowBearer {
			return nil, ErrDPoPProofRequired{}
		}
		claims, err = v.validator.ValidatePlatformToken(ctx, token)
	}
	if err != nil {
		if v.logger != nil {
			v.logger.Debugf("platform-token: validation failed: %v", err)
		}
		return nil, err
	}
	return platformtoken.Authorize(claims), nil
}

// ValidateToken implements the legacy bool-only token-validator interface
// (grpccreds.TokenValidator / quic.TokenValidator / mcp.AuthManager) so the
// validator remains assignable where a claims-aware caller is not available.
// It validates as a bearer token; the claims path (AuthorizeToken) is preferred
// by every transport that supports it.
func (v *platformTokenValidator) ValidateToken(ctx context.Context, token string) (bool, error) {
	if _, err := v.validator.ValidatePlatformToken(ctx, token); err != nil {
		return false, err
	}
	return true, nil
}

// GetTokenClaims implements mcp.AuthManager. It returns the subject, tenant, and
// granted scopes/roles from a validated token as a generic claims map.
func (v *platformTokenValidator) GetTokenClaims(ctx context.Context, token string) (map[string]interface{}, error) {
	claims, err := v.validator.ValidatePlatformToken(ctx, token)
	if err != nil {
		return nil, err
	}
	authCtx := platformtoken.Authorize(claims)
	return map[string]interface{}{
		"sub":       authCtx.Subject,
		"tenant_id": authCtx.TenantID,
		"scp":       authCtx.Scopes,
		"roles":     authCtx.Roles,
	}, nil
}

// CheckPermission implements mcp.AuthorizationService for the legacy MCP seam.
// The subject argument is the bearer token (per the MCP authorization checker's
// convention). It validates the token and enforces the qrdb-canonical
// "resource:action" scope against the granted scope set.
func (v *platformTokenValidator) CheckPermission(ctx context.Context, subject, resource, action string) (bool, error) {
	claims, err := v.validator.ValidatePlatformToken(ctx, subject)
	if err != nil {
		return false, err
	}
	authCtx := platformtoken.Authorize(claims)
	if resource == "" || action == "" {
		return true, nil
	}
	if err := authCtx.RequireScope(resource + ":" + action); err != nil {
		return false, nil
	}
	return true, nil
}

// ErrPlatformTokenConfig indicates the shared platform-token validator was
// configured with a missing or invalid required field.
type ErrPlatformTokenConfig struct {
	Field  string
	Reason string
}

func (e ErrPlatformTokenConfig) Error() string {
	return "platform-token validator config invalid: " + e.Field + ": " + e.Reason
}

// ErrDPoPProofRequired indicates a claims-path request presented no DPoP proof
// while the validator is configured to reject non-sender-constrained bearers.
type ErrDPoPProofRequired struct{}

func (e ErrDPoPProofRequired) Error() string {
	return "DPoP proof required: bearer tokens are not accepted"
}
