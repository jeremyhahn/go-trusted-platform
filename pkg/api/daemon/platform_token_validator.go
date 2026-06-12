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
	"net/http"
	"strings"
	"time"

	"github.com/jeremyhahn/go-quicbaas/pkg/iam/dpop"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
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

	// AuthzMode selects the per-request liveness strategy: "offline" (no
	// liveness call), "online" (uncached RFC 7662 introspection on every
	// request), or "hybrid" (cached positive result with short TTL). Defaults
	// to "hybrid" when empty, which also requires IntrospectionURL.
	AuthzMode string

	// IntrospectionURL is the RFC 7662 token introspection endpoint. Required
	// when AuthzMode is "online" or "hybrid" (or empty, which defaults to
	// "hybrid").
	IntrospectionURL string

	// IntrospectionBearerToken, when non-empty, is sent as a Bearer
	// Authorization header on each introspection POST.
	IntrospectionBearerToken string

	// IntrospectionClientID and IntrospectionClientSecret enable HTTP Basic
	// authentication on the introspection endpoint. They are ignored when
	// IntrospectionBearerToken is set.
	IntrospectionClientID     string
	IntrospectionClientSecret string

	// LivenessCacheTTL bounds how long a positive introspection result is
	// cached on the hybrid path. Zero disables caching (every hybrid request
	// live-checks). Only used when AuthzMode is "hybrid".
	LivenessCacheTTL time.Duration
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

// Compile-time checks: the transports bind the shared validator via runtime
// type assertions, so a signature drift would otherwise degrade silently to
// the bool-only ValidateToken path. These assertions turn that into a build
// failure.
var (
	_ grpccreds.ClaimsTokenValidator = (*platformTokenValidator)(nil)
	_ quic.ClaimsTokenValidator      = (*platformTokenValidator)(nil)
	_ mcp.ClaimsAuthManager          = (*platformTokenValidator)(nil)
)

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

	mode := strings.TrimSpace(cfg.AuthzMode)
	if mode == "" {
		mode = string(platformtoken.AuthzModeHybrid)
	}
	switch platformtoken.AuthzMode(mode) {
	case platformtoken.AuthzModeOffline:
		// no introspection URL required
	case platformtoken.AuthzModeOnline, platformtoken.AuthzModeHybrid:
		if strings.TrimSpace(cfg.IntrospectionURL) == "" {
			return nil, ErrPlatformTokenConfig{Field: "introspection-url", Reason: "introspection URL is required for online and hybrid authz modes"}
		}
	default:
		return nil, ErrInvalidAuthzMode{Value: mode}
	}

	audience := strings.TrimSpace(cfg.Audience)
	if audience == "" {
		audience = DefaultPlatformAudience
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = time.Hour
	}

	opts := platformtoken.Options{
		Issuer:           cfg.Issuer,
		Audience:         audience,
		JWKSURL:          cfg.JWKSURL,
		CacheTTL:         cacheTTL,
		LivenessCacheTTL: cfg.LivenessCacheTTL,
	}

	// Build the liveness checker and mode resolver for non-offline modes.
	if platformtoken.AuthzMode(mode) != platformtoken.AuthzModeOffline {
		checker := buildIntrospectionChecker(cfg)
		var liveness platformtoken.LivenessChecker = checker
		if cfg.LivenessCacheTTL > 0 {
			liveness = platformtoken.NewCachedLivenessChecker(checker, cfg.LivenessCacheTTL, nil)
		}
		opts.LivenessChecker = liveness
		finalMode := platformtoken.AuthzMode(mode)
		opts.ModeResolver = func(_ string) platformtoken.AuthzMode { return finalMode }
	} else {
		opts.ModeResolver = func(_ string) platformtoken.AuthzMode { return platformtoken.AuthzModeOffline }
	}

	validator, err := platformtoken.NewValidator(opts)
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

// buildIntrospectionChecker constructs an RFC 7662 introspection liveness
// checker from the supplied config credentials.
func buildIntrospectionChecker(cfg PlatformTokenConfig) *platformtoken.IntrospectionLivenessChecker {
	checker := platformtoken.NewIntrospectionLivenessChecker(cfg.IntrospectionURL, (*http.Client)(nil))
	if cfg.IntrospectionBearerToken != "" {
		checker = checker.WithBearer(cfg.IntrospectionBearerToken)
	} else if cfg.IntrospectionClientID != "" || cfg.IntrospectionClientSecret != "" {
		checker = checker.WithBasicAuth(cfg.IntrospectionClientID, cfg.IntrospectionClientSecret)
	}
	return checker
}

// AuthorizeToken validates the bearer token, enforces the required permission
// scope when non-empty, and optionally binds a DPoP proof. It projects the
// validated claims into an AuthorizedContext (scp -> RBAC, tenant_id -> RLS).
//
// requiredPerm is the qrdb-canonical "resource:action" scope the operation
// requires; an empty string skips the scope check and only runs signature
// validation (and liveness, per the configured authz mode).
//
// When a DPoP proof is supplied the token must carry a cnf.jkt binding and the
// proof is verified against it (RFC 9449). When no proof is supplied the call
// succeeds only if AllowBearer is set, mirroring the HTTP path's policy.
func (v *platformTokenValidator) AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	if strings.TrimSpace(dpopProof) == "" && !v.allowBearer {
		return nil, ErrDPoPProofRequired{}
	}
	// When no required scope is specified, use Validate (no scope check) to
	// avoid RequireScope("") always denying.
	if strings.TrimSpace(requiredPerm) == "" {
		return v.validator.Validate(ctx, token, dpopProof, htm, htu)
	}
	return v.validator.Authorize(ctx, token, requiredPerm, dpopProof, htm, htu)
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

// ErrInvalidAuthzMode indicates an unrecognized authorization mode string.
type ErrInvalidAuthzMode struct {
	Value string
}

func (e ErrInvalidAuthzMode) Error() string {
	return "platform-token validator: invalid authz-mode " + e.Value + ": must be offline, online, or hybrid"
}

// ErrDPoPProofRequired indicates a claims-path request presented no DPoP proof
// while the validator is configured to reject non-sender-constrained bearers.
type ErrDPoPProofRequired struct{}

func (e ErrDPoPProofRequired) Error() string {
	return "DPoP proof required: bearer tokens are not accepted"
}
