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

	// IntrospectionURL is the broker RFC 7662 token-introspection endpoint the
	// validator uses for online liveness. Required when AuthzMode is online or
	// hybrid; unused for offline.
	IntrospectionURL string

	// IntrospectionClientID / IntrospectionClientSecret are the RFC 7662 HTTP
	// Basic credentials presented on the introspection request when set.
	IntrospectionClientID     string
	IntrospectionClientSecret string

	// IntrospectionBearerToken, when set, is presented as a Bearer credential
	// on the introspection request instead of Basic auth.
	IntrospectionBearerToken string

	// AuthzMode selects the deployment-wide authorization mode (offline,
	// online, or hybrid). Empty resolves to hybrid.
	AuthzMode string

	// LivenessCacheTTL bounds how long a positive hybrid-mode liveness result
	// is cached before the next request live-checks. Zero defaults to 15s for
	// hybrid; ignored in online mode.
	LivenessCacheTTL time.Duration
}

// DefaultPlatformAudience is the resource identifier the platform claims when no
// audience is configured.
const DefaultPlatformAudience = "api://platform"

// DefaultLivenessCacheTTL bounds how long a positive hybrid-mode liveness
// result is cached before the next request live-checks. It is the deployment
// default used when LivenessCacheTTL is unset (zero) in hybrid mode.
const DefaultLivenessCacheTTL = 15 * time.Second

// ErrInvalidAuthzMode is returned when the configured authz_mode string does not
// name one of the supported authorization modes.
type ErrInvalidAuthzMode struct {
	// Value is the offending authz_mode string.
	Value string
}

func (e ErrInvalidAuthzMode) Error() string {
	return "platform-token validator config invalid: authz-mode: must be one of offline, online, hybrid; got " + e.Value
}

// parseAuthzMode validates an authz_mode string and maps it to the SDK
// platformtoken.AuthzMode. An empty string resolves to the stack default
// (hybrid). Any unrecognized value returns an ErrInvalidAuthzMode.
func parseAuthzMode(s string) (platformtoken.AuthzMode, error) {
	switch s {
	case "":
		return platformtoken.AuthzModeHybrid, nil
	case string(platformtoken.AuthzModeOffline):
		return platformtoken.AuthzModeOffline, nil
	case string(platformtoken.AuthzModeOnline):
		return platformtoken.AuthzModeOnline, nil
	case string(platformtoken.AuthzModeHybrid):
		return platformtoken.AuthzModeHybrid, nil
	default:
		return "", ErrInvalidAuthzMode{Value: s}
	}
}

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
// It returns a typed error when a required field is missing or the authz-mode /
// liveness configuration is inconsistent, so callers fail closed rather than
// installing an unsafe validator.
//
// AuthzMode governs online liveness: "offline" trusts the signed scopes and
// expiry only; "online" enforces an uncached RFC 7662 introspection check on
// every request; "hybrid" (the default) caches positive introspection results
// for LivenessCacheTTL. When the effective mode requires liveness (online or
// hybrid) and no IntrospectionURL is configured, construction fails rather than
// silently downgrading to offline.
func newPlatformTokenValidator(cfg PlatformTokenConfig, logger *logging.Logger) (*platformTokenValidator, error) {
	if strings.TrimSpace(cfg.Issuer) == "" {
		return nil, ErrPlatformTokenConfig{Field: "issuer", Reason: "broker token issuer is required"}
	}
	if strings.TrimSpace(cfg.JWKSURL) == "" {
		return nil, ErrPlatformTokenConfig{Field: "jwks-url", Reason: "broker JWKS URL is required"}
	}

	mode, err := parseAuthzMode(strings.TrimSpace(cfg.AuthzMode))
	if err != nil {
		return nil, err
	}

	audience := strings.TrimSpace(cfg.Audience)
	if audience == "" {
		audience = DefaultPlatformAudience
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = time.Hour
	}

	introspectionURL := strings.TrimSpace(cfg.IntrospectionURL)

	// Build the online liveness checker for the modes that require it. A missing
	// introspection endpoint in a liveness-requiring mode is a fail-closed
	// misconfiguration, NOT a silent downgrade to offline.
	var (
		livenessChecker  platformtoken.LivenessChecker
		livenessCacheTTL time.Duration
	)
	switch mode {
	case platformtoken.AuthzModeOffline:
		// No liveness backend; revocation is bounded by token lifetime.
	case platformtoken.AuthzModeOnline:
		if introspectionURL == "" {
			return nil, ErrPlatformTokenConfig{
				Field:  "introspection-url",
				Reason: "introspection URL is required for online authz-mode",
			}
		}
		livenessChecker = newIntrospectionChecker(cfg, introspectionURL)
		// Online mode disables caching: every request live-checks.
		livenessCacheTTL = 0
	case platformtoken.AuthzModeHybrid:
		if introspectionURL == "" {
			return nil, ErrPlatformTokenConfig{
				Field:  "introspection-url",
				Reason: "introspection URL is required for hybrid authz-mode",
			}
		}
		livenessChecker = newIntrospectionChecker(cfg, introspectionURL)
		livenessCacheTTL = cfg.LivenessCacheTTL
		if livenessCacheTTL <= 0 {
			livenessCacheTTL = DefaultLivenessCacheTTL
		}
	}

	// A single deployment-wide mode resolver: every tenant resolves to the
	// configured mode. Per-tenant overrides can be layered on later by replacing
	// this constant resolver.
	modeResolver := func(string) platformtoken.AuthzMode { return mode }

	validator, err := platformtoken.NewValidator(platformtoken.Options{
		Issuer:           cfg.Issuer,
		Audience:         audience,
		JWKSURL:          cfg.JWKSURL,
		CacheTTL:         cacheTTL,
		LivenessChecker:  livenessChecker,
		ModeResolver:     modeResolver,
		LivenessCacheTTL: livenessCacheTTL,
		ReplayCache:      dpop.NewMemoryReplayCache(dpop.SystemClock{}),
	})
	if err != nil {
		return nil, err
	}

	return &platformTokenValidator{
		validator:   validator,
		allowBearer: cfg.AllowBearer,
		logger:      logger,
	}, nil
}

// newIntrospectionChecker builds the RFC 7662 introspection liveness checker
// from the config, applying Bearer credentials when a bearer token is set and
// HTTP Basic credentials when a client id/secret is set.
func newIntrospectionChecker(cfg PlatformTokenConfig, endpoint string) platformtoken.LivenessChecker {
	checker := platformtoken.NewIntrospectionLivenessChecker(endpoint, nil)
	if bearer := strings.TrimSpace(cfg.IntrospectionBearerToken); bearer != "" {
		return checker.WithBearer(bearer)
	}
	if strings.TrimSpace(cfg.IntrospectionClientID) != "" || strings.TrimSpace(cfg.IntrospectionClientSecret) != "" {
		return checker.WithBasicAuth(cfg.IntrospectionClientID, cfg.IntrospectionClientSecret)
	}
	return checker
}

// AuthorizeToken runs the canonical SDK validator pipeline for one request and
// returns the projected AuthorizedContext (scp -> RBAC, tenant_id -> RLS). It
// implements the claims interface every transport type-asserts for.
//
// When requiredPerm is non-empty it delegates to Validator.Authorize, which
// verifies the token (and its DPoP proof when the token is sender-constrained),
// enforces the required colon "resource:action" scope OFFLINE, and then applies
// the per-tenant authz mode's online liveness/revocation check (offline = none,
// online = uncached, hybrid = cached). When requiredPerm is empty it delegates
// to Validator.Validate, which runs the same pipeline WITHOUT the scope check —
// used for genuinely scope-free authenticated operations so liveness is still
// enforced on every request path.
//
// The bearer gate is preserved from the HTTP path: when no DPoP proof is
// supplied and AllowBearer is false, the request is rejected before any token
// work. A sender-constrained token without its proof is rejected by the SDK
// validator regardless of this gate.
func (v *platformTokenValidator) AuthorizeToken(ctx context.Context, token, requiredPerm, dpopProof, htm, htu string) (*platformtoken.AuthorizedContext, error) {
	if strings.TrimSpace(dpopProof) == "" && !v.allowBearer {
		return nil, ErrDPoPProofRequired{}
	}

	var (
		authCtx *platformtoken.AuthorizedContext
		err     error
	)
	if strings.TrimSpace(requiredPerm) != "" {
		authCtx, err = v.validator.Authorize(ctx, token, requiredPerm, dpopProof, htm, htu)
	} else {
		authCtx, err = v.validator.Validate(ctx, token, dpopProof, htm, htu)
	}
	if err != nil {
		if v.logger != nil {
			v.logger.Debugf("platform-token: authorization failed: %v", err)
		}
		return nil, err
	}
	return authCtx, nil
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
