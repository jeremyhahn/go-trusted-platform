// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package proxysvc

import (
	"context"
	"errors"
	"strings"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// DefaultTokenAudience is the resource identifier the proxy claims when the
// token-auth section sets no audience: inbound platform tokens must carry it
// in aud.
const DefaultTokenAudience = "api://platform-proxy"

// DefaultTokenLivenessCacheTTL bounds how long a positive hybrid-mode
// liveness result is cached, matching the platformd validator default.
const DefaultTokenLivenessCacheTTL = 15 * time.Second

// Authorization modes accepted by TokenAuthConfig.AuthzMode, mirroring the
// platformd platform-token validator: offline trusts the signed scopes and
// expiry, online introspects every request, hybrid (the default) caches
// positive introspection results briefly.
const (
	AuthzModeOffline = string(platformtoken.AuthzModeOffline)
	AuthzModeOnline  = string(platformtoken.AuthzModeOnline)
	AuthzModeHybrid  = string(platformtoken.AuthzModeHybrid)
)

// TokenAuthConfig is the proxy `token-auth:` section enabling the
// platform-token (DPoP) authentication path for token and mtls-or-token
// routes. Issuer and JWKSURL identify the QuicBaaS identity broker that
// issues the platform access tokens; both are deployment-specific and
// therefore required — there is no discoverable default.
type TokenAuthConfig struct {
	// Enabled activates the token path.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Issuer is the single trusted broker token issuer (iss must equal it).
	Issuer string `yaml:"issuer" json:"issuer" mapstructure:"issuer"`

	// JWKSURL is the broker JWKS endpoint, fetched and cached by kid.
	JWKSURL string `yaml:"jwks-url" json:"jwks_url" mapstructure:"jwks-url"`

	// Audience is this proxy's resource identifier; the token aud must
	// contain it. Empty defaults to DefaultTokenAudience.
	Audience string `yaml:"audience,omitempty" json:"audience,omitempty" mapstructure:"audience"`

	// CacheTTL bounds JWKS key caching. Zero defaults to one hour.
	CacheTTL time.Duration `yaml:"cache-ttl,omitempty" json:"cache_ttl,omitempty" mapstructure:"cache-ttl"`

	// AuthzMode is offline, online, or hybrid. Empty resolves to hybrid.
	AuthzMode string `yaml:"authz-mode,omitempty" json:"authz_mode,omitempty" mapstructure:"authz-mode"`

	// IntrospectionURL is the broker RFC 7662 introspection endpoint used
	// for online liveness. Required for the online and hybrid modes; a
	// liveness-requiring mode without it is a fail-closed configuration
	// error, never a silent downgrade to offline.
	IntrospectionURL string `yaml:"introspection-url,omitempty" json:"introspection_url,omitempty" mapstructure:"introspection-url"`

	// IntrospectionClientID / IntrospectionClientSecret are the RFC 7662
	// HTTP Basic credentials presented on introspection requests when set.
	IntrospectionClientID     string `yaml:"introspection-client-id,omitempty" json:"introspection_client_id,omitempty" mapstructure:"introspection-client-id"`
	IntrospectionClientSecret string `yaml:"introspection-client-secret,omitempty" json:"introspection_client_secret,omitempty" mapstructure:"introspection-client-secret"`

	// IntrospectionBearerToken, when set, is presented as a Bearer
	// credential on introspection requests instead of Basic auth.
	IntrospectionBearerToken string `yaml:"introspection-bearer-token,omitempty" json:"introspection_bearer_token,omitempty" mapstructure:"introspection-bearer-token"`

	// AllowBearer accepts a token presented without a DPoP proof. When
	// false (the default) every token-path request must present a DPoP
	// header; a sender-constrained token without a valid proof is rejected
	// by the SDK validator regardless of this gate.
	AllowBearer bool `yaml:"allow-bearer,omitempty" json:"allow_bearer,omitempty" mapstructure:"allow-bearer"`

	// LivenessCacheTTL bounds positive hybrid-mode liveness caching. Zero
	// defaults to DefaultTokenLivenessCacheTTL.
	LivenessCacheTTL time.Duration `yaml:"liveness-cache-ttl,omitempty" json:"liveness_cache_ttl,omitempty" mapstructure:"liveness-cache-ttl"`
}

// Validate checks the token-auth section. Disabled sections are not
// validated.
func (c *TokenAuthConfig) Validate() error {
	if !c.Enabled {
		return nil
	}
	if strings.TrimSpace(c.Issuer) == "" {
		return &ErrTokenAuthConfig{Field: "issuer", Reason: "broker token issuer is required"}
	}
	if strings.TrimSpace(c.JWKSURL) == "" {
		return &ErrTokenAuthConfig{Field: "jwks-url", Reason: "broker JWKS URL is required"}
	}
	mode, err := c.mode()
	if err != nil {
		return err
	}
	if mode != platformtoken.AuthzModeOffline && strings.TrimSpace(c.IntrospectionURL) == "" {
		return &ErrTokenAuthConfig{
			Field:  "introspection-url",
			Reason: "required for the " + string(mode) + " authz-mode",
		}
	}
	return nil
}

// mode resolves the configured authz mode, defaulting to hybrid.
func (c *TokenAuthConfig) mode() (platformtoken.AuthzMode, error) {
	switch strings.TrimSpace(c.AuthzMode) {
	case "":
		return platformtoken.AuthzModeHybrid, nil
	case AuthzModeOffline:
		return platformtoken.AuthzModeOffline, nil
	case AuthzModeOnline:
		return platformtoken.AuthzModeOnline, nil
	case AuthzModeHybrid:
		return platformtoken.AuthzModeHybrid, nil
	default:
		return "", &ErrTokenAuthConfig{Field: "authz-mode", Reason: "must be offline, online, or hybrid"}
	}
}

// PlatformTokenAuthenticator is the production proxy.TokenAuthenticator. It
// wraps the QuicBaaS platformtoken SDK validator — the same canonical
// pipeline platformd's transports use — so the proxy enforces the identical
// contract: JWKS-by-kid signature, iss/aud/exp, RFC 9068 typ, DPoP proof for
// cnf.jkt-bound tokens (RFC 9449), scope enforcement with qrdb wildcard
// grant semantics, and per-mode liveness/revocation.
//
// It lives here rather than in pkg/proxy so the engine package composes
// against the small TokenAuthenticator seam instead of linking the SDK
// validator's dependency graph; the platform-token contract stays owned by
// the SDK in exactly one place.
type PlatformTokenAuthenticator struct {
	validator   *platformtoken.Validator
	allowBearer bool
}

// NewPlatformTokenAuthenticator validates the configuration and builds the
// authenticator, mirroring the fail-closed construction rules of platformd's
// shared platform-token validator (liveness-requiring modes demand an
// introspection endpoint).
func NewPlatformTokenAuthenticator(cfg *TokenAuthConfig) (*PlatformTokenAuthenticator, error) {
	if cfg == nil {
		return nil, &ErrTokenAuthConfig{Field: "token-auth", Reason: "configuration is required"}
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if !cfg.Enabled {
		return nil, &ErrTokenAuthConfig{Field: "enabled", Reason: "token-auth section is disabled"}
	}
	mode, err := cfg.mode()
	if err != nil {
		return nil, err
	}

	audience := strings.TrimSpace(cfg.Audience)
	if audience == "" {
		audience = DefaultTokenAudience
	}
	cacheTTL := cfg.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = time.Hour
	}

	var (
		liveness         platformtoken.LivenessChecker
		livenessCacheTTL time.Duration
	)
	switch mode {
	case platformtoken.AuthzModeOffline:
		// No liveness backend; revocation is bounded by token lifetime.
	case platformtoken.AuthzModeOnline:
		liveness = newIntrospectionChecker(cfg)
		// Online mode disables caching: every request live-checks.
	case platformtoken.AuthzModeHybrid:
		liveness = newIntrospectionChecker(cfg)
		livenessCacheTTL = cfg.LivenessCacheTTL
		if livenessCacheTTL <= 0 {
			livenessCacheTTL = DefaultTokenLivenessCacheTTL
		}
	}

	validator, err := platformtoken.NewValidator(platformtoken.Options{
		Issuer:           cfg.Issuer,
		Audience:         audience,
		JWKSURL:          cfg.JWKSURL,
		CacheTTL:         cacheTTL,
		LivenessChecker:  liveness,
		ModeResolver:     func(string) platformtoken.AuthzMode { return mode },
		LivenessCacheTTL: livenessCacheTTL,
		ReplayCache:      quicbaas.NewDPoPMemoryReplayCache(quicbaas.DPoPSystemClock{}),
	})
	if err != nil {
		return nil, err
	}
	return &PlatformTokenAuthenticator{
		validator:   validator,
		allowBearer: cfg.AllowBearer,
	}, nil
}

// Authorize implements proxy.TokenAuthenticator. The first required scope
// rides through the SDK's unified Authorize pipeline, which enforces it
// OFFLINE before any liveness round trip; the remaining scopes are then
// enforced offline against the verified grant set with the same
// wildcard-aware semantics (RequireScope). Requests without any scope
// requirement go through Validate, which runs the identical pipeline minus
// the scope check so liveness is never skipped.
func (a *PlatformTokenAuthenticator) Authorize(ctx context.Context, req *proxy.TokenAuthRequest) (*proxy.TokenPrincipal, error) {
	if req == nil {
		return nil, &ErrNilTokenRequest{}
	}
	if strings.TrimSpace(req.DPoPProof) == "" && !a.allowBearer {
		return nil, &ErrBearerNotAllowed{}
	}

	var (
		authCtx *platformtoken.AuthorizedContext
		err     error
	)
	if len(req.RequiredScopes) > 0 {
		authCtx, err = a.validator.Authorize(ctx, req.Token, req.RequiredScopes[0], req.DPoPProof, req.HTM, req.HTU)
	} else {
		authCtx, err = a.validator.Validate(ctx, req.Token, req.DPoPProof, req.HTM, req.HTU)
	}
	if err != nil {
		return nil, mapScopeDenied(err)
	}
	if len(req.RequiredScopes) > 1 {
		for _, scope := range req.RequiredScopes[1:] {
			if err := authCtx.RequireScope(scope); err != nil {
				return nil, mapScopeDenied(err)
			}
		}
	}
	return &proxy.TokenPrincipal{
		Subject:  authCtx.Subject,
		TenantID: authCtx.TenantID,
		Scopes:   authCtx.Scopes,
		Roles:    authCtx.Roles,
	}, nil
}

// mapScopeDenied rewraps the SDK's scope-denial error so the chain can
// classify it (errors.Is against proxy.ErrTokenScopeDenied); every other
// error passes through verbatim and denies as an invalid token.
func mapScopeDenied(err error) error {
	var scopeErr *platformtoken.ScopeDeniedError
	if errors.As(err, &scopeErr) {
		return &ErrScopeDenied{Scope: scopeErr.Required}
	}
	return err
}

// newIntrospectionChecker builds the RFC 7662 introspection liveness checker
// with the configured credentials.
func newIntrospectionChecker(cfg *TokenAuthConfig) platformtoken.LivenessChecker {
	checker := platformtoken.NewIntrospectionLivenessChecker(strings.TrimSpace(cfg.IntrospectionURL), nil)
	if bearer := strings.TrimSpace(cfg.IntrospectionBearerToken); bearer != "" {
		return checker.WithBearer(bearer)
	}
	if strings.TrimSpace(cfg.IntrospectionClientID) != "" || strings.TrimSpace(cfg.IntrospectionClientSecret) != "" {
		return checker.WithBasicAuth(cfg.IntrospectionClientID, cfg.IntrospectionClientSecret)
	}
	return checker
}

var _ proxy.TokenAuthenticator = (*PlatformTokenAuthenticator)(nil)
