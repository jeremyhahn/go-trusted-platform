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

package iam

import (
	"net/http"
	"strings"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

const (
	// DefaultPlatformAudience is the resource identifier the platform claims
	// when no audience is configured.
	DefaultPlatformAudience = "api://platform"

	// DefaultPlatformTokenCacheTTL bounds JWKS key caching when unset.
	DefaultPlatformTokenCacheTTL = time.Hour

	// DefaultLivenessCacheTTL bounds how long a positive hybrid-mode liveness
	// result is cached before the next request live-checks. Used when
	// LivenessCacheTTL is unset (zero) in hybrid mode.
	DefaultLivenessCacheTTL = 15 * time.Second
)

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
// (hybrid). Any unrecognized value returns an *ErrInvalidAuthzMode.
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

// PlatformTokenValidatorParams resolves the broker validator inputs from the
// platform webservice configuration. It is the bridge between the YAML
// JWT.PlatformToken block and the QuicBaaS platformtoken.Validator.
type PlatformTokenValidatorParams struct {
	// Issuer is the single trusted broker token issuer (required).
	Issuer string

	// JWKSURL is the broker JWKS endpoint fetched and cached by kid
	// (required when JWKS is nil).
	JWKSURL string

	// Audience is this platform service's resource identifier. Defaults to
	// DefaultPlatformAudience when empty.
	Audience string

	// CacheTTL bounds JWKS key caching. Defaults to
	// DefaultPlatformTokenCacheTTL when zero.
	CacheTTL time.Duration

	// HTTPClient overrides the client used for JWKS fetches (e.g. to pin the
	// broker TLS trust anchor). Nil uses the default client.
	HTTPClient *http.Client

	// IntrospectionURL is the broker RFC 7662 token-introspection endpoint used
	// for online liveness. Required when AuthzMode is online or hybrid; unused
	// for offline.
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
	// is cached. Zero defaults to DefaultLivenessCacheTTL for hybrid; ignored in
	// online mode.
	LivenessCacheTTL time.Duration
}

// NewPlatformTokenValidator builds a QuicBaaS platformtoken.Validator from the
// resolved params, applying platform defaults. It returns a typed
// ErrInvalidConfig when a required field is missing so callers fail closed
// rather than constructing an unsafe validator.
func NewPlatformTokenValidator(params PlatformTokenValidatorParams) (*platformtoken.Validator, error) {
	if strings.TrimSpace(params.Issuer) == "" {
		return nil, ErrInvalidConfig{Field: "issuer", Reason: "broker token issuer is required"}
	}
	if strings.TrimSpace(params.JWKSURL) == "" {
		return nil, ErrInvalidConfig{Field: "jwks-url", Reason: "broker JWKS URL is required"}
	}

	mode, err := parseAuthzMode(strings.TrimSpace(params.AuthzMode))
	if err != nil {
		return nil, err
	}

	audience := strings.TrimSpace(params.Audience)
	if audience == "" {
		audience = DefaultPlatformAudience
	}

	cacheTTL := params.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = DefaultPlatformTokenCacheTTL
	}

	introspectionURL := strings.TrimSpace(params.IntrospectionURL)

	// Build the online liveness checker for the modes that require it. A missing
	// introspection endpoint in a liveness-requiring mode fails closed rather
	// than silently downgrading to offline.
	var (
		livenessChecker  platformtoken.LivenessChecker
		livenessCacheTTL time.Duration
	)
	switch mode {
	case platformtoken.AuthzModeOffline:
		// No liveness backend; revocation is bounded by token lifetime.
	case platformtoken.AuthzModeOnline:
		if introspectionURL == "" {
			return nil, ErrInvalidConfig{Field: "introspection-url", Reason: "introspection URL is required for online authz-mode"}
		}
		livenessChecker = newIntrospectionChecker(params, introspectionURL)
		livenessCacheTTL = 0
	case platformtoken.AuthzModeHybrid:
		if introspectionURL == "" {
			return nil, ErrInvalidConfig{Field: "introspection-url", Reason: "introspection URL is required for hybrid authz-mode"}
		}
		livenessChecker = newIntrospectionChecker(params, introspectionURL)
		livenessCacheTTL = params.LivenessCacheTTL
		if livenessCacheTTL <= 0 {
			livenessCacheTTL = DefaultLivenessCacheTTL
		}
	}

	modeResolver := func(string) platformtoken.AuthzMode { return mode }

	validator, err := platformtoken.NewValidator(platformtoken.Options{
		Issuer:           params.Issuer,
		Audience:         audience,
		JWKSURL:          params.JWKSURL,
		HTTPClient:       params.HTTPClient,
		CacheTTL:         cacheTTL,
		LivenessChecker:  livenessChecker,
		ModeResolver:     modeResolver,
		LivenessCacheTTL: livenessCacheTTL,
		ReplayCache:      quicbaas.NewDPoPMemoryReplayCache(quicbaas.DPoPSystemClock{}),
	})
	if err != nil {
		return nil, err
	}
	return validator, nil
}

// newIntrospectionChecker builds the RFC 7662 introspection liveness checker
// from the params, applying Bearer credentials when a bearer token is set and
// HTTP Basic credentials when a client id/secret is set.
func newIntrospectionChecker(params PlatformTokenValidatorParams, endpoint string) platformtoken.LivenessChecker {
	checker := platformtoken.NewIntrospectionLivenessChecker(endpoint, params.HTTPClient)
	if bearer := strings.TrimSpace(params.IntrospectionBearerToken); bearer != "" {
		return checker.WithBearer(bearer)
	}
	if strings.TrimSpace(params.IntrospectionClientID) != "" || strings.TrimSpace(params.IntrospectionClientSecret) != "" {
		return checker.WithBasicAuth(params.IntrospectionClientID, params.IntrospectionClientSecret)
	}
	return checker
}
