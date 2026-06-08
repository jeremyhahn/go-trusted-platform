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

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
)

const (
	// DefaultPlatformAudience is the resource identifier the platform claims
	// when no audience is configured.
	DefaultPlatformAudience = "api://platform"

	// DefaultPlatformTokenCacheTTL bounds JWKS key caching when unset.
	DefaultPlatformTokenCacheTTL = time.Hour
)

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

	audience := strings.TrimSpace(params.Audience)
	if audience == "" {
		audience = DefaultPlatformAudience
	}

	cacheTTL := params.CacheTTL
	if cacheTTL <= 0 {
		cacheTTL = DefaultPlatformTokenCacheTTL
	}

	validator, err := platformtoken.NewValidator(platformtoken.Options{
		Issuer:     params.Issuer,
		Audience:   audience,
		JWKSURL:    params.JWKSURL,
		HTTPClient: params.HTTPClient,
		CacheTTL:   cacheTTL,
	})
	if err != nil {
		return nil, err
	}
	return validator, nil
}
