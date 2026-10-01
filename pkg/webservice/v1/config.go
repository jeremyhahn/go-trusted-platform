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

package v1

import (
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
)

type Config struct {
	Name string      `yaml:"name" json:"name" mapstructure:"name"`
	ACME *ACMEConfig `yaml:"acme" json:"acme" mapstructure:"acme"`
	// BindHost is the address this webservice's HTTP, HTTPS and HTTP/3
	// listeners bind (#552, #93). Empty — the default — is the unspecified
	// address, every interface: the webservice is the platform's intended
	// external surface (console, API, ACME, the OCI registry), so exposure
	// is its purpose rather than an accident. Set an IP literal or hostname
	// to pin it to one interface; a `/29`-scoped management-only console is
	// `bind-host: 10.4.2.x`. The edge/surface split of what each
	// listener mounts is separate work.
	BindHost     string            `yaml:"bind-host" json:"bind_host" mapstructure:"bind-host"`
	Certificate  Identity          `yaml:"certificate" json:"certificate" mapstructure:"certificate"`
	Home         string            `yaml:"home" json:"home" mapstructure:"home"`
	Index        string            `yaml:"index" json:"index" mapstructure:"index"`
	JWT          JWT               `yaml:"jwt" json:"jwt" mapstructure:"jwt"`
	Key          *common.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	Port         int               `yaml:"port" json:"port" mapstructure:"port"`
	RewriteRules []*RewriteRule    `yaml:"rewrite" json:"rewrite" mapstructure:"rewrite"`
	TLSPort      int               `yaml:"tls-port" json:"tls_port" mapstructure:"tls-port"`
	VirtualHosts *[]VirtualHost    `yaml:"virtual-hosts" json:"virtual_hosts" mapstructure:"virtual-hosts"`
	WebAuthn     *WebAuthn         `yaml:"webauthn" json:"webauthn" mapstructure:"webauthn"`
	CORS         *CORSConfig       `yaml:"cors" json:"cors" mapstructure:"cors"`

	// Surface selects what this webservice mounts (#571). SurfaceFull (the
	// default when empty) is the whole platform: console, /api/v1, /v2, the
	// canonical root routes and the virtual hosts. SurfaceEdge is a public
	// listener that carries only the ACME routes, the virtual hosts and the
	// HTTPS redirect — no console, no API, no registry — and answers an
	// unknown Host with 421 rather than the SPA. Any other value refuses to
	// start.
	Surface string `yaml:"surface" json:"surface" mapstructure:"surface"`

	// Listener limits. Zero takes the surface's default (see
	// webservice.ListenerLimits); they apply to the plaintext and the TLS
	// listener alike.
	MaxHeaderBytes int           `yaml:"max-header-bytes" json:"max_header_bytes" mapstructure:"max-header-bytes"`
	ReadTimeout    time.Duration `yaml:"read-timeout" json:"read_timeout" mapstructure:"read-timeout"`
	WriteTimeout   time.Duration `yaml:"write-timeout" json:"write_timeout" mapstructure:"write-timeout"`
	IdleTimeout    time.Duration `yaml:"idle-timeout" json:"idle_timeout" mapstructure:"idle-timeout"`
	// MaxConnections caps concurrently accepted TCP connections per
	// listener (HTTP/3 over UDP is not counted). Zero is unlimited on a full
	// surface and the edge default on an edge surface.
	MaxConnections int `yaml:"max-connections" json:"max_connections" mapstructure:"max-connections"`
	// RateLimit is a per-source-address token bucket applied to every
	// request; nil is unlimited on a full surface and the edge default on
	// an edge surface.
	RateLimit *RateLimitConfig `yaml:"rate-limit" json:"rate_limit" mapstructure:"rate-limit"`
}

// Surface values.
const (
	// SurfaceFull mounts everything: the default.
	SurfaceFull = "full"
	// SurfaceEdge mounts only ACME, the virtual hosts and the TLS redirect.
	SurfaceEdge = "edge"
)

// RateLimitConfig is a per-source token bucket: RequestsPerSecond sustained,
// Burst at once. A zero RequestsPerSecond disables the limiter even when the
// block is present.
type RateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"requests-per-second" json:"requests_per_second" mapstructure:"requests-per-second"`
	Burst             int     `yaml:"burst" json:"burst" mapstructure:"burst"`
}

// ACMEConfig contains ACME server configuration for a webservice (YAML config)
type ACMEConfig struct {
	// Enabled indicates whether the ACME server is enabled for this webservice
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`
	// DirectoryURL is the ACME directory endpoint URL for this webservice
	DirectoryURL string `yaml:"directory" json:"directory" mapstructure:"directory"`
	// TermsOfService is the URL to the terms of service
	TermsOfService string `yaml:"terms-of-service" json:"terms_of_service" mapstructure:"terms-of-service"`
	// Challenges is the list of supported challenge types
	Challenges []string `yaml:"challenges" json:"challenges" mapstructure:"challenges"`
	// ExternalAccountRequired indicates whether external account binding is required
	ExternalAccountRequired bool `yaml:"external-account-required" json:"external_account_required" mapstructure:"external-account-required"`
}

type CORSConfig struct {
	AllowedOrigins   []string `yaml:"allowed-origins" json:"allowed_origins" mapstructure:"allowed-origins"`
	AllowedMethods   []string `yaml:"allowed-methods" json:"allowed_methods" mapstructure:"allowed-methods"`
	AllowedHeaders   []string `yaml:"allowed-headers" json:"allowed_headers" mapstructure:"allowed-headers"`
	AllowCredentials bool     `yaml:"allow-credentials" json:"allow_credentials" mapstructure:"allow-credentials"`
}

// ACMEIdentityConfig defines ACME-related configuration for an identity.
// Aliased from pkg/common so infrastructure packages (pkg/bmc) can use
// the same shape without importing webservice.
type ACMEIdentityConfig = common.ACMEIdentityConfig

// Identity is the webservice alias for common.Identity — the canonical
// ACME-managed TLS cert identity type shared across the platform.
type Identity = common.Identity

type JWT struct {
	Expiration int64  `yaml:"expiration" json:"expiration" mapstructure:"expiration"`
	Issuer     string `yaml:"issuer" json:"issuer" mapstructure:"issuer"`

	// PlatformToken configures the QuicBaaS broker platform-token validator
	// (the "pure validator" inbound auth path). When Enabled, the platform
	// validates broker-issued, JWKS-published, DPoP-bound access tokens
	// instead of locally minted JWTs. See pkg/webservice/v1/middleware/iam.
	PlatformToken PlatformTokenConfig `yaml:"platform-token" json:"platform_token" mapstructure:"platform-token"`
}

// PlatformTokenConfig configures the inbound platform-token validator that the
// platform uses as a pure consumer of QuicBaaS-issued access tokens. The
// validator verifies the token signature against the broker JWKS (selected by
// kid), checks iss/aud/exp, optionally binds a presented DPoP proof to the
// token's cnf.jkt, and maps scp -> RBAC + tenant_id -> RLS.
type PlatformTokenConfig struct {
	// Enabled turns on broker platform-token validation for the inbound
	// request path. When false the platform retains its legacy locally
	// minted JWT validation.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Issuer is the single trusted broker token issuer. The token iss claim
	// must equal this value (e.g. https://broker.example.com).
	Issuer string `yaml:"issuer" json:"issuer" mapstructure:"issuer"`

	// JWKSURL is the broker JWKS endpoint the validator fetches and caches
	// by kid (e.g. https://broker.example.com/.well-known/jwks.json). It is
	// typically discovered from the broker OIDC metadata.
	JWKSURL string `yaml:"jwks-url" json:"jwks_url" mapstructure:"jwks-url"`

	// Audience is this platform service's resource identifier. The token aud
	// claim must contain it. Defaults to "api://platform" when unset.
	Audience string `yaml:"audience" json:"audience" mapstructure:"audience"`

	// AllowBearer accepts a non-sender-constrained bearer token (no DPoP
	// proof) when no DPoP header is presented. When false, every request
	// must carry a DPoP proof bound to the token's cnf.jkt.
	AllowBearer bool `yaml:"allow-bearer" json:"allow_bearer" mapstructure:"allow-bearer"`

	// ClockSkewSeconds is the permitted clock drift, in seconds, applied to
	// DPoP proof iat checks. Defaults to 60 when unset.
	ClockSkewSeconds int64 `yaml:"clock-skew-seconds" json:"clock_skew_seconds" mapstructure:"clock-skew-seconds"`

	// CacheTTLSeconds bounds how long fetched JWKS keys are cached, in
	// seconds. Defaults to 3600 (one hour) when unset.
	CacheTTLSeconds int64 `yaml:"cache-ttl-seconds" json:"cache_ttl_seconds" mapstructure:"cache-ttl-seconds"`

	// IntrospectionURL is the broker RFC 7662 token-introspection endpoint the
	// validator POSTs tokens to for online liveness (revocation / subject
	// disablement). It is required when AuthzMode is "online" or "hybrid" and
	// unused for "offline".
	IntrospectionURL string `yaml:"introspection-url" json:"introspection_url" mapstructure:"introspection-url"`

	// IntrospectionClientID is the RFC 7662 client_id sent as HTTP Basic
	// credentials on the introspection request (paired with
	// IntrospectionClientSecret). Leave empty to omit Basic auth.
	IntrospectionClientID string `yaml:"introspection-client-id" json:"introspection_client_id" mapstructure:"introspection-client-id"`

	// IntrospectionClientSecret is the RFC 7662 client_secret sent as HTTP
	// Basic credentials on the introspection request.
	IntrospectionClientSecret string `yaml:"introspection-client-secret" json:"introspection_client_secret" mapstructure:"introspection-client-secret"`

	// IntrospectionBearerToken, when set, is sent as a Bearer Authorization
	// header on the introspection request instead of Basic credentials.
	IntrospectionBearerToken string `yaml:"introspection-bearer-token" json:"introspection_bearer_token" mapstructure:"introspection-bearer-token"`

	// AuthzMode selects how tokens are authorized: "offline" (signed scopes +
	// expiry only), "online" (uncached liveness every request), or "hybrid"
	// (liveness with a short positive-result cache). Empty resolves to the
	// stack default, "hybrid".
	AuthzMode string `yaml:"authz-mode" json:"authz_mode" mapstructure:"authz-mode"`

	// LivenessCacheTTLSeconds bounds, in seconds, how long a positive hybrid
	// liveness result is cached before the next request live-checks. Zero or
	// unset defaults to 15s for hybrid; ignored in online mode (no cache).
	LivenessCacheTTLSeconds int `yaml:"liveness-cache-ttl-seconds" json:"liveness_cache_ttl_seconds" mapstructure:"liveness-cache-ttl-seconds"`
}

type ProxyConfig struct {
	Backends []string `yaml:"backends" json:"backends" mapstructure:"backends"`
}

type RewriteRule struct {
	Pattern string `yaml:"pattern" json:"pattern" mapstructure:"pattern"`
	Target  string `yaml:"target" json:"target" mapstructure:"target"`
}

type VirtualHost struct {
	Certificate  *Identity         `yaml:"certificate" json:"certificate" mapstructure:"certificate"`
	CORS         *CORSConfig       `yaml:"cors" json:"cors" mapstructure:"cors"`
	Home         string            `yaml:"home" json:"home" mapstructure:"home"`
	Hosts        []string          `yaml:"hosts" json:"hosts" mapstructure:"hosts"`
	Index        string            `yaml:"index" json:"index" mapstructure:"index"`
	Key          *common.KeyConfig `yaml:"key" json:"key" mapstructure:"key"`
	Proxy        *ProxyConfig      `yaml:"proxy" json:"proxy" mapstructure:"proxy"`
	RewriteRules []*RewriteRule    `yaml:"rewrite" json:"rewrite" mapstructure:"rewrite"`
}

type WebAuthn struct {
	RPDisplayName string   `yaml:"display-name" json:"display_name" mapstructure:"display-name"`
	RPID          string   `yaml:"id" json:"id" mapstructure:"id"`
	RPOrigins     []string `yaml:"origins" json:"origins" mapstructure:"origins"`
}
