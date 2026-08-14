package proxy

import (
	"errors"
	"fmt"
)

// Sentinel errors returned (usually wrapped in a ConfigError) by Validate,
// New, Reload, Start, and Stop. Callers match them with errors.Is.
var (
	// ErrNoListeners is returned when the configuration declares no listeners.
	ErrNoListeners = errors.New("proxy: at least one listener is required")

	// ErrListenerIDRequired is returned when a listener has an empty ID.
	ErrListenerIDRequired = errors.New("proxy: listener id is required")

	// ErrListenerAddressRequired is returned when a listener has an empty address.
	ErrListenerAddressRequired = errors.New("proxy: listener address is required")

	// ErrDuplicateListenerID is returned when two listeners share an ID.
	ErrDuplicateListenerID = errors.New("proxy: duplicate listener id")

	// ErrUnknownProtocol is returned for a listener protocol other than "h1" or "h2".
	ErrUnknownProtocol = errors.New("proxy: unknown listener protocol")

	// ErrRouteIDRequired is returned when a route has an empty ID.
	ErrRouteIDRequired = errors.New("proxy: route id is required")

	// ErrDuplicateRouteID is returned when two routes share an ID.
	ErrDuplicateRouteID = errors.New("proxy: duplicate route id")

	// ErrInvalidPathPrefix is returned when a route path prefix does not start with "/".
	ErrInvalidPathPrefix = errors.New("proxy: route path prefix must start with \"/\"")

	// ErrTCPPassthroughUnsupported is returned when a route sets PassthroughTCP,
	// which is not supported by the engine yet.
	ErrTCPPassthroughUnsupported = errors.New("proxy: tcp passthrough is not supported")

	// ErrRouteAuthModeRequired is returned when a route omits Auth.Mode. The
	// engine is fail-closed: every route must declare an explicit auth mode.
	ErrRouteAuthModeRequired = errors.New("proxy: route auth mode is required")

	// ErrInvalidAuthMode is returned when a route declares an unknown auth mode.
	ErrInvalidAuthMode = errors.New("proxy: invalid route auth mode")

	// ErrRoutePoolRequired is returned when a route omits its backend pool ID.
	ErrRoutePoolRequired = errors.New("proxy: route pool id is required")

	// ErrUnknownPoolID is returned when a route references a pool that does not exist.
	ErrUnknownPoolID = errors.New("proxy: route references unknown pool")

	// ErrPoolIDRequired is returned when a backend pool has an empty ID.
	ErrPoolIDRequired = errors.New("proxy: pool id is required")

	// ErrDuplicatePoolID is returned when two backend pools share an ID.
	ErrDuplicatePoolID = errors.New("proxy: duplicate pool id")

	// ErrNoBackends is returned when a backend pool declares no backends.
	ErrNoBackends = errors.New("proxy: pool requires at least one backend")

	// ErrInvalidBackendURL is returned when a backend URL does not parse or has no host.
	ErrInvalidBackendURL = errors.New("proxy: invalid backend url")

	// ErrInvalidBackendScheme is returned when a backend URL scheme is not http or https.
	ErrInvalidBackendScheme = errors.New("proxy: backend url scheme must be http or https")

	// ErrInvalidBackendWeight is returned when a backend declares a negative weight.
	ErrInvalidBackendWeight = errors.New("proxy: backend weight must not be negative")

	// ErrUnknownBalancer is returned when a pool declares an unregistered balancer.
	ErrUnknownBalancer = errors.New("proxy: unknown balancer")

	// ErrAuthChainRequired is returned by New or Reload when any route requires
	// authentication but no AuthChain was injected. Fail-closed composition.
	ErrAuthChainRequired = errors.New("proxy: auth chain required for non-public routes")

	// ErrTrustResolverRequired is returned by New or Reload when any pool sets a
	// TLS trust class but no TrustResolver was injected.
	ErrTrustResolverRequired = errors.New("proxy: trust resolver required for pools with a trust class")

	// ErrTLSRequiredForAuth is returned by New or Reload when any route requires
	// authentication but no server TLS configuration was injected. Plain
	// listeners are permitted only when every route is public.
	ErrTLSRequiredForAuth = errors.New("proxy: server tls required for non-public routes")

	// ErrEngineStarted is returned by Start when the engine is already running.
	ErrEngineStarted = errors.New("proxy: engine already started")
)

// ConfigError wraps a sentinel validation error with the kind ("listener",
// "route", "pool") and ID of the offending configuration element.
type ConfigError struct {
	Kind string
	ID   string
	Err  error
}

// Error implements the error interface.
func (e *ConfigError) Error() string {
	return fmt.Sprintf("proxy: %s %q: %v", e.Kind, e.ID, e.Err)
}

// Unwrap returns the wrapped sentinel error.
func (e *ConfigError) Unwrap() error { return e.Err }

// ListenerError wraps a runtime listener failure with the listener ID.
type ListenerError struct {
	ID  string
	Err error
}

// Error implements the error interface.
func (e *ListenerError) Error() string {
	return fmt.Sprintf("proxy: listener %q: %v", e.ID, e.Err)
}

// Unwrap returns the wrapped error.
func (e *ListenerError) Unwrap() error { return e.Err }

// TrustResolveError wraps a TrustResolver failure with the pool and trust
// class that triggered the resolution.
type TrustResolveError struct {
	PoolID     string
	TrustClass string
	Err        error
}

// Error implements the error interface.
func (e *TrustResolveError) Error() string {
	return fmt.Sprintf("proxy: pool %q trust class %q: %v", e.PoolID, e.TrustClass, e.Err)
}

// Unwrap returns the wrapped error.
func (e *TrustResolveError) Unwrap() error { return e.Err }

// Phase 2 sentinel errors: auth-chain construction and capability
// fail-closed composition.
var (
	// ErrMTLSAuthenticatorRequired is returned by NewAuthChain when no mTLS
	// authenticator is configured. The chain cannot operate without one.
	ErrMTLSAuthenticatorRequired = errors.New("proxy: mtls authenticator required")

	// ErrZoneConfigIncomplete is returned by NewAuthChain when exactly one of
	// ZoneExtractor and Matrix is configured. Zone enforcement requires both.
	ErrZoneConfigIncomplete = errors.New("proxy: zone extractor and matrix must be configured together")

	// ErrNilRequest is returned by Chain.Authenticate for a nil request.
	ErrNilRequest = errors.New("proxy: nil request")

	// ErrNilRoute is returned by Chain.Authenticate for a nil compiled route.
	ErrNilRoute = errors.New("proxy: nil route")

	// ErrMTLSAuthNotConfigured is returned by New or Reload when a route
	// requires mTLS authentication but the injected chain reports no mTLS
	// capability.
	ErrMTLSAuthNotConfigured = errors.New("proxy: route requires mtls but chain has no mtls capability")

	// ErrTokenAuthNotConfigured is returned by New or Reload when a route
	// declares a token auth mode but the injected chain reports no token
	// capability (no TokenAuthenticator configured). The configuration is
	// rejected at composition time so the demand cannot silently deny.
	ErrTokenAuthNotConfigured = errors.New("proxy: route requires token auth but chain has no token capability")

	// ErrAttestationGateNotConfigured is returned by New or Reload when a
	// route sets RequireAttestation but the injected chain reports no
	// attestation capability.
	ErrAttestationGateNotConfigured = errors.New("proxy: route requires attestation but chain has no attestation capability")

	// ErrOPANotConfigured is returned by New or Reload when a route sets
	// OPAPolicy but the injected chain reports no OPA capability.
	ErrOPANotConfigured = errors.New("proxy: route sets opa policy but chain has no opa capability")

	// ErrZoneEnforcementNotConfigured is returned by New or Reload when a
	// route sets AllowedZones or BackendZone but the injected chain reports
	// no zone capability (zone extractor plus matrix provider).
	ErrZoneEnforcementNotConfigured = errors.New("proxy: route requires zone enforcement but chain has no zone capability")

	// ErrNilLeafCertificate is returned by zone extraction for a nil
	// certificate.
	ErrNilLeafCertificate = errors.New("proxy: nil leaf certificate")

	// ErrZoneExtensionMissing is returned by PolicyZoneExtractor when the
	// certificate carries no OIDTPNetworkZone extension.
	ErrZoneExtensionMissing = errors.New("proxy: certificate has no network zone extension")
)

// Phase 3 sentinel errors: attestation gating, platform-token
// authentication, and OPA policy evaluation.
var (
	// ErrAttestationStale is the sentinel an AttestationGate wraps (or returns)
	// when the device's attestation state definitively fails the freshness or
	// verification requirement: no manifest exists, the newest manifest is
	// older than the accepted maximum age, or platformd rejected its
	// verification. The chain maps it to the "attestation_stale" deny reason.
	// Any other gate error is an indeterminate failure (transport, platformd
	// unreachable) mapped to "attestation_unavailable" — both deny.
	ErrAttestationStale = errors.New("proxy: device attestation is stale or unverified")

	// ErrTokenScopeDenied is the sentinel a TokenAuthenticator wraps when the
	// token validated but was not granted a required scope. The chain maps it
	// to the "token_scope_denied" deny reason; every other authenticator error
	// maps to "token_invalid".
	ErrTokenScopeDenied = errors.New("proxy: token missing required scope")

	// ErrTokenModeRequired is returned by Validate when a route sets a
	// token-path-only field (TokenZone or RequiredScopes) but declares an auth
	// mode without a token path. Scopes and the operator-assigned token zone
	// are meaningless for pure-mTLS or public routes; rejecting the
	// configuration keeps them from silently never being enforced.
	ErrTokenModeRequired = errors.New("proxy: token-zone and required-scopes need a token auth mode")

	// ErrIDevIDRequiresMTLS is returned by Validate when a pure token-mode
	// route sets RequireIDevID. An IDevID is carried in the client
	// certificate, which a token-only route never presents, so the route
	// could never admit a request.
	ErrIDevIDRequiresMTLS = errors.New("proxy: require-idevid needs an mtls auth mode")
)
