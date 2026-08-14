package proxy

import (
	"net/url"
	"strings"
	"time"
)

// Auth modes accepted by AuthRequirements.Mode. The engine is fail-closed:
// every route must declare exactly one of these modes.
const (
	// AuthModePublic disables authentication for a route.
	AuthModePublic = "public"
	// AuthModeMTLS requires mutual-TLS client authentication.
	AuthModeMTLS = "mtls"
	// AuthModeToken requires bearer-token authentication.
	AuthModeToken = "token"
	// AuthModeMTLSOrToken accepts either mutual-TLS or bearer-token authentication.
	AuthModeMTLSOrToken = "mtls-or-token"
)

// Listener protocols accepted by ListenerConfig.Protocols.
const (
	// ProtocolH1 enables HTTP/1.1 on a listener.
	ProtocolH1 = "h1"
	// ProtocolH2 enables HTTP/2 on a listener (negotiated over TLS).
	ProtocolH2 = "h2"
)

// WildcardHost matches any request host in a route's Hosts list.
const WildcardHost = "*"

// Backend URL schemes accepted by BackendConfig.URL.
var validBackendSchemes = map[string]struct{}{
	"http":  {},
	"https": {},
}

var validAuthModes = map[string]struct{}{
	AuthModePublic:      {},
	AuthModeMTLS:        {},
	AuthModeToken:       {},
	AuthModeMTLSOrToken: {},
}

var validProtocols = map[string]struct{}{
	ProtocolH1: {},
	ProtocolH2: {},
}

// Config is the complete reverse-proxy engine configuration.
type Config struct {
	Listeners []ListenerConfig
	Routes    []RouteConfig
	Pools     []BackendPoolConfig
	Defaults  AuthDefaults
}

// ListenerConfig describes a single TCP listen address.
type ListenerConfig struct {
	ID        string
	Address   string
	Protocols []string // "h1", "h2" (empty enables both); "h3" arrives in a later phase
}

// RouteConfig maps inbound host/path pairs to a backend pool with per-route
// authentication requirements.
type RouteConfig struct {
	ID             string
	Hosts          []string // exact hosts or "*"; empty means wildcard
	PathPrefix     string
	PoolID         string
	Auth           AuthRequirements
	StripPrefix    bool
	PreserveHost   bool
	PassthroughTCP bool // must be false; validated with ErrTCPPassthroughUnsupported
}

// AuthRequirements declares what the Phase 2 auth chain must enforce for a
// route. The engine only interprets Mode; the remaining fields are carried to
// the injected AuthChain.
type AuthRequirements struct {
	Mode               string // "mtls" | "token" | "mtls-or-token" | "public"
	RequireIDevID      bool
	AllowedZones       []string
	BackendZone        string
	RequireAttestation bool
	AttestationMaxAge  time.Duration
	RequiredRoles      []string
	RequiredScopes     []string
	OPAPolicy          string

	// TokenZone is the operator-assigned platform network zone for
	// token-authenticated principals on this route. Token clients carry no
	// certificate and therefore no OIDTPNetworkZone extension, so a route
	// that enforces AllowedZones or a BackendZone matrix path cannot derive
	// their zone; the operator assigns one explicitly here and the chain
	// enforces it through the same AllowedZones and zone-matrix checks a
	// certificate zone passes. Without it, zone-enforcing routes deny token
	// principals with "zone_requires_mtls". Unknown zones fail closed: the
	// compiled zone matrix denies any (from, to) pair it does not contain.
	TokenZone string
}

// AuthDefaults supplies fallback values merged into route AuthRequirements at
// compile time when the route leaves the corresponding field unset.
type AuthDefaults struct {
	// AttestationMaxAge applies when a route sets RequireAttestation but no
	// AttestationMaxAge of its own.
	AttestationMaxAge time.Duration
	// BackendZone applies when a route leaves BackendZone empty.
	BackendZone string
}

// BackendPoolConfig describes a set of backends sharing one pooled transport.
type BackendPoolConfig struct {
	ID                  string
	Backends            []BackendConfig
	Balancer            string // "round-robin"; empty defaults to round-robin
	TLS                 BackendTLSConfig
	MaxIdleConnsPerHost int
	IdleConnTimeout     time.Duration
}

// BackendConfig describes a single backend endpoint.
type BackendConfig struct {
	URL    string
	Weight int
}

// BackendTLSConfig describes how the pool transport authenticates backends.
type BackendTLSConfig struct {
	// TrustClass selects the trust class resolved through the injected
	// TrustResolver. Empty leaves the transport with default TLS trust.
	TrustClass string
	// MTLSClientCert requests a client certificate in the resolved TLS
	// configuration. Interpreted by the TrustResolver implementation.
	MTLSClientCert bool
}

// Validate checks the configuration and normalizes route Hosts entries to
// lowercase in place. It is fail-closed: every route must declare a known
// auth mode and reference a declared pool. All errors wrap typed sentinels.
func (c *Config) Validate() error {
	if len(c.Listeners) == 0 {
		return ErrNoListeners
	}
	if err := validateListeners(c.Listeners); err != nil {
		return err
	}
	poolIDs, err := validatePools(c.Pools)
	if err != nil {
		return err
	}
	return validateRoutes(c.Routes, poolIDs)
}

func validateListeners(listeners []ListenerConfig) error {
	seen := make(map[string]struct{}, len(listeners))
	for i := range listeners {
		l := &listeners[i]
		if l.ID == "" {
			return &ConfigError{Kind: "listener", ID: l.Address, Err: ErrListenerIDRequired}
		}
		if _, dup := seen[l.ID]; dup {
			return &ConfigError{Kind: "listener", ID: l.ID, Err: ErrDuplicateListenerID}
		}
		seen[l.ID] = struct{}{}
		if l.Address == "" {
			return &ConfigError{Kind: "listener", ID: l.ID, Err: ErrListenerAddressRequired}
		}
		for _, p := range l.Protocols {
			if _, ok := validProtocols[p]; !ok {
				return &ConfigError{Kind: "listener", ID: l.ID, Err: ErrUnknownProtocol}
			}
		}
	}
	return nil
}

func validatePools(pools []BackendPoolConfig) (map[string]struct{}, error) {
	ids := make(map[string]struct{}, len(pools))
	for i := range pools {
		p := &pools[i]
		if p.ID == "" {
			return nil, &ConfigError{Kind: "pool", Err: ErrPoolIDRequired}
		}
		if _, dup := ids[p.ID]; dup {
			return nil, &ConfigError{Kind: "pool", ID: p.ID, Err: ErrDuplicatePoolID}
		}
		ids[p.ID] = struct{}{}
		if len(p.Backends) == 0 {
			return nil, &ConfigError{Kind: "pool", ID: p.ID, Err: ErrNoBackends}
		}
		for _, b := range p.Backends {
			u, err := url.Parse(b.URL)
			if err != nil || u.Host == "" {
				return nil, &ConfigError{Kind: "pool", ID: p.ID, Err: ErrInvalidBackendURL}
			}
			if _, ok := validBackendSchemes[u.Scheme]; !ok {
				return nil, &ConfigError{Kind: "pool", ID: p.ID, Err: ErrInvalidBackendScheme}
			}
			if b.Weight < 0 {
				return nil, &ConfigError{Kind: "pool", ID: p.ID, Err: ErrInvalidBackendWeight}
			}
		}
		if _, err := newBalancer(p.Balancer); err != nil {
			return nil, &ConfigError{Kind: "pool", ID: p.ID, Err: err}
		}
	}
	return ids, nil
}

func validateRoutes(routes []RouteConfig, poolIDs map[string]struct{}) error {
	seen := make(map[string]struct{}, len(routes))
	for i := range routes {
		r := &routes[i]
		if r.ID == "" {
			return &ConfigError{Kind: "route", Err: ErrRouteIDRequired}
		}
		if _, dup := seen[r.ID]; dup {
			return &ConfigError{Kind: "route", ID: r.ID, Err: ErrDuplicateRouteID}
		}
		seen[r.ID] = struct{}{}
		if r.PassthroughTCP {
			return &ConfigError{Kind: "route", ID: r.ID, Err: ErrTCPPassthroughUnsupported}
		}
		if !strings.HasPrefix(r.PathPrefix, "/") {
			return &ConfigError{Kind: "route", ID: r.ID, Err: ErrInvalidPathPrefix}
		}
		if r.Auth.Mode == "" {
			return &ConfigError{Kind: "route", ID: r.ID, Err: ErrRouteAuthModeRequired}
		}
		if _, ok := validAuthModes[r.Auth.Mode]; !ok {
			return &ConfigError{Kind: "route", ID: r.ID, Err: ErrInvalidAuthMode}
		}
		if r.PoolID == "" {
			return &ConfigError{Kind: "route", ID: r.ID, Err: ErrRoutePoolRequired}
		}
		if _, ok := poolIDs[r.PoolID]; !ok {
			return &ConfigError{Kind: "route", ID: r.ID, Err: ErrUnknownPoolID}
		}
		hasTokenPath := r.Auth.Mode == AuthModeToken || r.Auth.Mode == AuthModeMTLSOrToken
		if !hasTokenPath && (r.Auth.TokenZone != "" || len(r.Auth.RequiredScopes) > 0) {
			return &ConfigError{Kind: "route", ID: r.ID, Err: ErrTokenModeRequired}
		}
		if r.Auth.Mode == AuthModeToken && r.Auth.RequireIDevID {
			return &ConfigError{Kind: "route", ID: r.ID, Err: ErrIDevIDRequiresMTLS}
		}
		for j, h := range r.Hosts {
			r.Hosts[j] = strings.ToLower(h)
		}
	}
	return nil
}
