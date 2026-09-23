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
	Listeners []ListenerConfig    `yaml:"listeners" json:"listeners" mapstructure:"listeners"`
	Routes    []RouteConfig       `yaml:"routes,omitempty" json:"routes,omitempty" mapstructure:"routes"`
	Pools     []BackendPoolConfig `yaml:"pools,omitempty" json:"pools,omitempty" mapstructure:"pools"`
	Defaults  AuthDefaults        `yaml:"defaults,omitempty" json:"defaults,omitempty" mapstructure:"defaults"`
}

// ControlPlaneConfig is the platformd `proxy:` section: the routes, pools and
// auth defaults the control plane owns and hands to every gateway through the
// proxy sync loop (#570, ruling R4). Listeners are deliberately absent — a
// listener is a gatewayd-local bind and lives in gatewayd's own `proxy:`
// section. The file is the base layer of the platform proxy store: an entry
// whose ID the store already holds (authored over the API) is kept as
// stored; an absent one is seeded.
type ControlPlaneConfig struct {
	Routes   []RouteConfig       `yaml:"routes,omitempty" json:"routes,omitempty" mapstructure:"routes"`
	Pools    []BackendPoolConfig `yaml:"pools,omitempty" json:"pools,omitempty" mapstructure:"pools"`
	Defaults AuthDefaults        `yaml:"defaults,omitempty" json:"defaults,omitempty" mapstructure:"defaults"`
}

// validationListener stands in for the gatewayd-local listener a
// ControlPlaneConfig does not carry, so Config.Validate can check routes and
// pools on their own.
var validationListener = ListenerConfig{ID: "control-plane-validation", Address: "127.0.0.1:0"}

// Validate checks the control-plane section with the same rules the engine
// applies to a full configuration; it normalizes route Hosts in place.
func (c *ControlPlaneConfig) Validate() error {
	full := Config{
		Listeners: []ListenerConfig{validationListener},
		Routes:    c.Routes,
		Pools:     c.Pools,
		Defaults:  c.Defaults,
	}
	return full.Validate()
}

// ListenerConfig describes a single TCP listen address.
type ListenerConfig struct {
	ID        string   `yaml:"id" json:"id" mapstructure:"id"`
	Address   string   `yaml:"address" json:"address" mapstructure:"address"`
	Protocols []string `yaml:"protocols,omitempty" json:"protocols,omitempty" mapstructure:"protocols"` // "h1", "h2" (empty enables both); "h3" arrives in a later phase
}

// RouteConfig maps inbound host/path pairs to a backend pool with per-route
// authentication requirements.
type RouteConfig struct {
	ID             string           `yaml:"id" json:"id" mapstructure:"id"`
	Hosts          []string         `yaml:"hosts,omitempty" json:"hosts,omitempty" mapstructure:"hosts"` // exact hosts or "*"; empty means wildcard
	PathPrefix     string           `yaml:"path-prefix" json:"path_prefix" mapstructure:"path-prefix"`
	PoolID         string           `yaml:"pool" json:"pool" mapstructure:"pool"`
	Auth           AuthRequirements `yaml:"auth" json:"auth" mapstructure:"auth"`
	StripPrefix    bool             `yaml:"strip-prefix,omitempty" json:"strip_prefix,omitempty" mapstructure:"strip-prefix"`
	PreserveHost   bool             `yaml:"preserve-host,omitempty" json:"preserve_host,omitempty" mapstructure:"preserve-host"`
	PassthroughTCP bool             `yaml:"passthrough-tcp,omitempty" json:"passthrough_tcp,omitempty" mapstructure:"passthrough-tcp"` // must be false; validated with ErrTCPPassthroughUnsupported
}

// AuthRequirements declares what the Phase 2 auth chain must enforce for a
// route. The engine only interprets Mode; the remaining fields are carried to
// the injected AuthChain.
type AuthRequirements struct {
	Mode               string        `yaml:"mode" json:"mode" mapstructure:"mode"` // "mtls" | "token" | "mtls-or-token" | "public"
	RequireIDevID      bool          `yaml:"require-idevid,omitempty" json:"require_idevid,omitempty" mapstructure:"require-idevid"`
	AllowedZones       []string      `yaml:"allowed-zones,omitempty" json:"allowed_zones,omitempty" mapstructure:"allowed-zones"`
	BackendZone        string        `yaml:"backend-zone,omitempty" json:"backend_zone,omitempty" mapstructure:"backend-zone"`
	RequireAttestation bool          `yaml:"require-attestation,omitempty" json:"require_attestation,omitempty" mapstructure:"require-attestation"`
	AttestationMaxAge  time.Duration `yaml:"attestation-max-age,omitempty" json:"attestation_max_age,omitempty" mapstructure:"attestation-max-age"`
	RequiredRoles      []string      `yaml:"required-roles,omitempty" json:"required_roles,omitempty" mapstructure:"required-roles"`
	RequiredScopes     []string      `yaml:"required-scopes,omitempty" json:"required_scopes,omitempty" mapstructure:"required-scopes"`
	OPAPolicy          string        `yaml:"opa-policy,omitempty" json:"opa_policy,omitempty" mapstructure:"opa-policy"`

	// TokenZone is the operator-assigned platform network zone for
	// token-authenticated principals on this route. Token clients carry no
	// certificate and therefore no OIDTPNetworkZone extension, so a route
	// that enforces AllowedZones or a BackendZone matrix path cannot derive
	// their zone; the operator assigns one explicitly here and the chain
	// enforces it through the same AllowedZones and zone-matrix checks a
	// certificate zone passes. Without it, zone-enforcing routes deny token
	// principals with "zone_requires_mtls". Unknown zones fail closed: the
	// compiled zone matrix denies any (from, to) pair it does not contain.
	TokenZone string `yaml:"token-zone,omitempty" json:"token_zone,omitempty" mapstructure:"token-zone"`
}

// AuthDefaults supplies fallback values merged into route AuthRequirements at
// compile time when the route leaves the corresponding field unset.
type AuthDefaults struct {
	// AttestationMaxAge applies when a route sets RequireAttestation but no
	// AttestationMaxAge of its own.
	AttestationMaxAge time.Duration `yaml:"attestation-max-age,omitempty" json:"attestation_max_age,omitempty" mapstructure:"attestation-max-age"`
	// BackendZone applies when a route leaves BackendZone empty.
	BackendZone string `yaml:"backend-zone,omitempty" json:"backend_zone,omitempty" mapstructure:"backend-zone"`
}

// BackendPoolConfig describes a set of backends sharing one pooled transport.
type BackendPoolConfig struct {
	ID                  string           `yaml:"id" json:"id" mapstructure:"id"`
	Backends            []BackendConfig  `yaml:"backends" json:"backends" mapstructure:"backends"`
	Balancer            string           `yaml:"balancer,omitempty" json:"balancer,omitempty" mapstructure:"balancer"` // "round-robin"; empty defaults to round-robin
	TLS                 BackendTLSConfig `yaml:"tls,omitempty" json:"tls,omitempty" mapstructure:"tls"`
	MaxIdleConnsPerHost int              `yaml:"max-idle-conns-per-host,omitempty" json:"max_idle_conns_per_host,omitempty" mapstructure:"max-idle-conns-per-host"`
	IdleConnTimeout     time.Duration    `yaml:"idle-conn-timeout,omitempty" json:"idle_conn_timeout,omitempty" mapstructure:"idle-conn-timeout"`
}

// BackendConfig describes a single backend endpoint.
type BackendConfig struct {
	URL    string `yaml:"url" json:"url" mapstructure:"url"`
	Weight int    `yaml:"weight,omitempty" json:"weight,omitempty" mapstructure:"weight"`
}

// BackendTLSConfig describes how the pool transport authenticates backends.
type BackendTLSConfig struct {
	// TrustClass selects what the backend's certificate is verified
	// against, through the injected TrustResolver: "platform" for a backend
	// the platform CA issued, "bmc" for a baseboard management controller.
	// Empty leaves the transport with default TLS trust.
	TrustClass string `yaml:"trust-class,omitempty" json:"trust_class,omitempty" mapstructure:"trust-class"`
	// MTLSClientCert requests a client certificate in the resolved TLS
	// configuration. Interpreted by the TrustResolver implementation.
	MTLSClientCert bool `yaml:"mtls-client-cert,omitempty" json:"mtls_client_cert,omitempty" mapstructure:"mtls-client-cert"`
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
