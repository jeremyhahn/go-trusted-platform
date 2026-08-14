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

// Package proxysvc assembles the pkg/proxy authenticating reverse-proxy
// engine as a gatewayd service. It owns the gatewayd-side configuration
// schema, the platformd control-plane sync loop (routes/pools + zone matrix
// over the sdk/go proxy client), the trust-resolver and mTLS adapters the
// engine's auth chain composes against, and the gateway ServiceHandler that
// ties the engine into the gatewayd lifecycle.
package proxysvc

import (
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// ServiceName is the gateway service registry key for the proxy service.
// It matches gateway.ServiceProxy; proxysvc declares its own constant so it
// does not link the full gateway package into consumers that only need the
// engine assembly.
const ServiceName = "proxy"

// Platformd connection protocols accepted by PlatformdConfig.Protocol.
const (
	// PlatformdProtocolUnix connects over the platformd Unix domain socket
	// (gRPC over UDS). This is the default per cmd/gatewayd conventions.
	PlatformdProtocolUnix = "unix"
	// PlatformdProtocolGRPC connects over TCP gRPC with TLS anchored by the
	// platform trust resolver (class internal).
	PlatformdProtocolGRPC = "grpc"
)

// DefaultSyncInterval is the control-plane poll interval when the sync
// section does not set one.
const DefaultSyncInterval = 15 * time.Second

// DefaultPlatformdSocket is the default platformd Unix socket path.
const DefaultPlatformdSocket = "/run/platformd.sock"

// Config is the gatewayd `proxy:` configuration section. Listeners, static
// routes/pools, and defaults mirror the pkg/proxy engine configuration with
// kebab-case keys; TLS, Sync, and Platformd are gatewayd assembly concerns.
//
// Merge semantics with the platformd runtime configuration are documented on
// MergeConfig: the static file supplies the base, platformd wins per ID.
type Config struct {
	// Enabled activates the proxy service.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// TLS configures the front-door server TLS and the client CA source.
	TLS TLSConfig `yaml:"tls" json:"tls" mapstructure:"tls"`

	// Listeners are the gatewayd-local listen addresses. Listeners are never
	// synced from platformd.
	Listeners []ListenerConfig `yaml:"listeners" json:"listeners" mapstructure:"listeners"`

	// Routes are the static file-configured routes (base layer of the merge).
	Routes []RouteConfig `yaml:"routes,omitempty" json:"routes,omitempty" mapstructure:"routes"`

	// Pools are the static file-configured backend pools (base layer of the
	// merge).
	Pools []PoolConfig `yaml:"pools,omitempty" json:"pools,omitempty" mapstructure:"pools"`

	// Defaults supplies fallback auth values merged into routes at compile
	// time.
	Defaults DefaultsConfig `yaml:"defaults,omitempty" json:"defaults,omitempty" mapstructure:"defaults"`

	// Sync configures the platformd control-plane poll loop.
	Sync SyncConfig `yaml:"sync,omitempty" json:"sync,omitempty" mapstructure:"sync"`

	// Platformd selects how the sdk/go client reaches platformd.
	Platformd PlatformdConfig `yaml:"platformd,omitempty" json:"platformd,omitempty" mapstructure:"platformd"`

	// Attestation enables the platformd-backed attestation gate for routes
	// that set auth.require-attestation.
	Attestation AttestationConfig `yaml:"attestation,omitempty" json:"attestation,omitempty" mapstructure:"attestation"`

	// TokenAuth enables the platform-token (DPoP) path for token and
	// mtls-or-token routes.
	TokenAuth TokenAuthConfig `yaml:"token-auth,omitempty" json:"token_auth,omitempty" mapstructure:"token-auth"`

	// OPA enables per-route OPA policy evaluation for routes that set
	// auth.opa-policy.
	OPA OPAConfig `yaml:"opa,omitempty" json:"opa,omitempty" mapstructure:"opa"`
}

// TLSConfig configures the proxy front-door TLS material.
type TLSConfig struct {
	// CertFile is the PEM server certificate (leaf plus optional chain).
	CertFile string `yaml:"cert-file" json:"cert_file" mapstructure:"cert-file"`

	// KeyFile is the PEM server private key.
	KeyFile string `yaml:"key-file" json:"key_file" mapstructure:"key-file"`

	// ClientCAFile is an optional PEM bundle anchoring client-certificate
	// verification. When empty and a trust: section is configured, the
	// platform trust resolver's internal-class CA pool is used instead.
	ClientCAFile string `yaml:"client-ca-file,omitempty" json:"client_ca_file,omitempty" mapstructure:"client-ca-file"`
}

// ListenerConfig mirrors proxy.ListenerConfig with config-file tags.
type ListenerConfig struct {
	ID        string   `yaml:"id" json:"id" mapstructure:"id"`
	Address   string   `yaml:"address" json:"address" mapstructure:"address"`
	Protocols []string `yaml:"protocols,omitempty" json:"protocols,omitempty" mapstructure:"protocols"`
}

// RouteConfig mirrors proxy.RouteConfig with config-file tags.
type RouteConfig struct {
	ID           string     `yaml:"id" json:"id" mapstructure:"id"`
	Hosts        []string   `yaml:"hosts,omitempty" json:"hosts,omitempty" mapstructure:"hosts"`
	PathPrefix   string     `yaml:"path-prefix" json:"path_prefix" mapstructure:"path-prefix"`
	Pool         string     `yaml:"pool" json:"pool" mapstructure:"pool"`
	Auth         AuthConfig `yaml:"auth" json:"auth" mapstructure:"auth"`
	StripPrefix  bool       `yaml:"strip-prefix,omitempty" json:"strip_prefix,omitempty" mapstructure:"strip-prefix"`
	PreserveHost bool       `yaml:"preserve-host,omitempty" json:"preserve_host,omitempty" mapstructure:"preserve-host"`
}

// AuthConfig mirrors proxy.AuthRequirements with config-file tags.
type AuthConfig struct {
	Mode               string        `yaml:"mode" json:"mode" mapstructure:"mode"`
	RequireIDevID      bool          `yaml:"require-idevid,omitempty" json:"require_idevid,omitempty" mapstructure:"require-idevid"`
	AllowedZones       []string      `yaml:"allowed-zones,omitempty" json:"allowed_zones,omitempty" mapstructure:"allowed-zones"`
	BackendZone        string        `yaml:"backend-zone,omitempty" json:"backend_zone,omitempty" mapstructure:"backend-zone"`
	RequireAttestation bool          `yaml:"require-attestation,omitempty" json:"require_attestation,omitempty" mapstructure:"require-attestation"`
	AttestationMaxAge  time.Duration `yaml:"attestation-max-age,omitempty" json:"attestation_max_age,omitempty" mapstructure:"attestation-max-age"`
	RequiredRoles      []string      `yaml:"required-roles,omitempty" json:"required_roles,omitempty" mapstructure:"required-roles"`
	RequiredScopes     []string      `yaml:"required-scopes,omitempty" json:"required_scopes,omitempty" mapstructure:"required-scopes"`
	OPAPolicy          string        `yaml:"opa-policy,omitempty" json:"opa_policy,omitempty" mapstructure:"opa-policy"`
	TokenZone          string        `yaml:"token-zone,omitempty" json:"token_zone,omitempty" mapstructure:"token-zone"`
}

// PoolConfig mirrors proxy.BackendPoolConfig with config-file tags.
type PoolConfig struct {
	ID                  string          `yaml:"id" json:"id" mapstructure:"id"`
	Backends            []BackendConfig `yaml:"backends" json:"backends" mapstructure:"backends"`
	Balancer            string          `yaml:"balancer,omitempty" json:"balancer,omitempty" mapstructure:"balancer"`
	TLS                 PoolTLSConfig   `yaml:"tls,omitempty" json:"tls,omitempty" mapstructure:"tls"`
	MaxIdleConnsPerHost int             `yaml:"max-idle-conns-per-host,omitempty" json:"max_idle_conns_per_host,omitempty" mapstructure:"max-idle-conns-per-host"`
	IdleConnTimeout     time.Duration   `yaml:"idle-conn-timeout,omitempty" json:"idle_conn_timeout,omitempty" mapstructure:"idle-conn-timeout"`
}

// BackendConfig mirrors proxy.BackendConfig with config-file tags.
type BackendConfig struct {
	URL    string `yaml:"url" json:"url" mapstructure:"url"`
	Weight int    `yaml:"weight,omitempty" json:"weight,omitempty" mapstructure:"weight"`
}

// PoolTLSConfig mirrors proxy.BackendTLSConfig with config-file tags.
type PoolTLSConfig struct {
	TrustClass     string `yaml:"trust-class,omitempty" json:"trust_class,omitempty" mapstructure:"trust-class"`
	MTLSClientCert bool   `yaml:"mtls-client-cert,omitempty" json:"mtls_client_cert,omitempty" mapstructure:"mtls-client-cert"`
}

// DefaultsConfig mirrors proxy.AuthDefaults with config-file tags.
type DefaultsConfig struct {
	AttestationMaxAge time.Duration `yaml:"attestation-max-age,omitempty" json:"attestation_max_age,omitempty" mapstructure:"attestation-max-age"`
	BackendZone       string        `yaml:"backend-zone,omitempty" json:"backend_zone,omitempty" mapstructure:"backend-zone"`
}

// SyncConfig configures the platformd control-plane poll loop.
type SyncConfig struct {
	// Enabled activates the sync loop. When disabled the proxy serves the
	// static file configuration only.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// Interval is the poll period. Zero defaults to DefaultSyncInterval.
	Interval time.Duration `yaml:"interval,omitempty" json:"interval,omitempty" mapstructure:"interval"`
}

// PlatformdConfig selects the sdk/go transport used to reach platformd.
type PlatformdConfig struct {
	// Protocol is "unix" (default) or "grpc".
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty" mapstructure:"protocol"`

	// Socket is the platformd Unix socket path (unix protocol). Empty
	// defaults to DefaultPlatformdSocket.
	Socket string `yaml:"socket,omitempty" json:"socket,omitempty" mapstructure:"socket"`

	// GRPCAddr is the platformd gRPC address (grpc protocol).
	GRPCAddr string `yaml:"grpc-addr,omitempty" json:"grpc_addr,omitempty" mapstructure:"grpc-addr"`
}

// Normalize fills defaulted fields in place.
func (c *Config) Normalize() {
	if c.Sync.Interval <= 0 {
		c.Sync.Interval = DefaultSyncInterval
	}
	if c.Platformd.Protocol == "" {
		c.Platformd.Protocol = PlatformdProtocolUnix
	}
	if c.Platformd.Socket == "" {
		c.Platformd.Socket = DefaultPlatformdSocket
	}
}

// Validate checks the gatewayd-owned fields, then delegates route/pool/
// listener validation to the pkg/proxy engine configuration — the single
// source of truth for proxy configuration rules.
func (c *Config) Validate() error {
	if !c.Enabled {
		return nil
	}
	c.Normalize()
	switch c.Platformd.Protocol {
	case PlatformdProtocolUnix, PlatformdProtocolGRPC:
	default:
		return &ErrConfigInvalid{Field: "platformd.protocol", Reason: "must be unix or grpc"}
	}
	if c.Platformd.Protocol == PlatformdProtocolGRPC && c.Platformd.GRPCAddr == "" {
		return &ErrConfigInvalid{Field: "platformd.grpc-addr", Reason: "required for the grpc protocol"}
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return &ErrConfigInvalid{Field: "tls", Reason: "cert-file and key-file must be set together"}
	}
	if err := c.TokenAuth.Validate(); err != nil {
		return err
	}
	engineCfg := c.EngineConfig()
	return engineCfg.Validate()
}

// EngineConfig converts the file schema into the pkg/proxy engine
// configuration (the static base layer of the runtime merge).
func (c *Config) EngineConfig() proxy.Config {
	out := proxy.Config{
		Defaults: proxy.AuthDefaults{
			AttestationMaxAge: c.Defaults.AttestationMaxAge,
			BackendZone:       c.Defaults.BackendZone,
		},
	}
	out.Listeners = make([]proxy.ListenerConfig, 0, len(c.Listeners))
	for _, l := range c.Listeners {
		out.Listeners = append(out.Listeners, proxy.ListenerConfig{
			ID:        l.ID,
			Address:   l.Address,
			Protocols: append([]string(nil), l.Protocols...),
		})
	}
	out.Routes = make([]proxy.RouteConfig, 0, len(c.Routes))
	for _, r := range c.Routes {
		out.Routes = append(out.Routes, proxy.RouteConfig{
			ID:         r.ID,
			Hosts:      append([]string(nil), r.Hosts...),
			PathPrefix: r.PathPrefix,
			PoolID:     r.Pool,
			Auth: proxy.AuthRequirements{
				Mode:               r.Auth.Mode,
				RequireIDevID:      r.Auth.RequireIDevID,
				AllowedZones:       append([]string(nil), r.Auth.AllowedZones...),
				BackendZone:        r.Auth.BackendZone,
				RequireAttestation: r.Auth.RequireAttestation,
				AttestationMaxAge:  r.Auth.AttestationMaxAge,
				RequiredRoles:      append([]string(nil), r.Auth.RequiredRoles...),
				RequiredScopes:     append([]string(nil), r.Auth.RequiredScopes...),
				OPAPolicy:          r.Auth.OPAPolicy,
				TokenZone:          r.Auth.TokenZone,
			},
			StripPrefix:  r.StripPrefix,
			PreserveHost: r.PreserveHost,
		})
	}
	out.Pools = make([]proxy.BackendPoolConfig, 0, len(c.Pools))
	for _, p := range c.Pools {
		backends := make([]proxy.BackendConfig, 0, len(p.Backends))
		for _, b := range p.Backends {
			backends = append(backends, proxy.BackendConfig{URL: b.URL, Weight: b.Weight})
		}
		out.Pools = append(out.Pools, proxy.BackendPoolConfig{
			ID:       p.ID,
			Backends: backends,
			Balancer: p.Balancer,
			TLS: proxy.BackendTLSConfig{
				TrustClass:     p.TLS.TrustClass,
				MTLSClientCert: p.TLS.MTLSClientCert,
			},
			MaxIdleConnsPerHost: p.MaxIdleConnsPerHost,
			IdleConnTimeout:     p.IdleConnTimeout,
		})
	}
	return out
}
