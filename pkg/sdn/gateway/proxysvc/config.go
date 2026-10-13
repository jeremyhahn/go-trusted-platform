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

	// Audit enables emitting routing/authentication decisions onto the
	// platform audit chain (quicbaasd) through the quicbaas SDK IAM audit
	// client. Disabled (or unreachable at runtime) leaves the pkg/proxy
	// no-op sink installed: the proxy always serves regardless of the
	// audit plane's health.
	Audit AuditConfig `yaml:"audit,omitempty" json:"audit,omitempty" mapstructure:"audit"`
}

// TLSConfig configures the proxy front-door TLS material.
type TLSConfig struct {
	// CertFile is the PEM server certificate (leaf plus optional chain).
	CertFile string `yaml:"cert-file" json:"cert_file" mapstructure:"cert-file"`

	// KeyFile is the PEM server private key.
	KeyFile string `yaml:"key-file" json:"key_file" mapstructure:"key-file"`

	// ClientCAFile is an optional PEM bundle anchoring client-certificate
	// verification. When empty and `platform-ca-file:` is configured, the
	// platform anchor is used instead: the proxy's callers are platform-issued.
	ClientCAFile string `yaml:"client-ca-file,omitempty" json:"client_ca_file,omitempty" mapstructure:"client-ca-file"`
}

// The engine's own configuration types carry the config-file tags (#570),
// so the gatewayd schema aliases them instead of mirroring them: one type,
// one set of keys, one Validate.

// ListenerConfig is proxy.ListenerConfig.
type ListenerConfig = proxy.ListenerConfig

// RouteConfig is proxy.RouteConfig.
type RouteConfig = proxy.RouteConfig

// AuthConfig is proxy.AuthRequirements.
type AuthConfig = proxy.AuthRequirements

// PoolConfig is proxy.BackendPoolConfig.
type PoolConfig = proxy.BackendPoolConfig

// BackendConfig is proxy.BackendConfig.
type BackendConfig = proxy.BackendConfig

// PoolTLSConfig is proxy.BackendTLSConfig.
type PoolTLSConfig = proxy.BackendTLSConfig

// DefaultsConfig is proxy.AuthDefaults.
type DefaultsConfig = proxy.AuthDefaults

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

	// CertFile and KeyFile are the client certificate gatewayd presents to
	// a platformd that authenticates its gRPC callers by mTLS (grpc
	// protocol). They are set together.
	CertFile string `yaml:"cert-file,omitempty" json:"cert_file,omitempty" mapstructure:"cert-file"`
	KeyFile  string `yaml:"key-file,omitempty" json:"key_file,omitempty" mapstructure:"key-file"`

	// TokenFile holds the platform bearer token gatewayd presents to a
	// platformd that authenticates its gRPC callers by token (grpc
	// protocol). It is read on every dial, so a rotated token is picked up
	// when the connection is re-established.
	TokenFile string `yaml:"token-file,omitempty" json:"token_file,omitempty" mapstructure:"token-file"`
}

// Validate checks the platformd connection settings. The grpc protocol
// needs an address and a client identity, because platformd's gRPC
// listener refuses unauthenticated callers: a client certificate, a token
// file, or both.
func (p PlatformdConfig) Validate() error {
	switch p.Protocol {
	case PlatformdProtocolUnix:
		return nil
	case PlatformdProtocolGRPC:
	default:
		return &ErrConfigInvalid{Field: "platformd.protocol", Reason: "must be unix or grpc"}
	}
	if p.GRPCAddr == "" {
		return &ErrConfigInvalid{Field: "platformd.grpc-addr", Reason: "required for the grpc protocol"}
	}
	if (p.CertFile == "") != (p.KeyFile == "") {
		return &ErrConfigInvalid{Field: "platformd", Reason: "cert-file and key-file must be set together"}
	}
	if p.CertFile == "" && p.TokenFile == "" {
		return &ErrConfigInvalid{
			Field:  "platformd",
			Reason: "the grpc protocol requires a client identity: cert-file and key-file, or token-file",
		}
	}
	return nil
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
	if err := c.Platformd.Validate(); err != nil {
		return err
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return &ErrConfigInvalid{Field: "tls", Reason: "cert-file and key-file must be set together"}
	}
	if err := c.TokenAuth.Validate(); err != nil {
		return err
	}
	if err := c.Audit.Validate(); err != nil {
		return err
	}
	engineCfg := c.EngineConfig()
	return engineCfg.Validate()
}

// EngineConfig converts the file schema into the pkg/proxy engine
// configuration (the static base layer of the runtime merge).
func (c *Config) EngineConfig() proxy.Config {
	out := proxy.Config{Defaults: c.Defaults}
	out.Listeners = make([]proxy.ListenerConfig, 0, len(c.Listeners))
	for _, l := range c.Listeners {
		l.Protocols = append([]string(nil), l.Protocols...)
		out.Listeners = append(out.Listeners, l)
	}
	out.Routes = make([]proxy.RouteConfig, 0, len(c.Routes))
	for _, r := range c.Routes {
		r.Hosts = append([]string(nil), r.Hosts...)
		r.Auth.AllowedZones = append([]string(nil), r.Auth.AllowedZones...)
		r.Auth.RequiredRoles = append([]string(nil), r.Auth.RequiredRoles...)
		r.Auth.RequiredScopes = append([]string(nil), r.Auth.RequiredScopes...)
		out.Routes = append(out.Routes, r)
	}
	out.Pools = make([]proxy.BackendPoolConfig, 0, len(c.Pools))
	for _, p := range c.Pools {
		p.Backends = append([]proxy.BackendConfig(nil), p.Backends...)
		out.Pools = append(out.Pools, p)
	}
	return out
}
