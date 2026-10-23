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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// validConfig returns a minimal enabled configuration with one public
// route.
func validConfig() *Config {
	return &Config{
		Enabled:   true,
		Listeners: []ListenerConfig{{ID: "https", Address: "127.0.0.1:0"}},
		Routes: []RouteConfig{{
			ID:         "app",
			PathPrefix: "/",
			PoolID:     "backend",
			Auth:       AuthConfig{Mode: proxy.AuthModePublic},
		}},
		Pools: []PoolConfig{{
			ID:       "backend",
			Backends: []BackendConfig{{URL: "http://127.0.0.1:8080"}},
		}},
	}
}

func TestConfigValidate(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if cfg.Sync.Interval != DefaultSyncInterval {
		t.Fatalf("Sync.Interval = %v, want default %v", cfg.Sync.Interval, DefaultSyncInterval)
	}
	if cfg.Platformd.Protocol != PlatformdProtocolUnix {
		t.Fatalf("Platformd.Protocol = %q, want unix", cfg.Platformd.Protocol)
	}
	if cfg.Platformd.Socket != DefaultPlatformdSocket {
		t.Fatalf("Platformd.Socket = %q, want %q", cfg.Platformd.Socket, DefaultPlatformdSocket)
	}
}

func TestConfigValidateDisabledSkipsChecks(t *testing.T) {
	cfg := &Config{Enabled: false}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("disabled config must validate: %v", err)
	}
}

func TestConfigValidateErrors(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		field  string
	}{
		{
			name:   "unknown platformd protocol",
			mutate: func(c *Config) { c.Platformd.Protocol = "quic" },
			field:  "platformd.protocol",
		},
		{
			name:   "grpc without address",
			mutate: func(c *Config) { c.Platformd.Protocol = PlatformdProtocolGRPC },
			field:  "platformd.grpc-addr",
		},
		{
			name: "grpc without a client identity",
			mutate: func(c *Config) {
				c.Platformd.Protocol = PlatformdProtocolGRPC
				c.Platformd.GRPCAddr = "platformd:10443"
			},
			field: "platformd",
		},
		{
			name: "grpc client cert without key",
			mutate: func(c *Config) {
				c.Platformd.Protocol = PlatformdProtocolGRPC
				c.Platformd.GRPCAddr = "platformd:10443"
				c.Platformd.CertFile = "/etc/gatewayd/platformd-client.pem"
			},
			field: "platformd",
		},
		{
			name:   "cert without key",
			mutate: func(c *Config) { c.TLS.CertFile = "/etc/gatewayd/server.pem" },
			field:  "tls",
		},
		{
			name:   "key without cert",
			mutate: func(c *Config) { c.TLS.KeyFile = "/etc/gatewayd/server-key.pem" },
			field:  "tls",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := validConfig()
			tc.mutate(cfg)
			err := cfg.Validate()
			var cfgErr *ErrConfigInvalid
			if !errors.As(err, &cfgErr) {
				t.Fatalf("Validate = %v, want *ErrConfigInvalid", err)
			}
			if cfgErr.Field != tc.field {
				t.Fatalf("Field = %q, want %q", cfgErr.Field, tc.field)
			}
		})
	}
}

func TestPlatformdConfigValidateAcceptsEitherGRPCIdentity(t *testing.T) {
	tests := []struct {
		name   string
		config PlatformdConfig
	}{
		{"unix needs no identity", PlatformdConfig{Protocol: PlatformdProtocolUnix}},
		{"grpc with a client certificate", PlatformdConfig{
			Protocol: PlatformdProtocolGRPC, GRPCAddr: "platformd:10443",
			CertFile: "/etc/gatewayd/platformd-client.pem", KeyFile: "/etc/gatewayd/platformd-client-key.pem",
		}},
		{"grpc with a token file", PlatformdConfig{
			Protocol: PlatformdProtocolGRPC, GRPCAddr: "platformd:10443",
			TokenFile: "/etc/gatewayd/platformd.token",
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.config.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
		})
	}
}

func TestConfigValidateDelegatesToEngine(t *testing.T) {
	cfg := validConfig()
	cfg.Routes[0].PoolID = "missing-pool"
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected engine validation error for unknown pool")
	}
}

func TestEngineConfigConversion(t *testing.T) {
	cfg := &Config{
		Enabled: true,
		Listeners: []ListenerConfig{
			{ID: "https", Address: ":8443", Protocols: []string{"h1", "h2"}},
		},
		Routes: []RouteConfig{{
			ID:         "legacy",
			Hosts:      []string{"App.Example.COM"},
			PathPrefix: "/api",
			PoolID:     "backend",
			Auth: AuthConfig{
				Mode:               proxy.AuthModeMTLS,
				RequireIDevID:      true,
				AllowedZones:       []string{"control-plane"},
				BackendZone:        "services",
				RequireAttestation: true,
				AttestationMaxAge:  time.Minute,
				RequiredScopes:     []string{"read"},
				OPAPolicy:          "policy.rego",
				TokenZone:          "edge",
			},
			StripPrefix:  true,
			PreserveHost: true,
		}},
		Pools: []PoolConfig{{
			ID:       "backend",
			Backends: []BackendConfig{{URL: "https://10.0.0.1:8443", Weight: 2}},
			Balancer: "round-robin",
			TLS: PoolTLSConfig{
				TrustClass:     "internal",
				MTLSClientCert: true,
			},
			MaxIdleConnsPerHost: 16,
			IdleConnTimeout:     time.Minute,
		}},
		Defaults: DefaultsConfig{AttestationMaxAge: time.Hour, BackendZone: "services"},
	}

	out := cfg.EngineConfig()
	if len(out.Listeners) != 1 || out.Listeners[0].ID != "https" || len(out.Listeners[0].Protocols) != 2 {
		t.Fatalf("listeners not converted: %+v", out.Listeners)
	}
	route := out.Routes[0]
	if route.PoolID != "backend" || !route.Auth.RequireIDevID || route.Auth.AttestationMaxAge != time.Minute {
		t.Fatalf("route not converted: %+v", route)
	}
	if route.Auth.OPAPolicy != "policy.rego" || route.Auth.RequiredScopes[0] != "read" ||
		route.Auth.TokenZone != "edge" {
		t.Fatalf("route auth not converted: %+v", route.Auth)
	}
	pool := out.Pools[0]
	if pool.TLS.TrustClass != "internal" || !pool.TLS.MTLSClientCert || pool.Backends[0].Weight != 2 {
		t.Fatalf("pool not converted: %+v", pool)
	}
	if out.Defaults.BackendZone != "services" || out.Defaults.AttestationMaxAge != time.Hour {
		t.Fatalf("defaults not converted: %+v", out.Defaults)
	}
}
