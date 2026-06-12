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

package bmc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
)

// ipmiBMCPort is the standard IPMI over LAN port. When a Config carries
// this port number (or zero) in a context where HTTPS connectivity is
// needed, httpsEndpoint falls back to port 443.
const ipmiBMCPort = 623

// TLSProvider produces a *tls.Config for a specific BMC endpoint.
//
// It is wired by the daemon as a closure over the platform trust
// resolver's ClassBMC chain, allowing pkg/bmc to build verified TLS
// connections against BMCs without coupling the package to pkg/trust.
// The endpoint argument is a host:port string derived from the Config.
type TLSProvider interface {
	TLSConfig(ctx context.Context, endpoint string) (*tls.Config, error)
}

// ErrTLSProvider is returned when a TLSProvider call fails.
type ErrTLSProvider struct {
	Endpoint string
	Err      error
}

func (e ErrTLSProvider) Error() string {
	if e.Endpoint != "" {
		return fmt.Sprintf("bmc: TLS provider failed for %s: %v", e.Endpoint, e.Err)
	}
	return fmt.Sprintf("bmc: TLS provider failed: %v", e.Err)
}

func (e ErrTLSProvider) Unwrap() error { return e.Err }

// httpsEndpoint derives the host:port string used when building a TLS
// connection to a BMC. If cfg.Port is the standard IPMI port (623) or
// zero — both indicate the config was originally created for IPMI and
// was not updated for HTTPS use — the port is overridden to 443.
// Otherwise cfg.Port is preserved as-is.
func httpsEndpoint(cfg *Config) string {
	port := cfg.Port
	if port == ipmiBMCPort || port == 0 {
		port = 443
	}
	return net.JoinHostPort(cfg.Address, strconv.Itoa(port))
}

// HTTPSEndpoint returns the host:port string suitable for HTTPS connections
// to the BMC described by cfg. It is the exported form of httpsEndpoint for
// callers outside the bmc package (e.g. pkg/app).
func HTTPSEndpoint(cfg *Config) string {
	return httpsEndpoint(cfg)
}

// BuildTLSConfig returns a *tls.Config suitable for connecting to the
// BMC described by cfg.
//
// Provider path: when cfg.TLS is non-nil, TLSConfig is called on the
// provider with the HTTPS endpoint derived from cfg. The provider's
// result is returned directly.
//
// Secure default: when cfg.TLS is nil, a standard verified TLS config
// is returned (system roots, TLS 1.2+, no InsecureSkipVerify). Connections
// to BMCs presenting self-signed or private-CA certificates will fail;
// operators must supply a TLSProvider (e.g. via the platform trust resolver
// ClassBMC scope with an spki, ca-file, or tofu strategy).
func BuildTLSConfig(ctx context.Context, cfg *Config) (*tls.Config, error) {
	if cfg.TLS != nil {
		endpoint := httpsEndpoint(cfg)
		tlsCfg, err := cfg.TLS.TLSConfig(ctx, endpoint)
		if err != nil {
			return nil, ErrTLSProvider{Endpoint: endpoint, Err: err}
		}
		return tlsCfg, nil
	}

	// No provider configured: return a secure system-roots default.
	// Callers must inject a TLSProvider for BMCs with private-CA or
	// self-signed certificates.
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
	}, nil
}
