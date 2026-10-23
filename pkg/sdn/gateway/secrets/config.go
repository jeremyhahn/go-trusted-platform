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

package secrets

import (
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/sdkclient"
)

// DefaultTimeout bounds one reference resolution (dial, read, close) when
// the section sets none.
const DefaultTimeout = 10 * time.Second

// Config is the gatewayd `secret-store:` section: where the platform
// secret store (quicbaasd's KMS secrets service) is and how to reach it.
// The section is optional; without it every kms:// reference
// in the configuration fails closed at service start. It is deliberately
// not called `secrets:` — that key is platformd's resolver switchboard and
// a gateway node's configuration file carries both.
type Config struct {
	// QuicBaaSAddr is the quicbaasd address (host:port, or a .sock path).
	QuicBaaSAddr string `yaml:"quicbaas-addr" json:"quicbaas_addr" mapstructure:"quicbaas-addr"`

	// QuicBaaSTransport selects the SDK transport: unix, rest, quic or mcp.
	// Empty (or grpc) lets the SDK auto-detect from QuicBaaSAddr.
	QuicBaaSTransport string `yaml:"quicbaas-transport,omitempty" json:"quicbaas_transport,omitempty" mapstructure:"quicbaas-transport"`

	// Timeout bounds one reference resolution. Zero means DefaultTimeout.
	Timeout time.Duration `yaml:"timeout,omitempty" json:"timeout,omitempty" mapstructure:"timeout"`
}

// knownTransports are the names QuicBaaSTransport accepts besides empty.
var knownTransports = map[string]struct{}{
	"grpc":                  {},
	sdkclient.TransportUnix: {},
	sdkclient.TransportREST: {},
	sdkclient.TransportQUIC: {},
	sdkclient.TransportMCP:  {},
}

// Validate checks the section.
func (c *Config) Validate() error {
	if c.QuicBaaSAddr == "" {
		return &ErrConfigInvalid{Field: "quicbaas-addr", Reason: "required"}
	}
	if c.QuicBaaSTransport != "" {
		if _, ok := knownTransports[c.QuicBaaSTransport]; !ok {
			return &ErrConfigInvalid{Field: "quicbaas-transport", Reason: "must be grpc, unix, rest, quic or mcp"}
		}
	}
	if c.Timeout < 0 {
		return &ErrConfigInvalid{Field: "timeout", Reason: "must not be negative"}
	}
	return nil
}

// EffectiveTimeout returns Timeout, or DefaultTimeout when unset.
func (c *Config) EffectiveTimeout() time.Duration {
	if c.Timeout <= 0 {
		return DefaultTimeout
	}
	return c.Timeout
}
