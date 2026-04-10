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

package quicbaaskms

import (
	"time"
)

// Transport represents the transport type for QuicBaaS KMS connections.
type Transport string

const (
	// TransportEmbedded uses in-process communication (no network overhead).
	TransportEmbedded Transport = "embedded"

	// TransportUnix uses Unix domain sockets for local IPC.
	TransportUnix Transport = "unix"

	// TransportGRPC uses gRPC for high-performance service-to-service communication.
	TransportGRPC Transport = "grpc"

	// TransportREST uses HTTP/HTTPS for web clients and external systems.
	TransportREST Transport = "rest"

	// TransportQUIC uses QUIC for low-latency UDP-based transport.
	TransportQUIC Transport = "quic"

	// TransportMCP uses JSON-RPC 2.0 over TCP (Model Context Protocol).
	TransportMCP Transport = "mcp"
)

// String returns the string representation of the transport type.
func (t Transport) String() string {
	return string(t)
}

// DefaultRequestTimeout is the default timeout for SDK requests.
const DefaultRequestTimeout = 30 * time.Second

// DefaultUnixSocketPath is the default Unix socket path for QuicBaaS.
const DefaultUnixSocketPath = "/run/quicbaas.sock"

// Config holds the configuration for the QuicBaaS KMS adapter.
// Mode is inferred from the presence of Backend:
//   - Backend specified -> remote mode
//   - Backend NOT specified -> embedded mode
type Config struct {
	// Backend is the name of the backend from the backends section.
	// If specified, the adapter operates in remote mode connecting to the
	// specified backend. If not specified, embedded mode is used.
	Backend string `yaml:"backend,omitempty" json:"backend,omitempty"`

	// Transport specifies the transport type (embedded, unix, grpc, rest, quic, mcp).
	// For remote mode, this is typically derived from the backend config.
	// Defaults to embedded if not specified and no backend is set.
	Transport Transport `yaml:"transport,omitempty" json:"transport,omitempty"`

	// Address is the server address for remote transports (grpc, rest, quic, mcp).
	// Format: "host:port" for gRPC/QUIC/MCP, "https://host:port" for REST.
	Address string `yaml:"address,omitempty" json:"address,omitempty"`

	// UnixSocket is the path to the Unix domain socket.
	// Used only when Transport is "unix".
	UnixSocket string `yaml:"unix_socket,omitempty" json:"unix_socket,omitempty"`

	// RequestTimeout is the timeout for SDK requests.
	// Defaults to 30 seconds if not specified.
	RequestTimeout time.Duration `yaml:"request_timeout,omitempty" json:"request_timeout,omitempty"`

	// TLS configuration for secure connections.
	TLS *TLSConfig `yaml:"tls,omitempty" json:"tls,omitempty"`

	// Pool configuration for connection pooling (remote modes).
	Pool *PoolConfig `yaml:"pool,omitempty" json:"pool,omitempty"`
}

// TLSConfig holds TLS configuration for secure connections.
// All remote transports enforce TLS 1.3 with certificate verification.
type TLSConfig struct {
	// CACert is the path to the CA certificate.
	CACert string `yaml:"ca_cert,omitempty" json:"ca_cert,omitempty"`

	// ClientCert is the path to the client certificate.
	ClientCert string `yaml:"client_cert,omitempty" json:"client_cert,omitempty"`

	// ClientKey is the path to the client private key.
	ClientKey string `yaml:"client_key,omitempty" json:"client_key,omitempty"`
}

// PoolConfig holds connection pool configuration for remote transports.
type PoolConfig struct {
	// MaxConnections is the maximum number of connections in the pool.
	MaxConnections int `yaml:"max_connections,omitempty" json:"max_connections,omitempty"`

	// MinConnections is the minimum number of connections to maintain.
	MinConnections int `yaml:"min_connections,omitempty" json:"min_connections,omitempty"`

	// MaxIdleTime is the maximum time a connection can be idle before closing.
	MaxIdleTime time.Duration `yaml:"max_idle_time,omitempty" json:"max_idle_time,omitempty"`
}

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Infer transport if not specified
	if c.Transport == "" {
		if c.Backend != "" {
			// Remote mode - default to gRPC if not specified
			c.Transport = TransportGRPC
		} else {
			// Embedded mode
			c.Transport = TransportEmbedded
		}
	}

	// Set default timeout
	if c.RequestTimeout == 0 {
		c.RequestTimeout = DefaultRequestTimeout
	}

	// Validate based on transport
	switch c.Transport {
	case TransportEmbedded:
		// No additional validation needed for embedded mode
	case TransportUnix:
		if c.UnixSocket == "" {
			return ErrMissingUnixSocket
		}
	case TransportGRPC, TransportREST, TransportQUIC, TransportMCP:
		if c.Address == "" {
			return ErrMissingAddress
		}
		// Remote transports require TLS with a CA certificate for verification
		if c.TLS == nil || c.TLS.CACert == "" {
			return ErrMissingTLSCACert
		}
	default:
		return ErrUnsupportedTransport{Transport: c.Transport}
	}

	return nil
}

// IsEmbedded returns true if the configuration specifies embedded mode.
// Mode is inferred: no backend = embedded, backend specified = remote.
func (c *Config) IsEmbedded() bool {
	return c.Backend == "" && (c.Transport == "" || c.Transport == TransportEmbedded)
}

// IsRemote returns true if the configuration specifies remote mode.
func (c *Config) IsRemote() bool {
	return !c.IsEmbedded()
}

// DefaultConfig returns a default configuration for embedded mode.
func DefaultConfig() *Config {
	return &Config{
		Transport:      TransportEmbedded,
		RequestTimeout: DefaultRequestTimeout,
	}
}

// RemoteConfig creates a configuration for connecting to a remote QuicBaaS KMS service.
func RemoteConfig(address string, transport Transport) *Config {
	return &Config{
		Address:        address,
		Transport:      transport,
		RequestTimeout: DefaultRequestTimeout,
	}
}

// UnixConfig creates a configuration for connecting via Unix socket.
func UnixConfig(socketPath string) *Config {
	return &Config{
		Transport:      TransportUnix,
		UnixSocket:     socketPath,
		RequestTimeout: DefaultRequestTimeout,
	}
}

// GRPCConfig creates a configuration for gRPC transport.
func GRPCConfig(address string) *Config {
	return &Config{
		Address:        address,
		Transport:      TransportGRPC,
		RequestTimeout: DefaultRequestTimeout,
	}
}

// RESTConfig creates a configuration for REST transport.
func RESTConfig(address string) *Config {
	return &Config{
		Address:        address,
		Transport:      TransportREST,
		RequestTimeout: DefaultRequestTimeout,
	}
}

// QUICConfig creates a configuration for QUIC transport.
func QUICConfig(address string) *Config {
	return &Config{
		Address:        address,
		Transport:      TransportQUIC,
		RequestTimeout: DefaultRequestTimeout,
	}
}

// MCPConfig creates a configuration for MCP transport.
func MCPConfig(address string) *Config {
	return &Config{
		Address:        address,
		Transport:      TransportMCP,
		RequestTimeout: DefaultRequestTimeout,
	}
}
