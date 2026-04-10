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

package quicbaas

import (
	"time"
)

// Transport represents the transport type for QuicBaaS connections.
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
)

// DefaultRequestTimeout is the default timeout for SDK requests.
const DefaultRequestTimeout = 30 * time.Second

// Config holds the configuration for the QuicBaaS adapter.
// Mode is inferred from the presence of Backend:
//   - Backend specified → remote mode
//   - Backend NOT specified → embedded mode
type Config struct {
	// Backend is the name of the backend from the backends section.
	// If specified, the adapter operates in remote mode connecting to the
	// specified backend. If not specified, embedded mode is used.
	Backend string `yaml:"backend,omitempty" json:"backend,omitempty"`

	// Transport specifies the transport type (embedded, unix, grpc, rest, quic).
	// For remote mode, this is typically derived from the backend config.
	// Defaults to embedded if not specified and no backend is set.
	Transport Transport `yaml:"transport,omitempty" json:"transport,omitempty"`

	// Address is the server address for remote transports (grpc, rest, quic).
	// Format: "host:port" for gRPC/QUIC, "https://host:port" for REST.
	Address string `yaml:"address,omitempty" json:"address,omitempty"`

	// UnixSocket is the path to the Unix domain socket.
	// Used only when Transport is "unix".
	UnixSocket string `yaml:"unix_socket,omitempty" json:"unix_socket,omitempty"`

	// DataDir is the data directory for embedded mode.
	// Only used when Transport is "embedded".
	DataDir string `yaml:"data_dir,omitempty" json:"data_dir,omitempty"`

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
// Secret values should use go-quicbaas secrets resolution:
//   - kms://path/to/secret - Local QuicBaaS KMS lookup
//   - remote-kms://host:port/path - Remote QuicBaaS secrets lookup
//   - auto - Auto-generate on first boot
type TLSConfig struct {
	// CACert is the path or KMS reference to the CA certificate.
	CACert string `yaml:"ca_cert,omitempty" json:"ca_cert,omitempty"`

	// ClientCert is the path or KMS reference to the client certificate.
	ClientCert string `yaml:"client_cert,omitempty" json:"client_cert,omitempty"`

	// ClientKey is the path or KMS reference to the client private key.
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
	case TransportGRPC, TransportREST, TransportQUIC:
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

// RemoteConfig creates a configuration for connecting to a remote QuicBaaS cluster.
func RemoteConfig(address string, transport Transport) *Config {
	return &Config{
		Address:        address,
		Transport:      transport,
		RequestTimeout: DefaultRequestTimeout,
	}
}
