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

package platform

import (
	"crypto/tls"
	"time"
)

// Default configuration values.
const (
	// DefaultTimeout is the default connection timeout.
	DefaultTimeout = 5 * time.Second

	// DefaultUnixSocket is the default Unix socket path for the daemon.
	DefaultUnixSocket = "/run/platformd.sock"

	// DefaultGRPCPort is the default gRPC port.
	DefaultGRPCPort = "10443"

	// DefaultRESTPort is the default REST API port.
	DefaultRESTPort = "8443"

	// DefaultQUICPort is the default QUIC port.
	DefaultQUICPort = "9444"

	// DefaultMCPPort is the default MCP port.
	DefaultMCPPort = "9445"

	// DefaultMaxMessageSize is the default maximum gRPC message size (4MB).
	DefaultMaxMessageSize = 4 * 1024 * 1024
)

// Options contains configuration for establishing a client connection.
type Options struct {
	// UnixSocket is the path to the Unix domain socket.
	// Used for local connections (requires root privileges).
	UnixSocket string

	// GRPCAddr is the gRPC server address (host:port).
	GRPCAddr string

	// RESTAddr is the REST API server address (host:port).
	RESTAddr string

	// QUICAddr is the QUIC server address (host:port).
	QUICAddr string

	// MCPAddr is the MCP server address (host:port).
	MCPAddr string

	// TLSConfig is the TLS configuration for secure connections. If nil,
	// the system roots verify the server. Connections never drop below
	// TLS 1.3 (see ClientTLSConfig).
	TLSConfig *tls.Config

	// TLSServerName overrides the SNI / certificate verification hostname
	// used when establishing TLS connections. When empty the host portion
	// of the configured address is used. Useful when the certificate's CN /
	// SAN does not match the dialed address (e.g. dialing by IP, or routing
	// through a proxy).
	TLSServerName string

	// BearerToken is an optional bearer/JWT token attached to every
	// outbound RPC. REST sends an `Authorization: Bearer` header, gRPC
	// injects metadata via PerRPCCredentials, QUIC frames it into each
	// request, and MCP sends the header over https:// only. The token is
	// never sent over plaintext: MCP refuses an http:// address when it is
	// set. Unix (SO_PEERCRED) and Embedded (in-process) refuse it, along
	// with TLSConfig and TLSServerName, with ErrUnsupportedOption.
	BearerToken string

	// Timeout is the connection timeout.
	// Defaults to DefaultTimeout if not set.
	Timeout time.Duration

	// MaxMessageSize is the maximum gRPC message size.
	// Defaults to DefaultMaxMessageSize if not set.
	MaxMessageSize int

	// PreferredProtocol specifies a preferred protocol to try first.
	// If empty, the default priority order is used (Unix > gRPC > REST > QUIC > MCP).
	PreferredProtocol Protocol

	// OnlyProtocol restricts connection to a single protocol.
	// If set, only this protocol will be attempted.
	OnlyProtocol Protocol

	// EmbeddedServices holds the service registry for embedded transport.
	// This is an opaque value that is passed to the embedded transport adapter.
	// Type: *embedded.ServiceRegistry (stored as interface{} to avoid circular import).
	EmbeddedServices interface{}

	// QuicBaaSAddr is the address of the QuicBaaS daemon (quicbaasd).
	// platformd and quicbaasd are independent processes; the platform
	// SDK client maintains a separate connection to quicbaasd alongside
	// the platformd connection. Empty means the QuicBaaS client is not
	// constructed.
	QuicBaaSAddr string

	// QuicBaaSTransport selects the transport used to dial quicbaasd.
	// Accepted values: "unix", "grpc", "rest", "quic", "mcp",
	// "embedded". Empty defers to the go-quicbaas SDK auto-detection
	// rules (HTTP URLs -> REST, .sock paths -> Unix, otherwise gRPC).
	QuicBaaSTransport string

	// QuicBaaSTLSConfig is the TLS configuration of the quicbaasd
	// connection. The go-quicbaas SDK refuses every transport without
	// TLS, the Unix one included (gRPC over TLS on the socket), so a
	// QuicBaaSAddr without it fails with ErrQuicBaaSTLSNotConfigured.
	// TLSConfig is not reused: it belongs to the platformd connection.
	QuicBaaSTLSConfig *tls.Config
}

// Option is a functional option for configuring Options.
type Option func(*Options)

// NewOptions creates a new Options with defaults applied.
func NewOptions(opts ...Option) *Options {
	o := &Options{
		UnixSocket:     DefaultUnixSocket,
		Timeout:        DefaultTimeout,
		MaxMessageSize: DefaultMaxMessageSize,
	}

	for _, opt := range opts {
		opt(o)
	}

	return o
}

// WithUnixSocket sets the Unix socket path.
func WithUnixSocket(path string) Option {
	return func(o *Options) {
		o.UnixSocket = path
	}
}

// WithGRPCAddr sets the gRPC server address.
func WithGRPCAddr(addr string) Option {
	return func(o *Options) {
		o.GRPCAddr = addr
	}
}

// WithRESTAddr sets the REST API server address.
func WithRESTAddr(addr string) Option {
	return func(o *Options) {
		o.RESTAddr = addr
	}
}

// WithQUICAddr sets the QUIC server address.
func WithQUICAddr(addr string) Option {
	return func(o *Options) {
		o.QUICAddr = addr
	}
}

// WithMCPAddr sets the MCP server address.
func WithMCPAddr(addr string) Option {
	return func(o *Options) {
		o.MCPAddr = addr
	}
}

// WithTLSConfig sets the TLS configuration.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(o *Options) {
		o.TLSConfig = cfg
	}
}

// WithTLSServerName overrides the SNI / certificate verification hostname.
// When set the value is propagated into the TLS configuration of every
// TLS transport adapter (REST, gRPC, QUIC, and MCP over https://) so the
// client honours the name regardless of the dialed address.
func WithTLSServerName(name string) Option {
	return func(o *Options) {
		o.TLSServerName = name
	}
}

// WithBearerToken sets the bearer/JWT token attached to every outbound
// RPC as `Authorization: Bearer <token>` (or the protocol equivalent).
// REST, gRPC and QUIC send it over TLS, and MCP over https:// only.
// Unix and Embedded refuse it with ErrUnsupportedOption.
func WithBearerToken(token string) Option {
	return func(o *Options) {
		o.BearerToken = token
	}
}

// WithTimeout sets the connection timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *Options) {
		o.Timeout = d
	}
}

// WithMaxMessageSize sets the maximum message size.
func WithMaxMessageSize(size int) Option {
	return func(o *Options) {
		o.MaxMessageSize = size
	}
}

// WithPreferredProtocol sets the preferred protocol.
func WithPreferredProtocol(p Protocol) Option {
	return func(o *Options) {
		o.PreferredProtocol = p
	}
}

// WithOnlyProtocol restricts to a single protocol.
func WithOnlyProtocol(p Protocol) Option {
	return func(o *Options) {
		o.OnlyProtocol = p
	}
}

// WithEmbeddedServices provides a service registry for in-process transport.
// The value must be a *embedded.ServiceRegistry.
func WithEmbeddedServices(registry interface{}) Option {
	return func(o *Options) {
		o.EmbeddedServices = registry
	}
}

// WithQuicBaaSAddr sets the QuicBaaS daemon address. When non-empty
// the platform SDK Client constructs a separate quicbaas SDK client
// connection alongside the platformd connection. The two connections
// are independent so callers can mix-and-match transports per daemon.
func WithQuicBaaSAddr(addr string) Option {
	return func(o *Options) {
		o.QuicBaaSAddr = addr
	}
}

// WithQuicBaaSTransport selects the transport used to dial quicbaasd.
// Accepted values: "unix", "grpc", "rest", "quic", "mcp",
// "embedded". Empty defers to the go-quicbaas SDK auto-detection
// rules.
func WithQuicBaaSTransport(transport string) Option {
	return func(o *Options) {
		o.QuicBaaSTransport = transport
	}
}

// WithQuicBaaSTLSConfig sets the TLS configuration of the quicbaasd
// connection: the CA that verifies quicbaasd and, for mTLS, the client
// certificate. It is required whenever WithQuicBaaSAddr is set.
func WithQuicBaaSTLSConfig(cfg *tls.Config) Option {
	return func(o *Options) {
		o.QuicBaaSTLSConfig = cfg
	}
}

// Validate validates the options and returns an error if invalid.
func (o *Options) Validate() error {
	if o.OnlyProtocol != ProtocolUnknown && !o.OnlyProtocol.IsValid() {
		return ErrInvalidOptions{Field: "OnlyProtocol", Reason: "invalid protocol value"}
	}

	if o.PreferredProtocol != ProtocolUnknown && !o.PreferredProtocol.IsValid() {
		return ErrInvalidOptions{Field: "PreferredProtocol", Reason: "invalid protocol value"}
	}

	if o.Timeout < 0 {
		return ErrInvalidOptions{Field: "Timeout", Reason: "cannot be negative"}
	}

	if o.MaxMessageSize < 0 {
		return ErrInvalidOptions{Field: "MaxMessageSize", Reason: "cannot be negative"}
	}

	return nil
}

// GetTimeout returns the timeout, defaulting to DefaultTimeout if not set.
func (o *Options) GetTimeout() time.Duration {
	if o.Timeout == 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

// GetMaxMessageSize returns the max message size, defaulting if not set.
func (o *Options) GetMaxMessageSize() int {
	if o.MaxMessageSize == 0 {
		return DefaultMaxMessageSize
	}
	return o.MaxMessageSize
}

// HasUnixSocket returns true if a Unix socket path is configured.
func (o *Options) HasUnixSocket() bool {
	return o.UnixSocket != ""
}

// HasGRPCAddr returns true if a gRPC address is configured.
func (o *Options) HasGRPCAddr() bool {
	return o.GRPCAddr != ""
}

// HasRESTAddr returns true if a REST address is configured.
func (o *Options) HasRESTAddr() bool {
	return o.RESTAddr != ""
}

// HasQUICAddr returns true if a QUIC address is configured.
func (o *Options) HasQUICAddr() bool {
	return o.QUICAddr != ""
}

// HasMCPAddr returns true if an MCP address is configured.
func (o *Options) HasMCPAddr() bool {
	return o.MCPAddr != ""
}

// HasEmbeddedServices returns true if embedded services are configured.
func (o *Options) HasEmbeddedServices() bool {
	return o.EmbeddedServices != nil
}

// HasQuicBaaSAddr returns true if a QuicBaaS address is configured.
func (o *Options) HasQuicBaaSAddr() bool {
	return o.QuicBaaSAddr != ""
}

// ClientTLSConfig returns the TLS configuration every TLS transport dials
// with: a clone of TLSConfig (or an empty config using the system roots),
// raised to at least TLS 1.3, with TLSServerName applied when set. The
// caller's TLSConfig is never modified.
func (o *Options) ClientTLSConfig() *tls.Config {
	cfg := &tls.Config{}
	if o.TLSConfig != nil {
		cfg = o.TLSConfig.Clone()
	}
	if cfg.MinVersion < tls.VersionTLS13 {
		cfg.MinVersion = tls.VersionTLS13
	}
	if o.TLSServerName != "" {
		cfg.ServerName = o.TLSServerName
	}
	return cfg
}

// CredentialOptions names the credential-bearing options that are set:
// BearerToken, TLSConfig and TLSServerName, in that order. A transport that
// cannot honour them uses this to refuse them instead of dropping them.
func (o *Options) CredentialOptions() []string {
	var set []string
	if o.BearerToken != "" {
		set = append(set, "BearerToken")
	}
	if o.TLSConfig != nil {
		set = append(set, "TLSConfig")
	}
	if o.TLSServerName != "" {
		set = append(set, "TLSServerName")
	}
	return set
}
