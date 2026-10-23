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

package cli

// OutputFormat represents the output format for CLI commands
type OutputFormat string

const (
	OutputFormatTable OutputFormat = "table"
	OutputFormatJSON  OutputFormat = "json"
	OutputFormatYAML  OutputFormat = "yaml"
)

// IsValid checks if the output format is valid
func (o OutputFormat) IsValid() bool {
	switch o {
	case OutputFormatTable, OutputFormatJSON, OutputFormatYAML:
		return true
	default:
		return false
	}
}

// ContextType represents the type of connection context
type ContextType string

const (
	ContextTypeLocal    ContextType = "local"    // Unix socket (root only)
	ContextTypeRemote   ContextType = "remote"   // HTTPS + mTLS
	ContextTypeEmbedded ContextType = "embedded" // In-process embedded service
)

// ValidProtocols contains all supported protocol strings.
var ValidProtocols = map[string]struct{}{
	"unix":     {},
	"grpc":     {},
	"rest":     {},
	"quic":     {},
	"mcp":      {},
	"embedded": {},
}

// DefaultQuicBaaSSocketPath is the default Unix socket path used to dial
// the QuicBaaS daemon (quicbaasd) when no override is configured. It
// matches the colocated installer layout where platformd and quicbaasd
// run side-by-side.
const DefaultQuicBaaSSocketPath = "/run/quicbaas.sock"

// Context represents a connection context (like kubeconfig)
type Context struct {
	Name     string         `yaml:"name" json:"name"`
	Type     ContextType    `yaml:"type" json:"type"`
	Protocol string         `yaml:"protocol,omitempty" json:"protocol,omitempty"` // unix, grpc, rest, quic, mcp, embedded
	Local    *LocalContext  `yaml:"local,omitempty" json:"local,omitempty"`
	Remote   *RemoteContext `yaml:"remote,omitempty" json:"remote,omitempty"`
}

// ResolveProtocol returns the effective protocol for this context.
// Priority: Context.Protocol > RemoteContext.Protocol > type-based default.
func (c *Context) ResolveProtocol() string {
	if c.Protocol != "" {
		return c.Protocol
	}
	if c.Type == ContextTypeRemote && c.Remote != nil && c.Remote.Protocol != "" {
		return c.Remote.Protocol
	}
	switch c.Type {
	case ContextTypeLocal:
		return "unix"
	case ContextTypeRemote:
		return "grpc"
	case ContextTypeEmbedded:
		return "embedded"
	default:
		return "grpc"
	}
}

// ResolveQuicBaaSAddr returns the effective QuicBaaS address for this
// context. The platform daemon (platformd) and the quicbaas daemon
// (quicbaasd) maintain independent connections; this resolver mirrors
// ResolveProtocol but for the QuicBaaS side of that pair.
//
// Priority:
//
//  1. LocalContext.QuicBaaSAddr / RemoteContext.QuicBaaSAddr (operator
//     override).
//  2. For local contexts: DefaultQuicBaaSSocketPath.
//  3. For remote contexts: RemoteContext.Server (colocated daemons share
//     a hostname; only the transport differs).
//
// The empty string is returned when the context has no resolvable
// QuicBaaS address (for example, an embedded context the caller must
// satisfy via PLATFORMCTL_QUICBAAS_ADDR).
func (c *Context) ResolveQuicBaaSAddr() string {
	switch c.Type {
	case ContextTypeLocal:
		if c.Local != nil && c.Local.QuicBaaSAddr != "" {
			return c.Local.QuicBaaSAddr
		}
		return DefaultQuicBaaSSocketPath
	case ContextTypeRemote:
		if c.Remote == nil {
			return ""
		}
		if c.Remote.QuicBaaSAddr != "" {
			return c.Remote.QuicBaaSAddr
		}
		return c.Remote.Server
	default:
		return ""
	}
}

// ResolveQuicBaaSTransport returns the transport the QuicBaaS SDK
// client should use to reach quicbaasd. Priority:
//
//  1. LocalContext.QuicBaaSTransport / RemoteContext.QuicBaaSTransport.
//  2. For local contexts: "unix".
//  3. For remote contexts: ResolveProtocol() (mirror platformd transport).
//
// The empty string is returned when the context cannot determine a
// transport; callers should treat that as "use SDK auto-detection".
func (c *Context) ResolveQuicBaaSTransport() string {
	switch c.Type {
	case ContextTypeLocal:
		if c.Local != nil && c.Local.QuicBaaSTransport != "" {
			return c.Local.QuicBaaSTransport
		}
		return "unix"
	case ContextTypeRemote:
		if c.Remote == nil {
			return ""
		}
		if c.Remote.QuicBaaSTransport != "" {
			return c.Remote.QuicBaaSTransport
		}
		return c.ResolveProtocol()
	default:
		return ""
	}
}

// LocalContext contains configuration for local Unix socket connections
type LocalContext struct {
	SocketPath string `yaml:"socket_path" json:"socket_path"`
	// GRPCAddr is the local gRPC server address for streaming RPCs.
	// Defaults to "localhost:10443" (daemon's default gRPC port).
	GRPCAddr string `yaml:"grpc_addr,omitempty" json:"grpc_addr,omitempty"`

	// QuicBaaSAddr is the local QuicBaaS daemon address. platformd and
	// quicbaasd run as independent processes; the CLI maintains a
	// separate connection to each. Defaults to
	// DefaultQuicBaaSSocketPath ("/run/quicbaas.sock").
	QuicBaaSAddr string `yaml:"quicbaas_addr,omitempty" json:"quicbaas_addr,omitempty"`
	// QuicBaaSTransport overrides the transport used to dial
	// quicbaasd. One of: unix, grpc, rest, quic, mcp, embedded.
	// Defaults to "unix" for local contexts.
	QuicBaaSTransport string `yaml:"quicbaas_transport,omitempty" json:"quicbaas_transport,omitempty"`
	// QuicBaaSCACert, QuicBaaSClientCert and QuicBaaSClientKey are the
	// TLS files of the quicbaas connection. The quicbaas SDK refuses every
	// connection without TLS, its Unix transport included, so a verb that
	// opens the quicbaas client fails without them. platformd's own Unix
	// socket authenticates by peer credentials and needs none.
	QuicBaaSCACert     string `yaml:"quicbaas_ca_cert,omitempty" json:"quicbaas_ca_cert,omitempty"`
	QuicBaaSClientCert string `yaml:"quicbaas_client_cert,omitempty" json:"quicbaas_client_cert,omitempty"`
	QuicBaaSClientKey  string `yaml:"quicbaas_client_key,omitempty" json:"quicbaas_client_key,omitempty"`
}

// RemoteContext contains configuration for remote HTTPS connections
type RemoteContext struct {
	Server     string `yaml:"server" json:"server"`                         // e.g., https://platform.example.com:8443
	Protocol   string `yaml:"protocol,omitempty" json:"protocol,omitempty"` // Override protocol (default: grpc)
	CACert     string `yaml:"ca_cert" json:"ca_cert"`                       // Path to CA certificate
	ClientCert string `yaml:"client_cert" json:"client_cert"`
	ClientKey  string `yaml:"client_key" json:"client_key"`
	Token      string `yaml:"token,omitempty" json:"token,omitempty" secret:"true"` // Bearer token for REST/MCP/QUIC
	// ServerName overrides the SNI / certificate verification hostname.
	// When empty the host portion of Server is used.
	ServerName string `yaml:"server_name,omitempty" json:"server_name,omitempty"`

	// QuicBaaSAddr is the remote QuicBaaS daemon address. When the
	// remote site colocates platformd and quicbaasd this can be left
	// empty and Server is reused; otherwise it must be set to the
	// quicbaasd ingress URL.
	QuicBaaSAddr string `yaml:"quicbaas_addr,omitempty" json:"quicbaas_addr,omitempty"`
	// QuicBaaSTransport overrides the transport used to dial
	// quicbaasd. One of: unix, grpc, rest, quic, mcp, embedded.
	// Defaults to the platformd transport (Protocol).
	QuicBaaSTransport string `yaml:"quicbaas_transport,omitempty" json:"quicbaas_transport,omitempty"`
}
