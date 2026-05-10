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

// LocalContext contains configuration for local Unix socket connections
type LocalContext struct {
	SocketPath string `yaml:"socket_path" json:"socket_path"`
	// GRPCAddr is the local gRPC server address for streaming RPCs.
	// Defaults to "localhost:10443" (daemon's default gRPC port).
	GRPCAddr string `yaml:"grpc_addr,omitempty" json:"grpc_addr,omitempty"`
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
}
