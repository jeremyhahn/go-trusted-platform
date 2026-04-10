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

import (
	"context"
	"crypto/tls"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/auth"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
	// Import transport adapters to register them with the platform package
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// CommonFlags contains flags common to all commands
type CommonFlags struct {
	ConfigPath   string
	ContextName  string
	OutputFormat OutputFormat
	Verbose      bool
	NoColor      bool
	GetConfig    func() (*Config, error)
	GetContext   func() (*Context, error)
}

// BaseCommand provides common functionality for all commands
type BaseCommand struct {
	flags   *CommonFlags
	client  platform.Client
	printer *Printer
}

// NewBaseCommand creates a new base command with SDK client
func NewBaseCommand(flags *CommonFlags) (*BaseCommand, error) {
	// Check for nil flags or GetContext
	if flags == nil || flags.GetContext == nil {
		return nil, ErrNoContextSet{}
	}

	// Get context
	ctx, err := flags.GetContext()
	if err != nil {
		return nil, fmt.Errorf("failed to get context: %w", err)
	}

	// Convert CLI context to SDK options
	opts, err := contextToSDKOptions(ctx)
	if err != nil {
		return nil, ErrConnectionFailed{Target: ctx.Name, Err: err}
	}

	// Create SDK client
	client, err := platform.Connect(context.Background(), opts)
	if err != nil {
		return nil, ErrConnectionFailed{Target: ctx.Name, Err: err}
	}

	// Create printer
	printer := NewPrinter(flags.OutputFormat, flags.NoColor)

	return &BaseCommand{
		flags:   flags,
		client:  client,
		printer: printer,
	}, nil
}

// protocolMap provides O(1) lookup from protocol string to platform.Protocol.
var protocolMap = map[string]platform.Protocol{
	"unix":     platform.ProtocolUnix,
	"grpc":     platform.ProtocolGRPC,
	"rest":     platform.ProtocolREST,
	"quic":     platform.ProtocolQUIC,
	"mcp":      platform.ProtocolMCP,
	"embedded": platform.ProtocolEmbedded,
}

// contextToSDKOptions converts a CLI Context to SDK Options.
// Supports all 6 protocols with backward-compatible defaults.
func contextToSDKOptions(ctx *Context) (*platform.Options, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context cannot be nil")
	}

	var opts []platform.Option

	// Resolve the effective protocol
	protoStr := ctx.ResolveProtocol()
	proto, ok := protocolMap[protoStr]
	if !ok {
		return nil, ErrInvalidContext{Context: fmt.Sprintf("unsupported protocol: %s", protoStr)}
	}

	opts = append(opts, platform.WithOnlyProtocol(proto))

	switch ctx.Type {
	case ContextTypeLocal:
		if ctx.Local == nil {
			return nil, fmt.Errorf("local context configuration is missing")
		}
		opts = append(opts, platform.WithUnixSocket(ctx.Local.SocketPath))
		if ctx.Local.GRPCAddr != "" {
			opts = append(opts, platform.WithGRPCAddr(ctx.Local.GRPCAddr))
		}

	case ContextTypeRemote:
		if ctx.Remote == nil {
			return nil, fmt.Errorf("remote context configuration is missing")
		}

		// Set the protocol-specific address
		opts = append(opts, protocolAddress(proto, ctx.Remote.Server)...)

		tlsConfig, err := buildTLSConfig(ctx.Remote)
		if err != nil {
			return nil, err
		}
		if tlsConfig != nil {
			opts = append(opts, platform.WithTLSConfig(tlsConfig))
		}

	case ContextTypeEmbedded:
		// Embedded contexts are handled by the caller providing services
		// via platform.WithEmbeddedServices()

	default:
		return nil, ErrInvalidContext{Context: string(ctx.Type)}
	}

	return platform.NewOptions(opts...), nil
}

// protocolAddress returns the appropriate address option for the given protocol.
func protocolAddress(proto platform.Protocol, server string) []platform.Option {
	switch proto {
	case platform.ProtocolGRPC:
		return []platform.Option{platform.WithGRPCAddr(server)}
	case platform.ProtocolREST:
		return []platform.Option{platform.WithRESTAddr(server)}
	case platform.ProtocolQUIC:
		return []platform.Option{platform.WithQUICAddr(server)}
	case platform.ProtocolMCP:
		return []platform.Option{platform.WithMCPAddr(server)}
	case platform.ProtocolUnix:
		return []platform.Option{platform.WithUnixSocket(server)}
	default:
		return nil
	}
}

// buildTLSConfig creates a TLS configuration from remote context settings
func buildTLSConfig(remote *RemoteContext) (*tls.Config, error) {
	if remote.ClientCert == "" && remote.ClientKey == "" && remote.CACert == "" {
		return nil, nil
	}

	var mtlsOpts []auth.MTLSOption

	if remote.CACert != "" {
		mtlsOpts = append(mtlsOpts, auth.WithCAFile(remote.CACert))
	}

	if remote.ClientCert != "" {
		mtlsOpts = append(mtlsOpts, auth.WithCertFile(remote.ClientCert))
	}

	if remote.ClientKey != "" {
		mtlsOpts = append(mtlsOpts, auth.WithKeyFile(remote.ClientKey))
	}

	// Create mTLS provider to build the TLS config
	provider, err := auth.NewMTLSProvider(mtlsOpts...)
	if err != nil {
		return nil, err
	}

	return provider.GetTLSConfig(), nil
}

// Close closes the client connection
func (b *BaseCommand) Close() error {
	if b.client != nil {
		return b.client.Close()
	}
	return nil
}

// Client returns the platform SDK client
func (b *BaseCommand) Client() platform.Client {
	return b.client
}

// Printer returns the output printer
func (b *BaseCommand) Printer() *Printer {
	return b.printer
}

// Output prints the given value using the configured output format
func (b *BaseCommand) Output(v any) error {
	return b.printer.Print(v)
}

// Context returns a context for gRPC calls
func (b *BaseCommand) Context() context.Context {
	// In the future, this could be enhanced with timeout/deadline from flags
	return context.Background()
}

// Flags returns the common flags
func (b *BaseCommand) Flags() *CommonFlags {
	return b.flags
}
