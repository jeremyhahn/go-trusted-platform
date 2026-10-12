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

// Package grpc provides the gRPC transport adapter for the platform SDK.
package grpc

import (
	"context"
	"crypto/tls"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

func init() {
	platform.RegisterProtocol(platform.ProtocolGRPC, Connect)
}

// Adapter implements the transport.Adapter interface for gRPC over TCP.
type Adapter struct {
	conn      *grpc.ClientConn
	connected atomic.Bool
	address   string
}

// Connect establishes a gRPC connection to the platform daemon.
func Connect(ctx context.Context, opts *platform.Options) (transport.Adapter, error) {
	if opts == nil {
		return nil, platform.ErrNilOptions
	}

	if opts.GRPCAddr == "" {
		return nil, platform.ErrEmptyAddress
	}

	// Set defaults
	maxMsgSize := opts.GetMaxMessageSize()

	// Build dial options - TLS is mandatory for gRPC transport
	var dialOpts []grpc.DialOption

	// The recorded handshake state lets calls bound to their channel
	// (transport.WithChannelBinding) read the exporter of the connection
	// they travel on.
	handshake := &atomic.Pointer[tls.ConnectionState]{}
	dialOpts = append(dialOpts,
		grpc.WithTransportCredentials(&recordingCreds{TransportCredentials: credentials.NewTLS(opts.ClientTLSConfig()), state: handshake}),
		grpc.WithChainUnaryInterceptor(bindingInterceptor(handshake)),
	)

	dialOpts = append(dialOpts, grpc.WithDefaultCallOptions(
		grpc.MaxCallRecvMsgSize(maxMsgSize),
		grpc.MaxCallSendMsgSize(maxMsgSize),
	))

	// Inject the bearer token via PerRPCCredentials so every unary /
	// streaming call carries `authorization: Bearer <token>` in its
	// gRPC metadata. The platform's gRPC servers use the same
	// authorization header convention as REST.
	if opts.BearerToken != "" {
		dialOpts = append(dialOpts, grpc.WithPerRPCCredentials(bearerTokenCreds{token: opts.BearerToken}))
	}

	// Connect to gRPC server
	conn, err := grpc.NewClient(opts.GRPCAddr, dialOpts...)
	if err != nil {
		return nil, platform.ErrConnectionFailed{
			Protocol: platform.ProtocolGRPC,
			Target:   opts.GRPCAddr,
			Err:      err,
		}
	}

	a := &Adapter{
		conn:    conn,
		address: opts.GRPCAddr,
	}
	a.connected.Store(true)

	return a, nil
}

// Connection returns the underlying gRPC client connection.
func (a *Adapter) Connection() grpc.ClientConnInterface {
	return a.conn
}

// Close closes the gRPC connection.
func (a *Adapter) Close() error {
	if !a.connected.Load() {
		return nil
	}

	a.connected.Store(false)

	if a.conn != nil {
		err := a.conn.Close()
		a.conn = nil
		if err != nil {
			return platform.ErrCloseFailed{
				Protocol: platform.ProtocolGRPC,
				Err:      err,
			}
		}
	}
	return nil
}

// IsConnected returns true if the adapter is connected.
func (a *Adapter) IsConnected() bool {
	return a.connected.Load()
}

// Target returns the gRPC server address.
func (a *Adapter) Target() string {
	return a.address
}

// Ensure Adapter implements transport.Adapter interface.
var _ transport.Adapter = (*Adapter)(nil)

// bearerTokenCreds implements credentials.PerRPCCredentials so every
// outbound gRPC request carries `authorization: Bearer <token>`. The
// daemon's gRPC interceptors compare this header against the JWT
// signing key.
type bearerTokenCreds struct{ token string }

func (c bearerTokenCreds) GetRequestMetadata(_ context.Context, _ ...string) (map[string]string, error) {
	return map[string]string{"authorization": "Bearer " + c.token}, nil
}

func (c bearerTokenCreds) RequireTransportSecurity() bool {
	// The gRPC transport mandates TLS (see Connect above), so
	// requiring transport security here mirrors that contract.
	return true
}
