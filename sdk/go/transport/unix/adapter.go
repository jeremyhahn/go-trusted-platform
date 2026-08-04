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

// Package unix provides the Unix domain socket transport adapter for the platform SDK.
package unix

import (
	"context"
	"os"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

func init() {
	platform.RegisterProtocol(platform.ProtocolUnix, Connect)
}

// Adapter implements the transport.Adapter interface for gRPC over Unix domain socket.
type Adapter struct {
	conn       *grpc.ClientConn
	connected  atomic.Bool
	socketPath string
}

// Connect establishes a gRPC connection over Unix domain socket to the platform daemon.
func Connect(ctx context.Context, opts *platform.Options) (transport.Adapter, error) {
	if opts == nil {
		return nil, platform.ErrNilOptions
	}

	socketPath := opts.UnixSocket
	if socketPath == "" {
		socketPath = platform.DefaultUnixSocket
	}

	// Check if socket exists
	if _, err := os.Stat(socketPath); err != nil {
		return nil, platform.ErrConnectionFailed{
			Protocol: platform.ProtocolUnix,
			Target:   socketPath,
			Err:      err,
		}
	}

	// Set defaults
	maxMsgSize := opts.GetMaxMessageSize()

	// Connect to gRPC server over Unix domain socket
	target := "unix://" + socketPath

	conn, err := grpc.NewClient(target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMsgSize),
			grpc.MaxCallSendMsgSize(maxMsgSize),
		),
	)
	if err != nil {
		return nil, platform.ErrConnectionFailed{
			Protocol: platform.ProtocolUnix,
			Target:   socketPath,
			Err:      err,
		}
	}

	a := &Adapter{
		conn:       conn,
		socketPath: socketPath,
	}
	a.connected.Store(true)

	return a, nil
}

// Connection returns the underlying gRPC client connection.
func (a *Adapter) Connection() grpc.ClientConnInterface {
	return a.conn
}

// Close closes the Unix socket connection.
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
				Protocol: platform.ProtocolUnix,
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

// Target returns the Unix socket path.
func (a *Adapter) Target() string {
	return a.socketPath
}

// Ensure Adapter implements transport.Adapter interface.
var _ transport.Adapter = (*Adapter)(nil)
