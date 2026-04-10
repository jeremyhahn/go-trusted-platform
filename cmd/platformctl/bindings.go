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

package main

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"

	// Import all transport adapters so they register via init().
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/embedded"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/grpc"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/unix"
)

// protocolAddrSetters provides O(1) dispatch for protocol-specific address options.
var protocolAddrSetters = map[platform.Protocol]func(string) platform.Option{
	platform.ProtocolREST: platform.WithRESTAddr,
	platform.ProtocolGRPC: platform.WithGRPCAddr,
	platform.ProtocolQUIC: platform.WithQUICAddr,
	platform.ProtocolMCP:  platform.WithMCPAddr,
	platform.ProtocolUnix: platform.WithUnixSocket,
}

// ConnectionBinding manages the SDK client connection for Wails.
// All other bindings hold a reference to this and use loadClient()
// to obtain the active client. The client is stored atomically for
// lock-free access from any goroutine.
type ConnectionBinding struct {
	logger *slog.Logger
	client atomic.Pointer[platform.Client]
	ctx    context.Context
}

// NewConnectionBinding creates a new ConnectionBinding.
func NewConnectionBinding(logger *slog.Logger) *ConnectionBinding {
	return &ConnectionBinding{
		logger: logger,
		ctx:    context.Background(),
	}
}

// SetClient atomically replaces the current SDK client. This is used
// by the connection wizard to inject a client after transport construction.
func (c *ConnectionBinding) SetClient(cl *platform.Client) {
	c.logger.Debug("SetClient called", "hasClient", cl != nil)
	c.client.Store(cl)
}

// loadClient returns the current SDK client or a NotConnectedError
// if no client has been set.
func (c *ConnectionBinding) loadClient() (*platform.Client, error) {
	cl := c.client.Load()
	if cl == nil {
		return nil, &NotConnectedError{}
	}
	return cl, nil
}

// IsConnected returns true when a client connection is active.
func (c *ConnectionBinding) IsConnected() bool {
	connected := c.client.Load() != nil
	c.logger.Debug("IsConnected called", "connected", connected)
	return connected
}

// Connect establishes a connection to a platform daemon.
func (c *ConnectionBinding) Connect(proto, address string, tlsOpts map[string]string) error {
	c.logger.Debug("Connect called", "protocol", proto, "address", address)

	p := platform.ParseProtocol(proto)
	if !p.IsValid() {
		return &ConnectError{
			Address: address,
			Err:     &InvalidProtocolError{Protocol: proto},
		}
	}

	opts := []platform.Option{
		platform.WithOnlyProtocol(p),
	}

	// Use map-based dispatch for protocol-specific address options.
	if setter, ok := protocolAddrSetters[p]; ok {
		opts = append(opts, setter(address))
	}

	// TLS is always required for remote connections.
	// The platform CA provides certificates for all services.

	cl, err := platform.NewClient(c.ctx, opts...)
	if err != nil {
		c.logger.Error("Connect failed", "error", err)
		return &ConnectError{Address: address, Err: err}
	}

	c.client.Store(&cl)
	c.logger.Debug("Connect completed", "protocol", proto)
	return nil
}

// Disconnect closes the current client connection and clears the
// client reference.
func (c *ConnectionBinding) Disconnect() error {
	c.logger.Debug("Disconnect called")
	cl := c.client.Load()
	if cl == nil {
		return nil
	}
	err := (*cl).Close()
	c.client.Store(nil)
	if err != nil {
		c.logger.Error("Disconnect failed", "error", err)
		return err
	}
	c.logger.Debug("Disconnect completed")
	return nil
}

// GetVersion returns the build version information.
func (c *ConnectionBinding) GetVersion() map[string]string {
	c.logger.Debug("GetVersion called")
	return map[string]string{
		"version":   version,
		"gitCommit": gitCommit,
		"buildDate": buildDate,
	}
}
