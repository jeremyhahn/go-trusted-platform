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

package grpc

import (
	"context"
	"crypto/tls"
	"net"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// recordingCreds wraps the adapter's TLS credentials and records the
// connection state of the latest completed client handshake, so a call
// bound to its channel (transport.WithChannelBinding) can read the
// exporter of the connection it is about to travel on. The client
// connection keeps one transport to the daemon; if it reconnects between
// the binding and the send, the daemon sees a different exporter and
// refuses the proof, so a race fails closed.
type recordingCreds struct {
	credentials.TransportCredentials
	state *atomic.Pointer[tls.ConnectionState]
}

func (c *recordingCreds) ClientHandshake(ctx context.Context, authority string, rawConn net.Conn) (net.Conn, credentials.AuthInfo, error) {
	conn, info, err := c.TransportCredentials.ClientHandshake(ctx, authority, rawConn)
	if err != nil {
		return conn, info, err
	}
	if tlsInfo, ok := info.(credentials.TLSInfo); ok {
		state := tlsInfo.State
		c.state.Store(&state)
	}
	return conn, info, nil
}

// Clone shares the recorded state: gRPC clones credentials per channel,
// and every clone must report into the same place.
func (c *recordingCreds) Clone() credentials.TransportCredentials {
	return &recordingCreds{TransportCredentials: c.TransportCredentials.Clone(), state: c.state}
}

// bindingInterceptor completes calls that carry a channel-binding option:
// it waits until the client connection is ready, hands the binding of its
// TLS connection to the option's BindFunc, then sends the request the
// BindFunc completed. Calls without the option pass straight through.
func bindingInterceptor(state *atomic.Pointer[tls.ConnectionState]) grpc.UnaryClientInterceptor {
	return func(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
		bind, ok := transport.ChannelBindingFrom(opts)
		if !ok {
			return invoker(ctx, method, req, reply, cc, opts...)
		}
		if err := awaitReady(ctx, cc); err != nil {
			return err
		}
		if err := transport.BindChannel(ctx, platform.ProtocolGRPC.String(), state.Load(), bind); err != nil {
			return err
		}
		return invoker(ctx, method, req, reply, cc, opts...)
	}
}

// awaitReady connects cc and waits until it is ready, so the recorded
// handshake is the one of the transport the call will use.
func awaitReady(ctx context.Context, cc *grpc.ClientConn) error {
	cc.Connect()
	for {
		current := cc.GetState()
		switch current {
		case connectivity.Ready:
			return nil
		case connectivity.TransientFailure, connectivity.Shutdown:
			return &transport.ErrChannelBindingUnavailable{
				Transport: platform.ProtocolGRPC.String(),
				Reason:    "the connection is " + current.String(),
			}
		}
		if !cc.WaitForStateChange(ctx, current) {
			return &transport.ErrChannelBindingUnavailable{
				Transport: platform.ProtocolGRPC.String(),
				Reason:    "the connection did not become ready",
				Cause:     ctx.Err(),
			}
		}
	}
}
