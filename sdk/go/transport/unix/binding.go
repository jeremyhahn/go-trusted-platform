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

package unix

import (
	"context"

	"google.golang.org/grpc"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// refuseChannelBinding refuses calls that carry a channel-binding option
// (transport.WithChannelBinding) before anything is sent: a Unix socket
// carries no TLS connection, so there is no exporter to bind a proof to,
// and the daemon refuses such calls on this transport by design (see
// docs/device/architecture.md). Other calls pass straight through.
func refuseChannelBinding(ctx context.Context, method string, req, reply any, cc *grpc.ClientConn, invoker grpc.UnaryInvoker, opts ...grpc.CallOption) error {
	if _, bound := transport.ChannelBindingFrom(opts); bound {
		return &transport.ErrChannelBindingUnavailable{
			Transport: platform.ProtocolUnix.String(),
			Reason:    "a Unix socket carries no TLS connection to bind to",
		}
	}
	return invoker(ctx, method, req, reply, cc, opts...)
}
