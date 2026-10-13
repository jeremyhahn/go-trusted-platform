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

package embedded

import (
	"context"
	"fmt"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/pollstream"
)

// handlerFunc is the signature for all unary gRPC service method handlers.
type handlerFunc func(ctx context.Context, req interface{}) (interface{}, error)

// embeddedClientConn implements grpc.ClientConnInterface by dispatching
// gRPC method strings to in-process service handlers using O(1) map lookup.
type embeddedClientConn struct {
	handlers map[string]handlerFunc
	caller   func(context.Context) context.Context
}

// newEmbeddedClientConn creates a new embedded client connection from a
// ServiceRegistry, building the O(1) dispatch map for all registered services.
func newEmbeddedClientConn(registry *ServiceRegistry) *embeddedClientConn {
	return &embeddedClientConn{
		handlers: buildHandlerMap(registry),
		caller:   registry.CallerContext,
	}
}

// Invoke implements grpc.ClientConnInterface.Invoke by dispatching the gRPC
// method to the corresponding in-process service handler. The response is
// copied into reply via protobuf marshal/unmarshal to maintain the same
// serialization semantics as a real gRPC transport. The registry's
// CallerContext, if set, supplies the caller's identity first.
func (c *embeddedClientConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...grpc.CallOption) error {
	// An in-process call has no connection at all, so a call that must be
	// bound to its connection's channel is refused before dispatch.
	if _, bound := transport.ChannelBindingFrom(opts); bound {
		return &transport.ErrChannelBindingUnavailable{
			Transport: platform.ProtocolEmbedded.String(),
			Reason:    "an in-process call has no TLS connection to bind to",
		}
	}

	handler, ok := c.handlers[method]
	if !ok {
		return status.Errorf(codes.Unimplemented, "embedded: method %s not registered", method)
	}

	if c.caller != nil {
		ctx = c.caller(ctx)
	}

	resp, err := handler(ctx, args)
	if err != nil {
		return err
	}

	if resp == nil {
		return nil
	}

	return copyProtoMessage(resp, reply)
}

// NewStream implements grpc.ClientConnInterface.NewStream. The streams the
// pollstream package knows are followed by long-polling their unary poll
// method in process; no transport timeout bounds an in-process call, so each
// poll waits the longest the service allows. Any other stream is
// Unimplemented.
func (c *embeddedClientConn) NewStream(ctx context.Context, _ *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return pollstream.NewStream(ctx, c, method, 0, opts...)
}

// copyProtoMessage copies a protobuf message from src to dst via marshal/unmarshal.
// This ensures the same serialization behavior as a real gRPC transport.
func copyProtoMessage(src, dst interface{}) error {
	srcMsg, ok := src.(proto.Message)
	if !ok {
		return status.Errorf(codes.Internal, "embedded: source is not a proto.Message: %T", src)
	}

	dstMsg, ok := dst.(proto.Message)
	if !ok {
		return status.Errorf(codes.Internal, "embedded: destination is not a proto.Message: %T", dst)
	}

	data, err := proto.Marshal(srcMsg)
	if err != nil {
		return status.Errorf(codes.Internal, "embedded: failed to marshal response: %v", err)
	}

	if err := proto.Unmarshal(data, dstMsg); err != nil {
		return status.Errorf(codes.Internal, "embedded: failed to unmarshal response: %v", err)
	}

	return nil
}

// MethodCount returns the number of registered handler methods.
// This is useful for testing and diagnostics.
func (c *embeddedClientConn) MethodCount() int {
	return len(c.handlers)
}

// HasMethod checks if a specific gRPC method is registered in the dispatch map.
func (c *embeddedClientConn) HasMethod(method string) bool {
	_, ok := c.handlers[method]
	return ok
}

// String returns a human-readable representation.
func (c *embeddedClientConn) String() string {
	return fmt.Sprintf("embeddedClientConn{methods: %d}", len(c.handlers))
}

// Ensure embeddedClientConn implements grpc.ClientConnInterface.
var _ grpc.ClientConnInterface = (*embeddedClientConn)(nil)
