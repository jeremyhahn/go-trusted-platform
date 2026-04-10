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
)

// handlerFunc is the signature for all unary gRPC service method handlers.
type handlerFunc func(ctx context.Context, req interface{}) (interface{}, error)

// embeddedClientConn implements grpc.ClientConnInterface by dispatching
// gRPC method strings to in-process service handlers using O(1) map lookup.
type embeddedClientConn struct {
	handlers map[string]handlerFunc
}

// newEmbeddedClientConn creates a new embedded client connection from a
// ServiceRegistry, building the O(1) dispatch map for all registered services.
func newEmbeddedClientConn(registry *ServiceRegistry) *embeddedClientConn {
	return &embeddedClientConn{
		handlers: buildHandlerMap(registry),
	}
}

// Invoke implements grpc.ClientConnInterface.Invoke by dispatching the gRPC
// method to the corresponding in-process service handler. The response is
// copied into reply via protobuf marshal/unmarshal to maintain the same
// serialization semantics as a real gRPC transport.
func (c *embeddedClientConn) Invoke(ctx context.Context, method string, args, reply interface{}, opts ...grpc.CallOption) error {
	handler, ok := c.handlers[method]
	if !ok {
		return status.Errorf(codes.Unimplemented, "embedded: method %s not registered", method)
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

// NewStream implements grpc.ClientConnInterface.NewStream.
// Server streaming is not supported over the embedded transport.
func (c *embeddedClientConn) NewStream(ctx context.Context, desc *grpc.StreamDesc, method string, opts ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "embedded: streaming not supported over embedded transport")
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
