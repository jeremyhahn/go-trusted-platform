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

package mcp

import (
	"context"

	"google.golang.org/protobuf/proto"
)

// grpcToolBinding is how a tool reaches one method of the gRPC servicer S:
// the schema it advertises and the call that serves it.
type grpcToolBinding[S any] struct {
	schema func() map[string]interface{}
	call   func(server S, ctx context.Context, args map[string]interface{}) (interface{}, error)
}

// grpcToolMethod binds a tool to one method of the gRPC servicer S: the
// arguments decode into its request and its response is the tool result,
// both in protojson form. required names the arguments the schema marks
// required.
func grpcToolMethod[S any, Req any, PReq interface {
	*Req
	proto.Message
}, Resp proto.Message](
	call func(S, context.Context, PReq) (Resp, error),
	required ...string,
) grpcToolBinding[S] {
	descriptor := PReq(new(Req)).ProtoReflect().Descriptor()
	return grpcToolBinding[S]{
		schema: func() map[string]interface{} {
			return appToolSchema(descriptor, required...)
		},
		call: func(server S, ctx context.Context, args map[string]interface{}) (interface{}, error) {
			request := PReq(new(Req))
			if err := decodeAppToolArgs(args, request); err != nil {
				return nil, err
			}
			response, err := call(server, ctx, request)
			if err != nil {
				return nil, err
			}
			return encodeAppToolResult(response)
		},
	}
}
