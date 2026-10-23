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

package daemon

import (
	"context"
	"fmt"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
)

// MCP DEK tools.
//
// Each dek_* tool calls the DEKServerAdapter method the gRPC DEKManagement
// RPC and the QUIC DEK sub-opcode call, so the three transports share one
// DEK store and an error carries the class gRPC answers.

// ErrDEKOperationFailed wraps a DEKManagement failure with the operation
// name; Unwrap keeps the gRPC status for error classification.
type ErrDEKOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrDEKOperationFailed) Error() string {
	return fmt.Sprintf("DEK operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrDEKOperationFailed) Unwrap() error {
	return e.Cause
}

// SetDEKService wires the DEKManagement adapter behind the dek_* tools.
func (p *MCPServiceProvider) SetDEKService(svc DEKServiceInterface) {
	p.dekService = svc
}

// callDEK runs one DEKManagement call, refusing when no DEK service is
// wired and naming the operation on failure.
func callDEK[Req, Resp any](p *MCPServiceProvider, ctx context.Context, op string, req *Req,
	call func(DEKServiceInterface, context.Context, *Req) (*Resp, error)) (interface{}, error) {
	if p.dekService == nil {
		return nil, ErrServiceNotAvailable{Service: "dek"}
	}
	resp, err := call(p.dekService, ctx, req)
	if err != nil {
		return nil, ErrDEKOperationFailed{Operation: op, Cause: err}
	}
	return resp, nil
}

// DEKCreate creates a DEK.
func (p *MCPServiceProvider) DEKCreate(ctx context.Context, req *mcp.DEKCreateRequest) (interface{}, error) {
	if req == nil {
		return nil, ErrKMSInvalidParameter{Parameter: "path", Reason: "DEK path is required"}
	}
	return callDEK(p, ctx, "CreateDEK", &pb.CreateDEKRequest{
		Path:           req.Path,
		Algorithm:      pb.KeyAlgorithm(req.Algorithm),
		Description:    req.Description,
		MaxOperations:  req.MaxOperations,
		MaxBytes:       req.MaxBytes,
		WarningPercent: req.WarningPercent,
		Tags:           req.Tags,
	}, DEKServiceInterface.CreateDEK)
}

// DEKList lists the DEKs under a prefix.
func (p *MCPServiceProvider) DEKList(ctx context.Context, req *mcp.DEKListRequest) (interface{}, error) {
	if req == nil {
		req = &mcp.DEKListRequest{}
	}
	return callDEK(p, ctx, "ListDEKs", &pb.ListDEKsRequest{
		Prefix:    req.Prefix,
		Recursive: req.Recursive,
		Limit:     req.Limit,
		Cursor:    req.Cursor,
	}, DEKServiceInterface.ListDEKs)
}

// DEKGet answers a DEK's metadata.
func (p *MCPServiceProvider) DEKGet(ctx context.Context, path string) (interface{}, error) {
	return callDEK(p, ctx, "GetDEK", &pb.GetDEKRequest{Path: path}, DEKServiceInterface.GetDEK)
}

// DEKStatus answers a DEK's usage and rotation status.
func (p *MCPServiceProvider) DEKStatus(ctx context.Context, path string) (interface{}, error) {
	return callDEK(p, ctx, "GetDEKStatus", &pb.GetDEKStatusRequest{Path: path}, DEKServiceInterface.GetDEKStatus)
}

// DEKRotate rotates a DEK to a new version.
func (p *MCPServiceProvider) DEKRotate(ctx context.Context, path string, background bool) (interface{}, error) {
	return callDEK(p, ctx, "RotateDEK", &pb.RotateDEKRequest{Path: path, Background: background}, DEKServiceInterface.RotateDEK)
}

// DEKDelete deletes a DEK.
func (p *MCPServiceProvider) DEKDelete(ctx context.Context, req *mcp.DEKDeleteRequest) (interface{}, error) {
	if req == nil {
		return nil, ErrKMSInvalidParameter{Parameter: "path", Reason: "DEK path is required"}
	}
	return callDEK(p, ctx, "DeleteDEK", &pb.DeleteDEKRequest{
		Path:      req.Path,
		Force:     req.Force,
		MigrateTo: req.MigrateTo,
	}, DEKServiceInterface.DeleteDEK)
}
