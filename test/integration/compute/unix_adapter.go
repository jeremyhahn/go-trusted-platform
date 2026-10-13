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

//go:build integration

package compute_test

import (
	"context"
	"fmt"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixConnectionFailed indicates a Unix socket connection failure.
type ErrUnixConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixConnectionFailed) Error() string {
	return fmt.Sprintf("compute: Unix connection failed to %s: %v", e.Path, e.Err)
}

func (e ErrUnixConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixRPCFailed indicates a gRPC call over Unix socket failed.
type ErrUnixRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixRPCFailed) Error() string {
	return fmt.Sprintf("compute: Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixRPCFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Unix Adapter
// =============================================================================

// UnixAdapter implements ComputeCommands using the compute SDK client over a
// gRPC connection on a Unix domain socket.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     *computesvc.Client
}

// NewUnixAdapter creates a new Unix socket adapter.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{
		socketPath: GetSocketPath(),
	}
}

// Setup creates a gRPC connection over the Unix domain socket.
func (a *UnixAdapter) Setup(ctx context.Context) error {
	conn, err := grpc.NewClient("unix://"+a.socketPath, helpers.GRPCUnixCredentials())
	if err != nil {
		return ErrUnixConnectionFailed{
			Path: a.socketPath,
			Err:  err,
		}
	}

	a.conn = conn
	a.client = computesvc.NewClientFromGRPC(pb.NewComputeServiceClient(conn))
	return nil
}

// Teardown closes the gRPC connection.
func (a *UnixAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Name returns the adapter name.
func (a *UnixAdapter) Name() string {
	return "Unix"
}

// =============================================================================
// ComputeCommands Implementation
// =============================================================================

// CreateVM creates a virtual machine via the SDK client over Unix socket.
func (a *UnixAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	vm, err := a.client.CreateVMDomain(ctx, createVMParamsFromOptions(opts))
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateVM", Err: err}
	}

	return createVMResultFromDomain(vm), nil
}

// StartVM starts a virtual machine via the SDK client over Unix socket.
func (a *UnixAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	status, err := a.client.StartVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "StartVM", Err: err}
	}

	result := &StartVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// StopVM stops a virtual machine via the SDK client over Unix socket.
func (a *UnixAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	status, err := a.client.StopVMDomain(ctx, &computesvc.StopVMParams{
		ID:             opts.VMID,
		Force:          opts.Force,
		TimeoutSeconds: opts.TimeoutSeconds,
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "StopVM", Err: err}
	}

	result := &StopVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// DeleteVM deletes a virtual machine via the SDK client over Unix socket.
func (a *UnixAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	status, err := a.client.DeleteVMDomain(ctx, &computesvc.DeleteVMParams{
		ID:          opts.VMID,
		DeleteDisks: opts.DeleteDisks,
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteVM", Err: err}
	}

	result := &DeleteVMResult{}
	if status != nil {
		result.Success = status.Success
		result.Message = status.Message
	}
	return result, nil
}

// GetVM retrieves a virtual machine via the SDK client over Unix socket.
func (a *UnixAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	vm, err := a.client.GetVMDomain(ctx, opts.VMID)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetVM", Err: err}
	}

	if vm == nil {
		return nil, ErrUnixRPCFailed{
			Method: "GetVM",
			Err:    ErrVMNotFound(opts),
		}
	}

	return getVMResultFromDomain(vm), nil
}

// ListVMs lists virtual machines via the SDK client over Unix socket.
func (a *UnixAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	domainResult, err := a.client.ListVMsDomain(ctx, listVMsParamsFromOptions(opts))
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListVMs", Err: err}
	}

	return listVMsResultFromDomain(domainResult), nil
}
