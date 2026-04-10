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
	"net"
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
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

// UnixAdapter implements ComputeCommands using gRPC over a Unix domain socket.
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     platformv1.ComputeServiceClient
}

// NewUnixAdapter creates a new Unix socket adapter.
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{
		socketPath: GetSocketPath(),
	}
}

// Setup creates a gRPC connection over the Unix domain socket.
func (a *UnixAdapter) Setup(ctx context.Context) error {
	conn, err := grpc.DialContext(ctx, "unix://"+a.socketPath,
		helpers.GRPCUnixCredentials(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			socketAddr := strings.TrimPrefix(addr, "unix://")
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketAddr)
		}),
	)
	if err != nil {
		return ErrUnixConnectionFailed{
			Path: a.socketPath,
			Err:  err,
		}
	}

	a.conn = conn
	a.client = platformv1.NewComputeServiceClient(conn)
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

// CreateVM creates a virtual machine via gRPC over Unix socket.
func (a *UnixAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	req := &platformv1.CreateVMRequest{
		Config: buildVMConfig(opts),
		Start:  opts.Start,
	}

	resp, err := a.client.CreateVM(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateVM", Err: err}
	}

	vm := resp.GetVm()
	result := &CreateVMResult{
		Success: resp.GetStatus().GetSuccess(),
	}

	if vm != nil {
		result.VMID = vm.GetId()
		result.Name = vm.GetConfig().GetName()
		result.State = normalizeVMState(vm.GetState().String())
		result.Labels = vm.GetConfig().GetLabels()
	}

	return result, nil
}

// StartVM starts a virtual machine via gRPC over Unix socket.
func (a *UnixAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	req := &platformv1.StartVMRequest{
		Id: opts.VMID,
	}

	resp, err := a.client.StartVM(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "StartVM", Err: err}
	}

	return &StartVMResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// StopVM stops a virtual machine via gRPC over Unix socket.
func (a *UnixAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	req := &platformv1.StopVMRequest{
		Id:             opts.VMID,
		Force:          opts.Force,
		TimeoutSeconds: opts.TimeoutSeconds,
	}

	resp, err := a.client.StopVM(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "StopVM", Err: err}
	}

	return &StopVMResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// DeleteVM deletes a virtual machine via gRPC over Unix socket.
func (a *UnixAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	req := &platformv1.DeleteVMRequest{
		Id:          opts.VMID,
		DeleteDisks: opts.DeleteDisks,
	}

	resp, err := a.client.DeleteVM(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteVM", Err: err}
	}

	return &DeleteVMResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// GetVM retrieves a virtual machine via gRPC over Unix socket.
func (a *UnixAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	req := &platformv1.GetVMRequest{
		Id: opts.VMID,
	}

	resp, err := a.client.GetVM(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetVM", Err: err}
	}

	vm := resp.GetVm()
	if vm == nil {
		return nil, ErrUnixRPCFailed{
			Method: "GetVM",
			Err:    ErrVMNotFound{VMID: opts.VMID},
		}
	}

	return &GetVMResult{
		VMID:     vm.GetId(),
		Name:     vm.GetConfig().GetName(),
		State:    normalizeVMState(vm.GetState().String()),
		CPUs:     vm.GetConfig().GetCpu().GetCores(),
		MemoryMB: vm.GetConfig().GetMemory().GetSizeMb(),
		Labels:   vm.GetConfig().GetLabels(),
	}, nil
}

// ListVMs lists virtual machines via gRPC over Unix socket.
func (a *UnixAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	req := &platformv1.ListVMsRequest{}

	if len(opts.Labels) > 0 {
		req.Selector = &platformv1.LabelSelector{
			MatchLabels: opts.Labels,
		}
	}

	if opts.PageSize > 0 {
		req.Pagination = &platformv1.PaginationRequest{
			PageSize: opts.PageSize,
		}
	}

	if opts.StateFilter != "" {
		state, ok := parseVMState(opts.StateFilter)
		if ok {
			req.States = []platformv1.VMState{state}
		}
	}

	resp, err := a.client.ListVMs(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ListVMs", Err: err}
	}

	vms := make([]VMSummary, len(resp.GetVms()))
	for i, vm := range resp.GetVms() {
		vms[i] = VMSummary{
			VMID:   vm.GetId(),
			Name:   vm.GetConfig().GetName(),
			State:  normalizeVMState(vm.GetState().String()),
			Labels: vm.GetConfig().GetLabels(),
		}
	}

	var totalItems uint64
	if resp.GetPagination() != nil {
		totalItems = resp.GetPagination().GetTotalItems()
	}

	return &ListVMsResult{
		VMs:        vms,
		TotalItems: totalItems,
	}, nil
}
