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
	"strings"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrGRPCConnectionFailed indicates a gRPC connection failure.
type ErrGRPCConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCConnectionFailed) Error() string {
	return fmt.Sprintf("compute: gRPC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCCallFailed indicates a gRPC method call failure.
type ErrGRPCCallFailed struct {
	Method string
	Err    error
}

func (e ErrGRPCCallFailed) Error() string {
	return fmt.Sprintf("compute: gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// gRPC Adapter
// =============================================================================

// GRPCAdapter implements ComputeCommands using the gRPC protocol.
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   platformv1.ComputeServiceClient
}

// NewGRPCAdapter creates a new gRPC adapter.
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{
		endpoint: GetGRPCEndpoint(),
	}
}

// Setup prepares the gRPC adapter for testing.
func (a *GRPCAdapter) Setup(ctx context.Context) error {
	tlsConfig := helpers.TLSConfigOrInsecure()

	conn, err := grpc.DialContext(ctx, a.endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{
			Endpoint: a.endpoint,
			Err:      err,
		}
	}

	a.conn = conn
	a.client = platformv1.NewComputeServiceClient(conn)
	return nil
}

// Teardown cleans up the gRPC connection.
func (a *GRPCAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Name returns the adapter name.
func (a *GRPCAdapter) Name() string {
	return "gRPC"
}

// =============================================================================
// ComputeCommands Implementation
// =============================================================================

// CreateVM creates a virtual machine via gRPC.
func (a *GRPCAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	req := &platformv1.CreateVMRequest{
		Config: buildVMConfig(opts),
		Start:  opts.Start,
	}

	resp, err := a.client.CreateVM(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateVM", Err: err}
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

// StartVM starts a virtual machine via gRPC.
func (a *GRPCAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	req := &platformv1.StartVMRequest{
		Id: opts.VMID,
	}

	resp, err := a.client.StartVM(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "StartVM", Err: err}
	}

	return &StartVMResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// StopVM stops a virtual machine via gRPC.
func (a *GRPCAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	req := &platformv1.StopVMRequest{
		Id:             opts.VMID,
		Force:          opts.Force,
		TimeoutSeconds: opts.TimeoutSeconds,
	}

	resp, err := a.client.StopVM(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "StopVM", Err: err}
	}

	return &StopVMResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// DeleteVM deletes a virtual machine via gRPC.
func (a *GRPCAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	req := &platformv1.DeleteVMRequest{
		Id:          opts.VMID,
		DeleteDisks: opts.DeleteDisks,
	}

	resp, err := a.client.DeleteVM(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteVM", Err: err}
	}

	return &DeleteVMResult{
		Success: resp.GetStatus().GetSuccess(),
		Message: resp.GetStatus().GetMessage(),
	}, nil
}

// GetVM retrieves a virtual machine via gRPC.
func (a *GRPCAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	req := &platformv1.GetVMRequest{
		Id: opts.VMID,
	}

	resp, err := a.client.GetVM(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetVM", Err: err}
	}

	vm := resp.GetVm()
	if vm == nil {
		return nil, ErrGRPCCallFailed{
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

// ListVMs lists virtual machines via gRPC.
func (a *GRPCAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
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
		return nil, ErrGRPCCallFailed{Method: "ListVMs", Err: err}
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

// =============================================================================
// Shared gRPC Helpers
// =============================================================================

// buildVMConfig constructs a platformv1.VMConfig from CreateVMOptions.
func buildVMConfig(opts CreateVMOptions) *platformv1.VMConfig {
	config := &platformv1.VMConfig{
		Name: opts.Name,
		Cpu: &platformv1.CPUConfig{
			Cores: opts.CPUs,
		},
		Memory: &platformv1.MemoryConfig{
			SizeMb: opts.MemoryMB,
		},
		SecureBoot: opts.SecureBoot,
		Labels:     opts.Labels,
	}

	if opts.DiskSizeGB > 0 {
		config.Disks = []*platformv1.DiskConfig{
			{SizeGb: opts.DiskSizeGB},
		}
	}

	if opts.TPM {
		config.Tpm = &platformv1.TPMConfig{}
	}

	config.Firmware = parseFirmwareType(opts.Firmware)

	return config
}

// parseFirmwareType converts a firmware string to the proto enum value.
func parseFirmwareType(firmware string) platformv1.FirmwareType {
	firmwareMap := map[string]platformv1.FirmwareType{
		"bios":             platformv1.FirmwareType_FIRMWARE_TYPE_BIOS,
		"uefi":             platformv1.FirmwareType_FIRMWARE_TYPE_UEFI,
		"uefi-secure-boot": platformv1.FirmwareType_FIRMWARE_TYPE_UEFI_SECURE_BOOT,
	}

	fw, ok := firmwareMap[strings.ToLower(firmware)]
	if !ok {
		return platformv1.FirmwareType_FIRMWARE_TYPE_UNSPECIFIED
	}
	return fw
}

// normalizeVMState normalizes protobuf VMState string to a lowercase form.
// Protobuf .String() returns "VM_STATE_RUNNING", this normalizes to "running".
func normalizeVMState(state string) string {
	s := strings.TrimPrefix(state, "VM_STATE_")
	return strings.ToLower(s)
}

// parseVMState parses a state filter string into the proto enum.
func parseVMState(state string) (platformv1.VMState, bool) {
	stateMap := map[string]platformv1.VMState{
		"stopped":  platformv1.VMState_VM_STATE_STOPPED,
		"starting": platformv1.VMState_VM_STATE_STARTING,
		"running":  platformv1.VMState_VM_STATE_RUNNING,
		"paused":   platformv1.VMState_VM_STATE_PAUSED,
		"stopping": platformv1.VMState_VM_STATE_STOPPING,
		"error":    platformv1.VMState_VM_STATE_ERROR,
	}

	s, ok := stateMap[strings.ToLower(state)]
	return s, ok
}

// ErrVMNotFound indicates a VM was not found.
type ErrVMNotFound struct {
	VMID string
}

func (e ErrVMNotFound) Error() string {
	return fmt.Sprintf("compute: VM %s not found", e.VMID)
}
