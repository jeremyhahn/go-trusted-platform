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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The VM lifecycle tools answer through their gRPC ComputeService twin, so
// each shares its RPC's validation, error class and reply (#304, #317).
var _ mcp.VMLifecycleProvider = (*MCPServiceProvider)(nil)

// computeService is the gRPC ComputeService over the daemon's compute
// orchestrator; a nil orchestrator answers FailedPrecondition as it does
// over gRPC.
func (m *MCPServiceProvider) computeService() *ComputeGRPCService {
	return NewComputeGRPCService(logging.NewFromSlog(m.logger), m.computeOrchestrator)
}

// VMCreate creates a VM through ComputeService.CreateVM. Sizes the spec
// leaves nil take the RPC's defaults.
func (m *MCPServiceProvider) VMCreate(ctx context.Context, spec mcp.VMCreateSpec) (interface{}, error) {
	config := &platformv1.VMConfig{
		Name:       spec.Name,
		SecureBoot: spec.SecureBoot,
	}
	if spec.MemoryMB != nil {
		config.Memory = &platformv1.MemoryConfig{SizeMb: *spec.MemoryMB}
	}
	if spec.CPUs != nil {
		config.Cpu = &platformv1.CPUConfig{Cores: *spec.CPUs}
	}
	if spec.TPMEnabled {
		config.Tpm = &platformv1.TPMConfig{Enabled: true, Version: platformv1.TPMVersion_TPM_VERSION_2_0}
	}
	return protoResult(m.computeService().CreateVM(ctx, &platformv1.CreateVMRequest{Config: config}))
}

// VMList lists every VM through ComputeService.ListVMs.
func (m *MCPServiceProvider) VMList(ctx context.Context) (interface{}, error) {
	return protoResult(m.computeService().ListVMs(ctx, &platformv1.ListVMsRequest{}))
}

// VMGet returns one VM through ComputeService.GetVM.
func (m *MCPServiceProvider) VMGet(ctx context.Context, vmID string) (interface{}, error) {
	return protoResult(m.computeService().GetVM(ctx, &platformv1.GetVMRequest{Id: vmID}))
}

// VMDelete deletes a VM through ComputeService.DeleteVM.
func (m *MCPServiceProvider) VMDelete(ctx context.Context, vmID string) (interface{}, error) {
	return protoResult(m.computeService().DeleteVM(ctx, &platformv1.DeleteVMRequest{Id: vmID}))
}

// VMStart starts a VM through ComputeService.StartVM.
func (m *MCPServiceProvider) VMStart(ctx context.Context, vmID string) (interface{}, error) {
	return protoResult(m.computeService().StartVM(ctx, &platformv1.StartVMRequest{Id: vmID}))
}

// VMStop stops a VM through ComputeService.StopVM.
func (m *MCPServiceProvider) VMStop(ctx context.Context, vmID string) (interface{}, error) {
	return protoResult(m.computeService().StopVM(ctx, &platformv1.StopVMRequest{Id: vmID}))
}

// VMReboot reboots a VM through ComputeService.RebootVM.
func (m *MCPServiceProvider) VMReboot(ctx context.Context, vmID string) (interface{}, error) {
	return protoResult(m.computeService().RebootVM(ctx, &platformv1.RebootVMRequest{Id: vmID}))
}
