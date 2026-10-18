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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Compile-time proof that MCPServiceProvider satisfies the optional MCP
// VMProvider capability interface.
var _ mcp.VMProvider = (*MCPServiceProvider)(nil)

// ErrVMComputeNotAvailable is returned when no compute orchestrator is
// configured for VM operations.
type ErrVMComputeNotAvailable struct{}

// Error implements the error interface.
func (e ErrVMComputeNotAvailable) Error() string {
	return "daemon: compute orchestrator not available for VM operations"
}

// ErrVMSnapshotNotFound is returned when a snapshot lookup finds no
// matching snapshot.
type ErrVMSnapshotNotFound struct {
	VMID       string
	SnapshotID string
}

// Error implements the error interface.
func (e ErrVMSnapshotNotFound) Error() string {
	return fmt.Sprintf("daemon: snapshot %q not found for VM %s", e.SnapshotID, e.VMID)
}

// The VM snapshot and attestation tools answer through ComputeService, so
// each reply is its RPC's response and each error carries the RPC's class,
// as on gRPC, REST and QUIC.

// VMSnapshotCreate creates a VM snapshot through ComputeService.CreateSnapshot.
func (m *MCPServiceProvider) VMSnapshotCreate(ctx context.Context, req *platformv1.CreateSnapshotRequest) (interface{}, error) {
	return protoResult(m.ComputeServiceServer().CreateSnapshot(ctx, req))
}

// VMSnapshotGet returns one snapshot: ComputeService.ListSnapshots filtered
// to the snapshot id. It has no RPC of its own.
func (m *MCPServiceProvider) VMSnapshotGet(ctx context.Context, vmID, snapshotID string) (interface{}, error) {
	resp, err := m.ComputeServiceServer().ListSnapshots(ctx, &platformv1.ListSnapshotsRequest{VmId: vmID})
	if err != nil {
		return nil, err
	}
	for _, snapshot := range resp.GetSnapshots() {
		if snapshot.GetId() == snapshotID {
			return protoResult(snapshot, nil)
		}
	}
	return nil, ErrVMSnapshotNotFound{VMID: vmID, SnapshotID: snapshotID}
}

// VMSnapshotList lists a VM's snapshots through ComputeService.ListSnapshots.
func (m *MCPServiceProvider) VMSnapshotList(ctx context.Context, vmID string) (interface{}, error) {
	return protoResult(m.ComputeServiceServer().ListSnapshots(ctx, &platformv1.ListSnapshotsRequest{VmId: vmID}))
}

// VMSnapshotDelete deletes a snapshot through ComputeService.DeleteSnapshot.
func (m *MCPServiceProvider) VMSnapshotDelete(ctx context.Context, vmID, snapshotID string) (interface{}, error) {
	return protoResult(m.ComputeServiceServer().DeleteSnapshot(ctx,
		&platformv1.DeleteSnapshotRequest{VmId: vmID, SnapshotId: snapshotID}))
}

// VMSnapshotRestore restores a VM from a snapshot through
// ComputeService.RestoreSnapshot.
func (m *MCPServiceProvider) VMSnapshotRestore(ctx context.Context, vmID, snapshotID string) (interface{}, error) {
	return protoResult(m.ComputeServiceServer().RestoreSnapshot(ctx,
		&platformv1.RestoreSnapshotRequest{VmId: vmID, SnapshotId: snapshotID}))
}

// VMAttest generates a VM's vTPM quote through ComputeService.AttestVM.
func (m *MCPServiceProvider) VMAttest(ctx context.Context, req *platformv1.AttestVMRequest) (interface{}, error) {
	return protoResult(m.ComputeServiceServer().AttestVM(ctx, req))
}

// VMAttestVerify verifies VM quote evidence through
// ComputeService.VerifyVMAttestation.
func (m *MCPServiceProvider) VMAttestVerify(ctx context.Context, req *platformv1.VerifyVMAttestationRequest) (interface{}, error) {
	return protoResult(m.ComputeServiceServer().VerifyVMAttestation(ctx, req))
}
