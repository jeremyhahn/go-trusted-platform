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
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// Compile-time proof that MCPServiceProvider satisfies the optional MCP
// VMProvider capability interface.
var _ mcp.VMProvider = (*MCPServiceProvider)(nil)

// ErrVMComputeNotAvailable is returned when no compute orchestrator is
// configured for VM snapshot/attestation operations.
type ErrVMComputeNotAvailable struct{}

// Error implements the error interface.
func (e ErrVMComputeNotAvailable) Error() string {
	return "daemon: compute orchestrator not available for VM operations"
}

// ErrVMSnapshotsNotSupported is returned when the configured compute
// orchestrator does not provide the VM snapshot capability (for example a
// container orchestrator).
type ErrVMSnapshotsNotSupported struct{}

// Error implements the error interface.
func (e ErrVMSnapshotsNotSupported) Error() string {
	return "daemon: VM snapshots not supported by the configured compute orchestrator"
}

// ErrVMAttestationNotSupported is returned when the configured compute
// orchestrator does not provide the VM attestation capability.
type ErrVMAttestationNotSupported struct{}

// Error implements the error interface.
func (e ErrVMAttestationNotSupported) Error() string {
	return "daemon: VM attestation not supported by the configured compute orchestrator"
}

// ErrVMEvidenceRequired is returned when attestation evidence is missing
// from a verification request.
type ErrVMEvidenceRequired struct{}

// Error implements the error interface.
func (e ErrVMEvidenceRequired) Error() string {
	return "daemon: VM attestation evidence is required"
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

// vmSnapshotter returns the compute orchestrator's VM snapshot capability.
func (m *MCPServiceProvider) vmSnapshotter() (compute.VMSnapshotter, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrVMComputeNotAvailable{}
	}
	snapshotter, ok := m.computeOrchestrator.(compute.VMSnapshotter)
	if !ok {
		return nil, ErrVMSnapshotsNotSupported{}
	}
	return snapshotter, nil
}

// vmAttester returns the compute orchestrator's VM attestation capability.
func (m *MCPServiceProvider) vmAttester() (compute.VMAttester, error) {
	if m.computeOrchestrator == nil {
		return nil, ErrVMComputeNotAvailable{}
	}
	attester, ok := m.computeOrchestrator.(compute.VMAttester)
	if !ok {
		return nil, ErrVMAttestationNotSupported{}
	}
	return attester, nil
}

// vmSnapshotToMap converts a compute.VMSnapshot to an MCP result map.
func vmSnapshotToMap(snapshot *compute.VMSnapshot) map[string]interface{} {
	if snapshot == nil {
		return nil
	}
	return map[string]interface{}{
		"name":        snapshot.Name,
		"vm_id":       snapshot.VMID,
		"created_at":  snapshot.CreatedAt.Format(time.RFC3339),
		"size_bytes":  snapshot.SizeBytes,
		"description": snapshot.Description,
	}
}

// VMSnapshotCreate creates an internal (memory + disk) snapshot of a
// running VM.
func (m *MCPServiceProvider) VMSnapshotCreate(ctx context.Context, vmID, name string) (interface{}, error) {
	snapshotter, err := m.vmSnapshotter()
	if err != nil {
		return nil, err
	}
	snapshot, err := snapshotter.CreateSnapshot(ctx, vmID, name)
	if err != nil {
		return nil, err
	}
	return vmSnapshotToMap(snapshot), nil
}

// VMSnapshotGet returns a single snapshot by name.
func (m *MCPServiceProvider) VMSnapshotGet(ctx context.Context, vmID, snapshotID string) (interface{}, error) {
	snapshotter, err := m.vmSnapshotter()
	if err != nil {
		return nil, err
	}
	snapshots, err := snapshotter.ListSnapshots(ctx, vmID)
	if err != nil {
		return nil, err
	}
	for _, snapshot := range snapshots {
		if snapshot.Name == snapshotID {
			return vmSnapshotToMap(snapshot), nil
		}
	}
	return nil, ErrVMSnapshotNotFound{VMID: vmID, SnapshotID: snapshotID}
}

// VMSnapshotList lists all snapshots for a VM.
func (m *MCPServiceProvider) VMSnapshotList(ctx context.Context, vmID string) (interface{}, error) {
	snapshotter, err := m.vmSnapshotter()
	if err != nil {
		return nil, err
	}
	snapshots, err := snapshotter.ListSnapshots(ctx, vmID)
	if err != nil {
		return nil, err
	}
	results := make([]interface{}, 0, len(snapshots))
	for _, snapshot := range snapshots {
		results = append(results, vmSnapshotToMap(snapshot))
	}
	return map[string]interface{}{
		"vm_id":     vmID,
		"snapshots": results,
		"count":     len(results),
	}, nil
}

// VMSnapshotDelete deletes a snapshot.
func (m *MCPServiceProvider) VMSnapshotDelete(ctx context.Context, vmID, snapshotID string) error {
	snapshotter, err := m.vmSnapshotter()
	if err != nil {
		return err
	}
	return snapshotter.DeleteSnapshot(ctx, vmID, snapshotID)
}

// VMSnapshotRestore restores a VM from a snapshot.
func (m *MCPServiceProvider) VMSnapshotRestore(ctx context.Context, vmID, snapshotID string) error {
	snapshotter, err := m.vmSnapshotter()
	if err != nil {
		return err
	}
	return snapshotter.RestoreSnapshot(ctx, vmID, snapshotID)
}

// VMAttest generates a vTPM quote for a running VM.
func (m *MCPServiceProvider) VMAttest(ctx context.Context, vmID string, nonce []byte, pcrs []int) (interface{}, error) {
	attester, err := m.vmAttester()
	if err != nil {
		return nil, err
	}
	report, err := attester.AttestVM(ctx, vmID, nonce, pcrs)
	if err != nil {
		return nil, err
	}

	pcrValues := make(map[string]string, len(report.PCRValues))
	for idx, value := range report.PCRValues {
		pcrValues[fmt.Sprintf("%d", idx)] = hex.EncodeToString(value)
	}

	return map[string]interface{}{
		"vm_id":      report.VMID,
		"vm_name":    report.VMName,
		"timestamp":  report.Timestamp.Format(time.RFC3339),
		"verified":   report.Verified,
		"nonce":      base64.StdEncoding.EncodeToString(report.Nonce),
		"pcr_values": pcrValues,
		"quote":      base64.StdEncoding.EncodeToString(report.Quote),
		"signature":  base64.StdEncoding.EncodeToString(report.Signature),
		"event_log":  base64.StdEncoding.EncodeToString(report.EventLog),
		"ak_public":  base64.StdEncoding.EncodeToString(report.AKPublicKey),
	}, nil
}

// VMAttestVerify verifies VM attestation evidence against the VM's live
// vTPM attestation key.
func (m *MCPServiceProvider) VMAttestVerify(ctx context.Context, vmID string, req *mcp.VMAttestVerifyMCPRequest) (interface{}, error) {
	attester, err := m.vmAttester()
	if err != nil {
		return nil, err
	}
	if req == nil {
		return nil, ErrVMEvidenceRequired{}
	}

	result, err := attester.VerifyVMAttestation(ctx, vmID, &compute.VMAttestationEvidence{
		Quote:        req.Quote,
		Signature:    req.Signature,
		Nonce:        req.Nonce,
		ExpectedPCRs: req.ExpectedPCRs,
	})
	if err != nil {
		return nil, err
	}

	actualPCRs := make(map[string]string, len(result.ActualPCRs))
	for idx, value := range result.ActualPCRs {
		actualPCRs[fmt.Sprintf("%d", idx)] = hex.EncodeToString(value)
	}

	return map[string]interface{}{
		"vm_id":           vmID,
		"verified":        result.Verified,
		"signature_valid": result.SignatureValid,
		"nonce_valid":     result.NonceValid,
		"pcrs_valid":      result.PCRsValid,
		"message":         result.Message,
		"actual_pcrs":     actualPCRs,
	}, nil
}
