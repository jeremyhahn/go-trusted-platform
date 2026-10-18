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
	"cmp"
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// VM snapshot / attestation tool wiring
// =============================================================================
//
// These tools mirror the platform.v1 ComputeService VM snapshot and
// attestation gRPC surface (CreateSnapshot / RestoreSnapshot /
// DeleteSnapshot / ListSnapshots / AttestVM / VerifyVMAttestation) so
// AI/LLM clients can drive them over MCP. Routing uses a map-based
// dispatcher (O(1) lookup per project conventions).
//
// The MCP server stays decoupled from the daemon: the compute orchestrator
// is exposed via the optional VMProvider interface, satisfied by the
// daemon's MCPServiceProvider when a VM-capable compute orchestrator is
// configured.

// ErrVMComputeNotConfigured indicates no VM-capable compute backend is
// wired into the MCP tool registry.
var ErrVMComputeNotConfigured = &VMError{
	Code:    "VM_COMPUTE_NOT_CONFIGURED",
	Message: "VM compute service not configured",
}

// ErrVMInvalidNonce indicates the nonce argument is not valid standard
// base64.
type ErrVMInvalidNonce struct {
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrVMInvalidNonce) Error() string {
	return fmt.Sprintf("vm: nonce must be base64 encoded: %v", e.Cause)
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrVMInvalidNonce) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// Unwrap exposes the underlying decode error for errors.Is/As.
func (e ErrVMInvalidNonce) Unwrap() error {
	return e.Cause
}

// ErrVMInvalidEvidence indicates a required attestation evidence argument
// is missing or not valid standard base64.
type ErrVMInvalidEvidence struct {
	Field string
	Cause error
}

// Error returns a human-readable description of the error.
func (e ErrVMInvalidEvidence) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("vm: invalid attestation evidence field %q: %v", e.Field, e.Cause)
	}
	return fmt.Sprintf("vm: attestation evidence field %q is required", e.Field)
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrVMInvalidEvidence) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// Unwrap exposes the underlying decode error for errors.Is/As.
func (e ErrVMInvalidEvidence) Unwrap() error {
	return e.Cause
}

// ErrVMInvalidPCRIndex indicates a negative include_pcrs entry: PCR
// indices are unsigned.
type ErrVMInvalidPCRIndex struct {
	Index int
}

// Error returns a human-readable description of the error.
func (e ErrVMInvalidPCRIndex) Error() string {
	return fmt.Sprintf("vm: PCR index %d is negative", e.Index)
}

// GRPCStatus classifies the error as InvalidArgument.
func (e ErrVMInvalidPCRIndex) GRPCStatus() *status.Status {
	return status.New(codes.InvalidArgument, e.Error())
}

// VMProvider is the optional interface a ServiceProvider can satisfy to
// unlock the VM snapshot and attestation MCP tools. Each method answers
// with its ComputeService RPC's result and error class.
type VMProvider interface {
	// VMSnapshotCreate creates a VM snapshot, as CreateSnapshot does.
	VMSnapshotCreate(ctx context.Context, req *platformv1.CreateSnapshotRequest) (interface{}, error)

	// VMSnapshotGet returns a single snapshot by id. It has no RPC of its
	// own: it is ListSnapshots filtered to the snapshot.
	VMSnapshotGet(ctx context.Context, vmID, snapshotID string) (interface{}, error)

	// VMSnapshotList lists a VM's snapshots, as ListSnapshots does.
	VMSnapshotList(ctx context.Context, vmID string) (interface{}, error)

	// VMSnapshotDelete deletes a snapshot, as DeleteSnapshot does.
	VMSnapshotDelete(ctx context.Context, vmID, snapshotID string) (interface{}, error)

	// VMSnapshotRestore restores a VM from a snapshot, as RestoreSnapshot
	// does.
	VMSnapshotRestore(ctx context.Context, vmID, snapshotID string) (interface{}, error)

	// VMAttest generates a VM's vTPM quote, as AttestVM does.
	VMAttest(ctx context.Context, req *platformv1.AttestVMRequest) (interface{}, error)

	// VMAttestVerify verifies VM quote evidence, as VerifyVMAttestation
	// does.
	VMAttestVerify(ctx context.Context, req *platformv1.VerifyVMAttestationRequest) (interface{}, error)
}

// vmProvider returns the VMProvider interface if the configured service
// implements it, or nil when VM compute tools are not available.
func (r *ToolRegistry) vmProvider() VMProvider {
	if p, ok := r.service.(VMProvider); ok {
		return p
	}
	return nil
}

// vmToolHandler is the executor signature for VM snapshot and attestation
// tools.
type vmToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

// vmToolDispatch maps VM snapshot and attestation tool names to executors
// for O(1) routing per project conventions. The VM lifecycle tools are
// bound to the gRPC ComputeService in vm_lifecycle_tools.go.
var vmToolDispatch = map[string]vmToolHandler{
	"vm_snapshot_create":  (*ToolRegistry).executeVMSnapshotCreate,
	"vm_snapshot_get":     (*ToolRegistry).executeVMSnapshotGet,
	"vm_snapshot_list":    (*ToolRegistry).executeVMSnapshotList,
	"vm_snapshot_delete":  (*ToolRegistry).executeVMSnapshotDelete,
	"vm_snapshot_restore": (*ToolRegistry).executeVMSnapshotRestore,
	"vm_attest":           (*ToolRegistry).executeVMAttest,
	"vm_attest_verify":    (*ToolRegistry).executeVMAttestVerify,
}

// dispatchVMTool looks up a VM lifecycle, snapshot or attestation tool and
// invokes it. Returns (result, handled, err) so the caller can fall through
// when handled is false (tool name doesn't belong to this dispatcher).
func (r *ToolRegistry) dispatchVMTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
	if result, handled, err := r.dispatchVMLifecycleTool(ctx, name, args); handled {
		return result, true, err
	}
	fn, ok := vmToolDispatch[name]
	if !ok {
		return nil, false, nil
	}
	result, err := fn(r, ctx, args)
	return result, true, err
}

// =============================================================================
// Argument helpers
// =============================================================================

// vmToolVMID extracts the required vm_id argument.
func vmToolVMID(args map[string]interface{}) (string, error) {
	id := getString(args, "vm_id")
	if id == "" {
		return "", ErrVMIDRequired
	}
	return id, nil
}

// vmToolSnapshotID extracts the required snapshot_id argument.
func vmToolSnapshotID(args map[string]interface{}) (string, error) {
	id := getString(args, "snapshot_id")
	if id == "" {
		return "", ErrSnapshotIDRequired
	}
	return id, nil
}

// vmToolBase64 extracts an optional base64-encoded argument.
func vmToolBase64(args map[string]interface{}, key string) ([]byte, error) {
	encoded := getString(args, key)
	if encoded == "" {
		return nil, nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	return decoded, nil
}

// =============================================================================
// Executors
// =============================================================================

// executeVMSnapshotCreate takes vm_id and name, plus the optional
// description, memory_snapshot and disk_snapshot of the snapshot config.
func (r *ToolRegistry) executeVMSnapshotCreate(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}
	name := getString(args, "name")
	if name == "" {
		return nil, ErrSnapshotNameRequired
	}
	return p.VMSnapshotCreate(ctx, &platformv1.CreateSnapshotRequest{
		VmId: vmID,
		Config: &platformv1.SnapshotConfig{
			Name:           name,
			Description:    getString(args, "description"),
			MemorySnapshot: getBool(args, "memory_snapshot"),
			DiskSnapshot:   getBool(args, "disk_snapshot"),
		},
	})
}

func (r *ToolRegistry) executeVMSnapshotGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return r.executeVMSnapshotByID(ctx, args, VMProvider.VMSnapshotGet)
}

func (r *ToolRegistry) executeVMSnapshotList(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}
	return p.VMSnapshotList(ctx, vmID)
}

func (r *ToolRegistry) executeVMSnapshotDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return r.executeVMSnapshotByID(ctx, args, VMProvider.VMSnapshotDelete)
}

func (r *ToolRegistry) executeVMSnapshotRestore(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	return r.executeVMSnapshotByID(ctx, args, VMProvider.VMSnapshotRestore)
}

// executeVMSnapshotByID runs a snapshot verb that names one snapshot of one
// VM by the vm_id and snapshot_id arguments.
func (r *ToolRegistry) executeVMSnapshotByID(ctx context.Context, args map[string]interface{},
	call func(VMProvider, context.Context, string, string) (interface{}, error)) (interface{}, error) {
	p := r.vmProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}
	snapshotID, err := vmToolSnapshotID(args)
	if err != nil {
		return nil, err
	}
	return call(p, ctx, vmID, snapshotID)
}

// executeVMAttest takes vm_id, a base64 nonce and the include_pcrs indices.
// The quote is over the SHA-256 bank, the only one AttestVM accepts.
func (r *ToolRegistry) executeVMAttest(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}
	nonce, err := vmToolBase64(args, "nonce")
	if err != nil {
		return nil, ErrVMInvalidNonce{Cause: err}
	}
	pcrs := getIntSlice(args, "include_pcrs")
	indices := make([]uint32, 0, len(pcrs))
	for _, idx := range pcrs {
		if idx < 0 {
			return nil, ErrVMInvalidPCRIndex{Index: idx}
		}
		indices = append(indices, uint32(idx))
	}
	return p.VMAttest(ctx, &platformv1.AttestVMRequest{
		VmId:       vmID,
		Nonce:      nonce,
		PcrIndices: indices,
	})
}

// executeVMAttestVerify takes vm_id, the base64 quote, signature and nonce,
// the optional signature_algorithm, and expected_pcrs: a map of PCR index
// to base64 SHA-256 value.
func (r *ToolRegistry) executeVMAttestVerify(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}

	quote, err := vmToolEvidence(args, "quote")
	if err != nil {
		return nil, err
	}
	signature, err := vmToolEvidence(args, "signature")
	if err != nil {
		return nil, err
	}
	nonce, err := vmToolEvidence(args, "nonce")
	if err != nil {
		return nil, err
	}
	expected, err := vmToolExpectedPCRs(args)
	if err != nil {
		return nil, err
	}

	return p.VMAttestVerify(ctx, &platformv1.VerifyVMAttestationRequest{
		VmId:               vmID,
		Quote:              quote,
		Signature:          signature,
		SignatureAlgorithm: getString(args, "signature_algorithm"),
		Nonce:              nonce,
		ExpectedPcrs:       expected,
	})
}

// vmToolEvidence extracts a required base64 evidence argument.
func vmToolEvidence(args map[string]interface{}, field string) ([]byte, error) {
	value, err := vmToolBase64(args, field)
	if err != nil {
		return nil, ErrVMInvalidEvidence{Field: field, Cause: err}
	}
	if len(value) == 0 {
		return nil, ErrVMInvalidEvidence{Field: field}
	}
	return value, nil
}

// vmToolExpectedPCRs decodes the optional expected_pcrs argument, a map of
// PCR index to base64 SHA-256 value, into SHA-256 PCR values in index order.
func vmToolExpectedPCRs(args map[string]interface{}) ([]*platformv1.PCRValue, error) {
	raw, ok := args["expected_pcrs"].(map[string]interface{})
	if !ok || len(raw) == 0 {
		return nil, nil
	}
	values := make([]*platformv1.PCRValue, 0, len(raw))
	for key, value := range raw {
		idx, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			return nil, ErrVMInvalidEvidence{Field: "expected_pcrs", Cause: err}
		}
		encoded, ok := value.(string)
		if !ok {
			return nil, ErrVMInvalidEvidence{Field: "expected_pcrs"}
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, ErrVMInvalidEvidence{Field: "expected_pcrs", Cause: err}
		}
		values = append(values, &platformv1.PCRValue{
			Index: uint32(idx),
			Value: decoded,
			Bank:  platformv1.PCRBank_PCR_BANK_SHA256,
		})
	}
	slices.SortFunc(values, func(a, b *platformv1.PCRValue) int {
		return cmp.Compare(a.GetIndex(), b.GetIndex())
	})
	return values, nil
}
