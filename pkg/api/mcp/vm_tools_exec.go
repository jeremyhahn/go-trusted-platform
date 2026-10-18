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
	"encoding/base64"
	"fmt"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// VMAttestVerifyMCPRequest carries decoded VM attestation evidence for the
// vm_attest_verify tool.
type VMAttestVerifyMCPRequest struct {
	Quote     []byte
	Signature []byte
	// SignatureAlgorithm is the scheme the quote declares; an absent or
	// unknown scheme fails verification.
	SignatureAlgorithm string
	Nonce              []byte
	ExpectedPCRs       map[int][]byte
}

// VMProvider is the optional interface a ServiceProvider can satisfy to
// unlock the VM snapshot and attestation MCP tools. Implementations
// delegate to the compute orchestrator's canonical VMSnapshotter /
// VMAttester capabilities.
type VMProvider interface {
	// VMSnapshotCreate creates an internal (memory + disk) VM snapshot.
	VMSnapshotCreate(ctx context.Context, vmID, name string) (interface{}, error)

	// VMSnapshotGet returns a single snapshot by name.
	VMSnapshotGet(ctx context.Context, vmID, snapshotID string) (interface{}, error)

	// VMSnapshotList lists all snapshots for a VM.
	VMSnapshotList(ctx context.Context, vmID string) (interface{}, error)

	// VMSnapshotDelete deletes a snapshot.
	VMSnapshotDelete(ctx context.Context, vmID, snapshotID string) error

	// VMSnapshotRestore restores a VM from a snapshot.
	VMSnapshotRestore(ctx context.Context, vmID, snapshotID string) error

	// VMAttest generates a vTPM quote for a VM.
	VMAttest(ctx context.Context, vmID string, nonce []byte, pcrs []int) (interface{}, error)

	// VMAttestVerify verifies VM attestation evidence.
	VMAttestVerify(ctx context.Context, vmID string, req *VMAttestVerifyMCPRequest) (interface{}, error)
}

// vmProvider returns the VMProvider interface if the configured service
// implements it, or nil when VM compute tools are not available.
func (r *ToolRegistry) vmProvider() VMProvider {
	if p, ok := r.service.(VMProvider); ok {
		return p
	}
	return nil
}

// vmToolHandler is the executor signature for VM lifecycle, snapshot and
// attestation tools.
type vmToolHandler func(*ToolRegistry, context.Context, map[string]interface{}) (interface{}, error)

// vmToolDispatch maps VM lifecycle, snapshot and attestation tool names to
// executors for O(1) routing per project conventions.
var vmToolDispatch = map[string]vmToolHandler{
	"vm_create":           (*ToolRegistry).executeVMCreate,
	"vm_list":             (*ToolRegistry).executeVMList,
	"vm_get":              (*ToolRegistry).executeVMGet,
	"vm_delete":           (*ToolRegistry).executeVMDelete,
	"vm_start":            (*ToolRegistry).executeVMStart,
	"vm_stop":             (*ToolRegistry).executeVMStop,
	"vm_reboot":           (*ToolRegistry).executeVMReboot,
	"vm_snapshot_create":  (*ToolRegistry).executeVMSnapshotCreate,
	"vm_snapshot_get":     (*ToolRegistry).executeVMSnapshotGet,
	"vm_snapshot_list":    (*ToolRegistry).executeVMSnapshotList,
	"vm_snapshot_delete":  (*ToolRegistry).executeVMSnapshotDelete,
	"vm_snapshot_restore": (*ToolRegistry).executeVMSnapshotRestore,
	"vm_attest":           (*ToolRegistry).executeVMAttest,
	"vm_attest_verify":    (*ToolRegistry).executeVMAttestVerify,
}

// dispatchVMTool looks up a VM snapshot/attestation tool and invokes it.
// Returns (result, handled, err) so the caller can fall through when
// handled is false (tool name doesn't belong to this dispatcher).
func (r *ToolRegistry) dispatchVMTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, bool, error) {
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
	result, err := p.VMSnapshotCreate(ctx, vmID, name)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeVMSnapshotGet(ctx context.Context, args map[string]interface{}) (interface{}, error) {
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
	result, err := p.VMSnapshotGet(ctx, vmID, snapshotID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
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
	result, err := p.VMSnapshotList(ctx, vmID)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeVMSnapshotDelete(ctx context.Context, args map[string]interface{}) (interface{}, error) {
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
	if err := p.VMSnapshotDelete(ctx, vmID, snapshotID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"success":     true,
		"vm_id":       vmID,
		"snapshot_id": snapshotID,
	}, nil
}

func (r *ToolRegistry) executeVMSnapshotRestore(ctx context.Context, args map[string]interface{}) (interface{}, error) {
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
	if err := p.VMSnapshotRestore(ctx, vmID, snapshotID); err != nil {
		return nil, err
	}
	return map[string]interface{}{
		"success":     true,
		"vm_id":       vmID,
		"snapshot_id": snapshotID,
	}, nil
}

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

	result, err := p.VMAttest(ctx, vmID, nonce, pcrs)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}

func (r *ToolRegistry) executeVMAttestVerify(ctx context.Context, args map[string]interface{}) (interface{}, error) {
	p := r.vmProvider()
	if p == nil {
		return nil, ErrVMComputeNotConfigured
	}
	vmID, err := vmToolVMID(args)
	if err != nil {
		return nil, err
	}

	quote, err := vmToolBase64(args, "quote")
	if err != nil {
		return nil, ErrVMInvalidEvidence{Field: "quote", Cause: err}
	}
	if len(quote) == 0 {
		return nil, ErrVMInvalidEvidence{Field: "quote"}
	}
	signature, err := vmToolBase64(args, "signature")
	if err != nil {
		return nil, ErrVMInvalidEvidence{Field: "signature", Cause: err}
	}
	if len(signature) == 0 {
		return nil, ErrVMInvalidEvidence{Field: "signature"}
	}
	nonce, err := vmToolBase64(args, "nonce")
	if err != nil {
		return nil, ErrVMInvalidEvidence{Field: "nonce", Cause: err}
	}
	if len(nonce) == 0 {
		return nil, ErrVMInvalidEvidence{Field: "nonce"}
	}

	req := &VMAttestVerifyMCPRequest{
		Quote:              quote,
		Signature:          signature,
		SignatureAlgorithm: getString(args, "signature_algorithm"),
		Nonce:              nonce,
	}

	if raw, ok := args["expected_pcrs"].(map[string]interface{}); ok && len(raw) > 0 {
		req.ExpectedPCRs = make(map[int][]byte, len(raw))
		for key, value := range raw {
			idx, convErr := strconv.Atoi(key)
			if convErr != nil {
				return nil, ErrVMInvalidEvidence{Field: "expected_pcrs", Cause: convErr}
			}
			encoded, ok := value.(string)
			if !ok {
				return nil, ErrVMInvalidEvidence{Field: "expected_pcrs"}
			}
			decoded, decErr := base64.StdEncoding.DecodeString(encoded)
			if decErr != nil {
				return nil, ErrVMInvalidEvidence{Field: "expected_pcrs", Cause: decErr}
			}
			req.ExpectedPCRs[idx] = decoded
		}
	}

	result, err := p.VMAttestVerify(ctx, vmID, req)
	if err != nil {
		return nil, err
	}
	return marshalResult(result)
}
