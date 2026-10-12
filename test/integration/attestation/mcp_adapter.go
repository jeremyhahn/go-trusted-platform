//go:build integration

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

package attestation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// MCPAdapterError represents an error from the MCP adapter
type MCPAdapterError struct {
	Operation string
	Code      int
	Message   string
}

func (e *MCPAdapterError) Error() string {
	return fmt.Sprintf("MCP adapter error [%s]: %s (code: %d)", e.Operation, e.Message, e.Code)
}

// JSONRPCRequest represents a JSON-RPC 2.0 request
type JSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// JSONRPCResponse represents a JSON-RPC 2.0 response
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

// JSONRPCError represents a JSON-RPC 2.0 error
type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// ToolCallParams represents MCP tool call parameters
type ToolCallParams struct {
	Name      string      `json:"name"`
	Arguments interface{} `json:"arguments"`
}

// MCPAdapter implements AttestationCommands using MCP (Model Context Protocol)
type MCPAdapter struct {
	endpoint  string
	client    *http.Client
	requestID int64
}

// NewMCPAdapter creates a new MCP adapter
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{
		endpoint: GetMCPEndpoint(),
		client:   helpers.NewHTTPClient(30 * time.Second),
	}
}

// Setup prepares the adapter for testing
func (a *MCPAdapter) Setup(ctx context.Context) error {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "attestation-integration-test",
				"version": "1.0.0",
			},
		},
		ID: atomic.AddInt64(&a.requestID, 1),
	}

	_, err := a.doRequest(ctx, req)
	if err != nil {
		return &MCPAdapterError{
			Operation: "Setup",
			Message:   "failed to initialize: " + err.Error(),
		}
	}

	return nil
}

// Teardown cleans up after testing
func (a *MCPAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name
func (a *MCPAdapter) Name() string {
	return "MCP"
}

// doRequest performs a JSON-RPC request and returns the response
func (a *MCPAdapter) doRequest(ctx context.Context, req JSONRPCRequest) (json.RawMessage, error) {
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to marshal request: " + err.Error(),
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, helpers.MCPEndpointURL(a.endpoint), bytes.NewReader(reqData))
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to create request: " + err.Error(),
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to read response: " + err.Error(),
		}
	}

	var rpcResp JSONRPCResponse
	if err := json.Unmarshal(respData, &rpcResp); err != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	if rpcResp.Error != nil {
		return nil, &MCPAdapterError{
			Operation: req.Method,
			Code:      rpcResp.Error.Code,
			Message:   rpcResp.Error.Message,
		}
	}

	return rpcResp.Result, nil
}

// callTool invokes an MCP tool and returns the result
func (a *MCPAdapter) callTool(ctx context.Context, toolName string, args interface{}) (json.RawMessage, error) {
	req := JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params: ToolCallParams{
			Name:      toolName,
			Arguments: args,
		},
		ID: atomic.AddInt64(&a.requestID, 1),
	}

	return a.doRequest(ctx, req)
}

// =============================================================================
// VM Attestation Operations
// =============================================================================

// GenerateVMQuote generates a TPM quote for a VM
func (a *MCPAdapter) GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error) {
	result, err := a.callTool(ctx, "attestation_vm_generate_quote", opts)
	if err != nil {
		return nil, err
	}

	var resp GenerateVMQuoteResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "GenerateVMQuote",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// GetVMIdentity retrieves VM identity from vTPM EK certificate
func (a *MCPAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	result, err := a.callTool(ctx, "attestation_vm_get_identity", opts)
	if err != nil {
		return nil, err
	}

	var resp GetVMIdentityResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "GetVMIdentity",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// GetVMAttestation generates a full VM attestation
func (a *MCPAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	result, err := a.callTool(ctx, "attestation_vm_get_attestation", opts)
	if err != nil {
		return nil, err
	}

	var resp GetVMAttestationResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "GetVMAttestation",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// VerifyVMAttestation verifies a VM attestation
func (a *MCPAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	result, err := a.callTool(ctx, "attestation_vm_verify", opts)
	if err != nil {
		return nil, err
	}

	var resp VerifyVMAttestationResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "VerifyVMAttestation",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds a host manifest with attestations
func (a *MCPAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	result, err := a.callTool(ctx, "attestation_manifest_build", opts)
	if err != nil {
		return nil, err
	}

	var resp BuildManifestResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "BuildManifest",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// SignManifest signs a manifest with the host TPM
func (a *MCPAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	result, err := a.callTool(ctx, "attestation_manifest_sign", opts)
	if err != nil {
		return nil, err
	}

	var resp SignManifestResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "SignManifest",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// VerifyManifest verifies a signed manifest
func (a *MCPAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	result, err := a.callTool(ctx, "attestation_manifest_verify", opts)
	if err != nil {
		return nil, err
	}

	var resp VerifyManifestResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "VerifyManifest",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// GetManifest retrieves a manifest by ID
func (a *MCPAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	result, err := a.callTool(ctx, "attestation_manifest_get", opts)
	if err != nil {
		return nil, err
	}

	var resp GetManifestResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "GetManifest",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// =============================================================================
// Push Operations
// =============================================================================

// PushAttestation pushes an attestation to a target
func (a *MCPAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	result, err := a.callTool(ctx, "attestation_push", opts)
	if err != nil {
		return nil, err
	}

	var resp PushAttestationResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "PushAttestation",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// PushAttestationBatch pushes to multiple targets concurrently
func (a *MCPAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	result, err := a.callTool(ctx, "attestation_push_batch", opts)
	if err != nil {
		return nil, err
	}

	var resp PushAttestationBatchResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "PushAttestationBatch",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// GetPushStatus retrieves the status of a push operation
func (a *MCPAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	result, err := a.callTool(ctx, "attestation_push_status", opts)
	if err != nil {
		return nil, err
	}

	var resp GetPushStatusResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "GetPushStatus",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// =============================================================================
// Workload Chain Operations
// =============================================================================

// ExtendWorkloadChain extends the workload PCR with a measurement
func (a *MCPAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	result, err := a.callTool(ctx, "attestation_workload_extend", opts)
	if err != nil {
		return nil, err
	}

	var resp ExtendWorkloadChainResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "ExtendWorkloadChain",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// GetWorkloadChainHistory retrieves the chain history
func (a *MCPAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	result, err := a.callTool(ctx, "attestation_workload_history", opts)
	if err != nil {
		return nil, err
	}

	var resp GetWorkloadChainHistoryResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "GetWorkloadChainHistory",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// VerifyWorkloadChain verifies the chain against expected PCR
func (a *MCPAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	result, err := a.callTool(ctx, "attestation_workload_verify", opts)
	if err != nil {
		return nil, err
	}

	var resp VerifyWorkloadChainResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "VerifyWorkloadChain",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// GetWorkloadChainStats retrieves chain statistics
func (a *MCPAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	result, err := a.callTool(ctx, "attestation_workload_stats", opts)
	if err != nil {
		return nil, err
	}

	var resp GetWorkloadChainStatsResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, &MCPAdapterError{
			Operation: "GetWorkloadChainStats",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &resp, nil
}

// mcpNeverCollected is the MCP tool's phrase for a device with no report.
const mcpNeverCollected = "no report has been collected for device"

// reportingTool calls one reporting tool and decodes its result into out.
// deviceID is the tool's device_id argument and, when set, lets a
// never-collected failure be told apart.
func (a *MCPAdapter) reportingTool(ctx context.Context, tool, operation, deviceID string, out any) error {
	args := map[string]any{}
	if deviceID != "" {
		args["device_id"] = deviceID
	}
	result, err := a.callTool(ctx, tool, args)
	if err != nil {
		return classifyReportingText(a.Name(), operation, deviceID, mcpNeverCollected, err)
	}
	if err := json.Unmarshal(result, out); err != nil {
		return &MCPAdapterError{Operation: operation, Message: "failed to parse response: " + err.Error()}
	}
	return nil
}

// ListDeviceReports reads every cached device report via MCP.
func (a *MCPAdapter) ListDeviceReports(ctx context.Context) (*DeviceReportsResult, error) {
	var result DeviceReportsResult
	if err := a.reportingTool(ctx, "attestation_device_reports", "ListDeviceReports", "", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetDeviceReport reads one device's cached report via MCP.
func (a *MCPAdapter) GetDeviceReport(ctx context.Context, opts DeviceReportOptions) (*DeviceReport, error) {
	var result DeviceReport
	if err := a.reportingTool(ctx, "attestation_device_report", "GetDeviceReport", opts.DeviceID, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// RefreshDeviceReport asks the collector to re-collect one device via MCP.
func (a *MCPAdapter) RefreshDeviceReport(ctx context.Context, opts DeviceReportOptions) (*RefreshDeviceReportResult, error) {
	var result RefreshDeviceReportResult
	if err := a.reportingTool(ctx, "attestation_device_refresh", "RefreshDeviceReport", opts.DeviceID, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// DescribeCallerPolicy reads the node's caller-admission policy via MCP.
func (a *MCPAdapter) DescribeCallerPolicy(ctx context.Context) (*calleradmission.Description, error) {
	var result calleradmission.Description
	if err := a.reportingTool(ctx, "attestation_caller_policy", "DescribeCallerPolicy", "", &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Verify MCPAdapter implements AttestationCommands
var _ AttestationCommands = (*MCPAdapter)(nil)
