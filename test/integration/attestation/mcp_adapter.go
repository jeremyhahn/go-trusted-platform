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
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
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

// protoArgs turns a platform.v1 request into tool arguments: the daemon's
// gRPC-bound tools decode their arguments as proto JSON with proto names.
func protoArgs(req proto.Message) (map[string]any, error) {
	raw, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(req)
	if err != nil {
		return nil, err
	}
	args := map[string]any{}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, err
	}
	return args, nil
}

// callProtoTool calls a tool and decodes its proto JSON result into out.
func (a *MCPAdapter) callProtoTool(ctx context.Context, operation, toolName string, args map[string]any, out proto.Message) error {
	result, err := a.callTool(ctx, toolName, args)
	if err != nil {
		return err
	}
	if err := protojson.Unmarshal(result, out); err != nil {
		return &MCPAdapterError{Operation: operation, Message: "failed to parse response: " + err.Error()}
	}
	return nil
}

// collectVMAttestation calls attestation_collect_vm with the request gRPC sends.
func (a *MCPAdapter) collectVMAttestation(ctx context.Context, operation, vmID string, nonce []byte, pcrIndices []int, hashAlgorithm string) (*platformv1.CollectVMAttestationResponse, error) {
	args, err := protoArgs(collectVMAttestationRequest(vmID, nonce, pcrIndices, hashAlgorithm))
	if err != nil {
		return nil, &MCPAdapterError{Operation: operation, Message: "failed to encode request: " + err.Error()}
	}
	var resp platformv1.CollectVMAttestationResponse
	if err := a.callProtoTool(ctx, operation, "attestation_collect_vm", args, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// GenerateVMQuote collects a VM quote via attestation_collect_vm.
func (a *MCPAdapter) GenerateVMQuote(ctx context.Context, opts GenerateVMQuoteOptions) (*GenerateVMQuoteResult, error) {
	resp, err := a.collectVMAttestation(ctx, "GenerateVMQuote", opts.VMID, opts.Nonce, opts.PCRIndices, opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	result, err := vmQuoteResult(resp)
	if err != nil {
		return nil, &MCPAdapterError{Operation: "GenerateVMQuote", Message: err.Error()}
	}
	return result, nil
}

// GetVMIdentity has no MCP tool: no transport serves it.
func (a *MCPAdapter) GetVMIdentity(ctx context.Context, opts GetVMIdentityOptions) (*GetVMIdentityResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "GetVMIdentity"}
}

// GetVMAttestation collects a full VM attestation via attestation_collect_vm.
func (a *MCPAdapter) GetVMAttestation(ctx context.Context, opts GetVMAttestationOptions) (*GetVMAttestationResult, error) {
	resp, err := a.collectVMAttestation(ctx, "GetVMAttestation", opts.VMID, opts.Nonce, opts.PCRIndices, opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	result, err := vmAttestationResult(resp)
	if err != nil {
		return nil, &MCPAdapterError{Operation: "GetVMAttestation", Message: err.Error()}
	}
	return result, nil
}

// VerifyVMAttestation verifies a quote via attestation_verify_quote with the
// request gRPC sends.
func (a *MCPAdapter) VerifyVMAttestation(ctx context.Context, opts VerifyVMAttestationOptions) (*VerifyVMAttestationResult, error) {
	args, err := protoArgs(verifyAttestationQuoteRequest(opts))
	if err != nil {
		return nil, &MCPAdapterError{Operation: "VerifyVMAttestation", Message: "failed to encode request: " + err.Error()}
	}
	var resp platformv1.VerifyAttestationQuoteResponse
	if err := a.callProtoTool(ctx, "VerifyVMAttestation", "attestation_verify_quote", args, &resp); err != nil {
		return nil, err
	}
	return verifyVMAttestationResult(opts, &resp), nil
}

// =============================================================================
// Manifest Operations
// =============================================================================

// BuildManifest builds and stores a signed host manifest via
// attestation_create_manifest.
func (a *MCPAdapter) BuildManifest(ctx context.Context, opts BuildManifestOptions) (*BuildManifestResult, error) {
	args := map[string]any{
		"host_id":            opts.HostID,
		"hash_algorithm":     opts.HashAlgorithm,
		"include_vms":        len(opts.VMAttestations) > 0,
		"include_containers": len(opts.ContainerAttestations) > 0,
		"sign":               true,
	}
	var resp platformv1.BuildManifestResponse
	if err := a.callProtoTool(ctx, "BuildManifest", "attestation_create_manifest", args, &resp); err != nil {
		return nil, err
	}
	result, err := buildManifestResult(&resp)
	if err != nil {
		return nil, &MCPAdapterError{Operation: "BuildManifest", Message: err.Error()}
	}
	return result, nil
}

// SignManifest has no MCP tool: no transport serves it, and
// attestation_create_manifest signs unless sign is false.
func (a *MCPAdapter) SignManifest(ctx context.Context, opts SignManifestOptions) (*SignManifestResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "SignManifest"}
}

// getManifest calls attestation_get_manifest.
func (a *MCPAdapter) getManifest(ctx context.Context, operation, manifestID string) (*platformv1.GetManifestResponse, error) {
	var resp platformv1.GetManifestResponse
	if err := a.callProtoTool(ctx, operation, "attestation_get_manifest", map[string]any{"id": manifestID}, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

// VerifyManifest verifies a stored manifest via attestation_verify_manifest.
// The stored manifest is fetched first, as gRPC does, so the host id can be
// compared.
func (a *MCPAdapter) VerifyManifest(ctx context.Context, opts VerifyManifestOptions) (*VerifyManifestResult, error) {
	getResp, err := a.getManifest(ctx, "VerifyManifest", opts.ManifestID)
	if err != nil {
		return nil, err
	}
	manifest, err := storedManifest(getResp)
	if err != nil {
		return nil, &MCPAdapterError{Operation: "VerifyManifest", Message: err.Error()}
	}

	var resp platformv1.VerifyManifestResponse
	if err := a.callProtoTool(ctx, "VerifyManifest", "attestation_verify_manifest", map[string]any{"id": opts.ManifestID}, &resp); err != nil {
		return nil, err
	}
	result, err := verifyManifestResult(opts, manifest, &resp)
	if err != nil {
		return nil, &MCPAdapterError{Operation: "VerifyManifest", Message: err.Error()}
	}
	return result, nil
}

// GetManifest retrieves a manifest by id via attestation_get_manifest.
func (a *MCPAdapter) GetManifest(ctx context.Context, opts GetManifestOptions) (*GetManifestResult, error) {
	resp, err := a.getManifest(ctx, "GetManifest", opts.ManifestID)
	if err != nil {
		return nil, err
	}
	result, err := getManifestResult(resp)
	if err != nil {
		return nil, &MCPAdapterError{Operation: "GetManifest", Message: err.Error()}
	}
	return result, nil
}

// =============================================================================
// Push Operations
// =============================================================================

// PushAttestation has no MCP tool: no transport serves it.
func (a *MCPAdapter) PushAttestation(ctx context.Context, opts PushAttestationOptions) (*PushAttestationResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "PushAttestation"}
}

// PushAttestationBatch has no MCP tool: no transport serves it.
func (a *MCPAdapter) PushAttestationBatch(ctx context.Context, opts PushAttestationBatchOptions) (*PushAttestationBatchResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "PushAttestationBatch"}
}

// GetPushStatus has no MCP tool: no transport serves it.
func (a *MCPAdapter) GetPushStatus(ctx context.Context, opts GetPushStatusOptions) (*GetPushStatusResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "GetPushStatus"}
}

// =============================================================================
// Workload Chain Operations
// =============================================================================

// ExtendWorkloadChain has no MCP tool: no transport serves it.
func (a *MCPAdapter) ExtendWorkloadChain(ctx context.Context, opts ExtendWorkloadChainOptions) (*ExtendWorkloadChainResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "ExtendWorkloadChain"}
}

// GetWorkloadChainHistory has no MCP tool: no transport serves it.
func (a *MCPAdapter) GetWorkloadChainHistory(ctx context.Context, opts GetWorkloadChainHistoryOptions) (*GetWorkloadChainHistoryResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "GetWorkloadChainHistory"}
}

// VerifyWorkloadChain has no MCP tool: no transport serves it.
func (a *MCPAdapter) VerifyWorkloadChain(ctx context.Context, opts VerifyWorkloadChainOptions) (*VerifyWorkloadChainResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "VerifyWorkloadChain"}
}

// GetWorkloadChainStats has no MCP tool: no transport serves it.
func (a *MCPAdapter) GetWorkloadChainStats(ctx context.Context, opts GetWorkloadChainStatsOptions) (*GetWorkloadChainStatsResult, error) {
	return nil, surface.ErrNoSurface{Transport: "MCP", Operation: "GetWorkloadChainStats"}
}

// classifyMCPReportingError maps a reporting tool's failure onto the suite's
// typed states. The tool answers a never-collected device with the JSON-RPC
// NotFound code (#505); an unconfigured reporting service is told by its
// text, as on the CLI.
func classifyMCPReportingError(transport, operation, deviceID string, err error) error {
	if isNotConfiguredText(err) {
		return ErrReportingUnavailable{Transport: transport, Operation: operation, Err: err}
	}
	var rpcErr *MCPAdapterError
	if deviceID != "" && errors.As(err, &rpcErr) && rpcErr.Code == mcpwire.NotFound {
		return ErrReportNotCollected{Transport: transport, DeviceID: deviceID, Err: err}
	}
	return err
}

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
		return classifyMCPReportingError(a.Name(), operation, deviceID, err)
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
