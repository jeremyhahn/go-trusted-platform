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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrMCPRequestFailed indicates an MCP JSON-RPC request failure.
type ErrMCPRequestFailed struct {
	Operation string
	Code      int
	Message   string
}

func (e ErrMCPRequestFailed) Error() string {
	return fmt.Sprintf("compute: MCP error [%s]: %s (code: %d)",
		e.Operation, e.Message, e.Code)
}

// ErrMCPSetupFailed indicates the MCP endpoint is unreachable.
type ErrMCPSetupFailed struct {
	Endpoint string
	Message  string
}

func (e ErrMCPSetupFailed) Error() string {
	return fmt.Sprintf("compute: MCP setup failed for %s: %s", e.Endpoint, e.Message)
}

// =============================================================================
// JSON-RPC Types
// =============================================================================

// mcpRequest represents a JSON-RPC 2.0 request.
type mcpRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// mcpResponse represents a JSON-RPC 2.0 response.
type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

// mcpError represents a JSON-RPC 2.0 error.
type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// mcpToolCallParams represents MCP tool call parameters.
type mcpToolCallParams struct {
	Name      string      `json:"name"`
	Arguments interface{} `json:"arguments"`
}

// =============================================================================
// MCP Tool Response Types
// =============================================================================

// mcpVMResult represents a VM result from an MCP tool call.
type mcpVMResult struct {
	ID       string            `json:"id"`
	Name     string            `json:"name"`
	State    string            `json:"state"`
	CPUs     uint32            `json:"cpus"`
	MemoryMB uint64            `json:"memory_mb"`
	Labels   map[string]string `json:"labels,omitempty"`
	Success  bool              `json:"success"`
	Message  string            `json:"message"`
}

// mcpListVMsResult represents the list VMs result from an MCP tool call.
type mcpListVMsResult struct {
	VMs        []mcpVMResult `json:"vms"`
	TotalItems uint64        `json:"total_items"`
}

// =============================================================================
// MCP Adapter
// =============================================================================

// MCPAdapter implements ComputeCommands using the MCP protocol (JSON-RPC 2.0).
type MCPAdapter struct {
	endpoint  string
	client    *http.Client
	requestID int64
}

// NewMCPAdapter creates a new MCP adapter.
func NewMCPAdapter() *MCPAdapter {
	return &MCPAdapter{
		endpoint: helpers.MCPEndpointURL(GetMCPEndpoint()),
		client:   helpers.NewHTTPClient(30 * time.Second),
	}
}

// Setup verifies the MCP endpoint is reachable by sending an initialize request.
func (a *MCPAdapter) Setup(ctx context.Context) error {
	req := mcpRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "compute-integration-test",
				"version": "1.0.0",
			},
		},
		ID: atomic.AddInt64(&a.requestID, 1),
	}

	_, err := a.doRequest(ctx, req)
	if err != nil {
		return ErrMCPSetupFailed{
			Endpoint: a.endpoint,
			Message:  "failed to initialize: " + err.Error(),
		}
	}

	return nil
}

// Teardown cleans up after testing.
func (a *MCPAdapter) Teardown(ctx context.Context) error {
	return nil
}

// Name returns the adapter name.
func (a *MCPAdapter) Name() string {
	return "MCP"
}

// doRequest performs a JSON-RPC request and returns the result payload.
func (a *MCPAdapter) doRequest(ctx context.Context, req mcpRequest) (json.RawMessage, error) {
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: req.Method,
			Message:   "failed to marshal request: " + err.Error(),
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, a.endpoint, bytes.NewReader(reqData))
	if err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: req.Method,
			Message:   "failed to create request: " + err.Error(),
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: req.Method,
			Message:   "request failed: " + err.Error(),
		}
	}
	defer resp.Body.Close()

	respData, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: req.Method,
			Message:   "failed to read response: " + err.Error(),
		}
	}

	var rpcResp mcpResponse
	if err := json.Unmarshal(respData, &rpcResp); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: req.Method,
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	if rpcResp.Error != nil {
		return nil, ErrMCPRequestFailed{
			Operation: req.Method,
			Code:      rpcResp.Error.Code,
			Message:   rpcResp.Error.Message,
		}
	}

	return rpcResp.Result, nil
}

// callTool invokes an MCP tool and returns the result payload.
func (a *MCPAdapter) callTool(ctx context.Context, toolName string, args interface{}) (json.RawMessage, error) {
	req := mcpRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params: mcpToolCallParams{
			Name:      toolName,
			Arguments: args,
		},
		ID: atomic.AddInt64(&a.requestID, 1),
	}

	return a.doRequest(ctx, req)
}

// =============================================================================
// ComputeCommands Implementation
// =============================================================================

// CreateVM creates a virtual machine via MCP.
func (a *MCPAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	args := map[string]interface{}{
		"name":         opts.Name,
		"cpus":         opts.CPUs,
		"memory_mb":    opts.MemoryMB,
		"disk_size_gb": opts.DiskSizeGB,
	}

	if opts.Firmware != "" {
		args["firmware"] = opts.Firmware
	}
	if opts.SecureBoot {
		args["secure_boot"] = true
	}
	if opts.TPM {
		args["tpm"] = true
	}
	if opts.Start {
		args["start"] = true
	}
	if len(opts.Labels) > 0 {
		args["labels"] = opts.Labels
	}

	result, err := a.callTool(ctx, "platform_compute_create_vm", args)
	if err != nil {
		return nil, err
	}

	var resp mcpVMResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "platform_compute_create_vm",
			Message:   "failed to parse tool result: " + err.Error(),
		}
	}

	return &CreateVMResult{
		VMID:    resp.ID,
		Name:    resp.Name,
		State:   resp.State,
		Success: resp.Success,
		Labels:  resp.Labels,
	}, nil
}

// StartVM starts a virtual machine via MCP.
func (a *MCPAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	args := map[string]interface{}{
		"id": opts.VMID,
	}

	result, err := a.callTool(ctx, "platform_compute_start_vm", args)
	if err != nil {
		return nil, err
	}

	var resp mcpVMResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "platform_compute_start_vm",
			Message:   "failed to parse tool result: " + err.Error(),
		}
	}

	return &StartVMResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// StopVM stops a virtual machine via MCP.
func (a *MCPAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	args := map[string]interface{}{
		"id": opts.VMID,
	}

	if opts.Force {
		args["force"] = true
	}
	if opts.TimeoutSeconds > 0 {
		args["timeout_seconds"] = opts.TimeoutSeconds
	}

	result, err := a.callTool(ctx, "platform_compute_stop_vm", args)
	if err != nil {
		return nil, err
	}

	var resp mcpVMResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "platform_compute_stop_vm",
			Message:   "failed to parse tool result: " + err.Error(),
		}
	}

	return &StopVMResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// DeleteVM deletes a virtual machine via MCP.
func (a *MCPAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	args := map[string]interface{}{
		"id": opts.VMID,
	}

	if opts.DeleteDisks {
		args["delete_disks"] = true
	}

	result, err := a.callTool(ctx, "platform_compute_delete_vm", args)
	if err != nil {
		return nil, err
	}

	var resp mcpVMResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "platform_compute_delete_vm",
			Message:   "failed to parse tool result: " + err.Error(),
		}
	}

	return &DeleteVMResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// GetVM retrieves a virtual machine via MCP.
func (a *MCPAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	args := map[string]interface{}{
		"id": opts.VMID,
	}

	result, err := a.callTool(ctx, "platform_compute_get_vm", args)
	if err != nil {
		return nil, err
	}

	var resp mcpVMResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "platform_compute_get_vm",
			Message:   "failed to parse tool result: " + err.Error(),
		}
	}

	return &GetVMResult{
		VMID:     resp.ID,
		Name:     resp.Name,
		State:    resp.State,
		CPUs:     resp.CPUs,
		MemoryMB: resp.MemoryMB,
		Labels:   resp.Labels,
	}, nil
}

// ListVMs lists virtual machines via MCP.
func (a *MCPAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	args := map[string]interface{}{}

	if opts.StateFilter != "" {
		args["state"] = opts.StateFilter
	}
	if opts.PageSize > 0 {
		args["page_size"] = opts.PageSize
	}
	if len(opts.Labels) > 0 {
		args["labels"] = opts.Labels
	}

	result, err := a.callTool(ctx, "platform_compute_list_vms", args)
	if err != nil {
		return nil, err
	}

	var resp mcpListVMsResult
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "platform_compute_list_vms",
			Message:   "failed to parse tool result: " + err.Error(),
		}
	}

	vms := make([]VMSummary, len(resp.VMs))
	for i, vm := range resp.VMs {
		vms[i] = VMSummary{
			VMID:   vm.ID,
			Name:   vm.Name,
			State:  vm.State,
			Labels: vm.Labels,
		}
	}

	return &ListVMsResult{
		VMs:        vms,
		TotalItems: resp.TotalItems,
	}, nil
}
