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

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	computesvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/compute"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// mcpToolsSource is where the daemon's VM tool arguments are defined; a
// declared gap names it so the skip says which tool lacks the option.
const mcpToolsSource = "pkg/api/mcp/vm_lifecycle_tools.go"

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

// mcpStatusResponse is the reply of a VM lifecycle tool, each of which
// carries a Status.
type mcpStatusResponse interface {
	proto.Message
	GetStatus() *pb.Status
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

// callProtoTool invokes an MCP tool and decodes its result, the protojson
// form of the ComputeService response, into out.
func (a *MCPAdapter) callProtoTool(ctx context.Context, toolName string, args map[string]interface{}, out proto.Message) error {
	result, err := a.callTool(ctx, toolName, args)
	if err != nil {
		return err
	}
	if err := protojson.Unmarshal(result, out); err != nil {
		return ErrMCPRequestFailed{
			Operation: toolName,
			Message:   "failed to parse tool result: " + err.Error(),
		}
	}
	return nil
}

// callVerb invokes a VM lifecycle tool that takes only the VM id and returns
// the status of its reply.
func (a *MCPAdapter) callVerb(ctx context.Context, toolName, vmID string, out mcpStatusResponse) (*pb.Status, error) {
	if err := a.callProtoTool(ctx, toolName, map[string]interface{}{"id": vmID}, out); err != nil {
		return nil, err
	}
	return out.GetStatus(), nil
}

// mcpNoSurface declares an option the daemon's MCP tool cannot carry, so the
// case skips as a declared gap instead of running without the option.
func mcpNoSurface(operation, reason string) error {
	return surface.ErrNoSurface{
		Transport: "MCP",
		Operation: operation,
		Reason:    reason + " (" + mcpToolsSource + ")",
	}
}

// =============================================================================
// ComputeCommands Implementation
// =============================================================================

// CreateVM creates a virtual machine via the vm_create tool.
func (a *MCPAdapter) CreateVM(ctx context.Context, opts CreateVMOptions) (*CreateVMResult, error) {
	if opts.DiskSizeGB > 0 || opts.Firmware != "" || opts.Start || len(opts.Labels) > 0 {
		return nil, mcpNoSurface("CreateVM", "vm_create carries only name, cpus, memory, tpm_enabled and secure_boot")
	}

	args := map[string]interface{}{
		"name":        opts.Name,
		"tpm_enabled": opts.TPM,
		"secure_boot": opts.SecureBoot,
	}
	if opts.CPUs > 0 {
		args["cpus"] = opts.CPUs
	}
	if opts.MemoryMB > 0 {
		args["memory"] = opts.MemoryMB
	}

	resp := &pb.CreateVMResponse{}
	if err := a.callProtoTool(ctx, "vm_create", args, resp); err != nil {
		return nil, err
	}
	return createVMResultFromDomain(computesvc.VMFromProto(resp.GetVm())), nil
}

// StartVM starts a virtual machine via the vm_start tool.
func (a *MCPAdapter) StartVM(ctx context.Context, opts StartVMOptions) (*StartVMResult, error) {
	status, err := a.callVerb(ctx, "vm_start", opts.VMID, &pb.StartVMResponse{})
	if err != nil {
		return nil, err
	}
	return &StartVMResult{Success: status.GetSuccess(), Message: status.GetMessage()}, nil
}

// StopVM stops a virtual machine via the vm_stop tool.
func (a *MCPAdapter) StopVM(ctx context.Context, opts StopVMOptions) (*StopVMResult, error) {
	if opts.Force || opts.TimeoutSeconds > 0 {
		return nil, mcpNoSurface("StopVM", "vm_stop carries only id, not force or timeout_seconds")
	}

	status, err := a.callVerb(ctx, "vm_stop", opts.VMID, &pb.StopVMResponse{})
	if err != nil {
		return nil, err
	}
	return &StopVMResult{Success: status.GetSuccess(), Message: status.GetMessage()}, nil
}

// RebootVM restarts a running virtual machine via the vm_reboot tool.
func (a *MCPAdapter) RebootVM(ctx context.Context, opts RebootVMOptions) (*RebootVMResult, error) {
	if opts.Force {
		return nil, mcpNoSurface("RebootVM", "vm_reboot carries only id, not force")
	}

	status, err := a.callVerb(ctx, "vm_reboot", opts.VMID, &pb.RebootVMResponse{})
	if err != nil {
		return nil, err
	}
	return &RebootVMResult{Success: status.GetSuccess(), Message: status.GetMessage()}, nil
}

// SuspendVM pauses a running virtual machine via the vm_suspend tool.
func (a *MCPAdapter) SuspendVM(ctx context.Context, opts SuspendVMOptions) (*SuspendVMResult, error) {
	status, err := a.callVerb(ctx, "vm_suspend", opts.VMID, &pb.SuspendVMResponse{})
	if err != nil {
		return nil, err
	}
	return &SuspendVMResult{Success: status.GetSuccess(), Message: status.GetMessage()}, nil
}

// ResumeVM continues a suspended virtual machine via the vm_resume tool.
func (a *MCPAdapter) ResumeVM(ctx context.Context, opts ResumeVMOptions) (*ResumeVMResult, error) {
	status, err := a.callVerb(ctx, "vm_resume", opts.VMID, &pb.ResumeVMResponse{})
	if err != nil {
		return nil, err
	}
	return &ResumeVMResult{Success: status.GetSuccess(), Message: status.GetMessage()}, nil
}

// DeleteVM deletes a virtual machine via the vm_delete tool.
func (a *MCPAdapter) DeleteVM(ctx context.Context, opts DeleteVMOptions) (*DeleteVMResult, error) {
	if opts.DeleteDisks {
		return nil, mcpNoSurface("DeleteVM", "vm_delete carries only id, not delete_disks")
	}

	status, err := a.callVerb(ctx, "vm_delete", opts.VMID, &pb.DeleteVMResponse{})
	if err != nil {
		return nil, err
	}
	return &DeleteVMResult{Success: status.GetSuccess(), Message: status.GetMessage()}, nil
}

// GetVM retrieves a virtual machine via the vm_get tool.
func (a *MCPAdapter) GetVM(ctx context.Context, opts GetVMOptions) (*GetVMResult, error) {
	resp := &pb.GetVMResponse{}
	if err := a.callProtoTool(ctx, "vm_get", map[string]interface{}{"id": opts.VMID}, resp); err != nil {
		return nil, err
	}
	if resp.GetVm() == nil {
		return nil, ErrMCPRequestFailed{Operation: "vm_get", Message: "tool result carries no vm"}
	}
	return getVMResultFromDomain(computesvc.VMFromProto(resp.GetVm())), nil
}

// ListVMs lists virtual machines via the vm_list tool.
func (a *MCPAdapter) ListVMs(ctx context.Context, opts ListVMsOptions) (*ListVMsResult, error) {
	if opts.StateFilter != "" || opts.PageSize > 0 || len(opts.Labels) > 0 {
		return nil, mcpNoSurface("ListVMs", "vm_list takes no state, page size or label filter")
	}

	resp := &pb.ListVMsResponse{}
	if err := a.callProtoTool(ctx, "vm_list", map[string]interface{}{}, resp); err != nil {
		return nil, err
	}

	vms := make([]*computesvc.VM, len(resp.GetVms()))
	for i, vm := range resp.GetVms() {
		vms[i] = computesvc.VMFromProto(vm)
	}
	result := listVMsResultFromDomain(&computesvc.ListVMsResult{VMs: vms})
	result.TotalItems = resp.GetPagination().GetTotalItems()
	return result, nil
}
