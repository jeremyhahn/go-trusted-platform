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

// Package tenant provides integration test adapters for Tenant services.
// This file implements the TenantCommands interface using MCP (Model Context Protocol).
package tenant

import (
	"bytes"
	"context"
	"encoding/base64"
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

// ErrMCPRequestFailed indicates an MCP request failure
type ErrMCPRequestFailed struct {
	Operation string
	Code      int
	Message   string
}

func (e ErrMCPRequestFailed) Error() string {
	return fmt.Sprintf("MCP request failed [%s]: %s (code: %d)", e.Operation, e.Message, e.Code)
}

// =============================================================================
// MCP Protocol Types
// =============================================================================

// MCPJSONRPCRequest represents a JSON-RPC 2.0 request
type MCPJSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// MCPJSONRPCResponse represents a JSON-RPC 2.0 response
type MCPJSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *MCPJSONRPCError `json:"error,omitempty"`
	ID      int64            `json:"id"`
}

// MCPJSONRPCError represents a JSON-RPC 2.0 error
type MCPJSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data,omitempty"`
}

// MCPToolCallParams represents MCP tool call parameters
type MCPToolCallParams struct {
	Name      string      `json:"name"`
	Arguments interface{} `json:"arguments"`
}

// =============================================================================
// MCP Protocol Adapter
// =============================================================================

// MCPAdapter implements TenantCommands using MCP (Model Context Protocol)
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
	req := MCPJSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "initialize",
		Params: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo": map[string]string{
				"name":    "tenant-integration-test",
				"version": "1.0.0",
			},
		},
		ID: atomic.AddInt64(&a.requestID, 1),
	}

	_, err := a.doRequest(ctx, req)
	if err != nil {
		return ErrMCPRequestFailed{
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
func (a *MCPAdapter) doRequest(ctx context.Context, req MCPJSONRPCRequest) (json.RawMessage, error) {
	reqData, err := json.Marshal(req)
	if err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: req.Method,
			Message:   "failed to marshal request: " + err.Error(),
		}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, helpers.MCPEndpointURL(a.endpoint), bytes.NewReader(reqData))
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

	var rpcResp MCPJSONRPCResponse
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

// callTool invokes an MCP tool and returns the result
func (a *MCPAdapter) callTool(ctx context.Context, toolName string, args interface{}) (json.RawMessage, error) {
	req := MCPJSONRPCRequest{
		JSONRPC: "2.0",
		Method:  "tools/call",
		Params: MCPToolCallParams{
			Name:      toolName,
			Arguments: args,
		},
		ID: atomic.AddInt64(&a.requestID, 1),
	}

	return a.doRequest(ctx, req)
}

// =============================================================================
// Tenant CRUD Operations
// =============================================================================

// CreateTenant creates a new tenant
func (a *MCPAdapter) CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error) {
	result, err := a.callTool(ctx, "tenant_create", opts)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(result, &tenant); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "CreateTenant",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &CreateTenantResult{Tenant: &tenant}, nil
}

// GetTenant retrieves a tenant by ID
func (a *MCPAdapter) GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error) {
	result, err := a.callTool(ctx, "tenant_get", opts)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(result, &tenant); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "GetTenant",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &GetTenantResult{Tenant: &tenant}, nil
}

// GetTenantByName retrieves a tenant by name
func (a *MCPAdapter) GetTenantByName(ctx context.Context, opts GetTenantByNameOptions) (*GetTenantByNameResult, error) {
	result, err := a.callTool(ctx, "tenant_get_by_name", opts)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(result, &tenant); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "GetTenantByName",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &GetTenantByNameResult{Tenant: &tenant}, nil
}

// UpdateTenant updates an existing tenant
func (a *MCPAdapter) UpdateTenant(ctx context.Context, opts UpdateTenantOptions) (*UpdateTenantResult, error) {
	result, err := a.callTool(ctx, "tenant_update", opts)
	if err != nil {
		return nil, err
	}

	var tenant TenantData
	if err := json.Unmarshal(result, &tenant); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "UpdateTenant",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &UpdateTenantResult{Tenant: &tenant}, nil
}

// DeleteTenant removes a tenant
func (a *MCPAdapter) DeleteTenant(ctx context.Context, opts DeleteTenantOptions) (*DeleteTenantResult, error) {
	_, err := a.callTool(ctx, "tenant_delete", opts)
	if err != nil {
		return nil, err
	}

	return &DeleteTenantResult{Success: true, Message: "tenant deleted successfully"}, nil
}

// ListTenants lists all tenants with optional pagination
func (a *MCPAdapter) ListTenants(ctx context.Context, opts ListTenantsOptions) (*ListTenantsResult, error) {
	result, err := a.callTool(ctx, "tenant_list", opts)
	if err != nil {
		return nil, err
	}

	var listResult ListTenantsResult
	if err := json.Unmarshal(result, &listResult); err != nil {
		var tenants []*TenantData
		if err := json.Unmarshal(result, &tenants); err != nil {
			return nil, ErrMCPRequestFailed{
				Operation: "ListTenants",
				Message:   "failed to parse response: " + err.Error(),
			}
		}
		listResult.Tenants = tenants
		listResult.Total = len(tenants)
	}

	return &listResult, nil
}

// =============================================================================
// Tenant Lifecycle Operations
// =============================================================================

// SuspendTenant suspends a tenant
func (a *MCPAdapter) SuspendTenant(ctx context.Context, opts SuspendTenantOptions) (*SuspendTenantResult, error) {
	_, err := a.callTool(ctx, "tenant_suspend", opts)
	if err != nil {
		return nil, err
	}

	return &SuspendTenantResult{Success: true, Message: "tenant suspended successfully"}, nil
}

// ResumeTenant resumes a suspended tenant
func (a *MCPAdapter) ResumeTenant(ctx context.Context, opts ResumeTenantOptions) (*ResumeTenantResult, error) {
	_, err := a.callTool(ctx, "tenant_resume", opts)
	if err != nil {
		return nil, err
	}

	return &ResumeTenantResult{Success: true, Message: "tenant resumed successfully"}, nil
}

// =============================================================================
// Quota Operations
// =============================================================================

// GetQuotas retrieves tenant quotas
func (a *MCPAdapter) GetQuotas(ctx context.Context, opts GetQuotasOptions) (*GetQuotasResult, error) {
	result, err := a.callTool(ctx, "tenant_quotas_get", opts)
	if err != nil {
		return nil, err
	}

	var quotasResult GetQuotasResult
	if err := json.Unmarshal(result, &quotasResult); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "GetQuotas",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &quotasResult, nil
}

// UpdateQuotas updates tenant quotas
func (a *MCPAdapter) UpdateQuotas(ctx context.Context, opts UpdateQuotasOptions) (*UpdateQuotasResult, error) {
	result, err := a.callTool(ctx, "tenant_quotas_update", opts)
	if err != nil {
		return nil, err
	}

	var quotasResult UpdateQuotasResult
	if err := json.Unmarshal(result, &quotasResult); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "UpdateQuotas",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &quotasResult, nil
}

// GetUsage retrieves tenant resource usage
func (a *MCPAdapter) GetUsage(ctx context.Context, opts GetUsageOptions) (*GetUsageResult, error) {
	result, err := a.callTool(ctx, "tenant_usage_get", opts)
	if err != nil {
		return nil, err
	}

	var usageResult GetUsageResult
	if err := json.Unmarshal(result, &usageResult); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "GetUsage",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &usageResult, nil
}

// CheckQuota checks if a resource request can be fulfilled
func (a *MCPAdapter) CheckQuota(ctx context.Context, opts CheckQuotaOptions) (*CheckQuotaResult, error) {
	result, err := a.callTool(ctx, "tenant_quota_check", opts)
	if err != nil {
		return &CheckQuotaResult{
			TenantID: opts.TenantID,
			Resource: opts.Resource,
			Amount:   opts.Amount,
			Allowed:  false,
			Message:  err.Error(),
		}, nil
	}

	var checkResult CheckQuotaResult
	if err := json.Unmarshal(result, &checkResult); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "CheckQuota",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	return &checkResult, nil
}

// =============================================================================
// Network Operations
// =============================================================================

// SyncTenants synchronizes tenant manager state
func (a *MCPAdapter) SyncTenants(ctx context.Context) (*SyncTenantsResult, error) {
	_, err := a.callTool(ctx, "tenant_sync", nil)
	if err != nil {
		return nil, err
	}

	return &SyncTenantsResult{Success: true, Message: "tenant manager synchronized successfully"}, nil
}

// =============================================================================
// Per-Tenant Barrier Operations
// =============================================================================

// InitTenantBarrier explicitly initializes a per-tenant barrier.
func (a *MCPAdapter) InitTenantBarrier(ctx context.Context, opts InitTenantBarrierOptions) (*InitTenantBarrierResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
	}
	if opts.Threshold > 0 {
		args["threshold"] = opts.Threshold
	}
	if opts.Shares > 0 {
		args["shares"] = opts.Shares
	}

	if _, err := a.callTool(ctx, "platform_tenant_barrier_init", args); err != nil {
		return nil, err
	}

	return &InitTenantBarrierResult{
		Success: true,
		Message: "tenant barrier initialized successfully",
	}, nil
}

// UnsealTenantBarrier unseals a per-tenant barrier with the provided key.
// The key bytes are base64-encoded for transport across the JSON-RPC channel.
func (a *MCPAdapter) UnsealTenantBarrier(ctx context.Context, opts UnsealTenantBarrierOptions) (*UnsealTenantBarrierResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
	}
	if len(opts.Key) > 0 {
		args["key"] = base64.StdEncoding.EncodeToString(opts.Key)
	}

	if _, err := a.callTool(ctx, "platform_tenant_barrier_unseal", args); err != nil {
		return nil, err
	}

	return &UnsealTenantBarrierResult{
		Success: true,
		Message: "tenant barrier unsealed successfully",
	}, nil
}

// SealTenantBarrier seals a per-tenant barrier.
func (a *MCPAdapter) SealTenantBarrier(ctx context.Context, opts SealTenantBarrierOptions) (*SealTenantBarrierResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
	}

	if _, err := a.callTool(ctx, "platform_tenant_barrier_seal", args); err != nil {
		return nil, err
	}

	return &SealTenantBarrierResult{
		Success: true,
		Message: "tenant barrier sealed successfully",
	}, nil
}

// TenantBarrierStatus reports the current sealed/initialized state of a
// per-tenant barrier.
func (a *MCPAdapter) TenantBarrierStatus(ctx context.Context, opts TenantBarrierStatusOptions) (*TenantBarrierStatusResult, error) {
	args := map[string]interface{}{
		"tenant_id": opts.TenantID,
	}

	result, err := a.callTool(ctx, "platform_tenant_barrier_status", args)
	if err != nil {
		return nil, err
	}

	var statusResult TenantBarrierStatusResult
	if err := json.Unmarshal(result, &statusResult); err != nil {
		return nil, ErrMCPRequestFailed{
			Operation: "TenantBarrierStatus",
			Message:   "failed to parse response: " + err.Error(),
		}
	}

	if statusResult.TenantID == "" {
		statusResult.TenantID = opts.TenantID
	}

	return &statusResult, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Verify MCPAdapter implements TenantCommands
var _ TenantCommands = (*MCPAdapter)(nil)
