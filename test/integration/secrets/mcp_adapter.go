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

// Package secrets provides integration test adapters for Secrets services.
// This file implements the SecretsCommands interface using the MCP (Model Context Protocol).

//go:build integration

package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
)

// =============================================================================
// Environment Variables and Constants
// =============================================================================

const (
	// EnvMCPEndpoint is the environment variable for the MCP server endpoint.
	EnvMCPEndpoint = "PLATFORM_MCP_ENDPOINT"

	// DefaultMCPEndpoint is the default MCP server endpoint.
	DefaultMCPEndpoint = "localhost:9445"

	// DefaultMCPTimeout is the default timeout for MCP requests.
	DefaultMCPTimeout = 30 * time.Second

	// MCPProtocolVersion is the MCP protocol version supported by this client.
	MCPProtocolVersion = "2024-11-05"

	// MCPClientName is the name of this MCP client.
	MCPClientName = "secrets-integration-test"

	// MCPClientVersion is the version of this MCP client.
	MCPClientVersion = "1.0.0"
)

// =============================================================================
// JSON-RPC 2.0 Types
// =============================================================================

// jsonRPCRequest represents a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// jsonRPCResponse represents a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

// jsonRPCError represents a JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// JSON-RPC 2.0 standard error codes.
const (
	jsonRPCParseError     = -32700
	jsonRPCInvalidRequest = -32600
	jsonRPCMethodNotFound = -32601
	jsonRPCInvalidParams  = -32602
	jsonRPCInternalError  = -32603
)

// =============================================================================
// MCP Protocol Types
// =============================================================================

// mcpInitializeRequest is the MCP initialize request payload.
type mcpInitializeRequest struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    mcpCapabilities `json:"capabilities"`
	ClientInfo      mcpClientInfo   `json:"clientInfo"`
}

// mcpCapabilities represents MCP client capabilities.
type mcpCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

// mcpClientInfo represents MCP client information.
type mcpClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpInitializeResult is the MCP initialize response payload.
type mcpInitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      mcpServerInfo          `json:"serverInfo"`
}

// mcpServerInfo represents MCP server information.
type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpCallToolRequest is the MCP tools/call request payload.
type mcpCallToolRequest struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// mcpCallToolResult is the MCP tools/call response payload.
type mcpCallToolResult struct {
	Content []mcpContentItem `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

// mcpContentItem represents a content item in a tool result.
type mcpContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// =============================================================================
// Error Types
// =============================================================================

// ErrMCPConnectionFailed indicates the MCP connection failed.
type ErrMCPConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPConnectionFailed) Error() string {
	return fmt.Sprintf("MCP connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrMCPConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrMCPInitializeFailed indicates MCP initialization failed.
type ErrMCPInitializeFailed struct {
	Err error
}

func (e ErrMCPInitializeFailed) Error() string {
	return fmt.Sprintf("MCP initialization failed: %v", e.Err)
}

func (e ErrMCPInitializeFailed) Unwrap() error {
	return e.Err
}

// ErrMCPToolCallFailed indicates an MCP tool call failed.
type ErrMCPToolCallFailed struct {
	Tool    string
	Code    int
	Message string
}

func (e ErrMCPToolCallFailed) Error() string {
	return fmt.Sprintf("MCP tool %q call failed (code %d): %s", e.Tool, e.Code, e.Message)
}

// ErrMCPResponseParseFailed indicates MCP response parsing failed.
type ErrMCPResponseParseFailed struct {
	Operation string
	Err       error
}

func (e ErrMCPResponseParseFailed) Error() string {
	return fmt.Sprintf("failed to parse MCP response for %s: %v", e.Operation, e.Err)
}

func (e ErrMCPResponseParseFailed) Unwrap() error {
	return e.Err
}

// ErrMCPRequestFailed indicates an MCP HTTP request failed.
type ErrMCPRequestFailed struct {
	Err error
}

func (e ErrMCPRequestFailed) Error() string {
	return fmt.Sprintf("MCP request failed: %v", e.Err)
}

func (e ErrMCPRequestFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// MCP Adapter Implementation
// =============================================================================

// MCPAdapter implements SecretsCommands using the MCP (Model Context Protocol).
// This adapter sends JSON-RPC 2.0 requests to an MCP server endpoint to test
// the MCP transport layer in integration tests.
type MCPAdapter struct {
	endpoint    string
	httpClient  *http.Client
	initialized bool
	requestID   int64
}

// NewMCPAdapter creates a new MCP adapter for integration testing.
// It reads the endpoint from the PLATFORM_MCP_ENDPOINT environment variable
// with a sensible default.
func NewMCPAdapter() *MCPAdapter {
	endpoint := os.Getenv(EnvMCPEndpoint)
	if endpoint == "" {
		endpoint = DefaultMCPEndpoint
	}

	return &MCPAdapter{
		endpoint:   endpoint,
		httpClient: helpers.NewHTTPClient(DefaultMCPTimeout),
	}
}

// NewMCPAdapterWithConfig creates an MCP adapter with explicit configuration.
func NewMCPAdapterWithConfig(endpoint string, timeout time.Duration) *MCPAdapter {
	return &MCPAdapter{
		endpoint:   endpoint,
		httpClient: helpers.NewHTTPClient(timeout),
	}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP connection and performs the initialize handshake.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	// Build MCP initialize request
	initReq := mcpInitializeRequest{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    mcpCapabilities{},
		ClientInfo: mcpClientInfo{
			Name:    MCPClientName,
			Version: MCPClientVersion,
		},
	}

	// Send initialize request
	var result mcpInitializeResult
	if err := m.sendRequest(ctx, "initialize", initReq, &result); err != nil {
		return ErrMCPInitializeFailed{Err: err}
	}

	m.initialized = true
	return nil
}

// Teardown closes the MCP connection.
func (m *MCPAdapter) Teardown() error {
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
	m.initialized = false
	return nil
}

// =============================================================================
// HTTP Transport Layer
// =============================================================================

// nextRequestID generates the next unique request ID.
func (m *MCPAdapter) nextRequestID() int64 {
	return atomic.AddInt64(&m.requestID, 1)
}

// sendRequest sends a JSON-RPC 2.0 request and parses the response.
func (m *MCPAdapter) sendRequest(ctx context.Context, method string, params interface{}, result interface{}) error {
	req := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      m.nextRequestID(),
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return ErrMCPRequestFailed{Err: fmt.Errorf("failed to marshal request: %w", err)}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, helpers.MCPEndpointURL(m.endpoint), bytes.NewReader(reqBody))
	if err != nil {
		return ErrMCPRequestFailed{Err: fmt.Errorf("failed to create request: %w", err)}
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return ErrMCPConnectionFailed{Endpoint: m.endpoint, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrMCPRequestFailed{Err: fmt.Errorf("failed to read response: %w", err)}
	}

	var rpcResp jsonRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return ErrMCPResponseParseFailed{Operation: method, Err: err}
	}

	if rpcResp.Error != nil {
		return ErrMCPToolCallFailed{
			Tool:    method,
			Code:    rpcResp.Error.Code,
			Message: rpcResp.Error.Message,
		}
	}

	if result != nil && len(rpcResp.Result) > 0 {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return ErrMCPResponseParseFailed{Operation: method, Err: err}
		}
	}

	return nil
}

// callTool sends an MCP tools/call request and returns the parsed result.
func (m *MCPAdapter) callTool(ctx context.Context, toolName string, args map[string]interface{}, result interface{}) error {
	toolReq := mcpCallToolRequest{
		Name:      toolName,
		Arguments: args,
	}

	var toolResult mcpCallToolResult
	if err := m.sendRequest(ctx, "tools/call", toolReq, &toolResult); err != nil {
		return err
	}

	if toolResult.IsError {
		// Extract error message from content
		var errMsg string
		for _, item := range toolResult.Content {
			if item.Type == "text" {
				errMsg = item.Text
				break
			}
		}
		return ErrMCPToolCallFailed{Tool: toolName, Code: jsonRPCInternalError, Message: errMsg}
	}

	// Parse the text content as JSON into the result
	if result != nil && len(toolResult.Content) > 0 {
		for _, item := range toolResult.Content {
			if item.Type == "text" && item.Text != "" {
				if err := json.Unmarshal([]byte(item.Text), result); err != nil {
					return ErrMCPResponseParseFailed{Operation: toolName, Err: err}
				}
				break
			}
		}
	}

	return nil
}

// =============================================================================
// Tool Surface
// =============================================================================

// The adapter calls the secret_* tools pkg/api/mcp registers
// (kms_tools_exec.go) with their snake_case arguments, and decodes each
// result into the go-quicbaas SDK type, or the map shape, that
// pkg/api/daemon.MCPServiceProvider returns for that tool.
const (
	// mcpTransport names this transport in surface.ErrNoSurface declarations.
	mcpTransport = "MCP"

	// mcpNoSecretLifecycleTool explains why rotate, version listing, rollback
	// and status leave the MCP matrix.
	mcpNoSecretLifecycleTool = "the MCP tool registry has no secret rotate, version listing, rollback or status tool (MISSING)"

	// mcpNoSecretPrefixTool explains why Prefix leaves the MCP matrix.
	mcpNoSecretPrefixTool = "the MCP tool registry has no secret prefix listing tool (MISSING)"
)

// mcpNoSurface declares an operation the MCP tool registry does not expose.
func mcpNoSurface(operation, reason string) error {
	return surface.ErrNoSurface{Transport: mcpTransport, Operation: operation, Reason: reason}
}

// mcpDeleteResult is the map secret_delete returns.
type mcpDeleteResult struct {
	Success  bool   `json:"success"`
	SecretID string `json:"secret_id"`
}

// storeMetadata folds the description into the metadata map; secret_store
// takes no separate description argument.
func storeMetadata(opts StoreOptions) map[string]string {
	metadata := make(map[string]string, len(opts.Metadata)+1)
	for key, value := range opts.Metadata {
		metadata[key] = value
	}
	if opts.Description != "" {
		metadata["description"] = opts.Description
	}
	return metadata
}

// =============================================================================
// Secrets Management Operations
// =============================================================================

// Store calls secret_store. The tool takes no tags, expiry, tenant, key or
// algorithm argument.
func (m *MCPAdapter) Store(ctx context.Context, opts StoreOptions) (*StoreResult, error) {
	args := map[string]interface{}{
		"secret_id": opts.Name,
		"data":      base64.StdEncoding.EncodeToString(opts.Data),
	}
	if metadata := storeMetadata(opts); len(metadata) > 0 {
		args["metadata"] = metadata
	}

	var resp baasservice.StoreSecretResponse
	if err := m.callTool(ctx, "secret_store", args, &resp); err != nil {
		return nil, err
	}

	return &StoreResult{SecretID: resp.SecretID, Version: resp.Version, Timestamp: resp.Timestamp}, nil
}

// Get calls secret_get for the current version.
func (m *MCPAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
	var resp baasservice.GetSecretResponse
	if err := m.callTool(ctx, "secret_get", map[string]interface{}{"secret_id": name}, &resp); err != nil {
		return nil, err
	}

	return &GetResult{
		SecretID:      resp.SecretID,
		Version:       resp.Version,
		Data:          resp.Data,
		Metadata:      resp.Metadata,
		Algorithm:     resp.Algorithm,
		KeyIdentifier: resp.KeyIdentifier,
		CreatedAt:     resp.CreatedAt,
		Timestamp:     resp.Timestamp,
	}, nil
}

// List calls secret_list. The tool takes a limit only; it has no cursor.
func (m *MCPAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	args := map[string]interface{}{}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}

	var resp baasservice.ListSecretsResponse
	if err := m.callTool(ctx, "secret_list", args, &resp); err != nil {
		return nil, err
	}

	secrets := make([]SecretSummary, 0, len(resp.Secrets))
	for _, secret := range resp.Secrets {
		if secret == nil {
			continue
		}
		secrets = append(secrets, SecretSummary{
			SecretID:       secret.SecretID,
			Name:           secret.Name,
			CurrentVersion: secret.CurrentVersion,
			Description:    secret.Description,
			Owner:          secret.Owner,
			CreatedAt:      secret.CreatedAt,
			UpdatedAt:      secret.UpdatedAt,
		})
	}

	return &ListResult{
		Secrets:    secrets,
		TotalCount: int32(resp.TotalCount),
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// Delete calls secret_delete. The tool has no permanent argument.
func (m *MCPAdapter) Delete(ctx context.Context, name string, _ bool) (*DeleteResult, error) {
	var resp mcpDeleteResult
	if err := m.callTool(ctx, "secret_delete", map[string]interface{}{"secret_id": name}, &resp); err != nil {
		return nil, err
	}

	return &DeleteResult{SecretID: resp.SecretID, Deleted: resp.Success}, nil
}

// Rotate has no MCP surface.
func (m *MCPAdapter) Rotate(_ context.Context, _ string, _ []byte) (*RotateResult, error) {
	return nil, mcpNoSurface("Rotate", mcpNoSecretLifecycleTool)
}

// Versions has no MCP surface.
func (m *MCPAdapter) Versions(_ context.Context, _ string) (*VersionsResult, error) {
	return nil, mcpNoSurface("Versions", mcpNoSecretLifecycleTool)
}

// Version calls secret_get for one version.
func (m *MCPAdapter) Version(ctx context.Context, name string, version int) (*VersionResult, error) {
	args := map[string]interface{}{"secret_id": name, "version": version}

	var resp baasservice.GetSecretResponse
	if err := m.callTool(ctx, "secret_get", args, &resp); err != nil {
		return nil, err
	}

	return &VersionResult{
		SecretID:  resp.SecretID,
		Version:   resp.Version,
		Data:      resp.Data,
		Metadata:  resp.Metadata,
		CreatedAt: resp.CreatedAt,
		Timestamp: resp.Timestamp,
	}, nil
}

// Rollback has no MCP surface.
func (m *MCPAdapter) Rollback(_ context.Context, _ string, _ int) (*RollbackResult, error) {
	return nil, mcpNoSurface("Rollback", mcpNoSecretLifecycleTool)
}

// Status has no MCP surface.
func (m *MCPAdapter) Status(_ context.Context, _ string, _ bool) (*StatusResult, error) {
	return nil, mcpNoSurface("Status", mcpNoSecretLifecycleTool)
}

// Policy calls secret_get_rotation_policy.
func (m *MCPAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	var resp baasservice.GetRotationPolicyResponse
	if err := m.callTool(ctx, "secret_get_rotation_policy", map[string]interface{}{"secret_id": name}, &resp); err != nil {
		return nil, err
	}

	result := &PolicyResult{SecretID: resp.SecretID, UpdatedAt: resp.Timestamp}
	if policy := resp.Policy; policy != nil {
		result.Enabled = policy.Enabled
		result.IntervalSeconds = int64(policy.Interval / time.Second)
		result.NextRotation = policy.NextRotation
		result.RetainVersions = int32(policy.RetainVersions)
		result.RotationLambda = policy.RotationLambda
	}
	return result, nil
}

// PolicySet calls secret_set_rotation_policy. The tool has no rotation
// lambda argument.
func (m *MCPAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	args := map[string]interface{}{
		"secret_id":        name,
		"enabled":          opts.Enabled,
		"interval_seconds": opts.IntervalSeconds,
		"retain_versions":  opts.RetainVersions,
	}

	var resp baasservice.SetRotationPolicyResponse
	if err := m.callTool(ctx, "secret_set_rotation_policy", args, &resp); err != nil {
		return nil, err
	}

	return &PolicySetResult{SecretID: resp.SecretID, Timestamp: resp.Timestamp}, nil
}

// Prefix has no MCP surface.
func (m *MCPAdapter) Prefix(_ context.Context, _ string, _ bool) (*PrefixResult, error) {
	return nil, mcpNoSurface("Prefix", mcpNoSecretPrefixTool)
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure MCPAdapter implements SecretsCommands interface.
var _ SecretsCommands = (*MCPAdapter)(nil)
