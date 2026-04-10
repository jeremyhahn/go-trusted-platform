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

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"os"
	"sync/atomic"
	"time"
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

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://"+m.endpoint+"/mcp", bytes.NewReader(reqBody))
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
// Time Conversion Helper
// =============================================================================

// unixMillisToTime converts Unix milliseconds to time.Time.
func unixMillisToTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.Unix(ms/1000, (ms%1000)*int64(time.Millisecond))
}

// =============================================================================
// MCP Response Types
// =============================================================================

type mcpSecretsStoreResponse struct {
	SecretID  string `json:"secretId"`
	Version   uint64 `json:"version"`
	Timestamp int64  `json:"timestamp"`
}

type mcpSecretsGetResponse struct {
	SecretID      string            `json:"secretId"`
	Version       uint64            `json:"version"`
	Data          string            `json:"data"` // base64
	Metadata      map[string]string `json:"metadata"`
	Algorithm     string            `json:"algorithm"`
	KeyIdentifier string            `json:"keyIdentifier"`
	CreatedAt     int64             `json:"createdAt"`
	Timestamp     int64             `json:"timestamp"`
}

type mcpSecretsListResponse struct {
	Secrets    []mcpSecretSummary `json:"secrets"`
	TotalCount int32              `json:"totalCount"`
	HasMore    bool               `json:"hasMore"`
	NextCursor string             `json:"nextCursor"`
}

type mcpSecretSummary struct {
	SecretID       string `json:"secretId"`
	Name           string `json:"name"`
	CurrentVersion uint64 `json:"currentVersion"`
	Description    string `json:"description"`
	Owner          string `json:"owner"`
	CreatedAt      int64  `json:"createdAt"`
	UpdatedAt      int64  `json:"updatedAt"`
}

type mcpSecretsDeleteResponse struct {
	SecretID  string `json:"secretId"`
	Deleted   bool   `json:"deleted"`
	Timestamp int64  `json:"timestamp"`
}

type mcpSecretsRotateResponse struct {
	SecretID   string `json:"secretId"`
	OldVersion uint64 `json:"oldVersion"`
	NewVersion uint64 `json:"newVersion"`
	Timestamp  int64  `json:"timestamp"`
}

type mcpSecretsVersionsResponse struct {
	SecretID   string                 `json:"secretId"`
	Versions   []mcpSecretVersionInfo `json:"versions"`
	HasMore    bool                   `json:"hasMore"`
	NextCursor string                 `json:"nextCursor"`
}

type mcpSecretVersionInfo struct {
	Version   uint64 `json:"version"`
	CreatedAt int64  `json:"createdAt"`
	CreatedBy string `json:"createdBy"`
	ExpiresAt int64  `json:"expiresAt"`
	DeletedAt int64  `json:"deletedAt"`
}

type mcpSecretsVersionResponse struct {
	SecretID  string            `json:"secretId"`
	Version   uint64            `json:"version"`
	Data      string            `json:"data"` // base64
	Metadata  map[string]string `json:"metadata"`
	CreatedAt int64             `json:"createdAt"`
	CreatedBy string            `json:"createdBy"`
	ExpiresAt int64             `json:"expiresAt"`
	Timestamp int64             `json:"timestamp"`
}

type mcpSecretsRollbackResponse struct {
	SecretID   string `json:"secretId"`
	NewVersion uint64 `json:"newVersion"`
	Timestamp  int64  `json:"timestamp"`
}

type mcpSecretsStatusResponse struct {
	SecretID  string `json:"secretId"`
	Status    string `json:"status"`
	Timestamp int64  `json:"timestamp"`
}

type mcpSecretsPolicyResponse struct {
	SecretID        string `json:"secretId"`
	Enabled         bool   `json:"enabled"`
	IntervalSeconds int64  `json:"intervalSeconds"`
	NextRotation    int64  `json:"nextRotation"`
	RetainVersions  int32  `json:"retainVersions"`
	RotationLambda  string `json:"rotationLambda"`
	UpdatedAt       int64  `json:"updatedAt"`
}

type mcpSecretsPolicySetResponse struct {
	SecretID  string `json:"secretId"`
	Timestamp int64  `json:"timestamp"`
}

type mcpSecretsPrefixResponse struct {
	Secrets    map[string]mcpPrefixSecretData `json:"secrets"`
	TotalCount int32                          `json:"totalCount"`
	HasMore    bool                           `json:"hasMore"`
	NextCursor string                         `json:"nextCursor"`
}

type mcpPrefixSecretData struct {
	Data     string            `json:"data"` // base64
	Metadata map[string]string `json:"metadata"`
	Version  int64             `json:"version"`
}

// =============================================================================
// Secrets Management Operations
// =============================================================================

// Store stores a new secret via MCP tool call.
func (m *MCPAdapter) Store(ctx context.Context, opts StoreOptions) (*StoreResult, error) {
	args := map[string]interface{}{
		"name": opts.Name,
		"data": base64.StdEncoding.EncodeToString(opts.Data),
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}
	if opts.TenantID != "" {
		args["tenantId"] = opts.TenantID
	}
	if opts.KeyID != "" {
		args["keyId"] = opts.KeyID
	}
	if opts.Algorithm != "" {
		args["algorithm"] = opts.Algorithm
	}

	var resp mcpSecretsStoreResponse
	if err := m.callTool(ctx, "platform.secrets.store", args, &resp); err != nil {
		return nil, err
	}

	return &StoreResult{
		SecretID:  resp.SecretID,
		Version:   resp.Version,
		Timestamp: unixMillisToTime(resp.Timestamp),
	}, nil
}

// Get retrieves a secret via MCP tool call.
func (m *MCPAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
	args := map[string]interface{}{
		"name": name,
	}

	var resp mcpSecretsGetResponse
	if err := m.callTool(ctx, "platform.secrets.get", args, &resp); err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "Get", Err: err}
	}

	return &GetResult{
		SecretID:      resp.SecretID,
		Version:       resp.Version,
		Data:          data,
		Metadata:      resp.Metadata,
		Algorithm:     resp.Algorithm,
		KeyIdentifier: resp.KeyIdentifier,
		CreatedAt:     unixMillisToTime(resp.CreatedAt),
		Timestamp:     unixMillisToTime(resp.Timestamp),
	}, nil
}

// List lists secrets via MCP tool call.
func (m *MCPAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	args := map[string]interface{}{}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Cursor != "" {
		args["cursor"] = opts.Cursor
	}

	var resp mcpSecretsListResponse
	if err := m.callTool(ctx, "platform.secrets.list", args, &resp); err != nil {
		return nil, err
	}

	secrets := make([]SecretSummary, len(resp.Secrets))
	for i, s := range resp.Secrets {
		secrets[i] = SecretSummary{
			SecretID:       s.SecretID,
			Name:           s.Name,
			CurrentVersion: s.CurrentVersion,
			Description:    s.Description,
			Owner:          s.Owner,
			CreatedAt:      unixMillisToTime(s.CreatedAt),
			UpdatedAt:      unixMillisToTime(s.UpdatedAt),
		}
	}

	return &ListResult{
		Secrets:    secrets,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// Delete deletes a secret via MCP tool call.
func (m *MCPAdapter) Delete(ctx context.Context, name string, permanent bool) (*DeleteResult, error) {
	args := map[string]interface{}{
		"name":      name,
		"permanent": permanent,
	}

	var resp mcpSecretsDeleteResponse
	if err := m.callTool(ctx, "platform.secrets.delete", args, &resp); err != nil {
		return nil, err
	}

	return &DeleteResult{
		SecretID:  resp.SecretID,
		Deleted:   resp.Deleted,
		Timestamp: unixMillisToTime(resp.Timestamp),
	}, nil
}

// Rotate rotates a secret to a new value via MCP tool call.
func (m *MCPAdapter) Rotate(ctx context.Context, name string, newData []byte) (*RotateResult, error) {
	args := map[string]interface{}{
		"name":    name,
		"newData": base64.StdEncoding.EncodeToString(newData),
	}

	var resp mcpSecretsRotateResponse
	if err := m.callTool(ctx, "platform.secrets.rotate", args, &resp); err != nil {
		return nil, err
	}

	return &RotateResult{
		SecretID:   resp.SecretID,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  unixMillisToTime(resp.Timestamp),
	}, nil
}

// Versions lists secret versions via MCP tool call.
func (m *MCPAdapter) Versions(ctx context.Context, name string) (*VersionsResult, error) {
	args := map[string]interface{}{
		"name": name,
	}

	var resp mcpSecretsVersionsResponse
	if err := m.callTool(ctx, "platform.secrets.versions", args, &resp); err != nil {
		return nil, err
	}

	versions := make([]VersionInfo, len(resp.Versions))
	for i, v := range resp.Versions {
		versions[i] = VersionInfo{
			Version:   v.Version,
			CreatedAt: unixMillisToTime(v.CreatedAt),
			CreatedBy: v.CreatedBy,
			ExpiresAt: unixMillisToTime(v.ExpiresAt),
			DeletedAt: unixMillisToTime(v.DeletedAt),
		}
	}

	return &VersionsResult{
		SecretID:   resp.SecretID,
		Versions:   versions,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// Version retrieves a specific secret version via MCP tool call.
func (m *MCPAdapter) Version(ctx context.Context, name string, version int) (*VersionResult, error) {
	args := map[string]interface{}{
		"name":    name,
		"version": version,
	}

	var resp mcpSecretsVersionResponse
	if err := m.callTool(ctx, "platform.secrets.version", args, &resp); err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "Version", Err: err}
	}

	return &VersionResult{
		SecretID:  resp.SecretID,
		Version:   resp.Version,
		Data:      data,
		Metadata:  resp.Metadata,
		CreatedAt: unixMillisToTime(resp.CreatedAt),
		CreatedBy: resp.CreatedBy,
		ExpiresAt: unixMillisToTime(resp.ExpiresAt),
		Timestamp: unixMillisToTime(resp.Timestamp),
	}, nil
}

// Rollback rolls back to a previous secret version via MCP tool call.
func (m *MCPAdapter) Rollback(ctx context.Context, name string, targetVersion int) (*RollbackResult, error) {
	args := map[string]interface{}{
		"name":          name,
		"targetVersion": targetVersion,
	}

	var resp mcpSecretsRollbackResponse
	if err := m.callTool(ctx, "platform.secrets.rollback", args, &resp); err != nil {
		return nil, err
	}

	return &RollbackResult{
		SecretID:   resp.SecretID,
		NewVersion: resp.NewVersion,
		Timestamp:  unixMillisToTime(resp.Timestamp),
	}, nil
}

// Status updates the status of a secret via MCP tool call.
func (m *MCPAdapter) Status(ctx context.Context, name string, enabled bool) (*StatusResult, error) {
	args := map[string]interface{}{
		"name":    name,
		"enabled": enabled,
	}

	var resp mcpSecretsStatusResponse
	if err := m.callTool(ctx, "platform.secrets.status", args, &resp); err != nil {
		return nil, err
	}

	return &StatusResult{
		SecretID:  resp.SecretID,
		Status:    resp.Status,
		Timestamp: unixMillisToTime(resp.Timestamp),
	}, nil
}

// Policy retrieves the rotation policy for a secret via MCP tool call.
func (m *MCPAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	args := map[string]interface{}{
		"name": name,
	}

	var resp mcpSecretsPolicyResponse
	if err := m.callTool(ctx, "platform.secrets.policy", args, &resp); err != nil {
		return nil, err
	}

	return &PolicyResult{
		SecretID:        resp.SecretID,
		Enabled:         resp.Enabled,
		IntervalSeconds: resp.IntervalSeconds,
		NextRotation:    unixMillisToTime(resp.NextRotation),
		RetainVersions:  resp.RetainVersions,
		RotationLambda:  resp.RotationLambda,
		UpdatedAt:       unixMillisToTime(resp.UpdatedAt),
	}, nil
}

// PolicySet sets the rotation policy for a secret via MCP tool call.
func (m *MCPAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	args := map[string]interface{}{
		"name":            name,
		"enabled":         opts.Enabled,
		"intervalSeconds": opts.IntervalSeconds,
		"retainVersions":  opts.RetainVersions,
	}
	if opts.RotationLambda != "" {
		args["rotationLambda"] = opts.RotationLambda
	}

	var resp mcpSecretsPolicySetResponse
	if err := m.callTool(ctx, "platform.secrets.policy.set", args, &resp); err != nil {
		return nil, err
	}

	return &PolicySetResult{
		SecretID:  resp.SecretID,
		Timestamp: unixMillisToTime(resp.Timestamp),
	}, nil
}

// Prefix searches for secrets by prefix via MCP tool call.
func (m *MCPAdapter) Prefix(ctx context.Context, prefix string, includeData bool) (*PrefixResult, error) {
	args := map[string]interface{}{
		"prefix":      prefix,
		"includeData": includeData,
	}

	var resp mcpSecretsPrefixResponse
	if err := m.callTool(ctx, "platform.secrets.prefix", args, &resp); err != nil {
		return nil, err
	}

	secrets := make(map[string]PrefixSecretData, len(resp.Secrets))
	for name, s := range resp.Secrets {
		var data []byte
		var err error
		if s.Data != "" {
			data, err = base64.StdEncoding.DecodeString(s.Data)
			if err != nil {
				return nil, ErrMCPResponseParseFailed{Operation: "Prefix", Err: err}
			}
		}
		secrets[name] = PrefixSecretData{
			Data:     data,
			Metadata: s.Metadata,
			Version:  s.Version,
		}
	}

	return &PrefixResult{
		Secrets:    secrets,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure MCPAdapter implements SecretsCommands interface.
var _ SecretsCommands = (*MCPAdapter)(nil)
