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

// Package kms provides integration test adapters for KMS services.
// This file implements the KMSCommands interface using the MCP (Model Context Protocol).

//go:build integration

package kms

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
	MCPClientName = "kms-integration-test"

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

// MCPAdapter implements KMSCommands using the MCP (Model Context Protocol).
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
// Key Management Operations
// =============================================================================

// KeyGenerate generates a new key via MCP tool call.
func (m *MCPAdapter) KeyGenerate(ctx context.Context, opts KeyGenerateOptions) (*KeyGenerateResult, error) {
	args := map[string]interface{}{
		"keyId":     opts.KeyID,
		"algorithm": opts.Algorithm,
		"purpose":   opts.Purpose,
	}
	if opts.Name != "" {
		args["name"] = opts.Name
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}
	if opts.Owner != "" {
		args["owner"] = opts.Owner
	}
	if opts.Exportable {
		args["exportable"] = true
	}
	if opts.DeletionProtection {
		args["deletionProtection"] = true
	}

	var resp mcpKeyGenerateResponse
	if err := m.callTool(ctx, "platform.kms.key.generate", args, &resp); err != nil {
		return nil, err
	}

	return &KeyGenerateResult{
		KeyID:              resp.KeyID,
		Version:            resp.Version,
		Algorithm:          resp.Algorithm,
		Status:             resp.Status,
		CreatedAt:          unixMillisToTime(resp.CreatedAt),
		Name:               resp.Name,
		Description:        resp.Description,
		Exportable:         resp.Exportable,
		DeletionProtection: resp.DeletionProtection,
	}, nil
}

// KeyGet retrieves a key via MCP tool call.
func (m *MCPAdapter) KeyGet(ctx context.Context, keyID string, version uint64) (*KeyGetResult, error) {
	args := map[string]interface{}{
		"keyId": keyID,
	}
	if version > 0 {
		args["version"] = version
	}

	var resp mcpKeyGetResponse
	if err := m.callTool(ctx, "platform.kms.key.get", args, &resp); err != nil {
		return nil, err
	}

	return &KeyGetResult{
		KeyID:              resp.KeyID,
		Version:            resp.Version,
		Algorithm:          resp.Algorithm,
		Status:             resp.Status,
		CreatedAt:          unixMillisToTime(resp.CreatedAt),
		UpdatedAt:          unixMillisToTime(resp.UpdatedAt),
		LastUsedAt:         unixMillisToTime(resp.LastUsedAt),
		Name:               resp.Name,
		Description:        resp.Description,
		Owner:              resp.Owner,
		Exportable:         resp.Exportable,
		DeletionProtection: resp.DeletionProtection,
		Usage:              resp.Usage,
	}, nil
}

// KeyList lists keys via MCP tool call.
func (m *MCPAdapter) KeyList(ctx context.Context, opts KeyListOptions) (*KeyListResult, error) {
	args := map[string]interface{}{}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Cursor != "" {
		args["cursor"] = opts.Cursor
	}

	var resp mcpKeyListResponse
	if err := m.callTool(ctx, "platform.kms.key.list", args, &resp); err != nil {
		return nil, err
	}

	keys := make([]KeySummary, len(resp.Keys))
	for i, k := range resp.Keys {
		keys[i] = KeySummary{
			KeyID:     k.KeyID,
			Version:   k.Version,
			Algorithm: k.Algorithm,
			Status:    k.Status,
			CreatedAt: unixMillisToTime(k.CreatedAt),
		}
	}

	return &KeyListResult{
		Keys:       keys,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// KeyDelete deletes a key via MCP tool call.
func (m *MCPAdapter) KeyDelete(ctx context.Context, keyID string, opts KeyDeleteOptions) (*KeyDeleteResult, error) {
	args := map[string]interface{}{
		"keyId": keyID,
	}
	if opts.PendingWindowDays > 0 {
		args["pendingWindowDays"] = opts.PendingWindowDays
	}
	if opts.Force {
		args["force"] = true
	}

	var resp mcpKeyDeleteResponse
	if err := m.callTool(ctx, "platform.kms.key.delete", args, &resp); err != nil {
		return nil, err
	}

	return &KeyDeleteResult{
		KeyID:        resp.KeyID,
		Status:       resp.Status,
		DeletionDate: unixMillisToTime(resp.DeletionDate),
	}, nil
}

// KeyRotate rotates a key via MCP tool call.
func (m *MCPAdapter) KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error) {
	args := map[string]interface{}{
		"keyId":            keyID,
		"retainOldVersion": retainOldVersion,
	}

	var resp mcpKeyRotateResponse
	if err := m.callTool(ctx, "platform.kms.key.rotate", args, &resp); err != nil {
		return nil, err
	}

	return &KeyRotateResult{
		KeyID:      resp.KeyID,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		RotatedAt:  unixMillisToTime(resp.RotatedAt),
	}, nil
}

// KeyVersions lists key versions via MCP tool call.
func (m *MCPAdapter) KeyVersions(ctx context.Context, keyID string, opts KeyVersionsOptions) (*KeyVersionsResult, error) {
	args := map[string]interface{}{
		"keyId": keyID,
	}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Cursor != "" {
		args["cursor"] = opts.Cursor
	}

	var resp mcpKeyVersionsResponse
	if err := m.callTool(ctx, "platform.kms.key.versions", args, &resp); err != nil {
		return nil, err
	}

	versions := make([]KeyVersionInfo, len(resp.Versions))
	for i, v := range resp.Versions {
		versions[i] = KeyVersionInfo{
			Version:    v.Version,
			Algorithm:  v.Algorithm,
			Status:     v.Status,
			CreatedAt:  unixMillisToTime(v.CreatedAt),
			DisabledAt: unixMillisToTime(v.DisabledAt),
		}
	}

	return &KeyVersionsResult{
		KeyID:      resp.KeyID,
		Versions:   versions,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// KeyStatus updates key status via MCP tool call.
func (m *MCPAdapter) KeyStatus(ctx context.Context, keyID string, version uint64, enabled bool) (*KeyStatusResult, error) {
	args := map[string]interface{}{
		"keyId":   keyID,
		"version": version,
		"enabled": enabled,
	}

	var resp mcpKeyStatusResponse
	if err := m.callTool(ctx, "platform.kms.key.status", args, &resp); err != nil {
		return nil, err
	}

	return &KeyStatusResult{
		KeyID:     resp.KeyID,
		Version:   resp.Version,
		Status:    resp.Status,
		UpdatedAt: unixMillisToTime(resp.UpdatedAt),
	}, nil
}

// KeyRevoke revokes a key via MCP tool call.
func (m *MCPAdapter) KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error) {
	args := map[string]interface{}{
		"keyId": keyID,
	}
	if reason != "" {
		args["reason"] = reason
	}

	var resp mcpKeyRevokeResponse
	if err := m.callTool(ctx, "platform.kms.key.revoke", args, &resp); err != nil {
		return nil, err
	}

	return &KeyRevokeResult{
		KeyID:     resp.KeyID,
		Status:    resp.Status,
		RevokedAt: unixMillisToTime(resp.RevokedAt),
	}, nil
}

// KeyMetadata retrieves key metadata via MCP tool call.
func (m *MCPAdapter) KeyMetadata(ctx context.Context, keyID string) (*KeyMetadataResult, error) {
	args := map[string]interface{}{
		"keyId": keyID,
	}

	var resp mcpKeyMetadataResponse
	if err := m.callTool(ctx, "platform.kms.key.metadata", args, &resp); err != nil {
		return nil, err
	}

	var rotationPolicy *RotationPolicy
	if resp.RotationPolicy != nil {
		rotationPolicy = &RotationPolicy{
			Enabled:         resp.RotationPolicy.Enabled,
			IntervalSeconds: resp.RotationPolicy.IntervalSeconds,
			NextRotation:    unixMillisToTime(resp.RotationPolicy.NextRotation),
			RetainVersions:  resp.RotationPolicy.RetainVersions,
		}
	}

	return &KeyMetadataResult{
		KeyID:              resp.KeyID,
		Name:               resp.Name,
		Description:        resp.Description,
		Algorithm:          resp.Algorithm,
		Status:             resp.Status,
		Version:            resp.Version,
		Exportable:         resp.Exportable,
		DeletionProtection: resp.DeletionProtection,
		Usage:              resp.Usage,
		Owner:              resp.Owner,
		CreatedAt:          unixMillisToTime(resp.CreatedAt),
		UpdatedAt:          unixMillisToTime(resp.UpdatedAt),
		LastUsedAt:         unixMillisToTime(resp.LastUsedAt),
		Tags:               resp.Tags,
		RotationPolicy:     rotationPolicy,
	}, nil
}

// KeyMetadataUpdate updates key metadata via MCP tool call.
func (m *MCPAdapter) KeyMetadataUpdate(ctx context.Context, keyID string, opts KeyMetadataUpdateOptions) (*KeyMetadataUpdateResult, error) {
	args := map[string]interface{}{
		"keyId": keyID,
	}
	if opts.Name != "" {
		args["name"] = opts.Name
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}
	if len(opts.Tags) > 0 {
		args["tags"] = opts.Tags
	}
	if len(opts.RemoveTags) > 0 {
		args["removeTags"] = opts.RemoveTags
	}

	var resp mcpKeyMetadataUpdateResponse
	if err := m.callTool(ctx, "platform.kms.key.metadata.update", args, &resp); err != nil {
		return nil, err
	}

	return &KeyMetadataUpdateResult{
		KeyID:     resp.KeyID,
		Name:      resp.Name,
		UpdatedAt: unixMillisToTime(resp.UpdatedAt),
		Tags:      resp.Tags,
	}, nil
}

// KeyPolicy retrieves key policy via MCP tool call.
func (m *MCPAdapter) KeyPolicy(ctx context.Context, keyID string) (*KeyPolicyResult, error) {
	args := map[string]interface{}{
		"keyId": keyID,
	}

	var resp mcpKeyPolicyResponse
	if err := m.callTool(ctx, "platform.kms.key.policy", args, &resp); err != nil {
		return nil, err
	}

	return &KeyPolicyResult{
		KeyID:             resp.KeyID,
		Version:           resp.Version,
		AllowedOperations: resp.AllowedOperations,
		AllowedPrincipals: resp.AllowedPrincipals,
		DeniedPrincipals:  resp.DeniedPrincipals,
		ExpiresAt:         unixMillisToTime(resp.ExpiresAt),
		RotationRequired:  resp.RotationRequired,
		MaxUsageCount:     resp.MaxUsageCount,
		RequireMFA:        resp.RequireMFA,
		UpdatedAt:         unixMillisToTime(resp.UpdatedAt),
	}, nil
}

// KeyPolicySet sets key policy via MCP tool call.
func (m *MCPAdapter) KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error) {
	args := map[string]interface{}{
		"keyId": keyID,
	}
	if len(opts.Operations) > 0 {
		args["operations"] = opts.Operations
	}
	if len(opts.AllowPrincipals) > 0 {
		args["allowPrincipals"] = opts.AllowPrincipals
	}
	if len(opts.DenyPrincipals) > 0 {
		args["denyPrincipals"] = opts.DenyPrincipals
	}
	if opts.ExpiresIn != "" {
		args["expiresIn"] = opts.ExpiresIn
	}
	if opts.RotationRequired {
		args["rotationRequired"] = true
	}
	if opts.MaxUsageCount > 0 {
		args["maxUsageCount"] = opts.MaxUsageCount
	}
	if opts.RequireMFA {
		args["requireMFA"] = true
	}

	var resp mcpKeyPolicySetResponse
	if err := m.callTool(ctx, "platform.kms.key.policy.set", args, &resp); err != nil {
		return nil, err
	}

	return &KeyPolicySetResult{
		KeyID:         resp.KeyID,
		PolicyVersion: resp.PolicyVersion,
		UpdatedAt:     unixMillisToTime(resp.UpdatedAt),
	}, nil
}

// KeyAlgorithms lists supported algorithms via MCP tool call.
func (m *MCPAdapter) KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error) {
	var resp mcpKeyAlgorithmsResponse
	if err := m.callTool(ctx, "platform.kms.key.algorithms", nil, &resp); err != nil {
		return nil, err
	}

	return &KeyAlgorithmsResult{
		Algorithms: resp.Algorithms,
	}, nil
}

// =============================================================================
// Crypto Operations
// =============================================================================

// CryptoEncrypt encrypts data via MCP tool call.
func (m *MCPAdapter) CryptoEncrypt(ctx context.Context, opts CryptoEncryptOptions) (*CryptoEncryptResult, error) {
	args := map[string]interface{}{
		"keyId":     opts.KeyID,
		"plaintext": base64.StdEncoding.EncodeToString(opts.Plaintext),
	}
	if len(opts.Context) > 0 {
		args["context"] = base64.StdEncoding.EncodeToString(opts.Context)
	}
	if len(opts.Nonce) > 0 {
		args["nonce"] = base64.StdEncoding.EncodeToString(opts.Nonce)
	}

	var resp mcpCryptoEncryptResponse
	if err := m.callTool(ctx, "platform.kms.crypto.encrypt", args, &resp); err != nil {
		return nil, err
	}

	ciphertext, err := base64.StdEncoding.DecodeString(resp.Ciphertext)
	if err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "CryptoEncrypt", Err: err}
	}

	var nonce []byte
	if resp.Nonce != "" {
		nonce, err = base64.StdEncoding.DecodeString(resp.Nonce)
		if err != nil {
			return nil, ErrMCPResponseParseFailed{Operation: "CryptoEncrypt", Err: err}
		}
	}

	return &CryptoEncryptResult{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Ciphertext: ciphertext,
		Nonce:      nonce,
		Timestamp:  unixMillisToTime(resp.Timestamp),
	}, nil
}

// CryptoDecrypt decrypts data via MCP tool call.
func (m *MCPAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	args := map[string]interface{}{
		"keyId":      opts.KeyID,
		"ciphertext": base64.StdEncoding.EncodeToString(opts.Ciphertext),
	}
	if len(opts.Context) > 0 {
		args["context"] = base64.StdEncoding.EncodeToString(opts.Context)
	}
	if len(opts.Nonce) > 0 {
		args["nonce"] = base64.StdEncoding.EncodeToString(opts.Nonce)
	}
	if opts.KeyVersion > 0 {
		args["keyVersion"] = opts.KeyVersion
	}

	var resp mcpCryptoDecryptResponse
	if err := m.callTool(ctx, "platform.kms.crypto.decrypt", args, &resp); err != nil {
		return nil, err
	}

	plaintext, err := base64.StdEncoding.DecodeString(resp.Plaintext)
	if err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "CryptoDecrypt", Err: err}
	}

	return &CryptoDecryptResult{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Plaintext:  plaintext,
		Timestamp:  unixMillisToTime(resp.Timestamp),
	}, nil
}

// CryptoSign signs data via MCP tool call.
func (m *MCPAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	args := map[string]interface{}{
		"keyId":   opts.KeyID,
		"message": base64.StdEncoding.EncodeToString(opts.Message),
	}
	if opts.HashAlgorithm != "" {
		args["hashAlgorithm"] = opts.HashAlgorithm
	}

	var resp mcpCryptoSignResponse
	if err := m.callTool(ctx, "platform.kms.crypto.sign", args, &resp); err != nil {
		return nil, err
	}

	signature, err := base64.StdEncoding.DecodeString(resp.Signature)
	if err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "CryptoSign", Err: err}
	}

	return &CryptoSignResult{
		KeyID:         resp.KeyID,
		KeyVersion:    resp.KeyVersion,
		Signature:     signature,
		HashAlgorithm: resp.HashAlgorithm,
		Timestamp:     unixMillisToTime(resp.Timestamp),
	}, nil
}

// CryptoVerify verifies a signature via MCP tool call.
func (m *MCPAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	args := map[string]interface{}{
		"keyId":     opts.KeyID,
		"message":   base64.StdEncoding.EncodeToString(opts.Message),
		"signature": base64.StdEncoding.EncodeToString(opts.Signature),
	}
	if opts.HashAlgorithm != "" {
		args["hashAlgorithm"] = opts.HashAlgorithm
	}
	if opts.KeyVersion > 0 {
		args["keyVersion"] = opts.KeyVersion
	}

	var resp mcpCryptoVerifyResponse
	if err := m.callTool(ctx, "platform.kms.crypto.verify", args, &resp); err != nil {
		return nil, err
	}

	return &CryptoVerifyResult{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  unixMillisToTime(resp.Timestamp),
	}, nil
}

// CryptoHash computes a hash via MCP tool call.
func (m *MCPAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	args := map[string]interface{}{
		"data":      base64.StdEncoding.EncodeToString(data),
		"algorithm": algorithm,
	}

	var resp mcpCryptoHashResponse
	if err := m.callTool(ctx, "platform.kms.crypto.hash", args, &resp); err != nil {
		return nil, err
	}

	hash, err := base64.StdEncoding.DecodeString(resp.Hash)
	if err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "CryptoHash", Err: err}
	}

	return &CryptoHashResult{
		Algorithm: resp.Algorithm,
		Hash:      hash,
		Timestamp: unixMillisToTime(resp.Timestamp),
	}, nil
}

// CryptoHMAC generates an HMAC via MCP tool call.
func (m *MCPAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	args := map[string]interface{}{
		"keyId":   opts.KeyID,
		"message": base64.StdEncoding.EncodeToString(opts.Message),
	}
	if opts.HashAlgorithm != "" {
		args["hashAlgorithm"] = opts.HashAlgorithm
	}

	var resp mcpCryptoHMACResponse
	if err := m.callTool(ctx, "platform.kms.crypto.hmac", args, &resp); err != nil {
		return nil, err
	}

	hmac, err := base64.StdEncoding.DecodeString(resp.HMAC)
	if err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "CryptoHMAC", Err: err}
	}

	return &CryptoHMACResult{
		KeyID:         resp.KeyID,
		KeyVersion:    resp.KeyVersion,
		HMAC:          hmac,
		HashAlgorithm: resp.HashAlgorithm,
		Timestamp:     unixMillisToTime(resp.Timestamp),
	}, nil
}

// CryptoVerifyHMAC verifies an HMAC via MCP tool call.
func (m *MCPAdapter) CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error) {
	args := map[string]interface{}{
		"keyId":   opts.KeyID,
		"message": base64.StdEncoding.EncodeToString(opts.Message),
		"hmac":    base64.StdEncoding.EncodeToString(opts.HMAC),
	}
	if opts.HashAlgorithm != "" {
		args["hashAlgorithm"] = opts.HashAlgorithm
	}
	if opts.KeyVersion > 0 {
		args["keyVersion"] = opts.KeyVersion
	}

	var resp mcpCryptoVerifyHMACResponse
	if err := m.callTool(ctx, "platform.kms.crypto.hmac.verify", args, &resp); err != nil {
		return nil, err
	}

	return &CryptoVerifyHMACResult{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  unixMillisToTime(resp.Timestamp),
	}, nil
}

// CryptoRandom generates random bytes via MCP tool call.
func (m *MCPAdapter) CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error) {
	args := map[string]interface{}{
		"numBytes": numBytes,
	}

	var resp mcpCryptoRandomResponse
	if err := m.callTool(ctx, "platform.kms.crypto.random", args, &resp); err != nil {
		return nil, err
	}

	randomBytes, err := base64.StdEncoding.DecodeString(resp.RandomBytes)
	if err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "CryptoRandom", Err: err}
	}

	return &CryptoRandomResult{
		RandomBytes: randomBytes,
		Timestamp:   unixMillisToTime(resp.Timestamp),
	}, nil
}

// =============================================================================
// DEK Operations
// =============================================================================

// DEKCreate creates a DEK via MCP tool call.
func (m *MCPAdapter) DEKCreate(ctx context.Context, opts DEKCreateOptions) (*DEKCreateResult, error) {
	args := map[string]interface{}{
		"path": opts.Path,
	}
	if opts.Algorithm != "" {
		args["algorithm"] = opts.Algorithm
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}
	if opts.MaxOperations > 0 {
		args["maxOperations"] = opts.MaxOperations
	}
	if opts.MaxBytes > 0 {
		args["maxBytes"] = opts.MaxBytes
	}
	if opts.WarningPercent > 0 {
		args["warningPercent"] = opts.WarningPercent
	}

	var resp mcpDEKCreateResponse
	if err := m.callTool(ctx, "platform.kms.dek.create", args, &resp); err != nil {
		return nil, err
	}

	return &DEKCreateResult{
		Path:        resp.Path,
		Algorithm:   resp.Algorithm,
		Version:     resp.Version,
		CreatedAt:   unixMillisToTime(resp.CreatedAt),
		Description: resp.Description,
	}, nil
}

// DEKGet retrieves a DEK via MCP tool call.
func (m *MCPAdapter) DEKGet(ctx context.Context, path string) (*DEKGetResult, error) {
	args := map[string]interface{}{
		"path": path,
	}

	var resp mcpDEKGetResponse
	if err := m.callTool(ctx, "platform.kms.dek.get", args, &resp); err != nil {
		return nil, err
	}

	return &DEKGetResult{
		Path:           resp.Path,
		Algorithm:      resp.Algorithm,
		Version:        resp.Version,
		Status:         resp.Status,
		IsDefault:      resp.IsDefault,
		CreatedAt:      unixMillisToTime(resp.CreatedAt),
		RotatedAt:      unixMillisToTime(resp.RotatedAt),
		Description:    resp.Description,
		BackendType:    resp.BackendType,
		UsageCount:     resp.UsageCount,
		BytesUsed:      resp.BytesUsed,
		MaxUsageCount:  resp.MaxUsageCount,
		MaxBytesUsed:   resp.MaxBytesUsed,
		WarningPercent: resp.WarningPercent,
	}, nil
}

// DEKList lists DEKs via MCP tool call.
func (m *MCPAdapter) DEKList(ctx context.Context, opts DEKListOptions) (*DEKListResult, error) {
	args := map[string]interface{}{}
	if opts.Prefix != "" {
		args["prefix"] = opts.Prefix
	}
	if opts.Recursive {
		args["recursive"] = true
	}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Cursor != "" {
		args["cursor"] = opts.Cursor
	}

	var resp mcpDEKListResponse
	if err := m.callTool(ctx, "platform.kms.dek.list", args, &resp); err != nil {
		return nil, err
	}

	deks := make([]DEKSummary, len(resp.DEKs))
	for i, d := range resp.DEKs {
		deks[i] = DEKSummary{
			Path:      d.Path,
			Algorithm: d.Algorithm,
			Version:   d.Version,
			Status:    d.Status,
			IsDefault: d.IsDefault,
			CreatedAt: unixMillisToTime(d.CreatedAt),
		}
	}

	return &DEKListResult{
		DEKs:       deks,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// DEKDelete deletes a DEK via MCP tool call.
func (m *MCPAdapter) DEKDelete(ctx context.Context, path string, opts DEKDeleteOptions) (*DEKDeleteResult, error) {
	args := map[string]interface{}{
		"path": path,
	}
	if opts.Force {
		args["force"] = true
	}
	if opts.MigrateTo != "" {
		args["migrateTo"] = opts.MigrateTo
	}

	var resp mcpDEKDeleteResponse
	if err := m.callTool(ctx, "platform.kms.dek.delete", args, &resp); err != nil {
		return nil, err
	}

	return &DEKDeleteResult{
		Path:    resp.Path,
		Deleted: resp.Deleted,
	}, nil
}

// DEKRotate rotates a DEK via MCP tool call.
func (m *MCPAdapter) DEKRotate(ctx context.Context, path string, background bool) (*DEKRotateResult, error) {
	args := map[string]interface{}{
		"path":       path,
		"background": background,
	}

	var resp mcpDEKRotateResponse
	if err := m.callTool(ctx, "platform.kms.dek.rotate", args, &resp); err != nil {
		return nil, err
	}

	return &DEKRotateResult{
		Path:       resp.Path,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
	}, nil
}

// DEKStatus retrieves DEK status via MCP tool call.
func (m *MCPAdapter) DEKStatus(ctx context.Context, path string) (*DEKStatusResult, error) {
	args := map[string]interface{}{
		"path": path,
	}

	var resp mcpDEKStatusResponse
	if err := m.callTool(ctx, "platform.kms.dek.status", args, &resp); err != nil {
		return nil, err
	}

	return &DEKStatusResult{
		Path:                   resp.Path,
		Algorithm:              resp.Algorithm,
		Version:                resp.Version,
		Status:                 resp.Status,
		IsDefault:              resp.IsDefault,
		CreatedAt:              unixMillisToTime(resp.CreatedAt),
		RotatedAt:              unixMillisToTime(resp.RotatedAt),
		Description:            resp.Description,
		BackendType:            resp.BackendType,
		UsageCount:             resp.UsageCount,
		BytesUsed:              resp.BytesUsed,
		MaxUsageCount:          resp.MaxUsageCount,
		MaxBytesUsed:           resp.MaxBytesUsed,
		WarningPercent:         resp.WarningPercent,
		ReencryptionInProgress: resp.ReencryptionInProgress,
		ProcessedKeys:          resp.ProcessedKeys,
		TotalKeys:              resp.TotalKeys,
		FailedKeys:             resp.FailedKeys,
		ReencryptionStartedAt:  unixMillisToTime(resp.ReencryptionStartedAt),
		EstimatedCompletion:    unixMillisToTime(resp.EstimatedCompletion),
	}, nil
}

// =============================================================================
// Secrets Operations
// =============================================================================

// SecretsStore stores a secret via MCP tool call.
func (m *MCPAdapter) SecretsStore(ctx context.Context, opts SecretsStoreOptions) (*SecretsStoreResult, error) {
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
	if err := m.callTool(ctx, "platform.kms.secrets.store", args, &resp); err != nil {
		return nil, err
	}

	return &SecretsStoreResult{
		SecretID:  resp.SecretID,
		Version:   resp.Version,
		Timestamp: unixMillisToTime(resp.Timestamp),
	}, nil
}

// SecretsGet retrieves a secret via MCP tool call.
func (m *MCPAdapter) SecretsGet(ctx context.Context, name string) (*SecretsGetResult, error) {
	args := map[string]interface{}{
		"name": name,
	}

	var resp mcpSecretsGetResponse
	if err := m.callTool(ctx, "platform.kms.secrets.get", args, &resp); err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "SecretsGet", Err: err}
	}

	return &SecretsGetResult{
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

// SecretsList lists secrets via MCP tool call.
func (m *MCPAdapter) SecretsList(ctx context.Context, opts SecretsListOptions) (*SecretsListResult, error) {
	args := map[string]interface{}{}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Cursor != "" {
		args["cursor"] = opts.Cursor
	}

	var resp mcpSecretsListResponse
	if err := m.callTool(ctx, "platform.kms.secrets.list", args, &resp); err != nil {
		return nil, err
	}

	secrets := make([]SecretSummary, len(resp.Secrets))
	for i, s := range resp.Secrets {
		secrets[i] = SecretSummary{
			Name:           s.Name,
			CurrentVersion: s.CurrentVersion,
			Description:    s.Description,
			Owner:          s.Owner,
			CreatedAt:      unixMillisToTime(s.CreatedAt),
			UpdatedAt:      unixMillisToTime(s.UpdatedAt),
		}
	}

	return &SecretsListResult{
		Secrets:    secrets,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// SecretsDelete deletes a secret via MCP tool call.
func (m *MCPAdapter) SecretsDelete(ctx context.Context, name string, permanent bool) (*SecretsDeleteResult, error) {
	args := map[string]interface{}{
		"name":      name,
		"permanent": permanent,
	}

	var resp mcpSecretsDeleteResponse
	if err := m.callTool(ctx, "platform.kms.secrets.delete", args, &resp); err != nil {
		return nil, err
	}

	return &SecretsDeleteResult{
		SecretID:  resp.SecretID,
		Deleted:   resp.Deleted,
		Timestamp: unixMillisToTime(resp.Timestamp),
	}, nil
}

// SecretsRotate rotates a secret via MCP tool call.
func (m *MCPAdapter) SecretsRotate(ctx context.Context, opts SecretsRotateOptions) (*SecretsRotateResult, error) {
	args := map[string]interface{}{
		"name":    opts.Name,
		"newData": base64.StdEncoding.EncodeToString(opts.NewData),
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

	var resp mcpSecretsRotateResponse
	if err := m.callTool(ctx, "platform.kms.secrets.rotate", args, &resp); err != nil {
		return nil, err
	}

	return &SecretsRotateResult{
		SecretID:   resp.SecretID,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		Timestamp:  unixMillisToTime(resp.Timestamp),
	}, nil
}

// SecretsVersions lists secret versions via MCP tool call.
func (m *MCPAdapter) SecretsVersions(ctx context.Context, name string, opts SecretsVersionsOptions) (*SecretsVersionsResult, error) {
	args := map[string]interface{}{
		"name": name,
	}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Cursor != "" {
		args["cursor"] = opts.Cursor
	}

	var resp mcpSecretsVersionsResponse
	if err := m.callTool(ctx, "platform.kms.secrets.versions", args, &resp); err != nil {
		return nil, err
	}

	versions := make([]SecretVersionInfo, len(resp.Versions))
	for i, v := range resp.Versions {
		versions[i] = SecretVersionInfo{
			Version:   v.Version,
			CreatedAt: unixMillisToTime(v.CreatedAt),
			CreatedBy: v.CreatedBy,
			ExpiresAt: unixMillisToTime(v.ExpiresAt),
		}
	}

	return &SecretsVersionsResult{
		SecretID:   resp.SecretID,
		Versions:   versions,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// SecretsVersion retrieves a specific secret version via MCP tool call.
func (m *MCPAdapter) SecretsVersion(ctx context.Context, name string, version uint64) (*SecretsVersionResult, error) {
	args := map[string]interface{}{
		"name":    name,
		"version": version,
	}

	var resp mcpSecretsVersionResponse
	if err := m.callTool(ctx, "platform.kms.secrets.version", args, &resp); err != nil {
		return nil, err
	}

	data, err := base64.StdEncoding.DecodeString(resp.Data)
	if err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "SecretsVersion", Err: err}
	}

	return &SecretsVersionResult{
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

// SecretsRollback rolls back a secret to a previous version via MCP tool call.
func (m *MCPAdapter) SecretsRollback(ctx context.Context, name string, targetVersion uint64) (*SecretsRollbackResult, error) {
	args := map[string]interface{}{
		"name":          name,
		"targetVersion": targetVersion,
	}

	var resp mcpSecretsRollbackResponse
	if err := m.callTool(ctx, "platform.kms.secrets.rollback", args, &resp); err != nil {
		return nil, err
	}

	return &SecretsRollbackResult{
		SecretID:   resp.SecretID,
		NewVersion: resp.NewVersion,
		Timestamp:  unixMillisToTime(resp.Timestamp),
	}, nil
}

// SecretsStatus updates secret status via MCP tool call.
func (m *MCPAdapter) SecretsStatus(ctx context.Context, name string, enabled bool) (*SecretsStatusResult, error) {
	args := map[string]interface{}{
		"name":    name,
		"enabled": enabled,
	}

	var resp mcpSecretsStatusResponse
	if err := m.callTool(ctx, "platform.kms.secrets.status", args, &resp); err != nil {
		return nil, err
	}

	return &SecretsStatusResult{
		SecretID:  resp.SecretID,
		Status:    resp.Status,
		Timestamp: unixMillisToTime(resp.Timestamp),
	}, nil
}

// =============================================================================
// MCP Response Types
// =============================================================================

// Key Management response types

type mcpKeyGenerateResponse struct {
	KeyID              string `json:"keyId"`
	Version            uint64 `json:"version"`
	Algorithm          string `json:"algorithm"`
	Status             string `json:"status"`
	CreatedAt          int64  `json:"createdAt"`
	Name               string `json:"name"`
	Description        string `json:"description"`
	Exportable         bool   `json:"exportable"`
	DeletionProtection bool   `json:"deletionProtection"`
}

type mcpKeyGetResponse struct {
	KeyID              string   `json:"keyId"`
	Version            uint64   `json:"version"`
	Algorithm          string   `json:"algorithm"`
	Status             string   `json:"status"`
	CreatedAt          int64    `json:"createdAt"`
	UpdatedAt          int64    `json:"updatedAt"`
	LastUsedAt         int64    `json:"lastUsedAt"`
	Name               string   `json:"name"`
	Description        string   `json:"description"`
	Owner              string   `json:"owner"`
	Exportable         bool     `json:"exportable"`
	DeletionProtection bool     `json:"deletionProtection"`
	Usage              []string `json:"usage"`
}

type mcpKeyListResponse struct {
	Keys       []mcpKeySummary `json:"keys"`
	TotalCount int32           `json:"totalCount"`
	HasMore    bool            `json:"hasMore"`
	NextCursor string          `json:"nextCursor"`
}

type mcpKeySummary struct {
	KeyID     string `json:"keyId"`
	Version   uint64 `json:"version"`
	Algorithm string `json:"algorithm"`
	Status    string `json:"status"`
	CreatedAt int64  `json:"createdAt"`
}

type mcpKeyDeleteResponse struct {
	KeyID        string `json:"keyId"`
	Status       string `json:"status"`
	DeletionDate int64  `json:"deletionDate"`
}

type mcpKeyRotateResponse struct {
	KeyID      string `json:"keyId"`
	OldVersion uint64 `json:"oldVersion"`
	NewVersion uint64 `json:"newVersion"`
	RotatedAt  int64  `json:"rotatedAt"`
}

type mcpKeyVersionsResponse struct {
	KeyID      string              `json:"keyId"`
	Versions   []mcpKeyVersionInfo `json:"versions"`
	HasMore    bool                `json:"hasMore"`
	NextCursor string              `json:"nextCursor"`
}

type mcpKeyVersionInfo struct {
	Version    uint64 `json:"version"`
	Algorithm  string `json:"algorithm"`
	Status     string `json:"status"`
	CreatedAt  int64  `json:"createdAt"`
	DisabledAt int64  `json:"disabledAt"`
}

type mcpKeyStatusResponse struct {
	KeyID     string `json:"keyId"`
	Version   uint64 `json:"version"`
	Status    string `json:"status"`
	UpdatedAt int64  `json:"updatedAt"`
}

type mcpKeyRevokeResponse struct {
	KeyID     string `json:"keyId"`
	Status    string `json:"status"`
	RevokedAt int64  `json:"revokedAt"`
}

type mcpKeyMetadataResponse struct {
	KeyID              string                 `json:"keyId"`
	Name               string                 `json:"name"`
	Description        string                 `json:"description"`
	Algorithm          string                 `json:"algorithm"`
	Status             string                 `json:"status"`
	Version            uint64                 `json:"version"`
	Exportable         bool                   `json:"exportable"`
	DeletionProtection bool                   `json:"deletionProtection"`
	Usage              []string               `json:"usage"`
	Owner              string                 `json:"owner"`
	CreatedAt          int64                  `json:"createdAt"`
	UpdatedAt          int64                  `json:"updatedAt"`
	LastUsedAt         int64                  `json:"lastUsedAt"`
	Tags               map[string]string      `json:"tags"`
	RotationPolicy     *mcpRotationPolicyInfo `json:"rotationPolicy,omitempty"`
}

type mcpRotationPolicyInfo struct {
	Enabled         bool  `json:"enabled"`
	IntervalSeconds int64 `json:"intervalSeconds"`
	NextRotation    int64 `json:"nextRotation"`
	RetainVersions  int32 `json:"retainVersions"`
}

type mcpKeyMetadataUpdateResponse struct {
	KeyID     string            `json:"keyId"`
	Name      string            `json:"name"`
	UpdatedAt int64             `json:"updatedAt"`
	Tags      map[string]string `json:"tags"`
}

type mcpKeyPolicyResponse struct {
	KeyID             string   `json:"keyId"`
	Version           int32    `json:"version"`
	AllowedOperations []string `json:"allowedOperations"`
	AllowedPrincipals []string `json:"allowedPrincipals"`
	DeniedPrincipals  []string `json:"deniedPrincipals"`
	ExpiresAt         int64    `json:"expiresAt"`
	RotationRequired  bool     `json:"rotationRequired"`
	MaxUsageCount     uint64   `json:"maxUsageCount"`
	RequireMFA        bool     `json:"requireMFA"`
	UpdatedAt         int64    `json:"updatedAt"`
}

type mcpKeyPolicySetResponse struct {
	KeyID         string `json:"keyId"`
	PolicyVersion int32  `json:"policyVersion"`
	UpdatedAt     int64  `json:"updatedAt"`
}

type mcpKeyAlgorithmsResponse struct {
	Algorithms []string `json:"algorithms"`
}

// Crypto response types

type mcpCryptoEncryptResponse struct {
	KeyID      string `json:"keyId"`
	KeyVersion uint64 `json:"keyVersion"`
	Ciphertext string `json:"ciphertext"` // base64
	Nonce      string `json:"nonce"`      // base64
	Timestamp  int64  `json:"timestamp"`
}

type mcpCryptoDecryptResponse struct {
	KeyID      string `json:"keyId"`
	KeyVersion uint64 `json:"keyVersion"`
	Plaintext  string `json:"plaintext"` // base64
	Timestamp  int64  `json:"timestamp"`
}

type mcpCryptoSignResponse struct {
	KeyID         string `json:"keyId"`
	KeyVersion    uint64 `json:"keyVersion"`
	Signature     string `json:"signature"` // base64
	HashAlgorithm string `json:"hashAlgorithm"`
	Timestamp     int64  `json:"timestamp"`
}

type mcpCryptoVerifyResponse struct {
	KeyID      string `json:"keyId"`
	KeyVersion uint64 `json:"keyVersion"`
	Valid      bool   `json:"valid"`
	Timestamp  int64  `json:"timestamp"`
}

type mcpCryptoHashResponse struct {
	Algorithm string `json:"algorithm"`
	Hash      string `json:"hash"` // base64
	Timestamp int64  `json:"timestamp"`
}

type mcpCryptoHMACResponse struct {
	KeyID         string `json:"keyId"`
	KeyVersion    uint64 `json:"keyVersion"`
	HMAC          string `json:"hmac"` // base64
	HashAlgorithm string `json:"hashAlgorithm"`
	Timestamp     int64  `json:"timestamp"`
}

type mcpCryptoVerifyHMACResponse struct {
	KeyID      string `json:"keyId"`
	KeyVersion uint64 `json:"keyVersion"`
	Valid      bool   `json:"valid"`
	Timestamp  int64  `json:"timestamp"`
}

type mcpCryptoRandomResponse struct {
	RandomBytes string `json:"randomBytes"` // base64
	Timestamp   int64  `json:"timestamp"`
}

// DEK response types

type mcpDEKCreateResponse struct {
	Path        string `json:"path"`
	Algorithm   string `json:"algorithm"`
	Version     uint64 `json:"version"`
	CreatedAt   int64  `json:"createdAt"`
	Description string `json:"description"`
}

type mcpDEKGetResponse struct {
	Path           string `json:"path"`
	Algorithm      string `json:"algorithm"`
	Version        uint64 `json:"version"`
	Status         string `json:"status"`
	IsDefault      bool   `json:"isDefault"`
	CreatedAt      int64  `json:"createdAt"`
	RotatedAt      int64  `json:"rotatedAt"`
	Description    string `json:"description"`
	BackendType    string `json:"backendType"`
	UsageCount     uint64 `json:"usageCount"`
	BytesUsed      uint64 `json:"bytesUsed"`
	MaxUsageCount  uint64 `json:"maxUsageCount"`
	MaxBytesUsed   uint64 `json:"maxBytesUsed"`
	WarningPercent int32  `json:"warningPercent"`
}

type mcpDEKListResponse struct {
	DEKs       []mcpDEKSummary `json:"deks"`
	HasMore    bool            `json:"hasMore"`
	NextCursor string          `json:"nextCursor"`
}

type mcpDEKSummary struct {
	Path      string `json:"path"`
	Algorithm string `json:"algorithm"`
	Version   uint64 `json:"version"`
	Status    string `json:"status"`
	IsDefault bool   `json:"isDefault"`
	CreatedAt int64  `json:"createdAt"`
}

type mcpDEKDeleteResponse struct {
	Path    string `json:"path"`
	Deleted bool   `json:"deleted"`
}

type mcpDEKRotateResponse struct {
	Path       string `json:"path"`
	OldVersion uint64 `json:"oldVersion"`
	NewVersion uint64 `json:"newVersion"`
}

type mcpDEKStatusResponse struct {
	Path                   string `json:"path"`
	Algorithm              string `json:"algorithm"`
	Version                uint64 `json:"version"`
	Status                 string `json:"status"`
	IsDefault              bool   `json:"isDefault"`
	CreatedAt              int64  `json:"createdAt"`
	RotatedAt              int64  `json:"rotatedAt"`
	Description            string `json:"description"`
	BackendType            string `json:"backendType"`
	UsageCount             uint64 `json:"usageCount"`
	BytesUsed              uint64 `json:"bytesUsed"`
	MaxUsageCount          uint64 `json:"maxUsageCount"`
	MaxBytesUsed           uint64 `json:"maxBytesUsed"`
	WarningPercent         int32  `json:"warningPercent"`
	ReencryptionInProgress bool   `json:"reencryptionInProgress"`
	ProcessedKeys          int64  `json:"processedKeys"`
	TotalKeys              int64  `json:"totalKeys"`
	FailedKeys             int64  `json:"failedKeys"`
	ReencryptionStartedAt  int64  `json:"reencryptionStartedAt"`
	EstimatedCompletion    int64  `json:"estimatedCompletion"`
}

// Secrets response types

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

// =============================================================================
// Time Conversion Helpers
// =============================================================================

// unixMillisToTime converts Unix milliseconds to time.Time.
func unixMillisToTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.Unix(ms/1000, (ms%1000)*int64(time.Millisecond))
}
