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
	"os"
	"strings"
	"sync/atomic"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	baasservice "github.com/jeremyhahn/go-quicbaas/sdk/go/service"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
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

	var rawResult json.RawMessage
	if err := m.sendRequest(ctx, "tools/call", toolReq, &rawResult); err != nil {
		return err
	}

	// The tool output is JSON in the CallToolResult's text block.
	var err error
	if result == nil {
		_, err = mcpwire.ToolOutputJSON(rawResult)
	} else {
		err = mcpwire.DecodeToolOutput(rawResult, result)
	}
	if err != nil {
		return ErrMCPResponseParseFailed{Operation: toolName, Err: err}
	}
	return nil
}

// =============================================================================
// Tool Surface
// =============================================================================

// The adapter calls the tools pkg/api/mcp registers (kms_tools_exec.go,
// tools_exec.go) with their snake_case arguments, and decodes each result
// into the go-quicbaas SDK type, or the map shape, that
// pkg/api/daemon.MCPServiceProvider returns for that tool.
const (
	// mcpTransport names this transport in surface.ErrNoSurface declarations.
	mcpTransport = "MCP"

	// mcpNoSecretVersionTool explains why secret version operations leave the MCP matrix.
	mcpNoSecretVersionTool = "the MCP tool registry has no secret rotate, version listing, rollback or status tool (MISSING)"
)

// mcpPurposeUsages maps a test key purpose to the usage names
// kms_generate_key accepts (parseKMSKeyUsage in pkg/api/daemon/mcp_service.go).
var mcpPurposeUsages = map[string][]string{
	"encrypt":    {"encrypt", "decrypt"},
	"encryption": {"encrypt", "decrypt"},
	"sign":       {"sign", "verify"},
	"signing":    {"sign", "verify"},
	"hmac":       {"generate_mac", "verify_mac"},
	"mac":        {"generate_mac", "verify_mac"},
	"wrap":       {"wrap", "unwrap"},
	"wrapping":   {"wrap", "unwrap"},
	"derive":     {"derive"},
	"derivation": {"derive"},
}

// ErrMCPInvalidOption reports a test option the adapter cannot express as a
// tool argument.
type ErrMCPInvalidOption struct {
	Option string
	Value  string
	Err    error
}

func (e ErrMCPInvalidOption) Error() string {
	return fmt.Sprintf("invalid MCP option %s=%q: %v", e.Option, e.Value, e.Err)
}

func (e ErrMCPInvalidOption) Unwrap() error {
	return e.Err
}

// mcpNoSurface declares an operation the MCP tool registry does not expose.
func mcpNoSurface(operation, reason string) error {
	return surface.ErrNoSurface{Transport: mcpTransport, Operation: operation, Reason: reason}
}

// mcpKeyListResult is the map MCPServiceProvider.KMSListKeys returns.
type mcpKeyListResult struct {
	Keys       []*baasservice.KeyHandle `json:"keys"`
	TotalCount int32                    `json:"total_count"`
	HasMore    bool                     `json:"has_more"`
	NextCursor string                   `json:"next_cursor"`
}

// mcpDeleteResult is the map kms_delete_key and secret_delete return.
type mcpDeleteResult struct {
	Success  bool   `json:"success"`
	KeyID    string `json:"key_id"`
	SecretID string `json:"secret_id"`
}

// mcpAlgorithmsResult is the map kms_supported_algorithms returns.
type mcpAlgorithmsResult struct {
	Algorithms []string `json:"algorithms"`
}

// mcpEncryptResult is the map MCPServiceProvider.KMSEncrypt returns.
type mcpEncryptResult struct {
	Ciphertext []byte `json:"ciphertext"`
	Nonce      []byte `json:"nonce"`
	KeyVersion uint64 `json:"key_version"`
}

// mcpDecryptResult is the map MCPServiceProvider.KMSDecrypt returns.
type mcpDecryptResult struct {
	Plaintext []byte `json:"plaintext"`
}

// mcpSignResult is the map MCPServiceProvider.KMSSign returns.
type mcpSignResult struct {
	Signature  []byte `json:"signature"`
	KeyVersion uint64 `json:"key_version"`
}

// mcpVerifyResult is the map MCPServiceProvider.KMSVerify returns.
type mcpVerifyResult struct {
	Valid bool `json:"valid"`
}

// mcpRandomResult is the map kms_random returns.
type mcpRandomResult struct {
	RandomBytes []byte `json:"random_bytes"`
	NumBytes    int    `json:"num_bytes"`
}

// mcpKeyStatusResult is the kms_update_key_status output. The status is a
// platform.v1 KeyStatus number.
type mcpKeyStatusResult struct {
	KeyID     string `json:"key_id"`
	Version   uint64 `json:"version"`
	KeyStatus int32  `json:"key_status"`
	Timestamp int64  `json:"timestamp"`
}

// mcpKeyVersionsResult is the kms_list_key_versions output. Status and
// algorithm are platform.v1 numbers.
type mcpKeyVersionsResult struct {
	KeyID    string `json:"key_id"`
	Versions []struct {
		Version    uint64 `json:"version"`
		Status     int32  `json:"status"`
		Algorithm  int32  `json:"algorithm"`
		CreatedAt  int64  `json:"created_at"`
		DisabledAt int64  `json:"disabled_at"`
	} `json:"versions"`
	NextCursor string `json:"next_cursor"`
	HasMore    bool   `json:"has_more"`
}

// mcpHashResult is the kms_hash output. The algorithm is a platform.v1
// HashAlgorithm number.
type mcpHashResult struct {
	Algorithm int32  `json:"algorithm"`
	Hash      []byte `json:"hash"`
	Timestamp int64  `json:"timestamp"`
}

// mcpHMACResult is the kms_hmac output.
type mcpHMACResult struct {
	KeyID         string `json:"key_id"`
	KeyVersion    uint64 `json:"key_version"`
	HMAC          []byte `json:"hmac"`
	HashAlgorithm int32  `json:"hash_algorithm"`
	Timestamp     int64  `json:"timestamp"`
}

// mcpVerifyHMACResult is the kms_verify_hmac output.
type mcpVerifyHMACResult struct {
	KeyID      string `json:"key_id"`
	KeyVersion uint64 `json:"key_version"`
	Valid      bool   `json:"valid"`
	Timestamp  int64  `json:"timestamp"`
}

// mcpStatusName upper-cases an SDK key status ("enabled" -> "ENABLED").
func mcpStatusName(status baasservice.KeyStatus) string {
	return strings.ToUpper(string(status))
}

// mcpHashAlgorithm maps a test hash name to the platform.v1 HashAlgorithm
// number the MCP digest tools take, the same numbers QUIC carries.
func mcpHashAlgorithm(name string) (int32, error) {
	hash, err := quicHashAlgorithm(name)
	if err != nil {
		return 0, ErrMCPInvalidOption{Option: "HashAlgorithm", Value: name, Err: err}
	}
	return hash, nil
}

// mcpKeyStatus maps the enabled flag to the platform.v1 KeyStatus number
// kms_update_key_status takes.
func mcpKeyStatus(enabled bool) int32 {
	if enabled {
		return int32(platformv1.KeyStatus_KEY_STATUS_ENABLED)
	}
	return int32(platformv1.KeyStatus_KEY_STATUS_DISABLED)
}

// mcpUsageNames converts SDK key usages to their names.
func mcpUsageNames(usages []baasservice.KeyUsage) []string {
	names := make([]string, 0, len(usages))
	for _, usage := range usages {
		names = append(names, string(usage))
	}
	return names
}

// mcpTime dereferences an optional SDK timestamp.
func mcpTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// encodeBytes base64-encodes a binary tool argument.
func encodeBytes(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// keyMetadata reads the metadata kms_generate_key and kms_get_key leave out
// of the key handle.
func (m *MCPAdapter) keyMetadata(ctx context.Context, keyID string) (*baasservice.KeyMetadata, error) {
	var metadata baasservice.KeyMetadata
	if err := m.callTool(ctx, "kms_get_key_metadata", map[string]interface{}{"key_id": keyID}, &metadata); err != nil {
		return nil, err
	}
	return &metadata, nil
}

// =============================================================================
// Key Management Operations
// =============================================================================

// KeyGenerate calls kms_generate_key, then kms_get_key_metadata for the
// fields the key handle does not carry.
func (m *MCPAdapter) KeyGenerate(ctx context.Context, opts KeyGenerateOptions) (*KeyGenerateResult, error) {
	args := map[string]interface{}{
		"name":                keyName(opts),
		"algorithm":           opts.Algorithm,
		"exportable":          opts.Exportable,
		"deletion_protection": opts.DeletionProtection,
	}
	if usages := mcpPurposeUsages[strings.ToLower(opts.Purpose)]; len(usages) > 0 {
		args["usage"] = usages
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}
	if opts.Owner != "" {
		args["owner"] = opts.Owner
	}

	var handle baasservice.KeyHandle
	if err := m.callTool(ctx, "kms_generate_key", args, &handle); err != nil {
		return nil, err
	}

	metadata, err := m.keyMetadata(ctx, handle.KeyID)
	if err != nil {
		return nil, err
	}

	result := &KeyGenerateResult{
		KeyID:              handle.KeyID,
		Version:            handle.Version,
		Algorithm:          string(handle.Algorithm),
		Status:             mcpStatusName(handle.Status),
		CreatedAt:          handle.CreatedAt,
		Name:               metadata.Name,
		Description:        metadata.Description,
		Exportable:         metadata.Exportable,
		DeletionProtection: metadata.DeletionProtection,
	}
	if err := applyKeyDisplay(ctx, m, opts, result); err != nil {
		return nil, err
	}
	return result, nil
}

// KeyGet calls kms_get_key, then kms_get_key_metadata for the descriptive fields.
func (m *MCPAdapter) KeyGet(ctx context.Context, keyID string, version uint64) (*KeyGetResult, error) {
	args := map[string]interface{}{"key_id": keyID}
	if version > 0 {
		args["version"] = version
	}

	var handle baasservice.KeyHandle
	if err := m.callTool(ctx, "kms_get_key", args, &handle); err != nil {
		return nil, err
	}

	metadata, err := m.keyMetadata(ctx, keyID)
	if err != nil {
		return nil, err
	}

	return &KeyGetResult{
		KeyID:              handle.KeyID,
		Version:            handle.Version,
		Algorithm:          string(handle.Algorithm),
		Status:             mcpStatusName(handle.Status),
		CreatedAt:          handle.CreatedAt,
		UpdatedAt:          metadata.UpdatedAt,
		LastUsedAt:         mcpTime(metadata.LastUsedAt),
		Name:               metadata.Name,
		Description:        metadata.Description,
		Owner:              metadata.Owner,
		Exportable:         metadata.Exportable,
		DeletionProtection: metadata.DeletionProtection,
		Usage:              mcpUsageNames(metadata.Usage),
	}, nil
}

// KeyList calls kms_list_keys. The tool takes a limit only; it has no cursor.
func (m *MCPAdapter) KeyList(ctx context.Context, opts KeyListOptions) (*KeyListResult, error) {
	args := map[string]interface{}{}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}

	var resp mcpKeyListResult
	if err := m.callTool(ctx, "kms_list_keys", args, &resp); err != nil {
		return nil, err
	}

	keys := make([]KeySummary, 0, len(resp.Keys))
	for _, key := range resp.Keys {
		if key == nil {
			continue
		}
		keys = append(keys, KeySummary{
			KeyID:     key.KeyID,
			Version:   key.Version,
			Algorithm: string(key.Algorithm),
			Status:    mcpStatusName(key.Status),
			CreatedAt: key.CreatedAt,
		})
	}

	return &KeyListResult{
		Keys:       keys,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// KeyDelete calls kms_delete_key. The tool takes the key ID only; it has no
// pending window or force argument.
func (m *MCPAdapter) KeyDelete(ctx context.Context, keyID string, _ KeyDeleteOptions) (*KeyDeleteResult, error) {
	var resp mcpDeleteResult
	if err := m.callTool(ctx, "kms_delete_key", map[string]interface{}{"key_id": keyID}, &resp); err != nil {
		return nil, err
	}

	return &KeyDeleteResult{KeyID: resp.KeyID}, nil
}

// KeyRotate calls kms_rotate_key. The tool has no retain-old-version argument.
func (m *MCPAdapter) KeyRotate(ctx context.Context, keyID string, _ bool) (*KeyRotateResult, error) {
	var resp baasservice.RotateKeyResponse
	if err := m.callTool(ctx, "kms_rotate_key", map[string]interface{}{"key_id": keyID}, &resp); err != nil {
		return nil, err
	}

	return &KeyRotateResult{
		KeyID:      resp.KeyID,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		RotatedAt:  resp.Timestamp,
	}, nil
}

// KeyVersions calls kms_list_key_versions.
func (m *MCPAdapter) KeyVersions(ctx context.Context, keyID string, opts KeyVersionsOptions) (*KeyVersionsResult, error) {
	args := map[string]interface{}{"key_id": keyID}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Cursor != "" {
		args["cursor"] = opts.Cursor
	}

	var resp mcpKeyVersionsResult
	if err := m.callTool(ctx, "kms_list_key_versions", args, &resp); err != nil {
		return nil, err
	}

	versions := make([]KeyVersionInfo, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		versions = append(versions, KeyVersionInfo{
			Version:    v.Version,
			Algorithm:  quicAlgorithmName(v.Algorithm),
			Status:     quicStatusName(v.Status),
			CreatedAt:  grpcUnixToTime(v.CreatedAt),
			DisabledAt: grpcUnixToTime(v.DisabledAt),
		})
	}

	return &KeyVersionsResult{
		KeyID:      resp.KeyID,
		Versions:   versions,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// KeyStatus calls kms_update_key_status. Version 0 addresses the key itself.
func (m *MCPAdapter) KeyStatus(ctx context.Context, keyID string, version uint64, enabled bool) (*KeyStatusResult, error) {
	args := map[string]interface{}{
		"key_id": keyID,
		"status": mcpKeyStatus(enabled),
	}
	if version > 0 {
		args["version"] = version
	}

	var resp mcpKeyStatusResult
	if err := m.callTool(ctx, "kms_update_key_status", args, &resp); err != nil {
		return nil, err
	}

	return &KeyStatusResult{
		KeyID:     resp.KeyID,
		Version:   resp.Version,
		Status:    quicStatusName(resp.KeyStatus),
		UpdatedAt: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// KeyRevoke calls kms_revoke_key.
func (m *MCPAdapter) KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error) {
	args := map[string]interface{}{"key_id": keyID, "reason": reason}

	var resp baasservice.RevokeKeyResponse
	if err := m.callTool(ctx, "kms_revoke_key", args, &resp); err != nil {
		return nil, err
	}

	return &KeyRevokeResult{
		KeyID:     resp.KeyID,
		Status:    mcpStatusName(resp.Status),
		RevokedAt: resp.Timestamp,
	}, nil
}

// KeyMetadata calls kms_get_key_metadata.
func (m *MCPAdapter) KeyMetadata(ctx context.Context, keyID string) (*KeyMetadataResult, error) {
	metadata, err := m.keyMetadata(ctx, keyID)
	if err != nil {
		return nil, err
	}

	result := &KeyMetadataResult{
		KeyID:              metadata.KeyID,
		Name:               metadata.Name,
		Description:        metadata.Description,
		Algorithm:          string(metadata.Algorithm),
		Status:             mcpStatusName(metadata.Status),
		Version:            metadata.Version,
		Exportable:         metadata.Exportable,
		DeletionProtection: metadata.DeletionProtection,
		Usage:              mcpUsageNames(metadata.Usage),
		Owner:              metadata.Owner,
		CreatedAt:          metadata.CreatedAt,
		UpdatedAt:          metadata.UpdatedAt,
		LastUsedAt:         mcpTime(metadata.LastUsedAt),
		Tags:               metadata.Tags,
	}
	if policy := metadata.RotationPolicy; policy != nil {
		result.RotationPolicy = &RotationPolicy{
			Enabled:         policy.Enabled,
			IntervalSeconds: int64(policy.Interval / time.Second),
			NextRotation:    policy.NextRotation,
			RetainVersions:  int32(policy.RetainVersions),
		}
	}
	return result, nil
}

// KeyMetadataUpdate calls kms_update_key_metadata.
func (m *MCPAdapter) KeyMetadataUpdate(ctx context.Context, keyID string, opts KeyMetadataUpdateOptions) (*KeyMetadataUpdateResult, error) {
	args := map[string]interface{}{"key_id": keyID}
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
		args["remove_tags"] = opts.RemoveTags
	}

	var metadata baasservice.KeyMetadata
	if err := m.callTool(ctx, "kms_update_key_metadata", args, &metadata); err != nil {
		return nil, err
	}

	return &KeyMetadataUpdateResult{
		KeyID:     metadata.KeyID,
		Name:      metadata.Name,
		UpdatedAt: metadata.UpdatedAt,
		Tags:      metadata.Tags,
	}, nil
}

// KeyPolicy calls kms_get_key_policy.
func (m *MCPAdapter) KeyPolicy(ctx context.Context, keyID string) (*KeyPolicyResult, error) {
	var policy baasservice.KeyPolicy
	if err := m.callTool(ctx, "kms_get_key_policy", map[string]interface{}{"key_id": keyID}, &policy); err != nil {
		return nil, err
	}

	result := &KeyPolicyResult{
		KeyID:             policy.KeyID,
		Version:           int32(policy.Version),
		AllowedOperations: mcpUsageNames(policy.AllowedOperations),
		AllowedPrincipals: policy.AllowedPrincipals,
		DeniedPrincipals:  policy.DeniedPrincipals,
		ExpiresAt:         mcpTime(policy.ExpiresAt),
		RotationRequired:  policy.RotationRequired,
		RequireMFA:        policy.RequireMFA,
		UpdatedAt:         policy.UpdatedAt,
	}
	if policy.MaxUsageCount != nil {
		result.MaxUsageCount = *policy.MaxUsageCount
	}
	return result, nil
}

// KeyPolicySet calls kms_set_key_policy. ExpiresIn is a Go duration; the tool
// takes the absolute expiry in Unix seconds.
func (m *MCPAdapter) KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error) {
	args := map[string]interface{}{
		"key_id":            keyID,
		"rotation_required": opts.RotationRequired,
		"require_mfa":       opts.RequireMFA,
	}
	if len(opts.Operations) > 0 {
		args["allowed_operations"] = opts.Operations
	}
	if len(opts.AllowPrincipals) > 0 {
		args["allowed_principals"] = opts.AllowPrincipals
	}
	if len(opts.DenyPrincipals) > 0 {
		args["denied_principals"] = opts.DenyPrincipals
	}
	if opts.MaxUsageCount > 0 {
		args["max_usage_count"] = opts.MaxUsageCount
	}
	if opts.ExpiresIn != "" {
		expiresIn, err := time.ParseDuration(opts.ExpiresIn)
		if err != nil {
			return nil, ErrMCPInvalidOption{Option: "ExpiresIn", Value: opts.ExpiresIn, Err: err}
		}
		args["expires_at"] = time.Now().Add(expiresIn).Unix()
	}

	var resp baasservice.SetKeyPolicyResponse
	if err := m.callTool(ctx, "kms_set_key_policy", args, &resp); err != nil {
		return nil, err
	}

	return &KeyPolicySetResult{
		KeyID:         resp.KeyID,
		PolicyVersion: int32(resp.PolicyVersion),
		UpdatedAt:     resp.Timestamp,
	}, nil
}

// KeyAlgorithms calls kms_supported_algorithms.
func (m *MCPAdapter) KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error) {
	var resp mcpAlgorithmsResult
	if err := m.callTool(ctx, "kms_supported_algorithms", map[string]interface{}{}, &resp); err != nil {
		return nil, err
	}

	return &KeyAlgorithmsResult{Algorithms: resp.Algorithms}, nil
}

// =============================================================================
// Crypto Operations
// =============================================================================

// CryptoEncrypt calls kms_encrypt.
func (m *MCPAdapter) CryptoEncrypt(ctx context.Context, opts CryptoEncryptOptions) (*CryptoEncryptResult, error) {
	args := map[string]interface{}{
		"key_id":    opts.KeyID,
		"plaintext": encodeBytes(opts.Plaintext),
	}
	if len(opts.Context) > 0 {
		args["context"] = encodeBytes(opts.Context)
	}
	if len(opts.Nonce) > 0 {
		args["nonce"] = encodeBytes(opts.Nonce)
	}

	var resp mcpEncryptResult
	if err := m.callTool(ctx, "kms_encrypt", args, &resp); err != nil {
		return nil, err
	}

	return &CryptoEncryptResult{
		KeyID:      opts.KeyID,
		KeyVersion: resp.KeyVersion,
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
	}, nil
}

// CryptoDecrypt calls kms_decrypt.
func (m *MCPAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	args := map[string]interface{}{
		"key_id":     opts.KeyID,
		"ciphertext": encodeBytes(opts.Ciphertext),
	}
	if len(opts.Context) > 0 {
		args["context"] = encodeBytes(opts.Context)
	}
	if len(opts.Nonce) > 0 {
		args["nonce"] = encodeBytes(opts.Nonce)
	}
	if opts.KeyVersion > 0 {
		args["key_version"] = opts.KeyVersion
	}

	var resp mcpDecryptResult
	if err := m.callTool(ctx, "kms_decrypt", args, &resp); err != nil {
		return nil, err
	}

	return &CryptoDecryptResult{
		KeyID:      opts.KeyID,
		KeyVersion: opts.KeyVersion,
		Plaintext:  resp.Plaintext,
	}, nil
}

// CryptoSign calls kms_sign over the unhashed message.
func (m *MCPAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	args := map[string]interface{}{
		"key_id":     opts.KeyID,
		"message":    encodeBytes(opts.Message),
		"pre_hashed": false,
	}
	if opts.HashAlgorithm != "" {
		args["hash_algorithm"] = opts.HashAlgorithm
	}

	var resp mcpSignResult
	if err := m.callTool(ctx, "kms_sign", args, &resp); err != nil {
		return nil, err
	}

	return &CryptoSignResult{
		KeyID:         opts.KeyID,
		KeyVersion:    resp.KeyVersion,
		Signature:     resp.Signature,
		HashAlgorithm: opts.HashAlgorithm,
	}, nil
}

// CryptoVerify calls kms_verify.
func (m *MCPAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	args := map[string]interface{}{
		"key_id":    opts.KeyID,
		"message":   encodeBytes(opts.Message),
		"signature": encodeBytes(opts.Signature),
	}
	if opts.HashAlgorithm != "" {
		args["hash_algorithm"] = opts.HashAlgorithm
	}
	if opts.KeyVersion > 0 {
		args["key_version"] = opts.KeyVersion
	}

	var resp mcpVerifyResult
	if err := m.callTool(ctx, "kms_verify", args, &resp); err != nil {
		return nil, err
	}

	return &CryptoVerifyResult{
		KeyID:      opts.KeyID,
		KeyVersion: opts.KeyVersion,
		Valid:      resp.Valid,
	}, nil
}

// CryptoHash calls kms_hash.
func (m *MCPAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	hash, err := mcpHashAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}
	args := map[string]interface{}{
		"data":      encodeBytes(data),
		"algorithm": hash,
	}

	var resp mcpHashResult
	if err := m.callTool(ctx, "kms_hash", args, &resp); err != nil {
		return nil, err
	}

	return &CryptoHashResult{
		Algorithm: quicHashName(resp.Algorithm),
		Hash:      resp.Hash,
		Timestamp: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoHMAC calls kms_hmac.
func (m *MCPAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	hash, err := mcpHashAlgorithm(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	args := map[string]interface{}{
		"key_id":         opts.KeyID,
		"message":        encodeBytes(opts.Message),
		"hash_algorithm": hash,
	}

	var resp mcpHMACResult
	if err := m.callTool(ctx, "kms_hmac", args, &resp); err != nil {
		return nil, err
	}

	return &CryptoHMACResult{
		KeyID:         resp.KeyID,
		KeyVersion:    resp.KeyVersion,
		HMAC:          resp.HMAC,
		HashAlgorithm: quicHashName(resp.HashAlgorithm),
		Timestamp:     grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoVerifyHMAC calls kms_verify_hmac.
func (m *MCPAdapter) CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error) {
	hash, err := mcpHashAlgorithm(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	args := map[string]interface{}{
		"key_id":         opts.KeyID,
		"message":        encodeBytes(opts.Message),
		"hmac":           encodeBytes(opts.HMAC),
		"hash_algorithm": hash,
	}
	if opts.KeyVersion > 0 {
		args["key_version"] = opts.KeyVersion
	}

	var resp mcpVerifyHMACResult
	if err := m.callTool(ctx, "kms_verify_hmac", args, &resp); err != nil {
		return nil, err
	}

	return &CryptoVerifyHMACResult{
		KeyID:      resp.KeyID,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoRandom calls kms_random.
func (m *MCPAdapter) CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error) {
	var resp mcpRandomResult
	if err := m.callTool(ctx, "kms_random", map[string]interface{}{"num_bytes": numBytes}, &resp); err != nil {
		return nil, err
	}

	return &CryptoRandomResult{RandomBytes: resp.RandomBytes}, nil
}

// =============================================================================
// DEK Operations
// =============================================================================

// DEKCreate calls dek_create.
func (m *MCPAdapter) DEKCreate(ctx context.Context, opts DEKCreateOptions) (*DEKCreateResult, error) {
	req := newCreateDEKRequest(opts)
	args := map[string]interface{}{
		"path":      req.Path,
		"algorithm": int32(req.Algorithm),
	}
	if req.Description != "" {
		args["description"] = req.Description
	}
	if req.MaxOperations > 0 {
		args["max_operations"] = req.MaxOperations
	}
	if req.MaxBytes > 0 {
		args["max_bytes"] = req.MaxBytes
	}
	if req.WarningPercent > 0 {
		args["warning_percent"] = req.WarningPercent
	}

	var resp pb.CreateDEKResponse
	if err := m.callTool(ctx, "dek_create", args, &resp); err != nil {
		return nil, err
	}
	return dekCreateResult(&resp)
}

// DEKGet calls dek_get.
func (m *MCPAdapter) DEKGet(ctx context.Context, path string) (*DEKGetResult, error) {
	var resp pb.GetDEKResponse
	if err := m.callTool(ctx, "dek_get", map[string]interface{}{"path": path}, &resp); err != nil {
		return nil, err
	}
	return dekGetResult(&resp)
}

// DEKList calls dek_list.
func (m *MCPAdapter) DEKList(ctx context.Context, opts DEKListOptions) (*DEKListResult, error) {
	args := map[string]interface{}{
		"prefix":    opts.Prefix,
		"recursive": opts.Recursive,
	}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Cursor != "" {
		args["cursor"] = opts.Cursor
	}

	var resp pb.ListDEKsResponse
	if err := m.callTool(ctx, "dek_list", args, &resp); err != nil {
		return nil, err
	}
	return dekListResult(&resp), nil
}

// DEKDelete calls dek_delete.
func (m *MCPAdapter) DEKDelete(ctx context.Context, path string, opts DEKDeleteOptions) (*DEKDeleteResult, error) {
	args := map[string]interface{}{
		"path":  path,
		"force": opts.Force,
	}
	if opts.MigrateTo != "" {
		args["migrate_to"] = opts.MigrateTo
	}

	var resp pb.DeleteDEKResponse
	if err := m.callTool(ctx, "dek_delete", args, &resp); err != nil {
		return nil, err
	}
	return &DEKDeleteResult{
		Path:    resp.Path,
		Deleted: resp.Deleted,
	}, nil
}

// DEKRotate calls dek_rotate.
func (m *MCPAdapter) DEKRotate(ctx context.Context, path string, background bool) (*DEKRotateResult, error) {
	args := map[string]interface{}{
		"path":       path,
		"background": background,
	}

	var resp pb.RotateDEKResponse
	if err := m.callTool(ctx, "dek_rotate", args, &resp); err != nil {
		return nil, err
	}
	return &DEKRotateResult{
		Path:       resp.Path,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
	}, nil
}

// DEKStatus calls dek_status.
func (m *MCPAdapter) DEKStatus(ctx context.Context, path string) (*DEKStatusResult, error) {
	var resp pb.GetDEKStatusResponse
	if err := m.callTool(ctx, "dek_status", map[string]interface{}{"path": path}, &resp); err != nil {
		return nil, err
	}
	return dekStatusResult(&resp)
}

// =============================================================================
// Secrets Operations
// =============================================================================

// SecretsStore calls secret_store. The description travels as metadata; the
// tool takes no tenant, key or algorithm argument.
func (m *MCPAdapter) SecretsStore(ctx context.Context, opts SecretsStoreOptions) (*SecretsStoreResult, error) {
	args := map[string]interface{}{
		"secret_id": opts.Name,
		"data":      encodeBytes(opts.Data),
	}
	if opts.Description != "" {
		args["metadata"] = map[string]string{"description": opts.Description}
	}

	var resp baasservice.StoreSecretResponse
	if err := m.callTool(ctx, "secret_store", args, &resp); err != nil {
		return nil, err
	}

	return &SecretsStoreResult{SecretID: resp.SecretID, Version: resp.Version, Timestamp: resp.Timestamp}, nil
}

// SecretsGet calls secret_get for the current version.
func (m *MCPAdapter) SecretsGet(ctx context.Context, name string) (*SecretsGetResult, error) {
	var resp baasservice.GetSecretResponse
	if err := m.callTool(ctx, "secret_get", map[string]interface{}{"secret_id": name}, &resp); err != nil {
		return nil, err
	}

	return &SecretsGetResult{
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

// SecretsList calls secret_list. The tool takes a limit only; it has no cursor.
func (m *MCPAdapter) SecretsList(ctx context.Context, opts SecretsListOptions) (*SecretsListResult, error) {
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
			Name:           secret.SecretID,
			CurrentVersion: secret.CurrentVersion,
			Description:    secret.Description,
			Owner:          secret.Owner,
			CreatedAt:      secret.CreatedAt,
			UpdatedAt:      secret.UpdatedAt,
		})
	}

	return &SecretsListResult{
		Secrets:    secrets,
		TotalCount: int32(resp.TotalCount),
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// SecretsDelete calls secret_delete. The tool has no permanent argument.
func (m *MCPAdapter) SecretsDelete(ctx context.Context, name string, _ bool) (*SecretsDeleteResult, error) {
	var resp mcpDeleteResult
	if err := m.callTool(ctx, "secret_delete", map[string]interface{}{"secret_id": name}, &resp); err != nil {
		return nil, err
	}

	return &SecretsDeleteResult{SecretID: resp.SecretID, Deleted: resp.Success}, nil
}

// SecretsRotate has no MCP surface.
func (m *MCPAdapter) SecretsRotate(_ context.Context, _ SecretsRotateOptions) (*SecretsRotateResult, error) {
	return nil, mcpNoSurface("SecretsRotate", mcpNoSecretVersionTool)
}

// SecretsVersions has no MCP surface.
func (m *MCPAdapter) SecretsVersions(_ context.Context, _ string, _ SecretsVersionsOptions) (*SecretsVersionsResult, error) {
	return nil, mcpNoSurface("SecretsVersions", mcpNoSecretVersionTool)
}

// SecretsVersion calls secret_get for one version.
func (m *MCPAdapter) SecretsVersion(ctx context.Context, name string, version uint64) (*SecretsVersionResult, error) {
	args := map[string]interface{}{"secret_id": name, "version": version}

	var resp baasservice.GetSecretResponse
	if err := m.callTool(ctx, "secret_get", args, &resp); err != nil {
		return nil, err
	}

	return &SecretsVersionResult{
		SecretID:  resp.SecretID,
		Version:   resp.Version,
		Data:      resp.Data,
		Metadata:  resp.Metadata,
		CreatedAt: resp.CreatedAt,
		Timestamp: resp.Timestamp,
	}, nil
}

// SecretsRollback has no MCP surface.
func (m *MCPAdapter) SecretsRollback(_ context.Context, _ string, _ uint64) (*SecretsRollbackResult, error) {
	return nil, mcpNoSurface("SecretsRollback", mcpNoSecretVersionTool)
}

// SecretsStatus has no MCP surface.
func (m *MCPAdapter) SecretsStatus(_ context.Context, _ string, _ bool) (*SecretsStatusResult, error) {
	return nil, mcpNoSurface("SecretsStatus", mcpNoSecretVersionTool)
}
