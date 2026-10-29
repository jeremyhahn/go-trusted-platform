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

package tpm

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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// MCP Constants
// =============================================================================

const (
	// DefaultMCPTimeoutTPM is the default timeout for MCP operations.
	DefaultMCPTimeoutTPM = 10 * time.Second

	// mcpTPMProtocolVersion is the MCP protocol version.
	mcpTPMProtocolVersion = "2024-11-05"

	// mcpTPMClientName is the name of this MCP test client.
	mcpTPMClientName = "tpm-integration-test"

	// mcpTPMClientVersion is the version of this MCP test client.
	mcpTPMClientVersion = "1.0.0"
)

// MCP Tool names for TPM operations.
const (
	MCPToolTPMInfo      = "platform_tpm_info"
	MCPToolTPMProvision = "platform_tpm_provision"
	MCPToolTPMClear     = "platform_tpm_clear"
	MCPToolTPMEK        = "platform_tpm_ek"
	MCPToolTPMEKCert    = "platform_tpm_ek_cert"
	MCPToolTPMEKCreate  = "platform_tpm_ek_create"
	MCPToolTPMEKDelete  = "platform_tpm_ek_delete"
	MCPToolTPMSRK       = "platform_tpm_srk"
	MCPToolTPMSRKCreate = "platform_tpm_srk_create"
	MCPToolTPMSRKDelete = "platform_tpm_srk_delete"
	MCPToolTPMSeal      = "platform_tpm_seal"
	MCPToolTPMUnseal    = "platform_tpm_unseal"
	MCPToolTPMEventLog  = "platform_tpm_eventlog"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrMCPTPMConnectionFailed indicates an MCP connection failure.
type ErrMCPTPMConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPTPMConnectionFailed) Error() string {
	return fmt.Sprintf("MCP TPM connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrMCPTPMConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrMCPTPMInitializeFailed indicates MCP initialization failure.
type ErrMCPTPMInitializeFailed struct {
	Err error
}

func (e ErrMCPTPMInitializeFailed) Error() string {
	return fmt.Sprintf("MCP TPM initialization failed: %v", e.Err)
}

func (e ErrMCPTPMInitializeFailed) Unwrap() error {
	return e.Err
}

// ErrMCPTPMToolCallFailed indicates an MCP tool call failure.
type ErrMCPTPMToolCallFailed struct {
	Tool    string
	Code    int
	Message string
}

func (e ErrMCPTPMToolCallFailed) Error() string {
	return fmt.Sprintf("MCP TPM tool call %s failed (code %d): %s", e.Tool, e.Code, e.Message)
}

// ErrMCPTPMResponseParseFailed indicates MCP response parsing failure.
type ErrMCPTPMResponseParseFailed struct {
	Tool string
	Err  error
}

func (e ErrMCPTPMResponseParseFailed) Error() string {
	return fmt.Sprintf("MCP TPM response parse failed for %s: %v", e.Tool, e.Err)
}

func (e ErrMCPTPMResponseParseFailed) Unwrap() error {
	return e.Err
}

// ErrMCPTPMRequestFailed indicates an MCP HTTP request failure.
type ErrMCPTPMRequestFailed struct {
	Err error
}

func (e ErrMCPTPMRequestFailed) Error() string {
	return fmt.Sprintf("MCP TPM request failed: %v", e.Err)
}

func (e ErrMCPTPMRequestFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// MCP JSON-RPC Types
// =============================================================================

// mcpTPMRequest represents an MCP JSON-RPC request.
type mcpTPMRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// mcpTPMResponse represents an MCP JSON-RPC response.
type mcpTPMResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpTPMError    `json:"error,omitempty"`
}

// mcpTPMError represents an MCP JSON-RPC error.
type mcpTPMError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// mcpTPMCallToolParams represents parameters for tools/call.
type mcpTPMCallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// mcpTPMCallToolResult represents the result of tools/call.
type mcpTPMCallToolResult struct {
	Content []mcpTPMContent `json:"content"`
	IsError bool            `json:"isError,omitempty"`
}

// mcpTPMContent represents content in an MCP response.
type mcpTPMContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// mcpTPMInitializeRequest represents the MCP initialize request params.
type mcpTPMInitializeRequest struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ClientInfo      mcpTPMClientInfo       `json:"clientInfo"`
}

// mcpTPMClientInfo represents the MCP client info.
type mcpTPMClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// =============================================================================
// MCP Adapter
// =============================================================================

// MCPAdapter implements TPMCommands using MCP (Model Context Protocol) calls to platformd.
type MCPAdapter struct {
	endpoint    string
	httpClient  *http.Client
	initialized bool
	requestID   int64
}

// NewMCPAdapter creates a new MCP protocol adapter instance.
func NewMCPAdapter() *MCPAdapter {
	endpoint := os.Getenv(EnvPlatformMCPEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformMCP
	}

	return &MCPAdapter{
		endpoint:   helpers.MCPBaseURL(endpoint),
		httpClient: helpers.NewHTTPClient(DefaultMCPTimeoutTPM),
	}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP connection by performing the JSON-RPC initialize handshake.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	initReq := mcpTPMInitializeRequest{
		ProtocolVersion: mcpTPMProtocolVersion,
		Capabilities:    map[string]interface{}{},
		ClientInfo: mcpTPMClientInfo{
			Name:    mcpTPMClientName,
			Version: mcpTPMClientVersion,
		},
	}

	var result json.RawMessage
	if err := m.sendRequest(ctx, "initialize", initReq, &result); err != nil {
		return ErrMCPTPMInitializeFailed{Err: err}
	}

	m.initialized = true
	return nil
}

// Teardown performs cleanup.
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

// nextRequestID returns a monotonically increasing request ID for JSON-RPC.
func (m *MCPAdapter) nextRequestID() int64 {
	return atomic.AddInt64(&m.requestID, 1)
}

// sendRequest sends a JSON-RPC request over HTTP and decodes the response.
func (m *MCPAdapter) sendRequest(ctx context.Context, method string, params interface{}, result interface{}) error {
	req := mcpTPMRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      m.nextRequestID(),
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return ErrMCPTPMRequestFailed{Err: fmt.Errorf("failed to marshal request: %w", err)}
	}

	url := m.endpoint + "/mcp"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return ErrMCPTPMRequestFailed{Err: fmt.Errorf("failed to create HTTP request: %w", err)}
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := m.httpClient.Do(httpReq)
	if err != nil {
		return ErrMCPTPMConnectionFailed{Endpoint: m.endpoint, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrMCPTPMRequestFailed{Err: fmt.Errorf("failed to read response body: %w", err)}
	}

	var rpcResp mcpTPMResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return ErrMCPTPMResponseParseFailed{Tool: method, Err: err}
	}

	if rpcResp.Error != nil {
		return ErrMCPTPMToolCallFailed{
			Tool:    method,
			Code:    rpcResp.Error.Code,
			Message: rpcResp.Error.Message,
		}
	}

	if result != nil && len(rpcResp.Result) > 0 {
		if err := json.Unmarshal(rpcResp.Result, result); err != nil {
			return ErrMCPTPMResponseParseFailed{Tool: method, Err: err}
		}
	}

	return nil
}

// callTool calls an MCP tool via the tools/call JSON-RPC method.
func (m *MCPAdapter) callTool(ctx context.Context, name string, args map[string]interface{}) (*mcpTPMCallToolResult, error) {
	params := mcpTPMCallToolParams{
		Name:      name,
		Arguments: args,
	}

	var rawResult json.RawMessage
	if err := m.sendRequest(ctx, "tools/call", params, &rawResult); err != nil {
		return nil, ErrMCPTPMToolCallFailed{Tool: name, Code: -1, Message: err.Error()}
	}

	// The tool output is JSON in the CallToolResult's text block.
	output, err := mcpwire.ToolOutputJSON(rawResult)
	if err != nil {
		return nil, ErrMCPTPMToolCallFailed{Tool: name, Code: -1, Message: err.Error()}
	}
	return &mcpTPMCallToolResult{
		Content: []mcpTPMContent{{Type: "text", Text: string(output)}},
	}, nil
}

// extractToolJSON extracts the JSON text from an MCP tool result.
func (m *MCPAdapter) extractToolJSON(result *mcpTPMCallToolResult) ([]byte, error) {
	if result == nil || len(result.Content) == 0 {
		return nil, fmt.Errorf("empty tool result")
	}

	return []byte(result.Content[0].Text), nil
}

// =============================================================================
// TPM Info Operations
// =============================================================================

// Info retrieves TPM information via MCP.
func (m *MCPAdapter) Info(ctx context.Context) (*InfoResult, error) {
	result, err := m.callTool(ctx, MCPToolTPMInfo, nil)
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMInfo, Err: err}
	}

	var resp struct {
		Info            string   `json:"info"`
		Version         string   `json:"version"`
		Manufacturer    string   `json:"manufacturer"`
		Model           string   `json:"model"`
		FirmwareVersion string   `json:"firmware_version"`
		IsSimulator     bool     `json:"is_simulator"`
		FIPSMode        bool     `json:"fips_mode"`
		MaxNVRAMSize    uint32   `json:"max_nvram_size"`
		PCRBanks        []string `json:"pcr_banks"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMInfo, Err: err}
	}

	ir := &InfoResult{
		Version:      resp.Version,
		IsSimulator:  resp.IsSimulator,
		FIPSMode:     resp.FIPSMode,
		MaxNVRAMSize: resp.MaxNVRAMSize,
		PCRBanks:     resp.PCRBanks,
	}

	if resp.Manufacturer != "" {
		ir.Manufacturer = &ManufacturerInfo{
			Name:            resp.Manufacturer,
			Model:           resp.Model,
			FirmwareVersion: resp.FirmwareVersion,
		}
	}

	return ir, nil
}

// =============================================================================
// TPM Provision Operations
// =============================================================================

// Provision provisions the TPM via MCP.
func (m *MCPAdapter) Provision(ctx context.Context, opts ProvisionOptions) (*ProvisionResult, error) {
	args := map[string]interface{}{}
	if opts.OwnerPassword != "" {
		args["owner_password"] = opts.OwnerPassword
	}

	result, err := m.callTool(ctx, MCPToolTPMProvision, args)
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMProvision, Err: err}
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMProvision, Err: err}
	}

	return &ProvisionResult{
		Success:    resp.Success,
		Message:    resp.Message,
		EKCreated:  resp.Success,
		SRKCreated: resp.Success,
		AKCreated:  resp.Success,
	}, nil
}

// =============================================================================
// TPM Clear Operations
// =============================================================================

// Clear clears the TPM via MCP.
func (m *MCPAdapter) Clear(ctx context.Context, opts ClearOptions) (*ClearResult, error) {
	args := map[string]interface{}{}
	if opts.OwnerPassword != "" {
		args["owner_password"] = opts.OwnerPassword
	}

	result, err := m.callTool(ctx, MCPToolTPMClear, args)
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMClear, Err: err}
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMClear, Err: err}
	}

	return &ClearResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// EK Operations
// =============================================================================

// EKCreate creates an EK via MCP.
func (m *MCPAdapter) EKCreate(ctx context.Context, opts EKCreateOptions) (*EKCreateResult, error) {
	result, err := m.callTool(ctx, MCPToolTPMEKCreate, nil)
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMEKCreate, Err: err}
	}

	var resp struct {
		Handle    uint32 `json:"handle"`
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMEKCreate, Err: err}
	}

	pubKey, decErr := base64.StdEncoding.DecodeString(resp.PublicKey)
	if decErr != nil {
		pubKey = []byte(resp.PublicKey)
	}

	return &EKCreateResult{
		Success:   true,
		Handle:    resp.Handle,
		Algorithm: resp.Algorithm,
		PublicKey: pubKey,
		CreatedAt: time.Now(),
	}, nil
}

// EKInfo retrieves EK information via MCP.
func (m *MCPAdapter) EKInfo(ctx context.Context, handle uint32) (*EKInfoResult, error) {
	result, err := m.callTool(ctx, MCPToolTPMEK, nil)
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMEK, Err: err}
	}

	var resp struct {
		Handle    uint32 `json:"handle"`
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMEK, Err: err}
	}

	pubKey, decErr := base64.StdEncoding.DecodeString(resp.PublicKey)
	if decErr != nil {
		pubKey = []byte(resp.PublicKey)
	}

	return &EKInfoResult{
		Handle:    resp.Handle,
		Algorithm: resp.Algorithm,
		PublicKey: pubKey,
	}, nil
}

// EKCertificate retrieves the EK certificate via MCP.
func (m *MCPAdapter) EKCertificate(ctx context.Context) (*EKCertificateResult, error) {
	result, err := m.callTool(ctx, MCPToolTPMEKCert, nil)
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMEKCert, Err: err}
	}

	var resp struct {
		Certificate string `json:"certificate"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMEKCert, Err: err}
	}

	cert, decErr := base64.StdEncoding.DecodeString(resp.Certificate)
	if decErr != nil {
		cert = []byte(resp.Certificate)
	}

	return &EKCertificateResult{
		Format:      "DER",
		Certificate: cert,
	}, nil
}

// EKDelete deletes the EK via MCP.
func (m *MCPAdapter) EKDelete(ctx context.Context, handle uint32, password string) (*EKDeleteResult, error) {
	result, err := m.callTool(ctx, MCPToolTPMEKDelete, map[string]interface{}{"handle": handle})
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMEKDelete, Err: err}
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMEKDelete, Err: err}
	}

	return &EKDeleteResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// SRK Operations
// =============================================================================

// SRKCreate creates an SRK via MCP.
func (m *MCPAdapter) SRKCreate(ctx context.Context, opts SRKCreateOptions) (*SRKCreateResult, error) {
	result, err := m.callTool(ctx, MCPToolTPMSRKCreate, nil)
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMSRKCreate, Err: err}
	}

	var resp struct {
		Handle    uint32 `json:"handle"`
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMSRKCreate, Err: err}
	}

	pubKey, decErr := base64.StdEncoding.DecodeString(resp.PublicKey)
	if decErr != nil {
		pubKey = []byte(resp.PublicKey)
	}

	return &SRKCreateResult{
		Success:   true,
		Handle:    resp.Handle,
		Algorithm: resp.Algorithm,
		PublicKey: pubKey,
		CreatedAt: time.Now(),
	}, nil
}

// SRKInfo retrieves SRK information via MCP.
func (m *MCPAdapter) SRKInfo(ctx context.Context, handle uint32) (*SRKInfoResult, error) {
	result, err := m.callTool(ctx, MCPToolTPMSRK, nil)
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMSRK, Err: err}
	}

	var resp struct {
		Handle    uint32 `json:"handle"`
		PublicKey string `json:"public_key"`
		Algorithm string `json:"algorithm"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMSRK, Err: err}
	}

	pubKey, decErr := base64.StdEncoding.DecodeString(resp.PublicKey)
	if decErr != nil {
		pubKey = []byte(resp.PublicKey)
	}

	return &SRKInfoResult{
		Handle:    resp.Handle,
		Algorithm: resp.Algorithm,
		PublicKey: pubKey,
	}, nil
}

// SRKDelete deletes the SRK via MCP.
func (m *MCPAdapter) SRKDelete(ctx context.Context, handle uint32, password string) (*SRKDeleteResult, error) {
	result, err := m.callTool(ctx, MCPToolTPMSRKDelete, map[string]interface{}{"handle": handle})
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMSRKDelete, Err: err}
	}

	var resp struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMSRKDelete, Err: err}
	}

	return &SRKDeleteResult{
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// Seal/Unseal Operations
// =============================================================================

// Seal seals data to the TPM via MCP.
func (m *MCPAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	args := map[string]interface{}{
		"data": base64.StdEncoding.EncodeToString(opts.Data),
	}

	result, err := m.callTool(ctx, MCPToolTPMSeal, args)
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMSeal, Err: err}
	}

	var resp struct {
		SealedData string `json:"sealed_data"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMSeal, Err: err}
	}

	return &SealResult{
		Success: true,
		Message: "data sealed successfully",
	}, nil
}

// Unseal unseals data from the TPM via MCP.
func (m *MCPAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	args := map[string]interface{}{
		"cn": opts.CN,
	}

	result, err := m.callTool(ctx, MCPToolTPMUnseal, args)
	if err != nil {
		return nil, err
	}

	toolData, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMUnseal, Err: err}
	}

	var resp struct {
		Data string `json:"data"`
	}

	if err := json.Unmarshal(toolData, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMUnseal, Err: err}
	}

	unsealedData, decErr := base64.StdEncoding.DecodeString(resp.Data)
	if decErr != nil {
		unsealedData = []byte(resp.Data)
	}

	return &UnsealResult{
		Success: true,
		Data:    unsealedData,
	}, nil
}

// =============================================================================
// Event Log Operations
// =============================================================================

// EventLog reads the TPM event log via MCP.
func (m *MCPAdapter) EventLog(ctx context.Context) (*EventLogResult, error) {
	result, err := m.callTool(ctx, MCPToolTPMEventLog, nil)
	if err != nil {
		return nil, err
	}

	data, err := m.extractToolJSON(result)
	if err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMEventLog, Err: err}
	}

	var resp struct {
		EventLog   string `json:"event_log"`
		Format     string `json:"format"`
		EventCount uint64 `json:"event_count"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, ErrMCPTPMResponseParseFailed{Tool: MCPToolTPMEventLog, Err: err}
	}

	eventResult := &EventLogResult{
		Events: make([]EventLogEntry, 0),
	}

	if resp.EventLog != "" {
		eventData, decErr := base64.StdEncoding.DecodeString(resp.EventLog)
		if decErr != nil {
			eventData = []byte(resp.EventLog)
		}
		eventResult.Events = append(eventResult.Events, EventLogEntry{
			EventData: eventData,
		})
	}

	return eventResult, nil
}

// Ensure MCPAdapter implements TPMCommands interface.
var _ TPMCommands = (*MCPAdapter)(nil)
