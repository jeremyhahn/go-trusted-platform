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

package ceremony

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

	ceremonysdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const (
	defaultMCPTimeout  = 15 * time.Second
	mcpProtocolVersion = "2024-11-05"
	mcpClientName      = "ceremony-integration-test"
	mcpClientVersion   = "1.0.0"
)

// MCP ceremony tool names per pkg/api/mcp/phase35_tools.go.
const (
	mcpToolInit               = "platform_ceremony_init"
	mcpToolStatus             = "platform_ceremony_status"
	mcpToolClaimCertBegin     = "platform_ceremony_claim_cert_begin"
	mcpToolClaimCertComplete  = "platform_ceremony_claim_cert_complete"
	mcpToolClaimShareBegin    = "platform_ceremony_claim_share_begin"
	mcpToolClaimShareComplete = "platform_ceremony_claim_share_complete"
	mcpToolSignCSR            = "platform_ceremony_sign_csr"
)

// MCPAdapter drives ceremony operations over MCP (JSON-RPC 2.0 over HTTPS, TLS 1.3).
type MCPAdapter struct {
	endpoint   string
	httpClient *http.Client
	requestID  int64
}

// NewMCPAdapter returns an unconfigured MCP adapter.
func NewMCPAdapter() *MCPAdapter { return &MCPAdapter{} }

// Name returns "MCP".
func (m *MCPAdapter) Name() string { return "MCP" }

// Setup connects to the MCP server and performs the JSON-RPC initialize
// handshake.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	endpoint := os.Getenv(EnvPlatformMCPEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformMCP
	}
	m.endpoint = helpers.MCPBaseURL(endpoint)
	m.httpClient = helpers.NewHTTPClient(defaultMCPTimeout)

	initParams := map[string]interface{}{
		"protocolVersion": mcpProtocolVersion,
		"capabilities":    map[string]interface{}{},
		"clientInfo": map[string]interface{}{
			"name":    mcpClientName,
			"version": mcpClientVersion,
		},
	}
	var raw json.RawMessage
	if err := m.rpc(ctx, "initialize", initParams, &raw); err != nil {
		return ErrConnectionFailed{Protocol: "MCP", Endpoint: m.endpoint, Err: err}
	}
	return nil
}

// Teardown closes idle HTTP connections.
func (m *MCPAdapter) Teardown() error {
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
	return nil
}

// jsonRPCRequest is the minimal JSON-RPC 2.0 request envelope.
type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

// jsonRPCResponse is the minimal JSON-RPC 2.0 response envelope.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

// jsonRPCError is the JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// mcpCallToolResult is the MCP tool-call result envelope.
type mcpCallToolResult struct {
	Content []mcpContentItem `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

// mcpContentItem is an MCP content item (text/resource/etc).
type mcpContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// rpc sends a JSON-RPC request and decodes result into out.
func (m *MCPAdapter) rpc(ctx context.Context, method string, params interface{}, out interface{}) error {
	body := jsonRPCRequest{
		JSONRPC: "2.0",
		ID:      atomic.AddInt64(&m.requestID, 1),
		Method:  method,
		Params:  params,
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.endpoint+"/mcp", bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	resp, err := m.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var envelope jsonRPCResponse
	if err := json.Unmarshal(respBody, &envelope); err != nil {
		return fmt.Errorf("MCP parse: %w (body=%s)", err, string(respBody))
	}
	if envelope.Error != nil {
		return fmt.Errorf("MCP error %d: %s", envelope.Error.Code, envelope.Error.Message)
	}
	if out != nil && len(envelope.Result) > 0 {
		return json.Unmarshal(envelope.Result, out)
	}
	return nil
}

// callTool invokes a tools/call for name + args and decodes the first text
// content body into out.
func (m *MCPAdapter) callTool(ctx context.Context, name string, args map[string]interface{}, out interface{}) error {
	params := map[string]interface{}{
		"name":      name,
		"arguments": args,
	}
	var raw json.RawMessage
	if err := m.rpc(ctx, "tools/call", params, &raw); err != nil {
		return err
	}
	if len(raw) == 0 {
		return nil
	}
	var result mcpCallToolResult
	if err := json.Unmarshal(raw, &result); err != nil || len(result.Content) == 0 {
		// Some servers return the result map directly without the content wrapper.
		if out != nil {
			return json.Unmarshal(raw, out)
		}
		return nil
	}
	if result.IsError {
		msg := ""
		if len(result.Content) > 0 {
			msg = result.Content[0].Text
		}
		return fmt.Errorf("MCP tool %s error: %s", name, msg)
	}
	if out == nil {
		return nil
	}
	for _, item := range result.Content {
		if item.Type == "text" && item.Text != "" {
			return json.Unmarshal([]byte(item.Text), out)
		}
	}
	return nil
}

// Init invokes platform_ceremony_init.
func (m *MCPAdapter) Init(ctx context.Context, req *ceremonysdk.InitRequest) (*ceremonysdk.InitResponse, error) {
	if req == nil {
		req = &ceremonysdk.InitRequest{}
	}
	args := map[string]interface{}{
		"so_pin":                   req.SOPIN,
		"user_pin":                 req.UserPIN,
		"threshold":                req.Threshold,
		"hostname":                 req.Hostname,
		"sans":                     req.SANs,
		"credential_seal_strategy": req.CredentialSealStrategy,
	}
	resp := &ceremonysdk.InitResponse{}
	if err := m.callTool(ctx, mcpToolInit, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolInit, Err: err}
	}
	return resp, nil
}

// Status invokes platform_ceremony_status.
func (m *MCPAdapter) Status(ctx context.Context) (*ceremonysdk.StatusResponse, error) {
	resp := &ceremonysdk.StatusResponse{}
	if err := m.callTool(ctx, mcpToolStatus, map[string]interface{}{}, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolStatus, Err: err}
	}
	return resp, nil
}

// ClaimCertBegin invokes platform_ceremony_claim_cert_begin.
func (m *MCPAdapter) ClaimCertBegin(ctx context.Context, req *ceremonysdk.ClaimCertBeginRequest) (*ceremonysdk.ClaimCertBeginResponse, error) {
	if req == nil {
		req = &ceremonysdk.ClaimCertBeginRequest{}
	}
	args := map[string]interface{}{
		"username":           req.Username,
		"authenticator_type": string(req.AuthenticatorType),
		"slot":               req.Slot,
		"credential_id":      req.CredentialID,
	}
	resp := &ceremonysdk.ClaimCertBeginResponse{}
	if err := m.callTool(ctx, mcpToolClaimCertBegin, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolClaimCertBegin, Err: err}
	}
	return resp, nil
}

// ClaimCertComplete invokes platform_ceremony_claim_cert_complete.
func (m *MCPAdapter) ClaimCertComplete(ctx context.Context, req *ceremonysdk.ClaimCertCompleteRequest) (*ceremonysdk.ClaimCertCompleteResponse, error) {
	if req == nil {
		req = &ceremonysdk.ClaimCertCompleteRequest{}
	}
	args := map[string]interface{}{
		"username":  req.Username,
		"nonce":     req.Nonce,
		"signature": req.Signature,
	}
	resp := &ceremonysdk.ClaimCertCompleteResponse{}
	if err := m.callTool(ctx, mcpToolClaimCertComplete, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolClaimCertComplete, Err: err}
	}
	return resp, nil
}

// ClaimShareBegin invokes platform_ceremony_claim_share_begin.
func (m *MCPAdapter) ClaimShareBegin(ctx context.Context, req *ceremonysdk.ClaimShareBeginRequest) (*ceremonysdk.ClaimShareBeginResponse, error) {
	if req == nil {
		req = &ceremonysdk.ClaimShareBeginRequest{}
	}
	args := map[string]interface{}{"username": req.Username}
	resp := &ceremonysdk.ClaimShareBeginResponse{}
	if err := m.callTool(ctx, mcpToolClaimShareBegin, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolClaimShareBegin, Err: err}
	}
	return resp, nil
}

// ClaimShareComplete invokes platform_ceremony_claim_share_complete. The
// signature travels base64-encoded because MCP tool arguments are JSON.
func (m *MCPAdapter) ClaimShareComplete(ctx context.Context, req *ceremonysdk.ClaimShareCompleteRequest) (*ceremonysdk.ClaimShareCompleteResponse, error) {
	if req == nil {
		req = &ceremonysdk.ClaimShareCompleteRequest{}
	}
	args := map[string]interface{}{
		"username":  req.Username,
		"nonce":     req.Nonce,
		"signature": base64.StdEncoding.EncodeToString(req.Signature),
	}
	resp := &ceremonysdk.ClaimShareCompleteResponse{}
	if err := m.callTool(ctx, mcpToolClaimShareComplete, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolClaimShareComplete, Err: err}
	}
	return resp, nil
}

// SignCSR invokes platform_ceremony_sign_csr.
func (m *MCPAdapter) SignCSR(ctx context.Context, req *ceremonysdk.SignCSRRequest) (*ceremonysdk.SignCSRResponse, error) {
	if req == nil {
		req = &ceremonysdk.SignCSRRequest{}
	}
	args := map[string]interface{}{
		"username": req.Username,
		"so_pin":   req.SOPIN,
		"csr_pem":  req.CSRPEM,
		"role":     string(req.Role),
	}
	resp := &ceremonysdk.SignCSRResponse{}
	if err := m.callTool(ctx, mcpToolSignCSR, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolSignCSR, Err: err}
	}
	return resp, nil
}

var _ CeremonyCommands = (*MCPAdapter)(nil)
