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

package fido2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	fido2sdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/fido2"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const (
	defaultMCPTimeout  = 15 * time.Second
	mcpProtocolVersion = "2024-11-05"
	mcpClientName      = "fido2-integration-test"
	mcpClientVersion   = "1.0.0"
)

// MCP FIDO2 tool names per pkg/api/mcp/phase35_tools.go.
const (
	mcpToolListDevices  = "platform_fido2_list_devices"
	mcpToolWaitDevice   = "platform_fido2_wait_device"
	mcpToolInfo         = "platform_fido2_info"
	mcpToolRegister     = "platform_fido2_register"
	mcpToolAuthenticate = "platform_fido2_authenticate"
)

// MCPAdapter drives FIDO2 operations over MCP (JSON-RPC 2.0 over HTTPS, TLS 1.3).
type MCPAdapter struct {
	endpoint   string
	httpClient *http.Client
	requestID  int64
}

// NewMCPAdapter returns an unconfigured MCP adapter.
func NewMCPAdapter() *MCPAdapter { return &MCPAdapter{} }

// Name returns "MCP".
func (m *MCPAdapter) Name() string { return "MCP" }

// Setup performs the MCP initialize handshake.
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
		"clientInfo":      map[string]interface{}{"name": mcpClientName, "version": mcpClientVersion},
	}
	var raw json.RawMessage
	if err := m.rpc(ctx, "initialize", initParams, &raw); err != nil {
		return ErrConnectionFailed{Protocol: "MCP", Endpoint: m.endpoint, Err: err}
	}
	return nil
}

// Teardown releases idle connections.
func (m *MCPAdapter) Teardown() error {
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
	return nil
}

type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      int64       `json:"id"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int64           `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// rpc sends a JSON-RPC request and decodes the result into out.
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

// callTool invokes tools/call and unwraps text content into out.
func (m *MCPAdapter) callTool(ctx context.Context, name string, args map[string]interface{}, out interface{}) error {
	params := map[string]interface{}{"name": name, "arguments": args}
	var raw json.RawMessage
	if err := m.rpc(ctx, "tools/call", params, &raw); err != nil {
		return err
	}
	if out == nil {
		_, err := mcpwire.ToolOutputJSON(raw)
		return err
	}
	return mcpwire.DecodeToolOutput(raw, out)
}

// ListDevices invokes platform_fido2_list_devices.
func (m *MCPAdapter) ListDevices(ctx context.Context, req *fido2sdk.ListDevicesRequest) (*fido2sdk.ListDevicesResponse, error) {
	_ = req
	resp := &fido2sdk.ListDevicesResponse{}
	if err := m.callTool(ctx, mcpToolListDevices, map[string]interface{}{}, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolListDevices, Err: err}
	}
	return resp, nil
}

// WaitDevice invokes platform_fido2_wait_device.
func (m *MCPAdapter) WaitDevice(ctx context.Context, req *fido2sdk.WaitDeviceRequest) (*fido2sdk.WaitDeviceResponse, error) {
	if req == nil {
		req = &fido2sdk.WaitDeviceRequest{}
	}
	args := map[string]interface{}{"timeout_seconds": int(req.TimeoutSeconds)}
	resp := &fido2sdk.WaitDeviceResponse{}
	if err := m.callTool(ctx, mcpToolWaitDevice, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolWaitDevice, Err: err}
	}
	return resp, nil
}

// Info invokes platform_fido2_info.
func (m *MCPAdapter) Info(ctx context.Context, req *fido2sdk.InfoRequest) (*fido2sdk.InfoResponse, error) {
	if req == nil {
		req = &fido2sdk.InfoRequest{}
	}
	args := map[string]interface{}{"device": req.Device}
	resp := &fido2sdk.InfoResponse{}
	if err := m.callTool(ctx, mcpToolInfo, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolInfo, Err: err}
	}
	return resp, nil
}

// Register invokes platform_fido2_register.
func (m *MCPAdapter) Register(ctx context.Context, req *fido2sdk.RegisterRequest) (*fido2sdk.RegisterResponse, error) {
	if req == nil {
		req = &fido2sdk.RegisterRequest{}
	}
	args := map[string]interface{}{
		"username":    req.Username,
		"role":        string(req.Role),
		"require_pin": req.RequirePIN,
		"require_uv":  req.RequireUV,
		"rp_id":       req.RPID,
	}
	resp := &fido2sdk.RegisterResponse{}
	if err := m.callTool(ctx, mcpToolRegister, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolRegister, Err: err}
	}
	return resp, nil
}

// Authenticate invokes platform_fido2_authenticate.
func (m *MCPAdapter) Authenticate(ctx context.Context, req *fido2sdk.AuthenticateRequest) (*fido2sdk.AuthenticateResponse, error) {
	if req == nil {
		req = &fido2sdk.AuthenticateRequest{}
	}
	args := map[string]interface{}{"credential_id": req.CredentialID}
	resp := &fido2sdk.AuthenticateResponse{}
	if err := m.callTool(ctx, mcpToolAuthenticate, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolAuthenticate, Err: err}
	}
	return resp, nil
}

var _ FIDO2Commands = (*MCPAdapter)(nil)
