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

package piv

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

	pivsdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/piv"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const (
	defaultMCPTimeout  = 15 * time.Second
	mcpProtocolVersion = "2024-11-05"
	mcpClientName      = "piv-integration-test"
	mcpClientVersion   = "1.0.0"
)

// MCP PIV tool names per pkg/api/mcp/phase35_tools.go.
const (
	mcpToolListDevices = "platform_piv_list_devices"
	mcpToolListSlots   = "platform_piv_list_slots"
	mcpToolSlotInfo    = "platform_piv_slot_info"
	mcpToolGenerate    = "platform_piv_generate"
	mcpToolImport      = "platform_piv_import"
	mcpToolSign        = "platform_piv_sign"
	mcpToolAttest      = "platform_piv_attest"
	mcpToolReset       = "platform_piv_reset"
)

// MCPAdapter drives PIV operations over MCP (JSON-RPC 2.0 over HTTPS, TLS 1.3).
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

// callTool invokes tools/call for name + args, decoding the first text
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
	if out == nil {
		_, err := mcpwire.ToolOutputJSON(raw)
		return err
	}
	return mcpwire.DecodeToolOutput(raw, out)
}

// ListDevices invokes platform_piv_list_devices.
func (m *MCPAdapter) ListDevices(ctx context.Context, req *pivsdk.ListDevicesRequest) (*pivsdk.ListDevicesResponse, error) {
	_ = req
	resp := &pivsdk.ListDevicesResponse{}
	if err := m.callTool(ctx, mcpToolListDevices, map[string]interface{}{}, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolListDevices, Err: err}
	}
	return resp, nil
}

// ListSlots invokes platform_piv_list_slots.
func (m *MCPAdapter) ListSlots(ctx context.Context, req *pivsdk.ListSlotsRequest) (*pivsdk.ListSlotsResponse, error) {
	if req == nil {
		req = &pivsdk.ListSlotsRequest{}
	}
	args := map[string]interface{}{"device": req.Device}
	resp := &pivsdk.ListSlotsResponse{}
	if err := m.callTool(ctx, mcpToolListSlots, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolListSlots, Err: err}
	}
	return resp, nil
}

// SlotInfo invokes platform_piv_slot_info.
func (m *MCPAdapter) SlotInfo(ctx context.Context, req *pivsdk.SlotInfoRequest) (*pivsdk.SlotInfoResponse, error) {
	if req == nil {
		req = &pivsdk.SlotInfoRequest{}
	}
	args := map[string]interface{}{
		"slot":   req.Slot,
		"device": req.Device,
	}
	resp := &pivsdk.SlotInfoResponse{}
	if err := m.callTool(ctx, mcpToolSlotInfo, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolSlotInfo, Err: err}
	}
	return resp, nil
}

// Generate invokes platform_piv_generate.
func (m *MCPAdapter) Generate(ctx context.Context, req *pivsdk.GenerateRequest) (*pivsdk.GenerateResponse, error) {
	if req == nil {
		req = &pivsdk.GenerateRequest{}
	}
	args := map[string]interface{}{
		"slot":      req.Slot,
		"algorithm": string(req.Algorithm),
		"pin":       req.PIN,
	}
	resp := &pivsdk.GenerateResponse{}
	if err := m.callTool(ctx, mcpToolGenerate, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolGenerate, Err: err}
	}
	return resp, nil
}

// Import invokes platform_piv_import.
func (m *MCPAdapter) Import(ctx context.Context, req *pivsdk.ImportRequest) (*pivsdk.ImportResponse, error) {
	if req == nil {
		req = &pivsdk.ImportRequest{}
	}
	args := map[string]interface{}{
		"slot":            req.Slot,
		"private_key_pem": req.PrivateKeyPEM,
		"pin":             req.PIN,
	}
	resp := &pivsdk.ImportResponse{}
	if err := m.callTool(ctx, mcpToolImport, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolImport, Err: err}
	}
	return resp, nil
}

// Sign invokes platform_piv_sign. The payload is base64-encoded per the
// tool schema.
func (m *MCPAdapter) Sign(ctx context.Context, req *pivsdk.SignRequest) (*pivsdk.SignResponse, error) {
	if req == nil {
		req = &pivsdk.SignRequest{}
	}
	args := map[string]interface{}{
		"slot":    req.Slot,
		"payload": base64.StdEncoding.EncodeToString(req.Payload),
		"pin":     req.PIN,
	}
	resp := &pivsdk.SignResponse{}
	if err := m.callTool(ctx, mcpToolSign, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolSign, Err: err}
	}
	return resp, nil
}

// Attest invokes platform_piv_attest.
func (m *MCPAdapter) Attest(ctx context.Context, req *pivsdk.AttestRequest) (*pivsdk.AttestResponse, error) {
	if req == nil {
		req = &pivsdk.AttestRequest{}
	}
	args := map[string]interface{}{"slot": req.Slot}
	resp := &pivsdk.AttestResponse{}
	if err := m.callTool(ctx, mcpToolAttest, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolAttest, Err: err}
	}
	return resp, nil
}

// Reset invokes platform_piv_reset.
func (m *MCPAdapter) Reset(ctx context.Context, req *pivsdk.ResetRequest) (*pivsdk.ResetResponse, error) {
	if req == nil {
		req = &pivsdk.ResetRequest{}
	}
	args := map[string]interface{}{"device": req.Device}
	resp := &pivsdk.ResetResponse{}
	if err := m.callTool(ctx, mcpToolReset, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolReset, Err: err}
	}
	return resp, nil
}

var _ PIVCommands = (*MCPAdapter)(nil)
