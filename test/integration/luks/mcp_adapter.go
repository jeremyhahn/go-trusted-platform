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

package luks

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

	lukssdk "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/luks"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

const (
	defaultMCPTimeout  = 15 * time.Second
	mcpProtocolVersion = "2024-11-05"
	mcpClientName      = "luks-integration-test"
	mcpClientVersion   = "1.0.0"
)

// MCP LUKS tool names per pkg/api/mcp/phase35_tools.go.
const (
	mcpToolStatus           = "platform_luks_status"
	mcpToolListSlots        = "platform_luks_list_slots"
	mcpToolInfo             = "platform_luks_info"
	mcpToolEnrollPassphrase = "platform_luks_enroll_passphrase"
	mcpToolEnrollFIDO2      = "platform_luks_enroll_fido2"
	mcpToolEnrollTPM        = "platform_luks_enroll_tpm"
	mcpToolEnrollRecovery   = "platform_luks_enroll_recovery"
	mcpToolRemoveKey        = "platform_luks_remove_key"
	mcpToolTestUnlock       = "platform_luks_test_unlock"
	mcpToolChangePassphrase = "platform_luks_change_passphrase"
)

// MCPAdapter drives LUKS operations over MCP (JSON-RPC 2.0 over HTTPS, TLS 1.3).
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

// Status invokes platform_luks_status.
func (m *MCPAdapter) Status(ctx context.Context, req *lukssdk.StatusRequest) (*lukssdk.StatusResponse, error) {
	if req == nil {
		req = &lukssdk.StatusRequest{}
	}
	args := map[string]interface{}{"device": req.Device}
	resp := &lukssdk.StatusResponse{}
	if err := m.callTool(ctx, mcpToolStatus, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolStatus, Err: err}
	}
	return resp, nil
}

// ListSlots invokes platform_luks_list_slots.
func (m *MCPAdapter) ListSlots(ctx context.Context, req *lukssdk.ListSlotsRequest) (*lukssdk.ListSlotsResponse, error) {
	if req == nil {
		req = &lukssdk.ListSlotsRequest{}
	}
	args := map[string]interface{}{"device": req.Device}
	resp := &lukssdk.ListSlotsResponse{}
	if err := m.callTool(ctx, mcpToolListSlots, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolListSlots, Err: err}
	}
	return resp, nil
}

// Info invokes platform_luks_info.
func (m *MCPAdapter) Info(ctx context.Context, req *lukssdk.InfoRequest) (*lukssdk.InfoResponse, error) {
	if req == nil {
		req = &lukssdk.InfoRequest{}
	}
	args := map[string]interface{}{"device": req.Device}
	resp := &lukssdk.InfoResponse{}
	if err := m.callTool(ctx, mcpToolInfo, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolInfo, Err: err}
	}
	return resp, nil
}

// EnrollPassphrase invokes platform_luks_enroll_passphrase.
func (m *MCPAdapter) EnrollPassphrase(ctx context.Context, req *lukssdk.EnrollPassphraseRequest) (*lukssdk.EnrollPassphraseResponse, error) {
	if req == nil {
		req = &lukssdk.EnrollPassphraseRequest{}
	}
	args := map[string]interface{}{
		"device":              req.Device,
		"existing_passphrase": req.ExistingPassphrase,
		"new_passphrase":      req.NewPassphrase,
	}
	resp := &lukssdk.EnrollPassphraseResponse{}
	if err := m.callTool(ctx, mcpToolEnrollPassphrase, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolEnrollPassphrase, Err: err}
	}
	return resp, nil
}

// EnrollFIDO2 invokes platform_luks_enroll_fido2.
func (m *MCPAdapter) EnrollFIDO2(ctx context.Context, req *lukssdk.EnrollFIDO2Request) (*lukssdk.EnrollFIDO2Response, error) {
	if req == nil {
		req = &lukssdk.EnrollFIDO2Request{}
	}
	args := map[string]interface{}{
		"device":              req.Device,
		"existing_passphrase": req.ExistingPassphrase,
		"credential_id":       req.CredentialID,
		"require_pin":         req.RequirePIN,
		"require_uv":          req.RequireUV,
	}
	resp := &lukssdk.EnrollFIDO2Response{}
	if err := m.callTool(ctx, mcpToolEnrollFIDO2, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolEnrollFIDO2, Err: err}
	}
	return resp, nil
}

// EnrollTPM invokes platform_luks_enroll_tpm.
func (m *MCPAdapter) EnrollTPM(ctx context.Context, req *lukssdk.EnrollTPMRequest) (*lukssdk.EnrollTPMResponse, error) {
	if req == nil {
		req = &lukssdk.EnrollTPMRequest{}
	}
	pcrs := make([]int, 0, len(req.PCRs))
	for _, p := range req.PCRs {
		pcrs = append(pcrs, int(p))
	}
	args := map[string]interface{}{
		"device":              req.Device,
		"existing_passphrase": req.ExistingPassphrase,
		"pcrs":                pcrs,
		"handle":              req.Handle,
	}
	resp := &lukssdk.EnrollTPMResponse{}
	if err := m.callTool(ctx, mcpToolEnrollTPM, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolEnrollTPM, Err: err}
	}
	return resp, nil
}

// EnrollRecovery invokes platform_luks_enroll_recovery.
func (m *MCPAdapter) EnrollRecovery(ctx context.Context, req *lukssdk.EnrollRecoveryRequest) (*lukssdk.EnrollRecoveryResponse, error) {
	if req == nil {
		req = &lukssdk.EnrollRecoveryRequest{}
	}
	args := map[string]interface{}{
		"device":              req.Device,
		"existing_passphrase": req.ExistingPassphrase,
	}
	resp := &lukssdk.EnrollRecoveryResponse{}
	if err := m.callTool(ctx, mcpToolEnrollRecovery, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolEnrollRecovery, Err: err}
	}
	return resp, nil
}

// RemoveKey invokes platform_luks_remove_key.
func (m *MCPAdapter) RemoveKey(ctx context.Context, req *lukssdk.RemoveKeyRequest) (*lukssdk.RemoveKeyResponse, error) {
	if req == nil {
		req = &lukssdk.RemoveKeyRequest{}
	}
	args := map[string]interface{}{"device": req.Device, "slot": int(req.Slot)}
	resp := &lukssdk.RemoveKeyResponse{}
	if err := m.callTool(ctx, mcpToolRemoveKey, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolRemoveKey, Err: err}
	}
	return resp, nil
}

// TestUnlock invokes platform_luks_test_unlock.
func (m *MCPAdapter) TestUnlock(ctx context.Context, req *lukssdk.TestUnlockRequest) (*lukssdk.TestUnlockResponse, error) {
	if req == nil {
		req = &lukssdk.TestUnlockRequest{}
	}
	args := map[string]interface{}{"device": req.Device, "slot": int(req.Slot)}
	resp := &lukssdk.TestUnlockResponse{}
	if err := m.callTool(ctx, mcpToolTestUnlock, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolTestUnlock, Err: err}
	}
	return resp, nil
}

// ChangePassphrase invokes platform_luks_change_passphrase.
func (m *MCPAdapter) ChangePassphrase(ctx context.Context, req *lukssdk.ChangePassphraseRequest) (*lukssdk.ChangePassphraseResponse, error) {
	if req == nil {
		req = &lukssdk.ChangePassphraseRequest{}
	}
	args := map[string]interface{}{
		"device":         req.Device,
		"slot":           int(req.Slot),
		"old_passphrase": req.OldPassphrase,
		"new_passphrase": req.NewPassphrase,
	}
	resp := &lukssdk.ChangePassphraseResponse{}
	if err := m.callTool(ctx, mcpToolChangePassphrase, args, resp); err != nil {
		return nil, ErrCallFailed{Protocol: "MCP", Method: mcpToolChangePassphrase, Err: err}
	}
	return resp, nil
}

var _ LUKSCommands = (*MCPAdapter)(nil)
