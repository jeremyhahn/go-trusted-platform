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

// Package pxe provides integration test adapters for PXE provisioning services.
// This file implements the PXECommands interface using MCP (Model Context Protocol).

//go:build integration

package pxe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// MCP Constants
// =============================================================================

const (
	// mcpTimeout is the default timeout for MCP requests.
	mcpTimeout = 30 * time.Second

	// mcpProtocolVersion is the MCP protocol version supported by this client.
	mcpProtocolVersion = "2024-11-05"

	// mcpClientName is the name of this MCP client.
	mcpClientName = "pxe-integration-test"

	// mcpClientVersion is the version of this MCP client.
	mcpClientVersion = "1.0.0"

	// mcpJSONRPCInternalError is the JSON-RPC 2.0 internal error code.
	mcpJSONRPCInternalError = -32603
)

// MCP tool names matching server-side definitions in pkg/api/mcp/pxe_tools.go.
const (
	mcpToolPXEListDevices       = "pxe_list_devices"
	mcpToolPXEGetDevice         = "pxe_get_device"
	mcpToolPXEGetDeviceByMAC    = "pxe_get_device_by_mac"
	mcpToolPXERegisterDevice    = "pxe_register_device"
	mcpToolPXEUpdateState       = "pxe_update_state"
	mcpToolPXEAuthorizeDevice   = "pxe_authorize_device"
	mcpToolPXEQuarantineDevice  = "pxe_quarantine_device"
	mcpToolPXERetryDevice       = "pxe_retry_device"
	mcpToolPXEServiceStatus     = "pxe_service_status"
	mcpToolPXEGetDeviceEvents   = "pxe_get_device_events"
	mcpToolPXERemoveDevice      = "pxe_remove_device"
	mcpToolPXESetDeviceEnrolled = "pxe_set_device_enrolled"
)

// =============================================================================
// MCP Error Types
// =============================================================================

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

// ErrMCPConnectionFailed indicates an MCP connection failure.
type ErrMCPConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPConnectionFailed) Error() string {
	return fmt.Sprintf("MCP connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrMCPConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrMCPRequestFailed indicates an MCP request failed.
type ErrMCPRequestFailed struct {
	Err error
}

func (e ErrMCPRequestFailed) Error() string {
	return fmt.Sprintf("MCP request failed: %v", e.Err)
}

func (e ErrMCPRequestFailed) Unwrap() error {
	return e.Err
}

// ErrMCPResponseParseFailed indicates MCP response parsing failed.
type ErrMCPResponseParseFailed struct {
	Operation string
	Err       error
}

func (e ErrMCPResponseParseFailed) Error() string {
	return fmt.Sprintf("MCP response parse failed for %s: %v", e.Operation, e.Err)
}

func (e ErrMCPResponseParseFailed) Unwrap() error {
	return e.Err
}

// ErrMCPToolCallFailed indicates an MCP tool call returned an error.
type ErrMCPToolCallFailed struct {
	Tool    string
	Code    int
	Message string
}

func (e ErrMCPToolCallFailed) Error() string {
	return fmt.Sprintf("MCP tool %s failed (code %d): %s", e.Tool, e.Code, e.Message)
}

// =============================================================================
// JSON-RPC 2.0 Types
// =============================================================================

type mcpJSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

type mcpJSONRPCResponse struct {
	JSONRPC string           `json:"jsonrpc"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *mcpJSONRPCError `json:"error,omitempty"`
	ID      int64            `json:"id"`
}

type mcpJSONRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// =============================================================================
// MCP Protocol Types
// =============================================================================

type mcpInitRequest struct {
	ProtocolVersion string           `json:"protocolVersion"`
	Capabilities    mcpCapabilities  `json:"capabilities"`
	ClientInfo      mcpClientInfoReq `json:"clientInfo"`
}

type mcpCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

type mcpClientInfoReq struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpInitResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      mcpServerInfoResp      `json:"serverInfo"`
}

type mcpServerInfoResp struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpCallToolReq struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

type mcpCallToolResult struct {
	Content []mcpContentItem `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

type mcpContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// =============================================================================
// MCP Response Types for PXE operations
// =============================================================================

type mcpPXEDeviceResponse struct {
	ID                string `json:"id"`
	MACAddress        string `json:"mac_address"`
	PortID            string `json:"port_id"`
	State             string `json:"state"`
	StateReason       string `json:"state_reason"`
	CertificateSerial string `json:"certificate_serial,omitempty"`
	CurrentVLAN       uint16 `json:"current_vlan"`
	TargetVLAN        uint16 `json:"target_vlan"`
	CreatedAt         string `json:"created_at"`
	UpdatedAt         string `json:"updated_at"`
	StateChangedAt    string `json:"state_changed_at"`
	RetryCount        int    `json:"retry_count"`
}

type mcpPXEListDevicesResponse struct {
	Devices []mcpPXEDeviceResponse `json:"devices"`
	Count   int                    `json:"count"`
}

type mcpPXEEventsResponse struct {
	DeviceID string                `json:"device_id"`
	Events   []mcpPXEEventResponse `json:"events"`
	Count    int                   `json:"count"`
}

type mcpPXEEventResponse struct {
	ID        string            `json:"id"`
	DeviceID  string            `json:"device_id"`
	Timestamp string            `json:"timestamp"`
	EventType string            `json:"event_type"`
	FromState string            `json:"from_state"`
	ToState   string            `json:"to_state"`
	Details   map[string]string `json:"details,omitempty"`
	Error     string            `json:"error,omitempty"`
}

type mcpPXEStatusResponse struct {
	Running          bool   `json:"running"`
	DeviceCount      int    `json:"device_count"`
	StartTime        string `json:"start_time"`
	IPXEServerAddr   string `json:"ipxe_server_addr"`
	QuarantineVLAN   uint16 `json:"quarantine_vlan"`
	ProvisioningVLAN uint16 `json:"provisioning_vlan"`
}

type mcpPXERemoveResponse struct {
	Success  bool   `json:"success"`
	DeviceID string `json:"device_id"`
	Message  string `json:"message"`
}

// =============================================================================
// MCP Adapter Implementation
// =============================================================================

// MCPAdapter implements PXECommands using MCP calls to platformd.
// This adapter makes MCP calls to the platformd server for testing
// the MCP transport layer consistency with other protocol adapters.
// MCP is used for AI/LLM integration.
type MCPAdapter struct {
	endpoint    string
	httpClient  *http.Client
	initialized bool
	requestID   int64
}

// NewMCPAdapter creates a new MCP protocol adapter instance.
// The MCP server serves plain HTTP (not HTTPS), so the adapter uses a plain
// HTTP client regardless of whether mTLS is configured for other protocols.
func NewMCPAdapter() *MCPAdapter {
	endpoint := os.Getenv(EnvPlatformMCPEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformMCP
	}

	return &MCPAdapter{
		endpoint:   endpoint,
		httpClient: helpers.NewPlainHTTPClient(mcpTimeout),
	}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP connection and performs the initialize handshake.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	initReq := mcpInitRequest{
		ProtocolVersion: mcpProtocolVersion,
		Capabilities:    mcpCapabilities{},
		ClientInfo: mcpClientInfoReq{
			Name:    mcpClientName,
			Version: mcpClientVersion,
		},
	}

	var result mcpInitResult
	if err := m.sendJSONRPCRequest(ctx, "initialize", initReq, &result); err != nil {
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

func (m *MCPAdapter) nextRequestID() int64 {
	return atomic.AddInt64(&m.requestID, 1)
}

func mcpBuildEndpointURL(endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint + "/mcp"
	}
	return "http://" + endpoint + "/mcp"
}

func (m *MCPAdapter) sendJSONRPCRequest(ctx context.Context, method string, params interface{}, result interface{}) error {
	req := mcpJSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      m.nextRequestID(),
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return ErrMCPRequestFailed{Err: fmt.Errorf("failed to marshal request: %w", err)}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, mcpBuildEndpointURL(m.endpoint), bytes.NewReader(reqBody))
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

	var rpcResp mcpJSONRPCResponse
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

func (m *MCPAdapter) callTool(ctx context.Context, toolName string, args map[string]interface{}, result interface{}) error {
	toolReq := mcpCallToolReq{
		Name:      toolName,
		Arguments: args,
	}

	var rawResult json.RawMessage
	if err := m.sendJSONRPCRequest(ctx, "tools/call", toolReq, &rawResult); err != nil {
		return err
	}

	if result == nil || len(rawResult) == 0 {
		return nil
	}

	// Try MCP content-wrapped format first: {"content":[{"type":"text","text":"..."}],"isError":false}
	var toolResult mcpCallToolResult
	if err := json.Unmarshal(rawResult, &toolResult); err == nil && len(toolResult.Content) > 0 {
		if toolResult.IsError {
			var errMsg string
			for _, item := range toolResult.Content {
				if item.Type == "text" {
					errMsg = item.Text
					break
				}
			}
			return ErrMCPToolCallFailed{Tool: toolName, Code: mcpJSONRPCInternalError, Message: errMsg}
		}

		for _, item := range toolResult.Content {
			if item.Type == "text" && item.Text != "" {
				if err := json.Unmarshal([]byte(item.Text), result); err != nil {
					return ErrMCPResponseParseFailed{Operation: toolName, Err: err}
				}
				return nil
			}
		}
		return nil
	}

	// Server returned result directly as a raw map (not wrapped in content items).
	if err := json.Unmarshal(rawResult, result); err != nil {
		return ErrMCPResponseParseFailed{Operation: toolName, Err: err}
	}

	return nil
}

// =============================================================================
// Conversion Helpers
// =============================================================================

func mcpParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func mcpDeviceToGetResult(d *mcpPXEDeviceResponse) *GetDeviceResult {
	if d == nil {
		return nil
	}
	return &GetDeviceResult{
		ID:                d.ID,
		MACAddress:        d.MACAddress,
		PortID:            d.PortID,
		State:             d.State,
		StateReason:       d.StateReason,
		CertificateSerial: d.CertificateSerial,
		CurrentVLAN:       d.CurrentVLAN,
		TargetVLAN:        d.TargetVLAN,
		RetryCount:        d.RetryCount,
		CreatedAt:         mcpParseTime(d.CreatedAt),
		UpdatedAt:         mcpParseTime(d.UpdatedAt),
		StateChangedAt:    mcpParseTime(d.StateChangedAt),
	}
}

func mcpDeviceToRegisterResult(d *mcpPXEDeviceResponse) *RegisterDeviceResult {
	if d == nil {
		return nil
	}
	return &RegisterDeviceResult{
		ID:          d.ID,
		MACAddress:  d.MACAddress,
		PortID:      d.PortID,
		State:       d.State,
		StateReason: d.StateReason,
		CurrentVLAN: d.CurrentVLAN,
		CreatedAt:   mcpParseTime(d.CreatedAt),
	}
}

// =============================================================================
// Device Management Commands
// =============================================================================

// RegisterDevice registers a new device via MCP.
func (m *MCPAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	args := map[string]interface{}{
		"mac_address": opts.MACAddress,
		"port_id":     opts.PortID,
	}

	var resp mcpPXEDeviceResponse
	if err := m.callTool(ctx, mcpToolPXERegisterDevice, args, &resp); err != nil {
		return nil, err
	}

	return mcpDeviceToRegisterResult(&resp), nil
}

// GetDevice retrieves device information via MCP.
func (m *MCPAdapter) GetDevice(ctx context.Context, deviceID string) (*GetDeviceResult, error) {
	args := map[string]interface{}{
		"device_id": deviceID,
	}

	var resp mcpPXEDeviceResponse
	if err := m.callTool(ctx, mcpToolPXEGetDevice, args, &resp); err != nil {
		return nil, err
	}

	return mcpDeviceToGetResult(&resp), nil
}

// GetDeviceByMAC retrieves a device by MAC address via MCP.
func (m *MCPAdapter) GetDeviceByMAC(ctx context.Context, mac string) (*GetDeviceResult, error) {
	args := map[string]interface{}{
		"mac_address": mac,
	}

	var resp mcpPXEDeviceResponse
	if err := m.callTool(ctx, mcpToolPXEGetDeviceByMAC, args, &resp); err != nil {
		return nil, err
	}

	return mcpDeviceToGetResult(&resp), nil
}

// ListDevices lists devices via MCP.
func (m *MCPAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	args := map[string]interface{}{}

	if opts.State != "" {
		args["state"] = opts.State
	}
	if opts.MACAddress != "" {
		args["mac_address"] = opts.MACAddress
	}
	if opts.VLAN > 0 {
		args["vlan"] = int(opts.VLAN)
	}
	if opts.Limit > 0 {
		args["limit"] = int(opts.Limit)
	}
	if opts.Offset > 0 {
		args["offset"] = int(opts.Offset)
	}

	var resp mcpPXEListDevicesResponse
	if err := m.callTool(ctx, mcpToolPXEListDevices, args, &resp); err != nil {
		return nil, err
	}

	result := &ListDevicesResult{
		TotalCount: int32(resp.Count),
	}

	for _, d := range resp.Devices {
		result.Devices = append(result.Devices, DeviceSummary{
			ID:          d.ID,
			MACAddress:  d.MACAddress,
			PortID:      d.PortID,
			State:       d.State,
			CurrentVLAN: d.CurrentVLAN,
			CreatedAt:   mcpParseTime(d.CreatedAt),
			UpdatedAt:   mcpParseTime(d.UpdatedAt),
		})
	}

	return result, nil
}

// RemoveDevice removes a device via MCP.
func (m *MCPAdapter) RemoveDevice(ctx context.Context, deviceID string) (*RemoveDeviceResult, error) {
	args := map[string]interface{}{
		"device_id": deviceID,
	}

	var resp mcpPXERemoveResponse
	if err := m.callTool(ctx, mcpToolPXERemoveDevice, args, &resp); err != nil {
		return nil, err
	}

	return &RemoveDeviceResult{
		ID:      resp.DeviceID,
		Removed: resp.Success,
	}, nil
}

// =============================================================================
// State Management Commands
// =============================================================================

// UpdateDeviceState updates device state via MCP.
func (m *MCPAdapter) UpdateDeviceState(ctx context.Context, opts UpdateStateOptions) (*UpdateStateResult, error) {
	args := map[string]interface{}{
		"device_id": opts.DeviceID,
		"state":     opts.State,
	}
	if opts.Reason != "" {
		args["reason"] = opts.Reason
	}

	// The server returns the updated device info after state change.
	var resp mcpPXEDeviceResponse
	if err := m.callTool(ctx, mcpToolPXEUpdateState, args, &resp); err != nil {
		return nil, err
	}

	return &UpdateStateResult{
		ID:        resp.ID,
		ToState:   resp.State,
		Reason:    opts.Reason,
		UpdatedAt: mcpParseTime(resp.UpdatedAt),
	}, nil
}

// SetDeviceEnrolled sets a device as enrolled via MCP.
func (m *MCPAdapter) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) (*SetEnrolledResult, error) {
	args := map[string]interface{}{
		"device_id":          deviceID,
		"certificate_serial": certSerial,
	}

	var resp mcpPXEDeviceResponse
	if err := m.callTool(ctx, mcpToolPXESetDeviceEnrolled, args, &resp); err != nil {
		return nil, err
	}

	return &SetEnrolledResult{
		ID:                resp.ID,
		State:             resp.State,
		CertificateSerial: resp.CertificateSerial,
		UpdatedAt:         mcpParseTime(resp.UpdatedAt),
	}, nil
}

// AuthorizeDevice authorizes a device via MCP.
func (m *MCPAdapter) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) (*AuthorizeResult, error) {
	args := map[string]interface{}{
		"device_id":   deviceID,
		"target_vlan": int(targetVLAN),
	}

	var resp mcpPXEDeviceResponse
	if err := m.callTool(ctx, mcpToolPXEAuthorizeDevice, args, &resp); err != nil {
		return nil, err
	}

	return &AuthorizeResult{
		ID:         resp.ID,
		State:      resp.State,
		TargetVLAN: resp.TargetVLAN,
		UpdatedAt:  mcpParseTime(resp.UpdatedAt),
	}, nil
}

// QuarantineDevice quarantines a device via MCP.
func (m *MCPAdapter) QuarantineDevice(ctx context.Context, deviceID, reason string) (*QuarantineResult, error) {
	args := map[string]interface{}{
		"device_id": deviceID,
		"reason":    reason,
	}

	var resp mcpPXEDeviceResponse
	if err := m.callTool(ctx, mcpToolPXEQuarantineDevice, args, &resp); err != nil {
		return nil, err
	}

	return &QuarantineResult{
		ID:          resp.ID,
		State:       resp.State,
		Reason:      resp.StateReason,
		CurrentVLAN: resp.CurrentVLAN,
		UpdatedAt:   mcpParseTime(resp.UpdatedAt),
	}, nil
}

// RetryDevice retries a device via MCP.
func (m *MCPAdapter) RetryDevice(ctx context.Context, deviceID string) (*RetryResult, error) {
	args := map[string]interface{}{
		"device_id": deviceID,
	}

	var resp mcpPXEDeviceResponse
	if err := m.callTool(ctx, mcpToolPXERetryDevice, args, &resp); err != nil {
		return nil, err
	}

	return &RetryResult{
		ID:         resp.ID,
		State:      resp.State,
		RetryCount: resp.RetryCount,
		UpdatedAt:  mcpParseTime(resp.UpdatedAt),
	}, nil
}

// =============================================================================
// Event Commands
// =============================================================================

// GetEvents retrieves device events via MCP.
func (m *MCPAdapter) GetEvents(ctx context.Context, deviceID string) (*GetEventsResult, error) {
	args := map[string]interface{}{
		"device_id": deviceID,
	}

	var resp mcpPXEEventsResponse
	if err := m.callTool(ctx, mcpToolPXEGetDeviceEvents, args, &resp); err != nil {
		return nil, err
	}

	result := &GetEventsResult{
		DeviceID: resp.DeviceID,
	}

	for _, e := range resp.Events {
		result.Events = append(result.Events, ProvisioningEventInfo{
			ID:        e.ID,
			DeviceID:  e.DeviceID,
			EventType: e.EventType,
			FromState: e.FromState,
			ToState:   e.ToState,
			Details:   e.Details,
			Error:     e.Error,
			Timestamp: mcpParseTime(e.Timestamp),
		})
	}

	return result, nil
}

// =============================================================================
// Service Status Commands
// =============================================================================

// GetStatus retrieves service status via MCP.
func (m *MCPAdapter) GetStatus(ctx context.Context) (*GetStatusResult, error) {
	var resp mcpPXEStatusResponse
	if err := m.callTool(ctx, mcpToolPXEServiceStatus, nil, &resp); err != nil {
		return nil, err
	}

	return &GetStatusResult{
		Running:          resp.Running,
		DeviceCount:      resp.DeviceCount,
		StartTime:        mcpParseTime(resp.StartTime),
		IPXEServerAddr:   resp.IPXEServerAddr,
		QuarantineVLAN:   resp.QuarantineVLAN,
		ProvisioningVLAN: resp.ProvisioningVLAN,
	}, nil
}

// Ensure MCPAdapter implements PXECommands interface.
var _ PXECommands = (*MCPAdapter)(nil)
