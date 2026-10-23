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

// Package daemon provides integration test adapters for daemon services.
// This file implements the DaemonCommands interface using the MCP (Model Context Protocol).

//go:build integration

package daemon

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

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// MCP Constants
// =============================================================================

const (
	// DefaultMCPTimeout is the default timeout for MCP requests.
	DefaultMCPTimeout = 30 * time.Second

	// MCPProtocolVersion is the MCP protocol version supported by this client.
	MCPProtocolVersion = "2024-11-05"

	// MCPClientName is the name of this MCP client.
	MCPClientName = "daemon-integration-test"

	// MCPClientVersion is the version of this MCP client.
	MCPClientVersion = "1.0.0"

	// jsonRPCInternalError is the JSON-RPC 2.0 internal error code.
	jsonRPCInternalError = -32603
)

// =============================================================================
// JSON-RPC 2.0 Types
// =============================================================================

type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// =============================================================================
// MCP Protocol Types
// =============================================================================

type mcpInitializeRequest struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    mcpCapabilities `json:"capabilities"`
	ClientInfo      mcpClientInfo   `json:"clientInfo"`
}

type mcpCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

type mcpClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpInitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      mcpServerInfo          `json:"serverInfo"`
}

type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpCallToolRequest struct {
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
// MCP Adapter Implementation
// =============================================================================

// MCPAdapter implements DaemonCommands using the MCP (Model Context Protocol).
type MCPAdapter struct {
	endpoint    string
	httpClient  *http.Client
	initialized bool
	requestID   int64
}

// NewMCPAdapter creates a new MCP adapter for integration testing.
// The MCP server serves TLS 1.3 only (#844), so the adapter uses the mTLS
// HTTPS client shared with the other transports.
func NewMCPAdapter() *MCPAdapter {
	endpoint := os.Getenv(EnvPlatformMCPEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformMCPEndpoint
	}

	return &MCPAdapter{
		endpoint:   endpoint,
		httpClient: helpers.NewHTTPClient(DefaultMCPTimeout),
	}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP connection and performs the initialize handshake.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	initReq := mcpInitializeRequest{
		ProtocolVersion: MCPProtocolVersion,
		Capabilities:    mcpCapabilities{},
		ClientInfo: mcpClientInfo{
			Name:    MCPClientName,
			Version: MCPClientVersion,
		},
	}

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

func (m *MCPAdapter) nextRequestID() int64 {
	return atomic.AddInt64(&m.requestID, 1)
}

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

func (m *MCPAdapter) callTool(ctx context.Context, toolName string, args map[string]interface{}, result interface{}) error {
	toolReq := mcpCallToolRequest{
		Name:      toolName,
		Arguments: args,
	}

	// Get the raw JSON result so we can handle both MCP content-wrapped
	// and raw map response formats.
	var rawResult json.RawMessage
	if err := m.sendRequest(ctx, "tools/call", toolReq, &rawResult); err != nil {
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
			return ErrMCPToolCallFailed{Tool: toolName, Code: jsonRPCInternalError, Message: errMsg}
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
// Health Operations
// =============================================================================

// Health retrieves health status via MCP tool call.
func (m *MCPAdapter) Health(ctx context.Context) (*HealthResult, error) {
	// platform_health is unauthenticated, so it answers the status only: a
	// GetHealthResponse with no components, in protojson.
	var raw json.RawMessage
	if err := m.callTool(ctx, "platform_health", nil, &raw); err != nil {
		return nil, err
	}

	var resp pb.GetHealthResponse
	if err := protojson.Unmarshal(raw, &resp); err != nil {
		return nil, ErrMCPResponseParseFailed{Operation: "platform_health", Err: err}
	}
	return healthResultFromProto(&resp), nil
}

// =============================================================================
// Status Operations
// =============================================================================

// Status retrieves daemon status via MCP tool call.
func (m *MCPAdapter) Status(ctx context.Context) (*StatusResult, error) {
	var resp mcpStatusResponse
	if err := m.callTool(ctx, "platform_daemon_status", nil, &resp); err != nil {
		return nil, err
	}

	return &StatusResult{
		Status:    resp.Status,
		Version:   resp.Version,
		BuildTime: resp.BuildTime,
		GitCommit: resp.GitCommit,
		GoVersion: resp.GoVersion,
		System: SystemInfo{
			OS:                resp.System.OS,
			Arch:              resp.System.Arch,
			NumCPUs:           resp.System.NumCPUs,
			TotalMemoryMB:     resp.System.TotalMemoryMB,
			AvailableMemoryMB: resp.System.AvailableMemoryMB,
			Uptime:            resp.System.Uptime,
		},
		Timestamp: mcpUnixMillisToTime(resp.Timestamp),
	}, nil
}

// =============================================================================
// Version Operations
// =============================================================================

// Version retrieves version information via MCP tool call.
func (m *MCPAdapter) Version(ctx context.Context) (*VersionResult, error) {
	var resp mcpVersionResponse
	if err := m.callTool(ctx, "platform_daemon_version", nil, &resp); err != nil {
		return nil, err
	}

	return &VersionResult{
		Version:   resp.Version,
		BuildTime: resp.BuildTime,
		GitCommit: resp.GitCommit,
		GoVersion: resp.GoVersion,
	}, nil
}

// =============================================================================
// Service Operations
// =============================================================================

// ListServices lists all services via MCP tool call.
func (m *MCPAdapter) ListServices(ctx context.Context) (*ListServicesResult, error) {
	var resp mcpListServicesResponse
	if err := m.callTool(ctx, "platform_daemon_list_services", nil, &resp); err != nil {
		return nil, err
	}

	result := &ListServicesResult{
		Count:     resp.Count,
		Timestamp: mcpUnixMillisToTime(resp.Timestamp),
	}

	for _, s := range resp.Services {
		info := ServiceInfoResult{
			Name:       s.Name,
			Status:     s.Status,
			Uptime:     s.Uptime,
			StartCount: s.StartCount,
			StopCount:  s.StopCount,
			LastError:  s.LastError,
		}
		if s.StartedAt > 0 {
			info.StartedAt = mcpUnixMillisToTime(s.StartedAt)
		}
		result.Services = append(result.Services, info)
	}

	return result, nil
}

// GetService retrieves a single service's information via MCP tool call.
func (m *MCPAdapter) GetService(ctx context.Context, serviceName string) (*ServiceInfoResult, error) {
	args := map[string]interface{}{
		"name": serviceName,
	}

	var resp mcpServiceInfoResponse
	if err := m.callTool(ctx, "platform_daemon_get_service", args, &resp); err != nil {
		return nil, err
	}

	result := &ServiceInfoResult{
		Name:       resp.Name,
		Status:     resp.Status,
		Uptime:     resp.Uptime,
		StartCount: resp.StartCount,
		StopCount:  resp.StopCount,
		LastError:  resp.LastError,
	}

	if resp.StartedAt > 0 {
		result.StartedAt = mcpUnixMillisToTime(resp.StartedAt)
	}

	return result, nil
}

// StartService starts a service via MCP tool call.
func (m *MCPAdapter) StartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	args := map[string]interface{}{
		"name": serviceName,
	}

	var resp mcpServiceActionResponse
	if err := m.callTool(ctx, "platform_daemon_start_service", args, &resp); err != nil {
		return nil, err
	}

	return &ServiceActionResult{
		Service: resp.Service,
		Action:  resp.Action,
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// StopService stops a service via MCP tool call.
func (m *MCPAdapter) StopService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	args := map[string]interface{}{
		"name": serviceName,
	}

	var resp mcpServiceActionResponse
	if err := m.callTool(ctx, "platform_daemon_stop_service", args, &resp); err != nil {
		return nil, err
	}

	return &ServiceActionResult{
		Service: resp.Service,
		Action:  resp.Action,
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// RestartService restarts a service via MCP tool call.
func (m *MCPAdapter) RestartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	args := map[string]interface{}{
		"name": serviceName,
	}

	var resp mcpServiceActionResponse
	if err := m.callTool(ctx, "platform_daemon_restart_service", args, &resp); err != nil {
		return nil, err
	}

	return &ServiceActionResult{
		Service: resp.Service,
		Action:  resp.Action,
		Success: resp.Success,
		Message: resp.Message,
	}, nil
}

// =============================================================================
// Protocol Operations
// =============================================================================

// ListProtocols lists all protocols via MCP tool call.
func (m *MCPAdapter) ListProtocols(ctx context.Context) (*ListProtocolsResult, error) {
	var resp mcpListProtocolsResponse
	if err := m.callTool(ctx, "platform_daemon_list_protocols", nil, &resp); err != nil {
		return nil, err
	}

	result := &ListProtocolsResult{
		Timestamp: mcpUnixMillisToTime(resp.Timestamp),
	}

	for _, p := range resp.Protocols {
		result.Protocols = append(result.Protocols, ProtocolInfo{
			Name:    p.Name,
			Enabled: p.Enabled,
			Address: p.Address,
			Port:    p.Port,
			Status:  p.Status,
			TLS:     p.TLS,
		})
	}

	return result, nil
}

// =============================================================================
// MCP Response Types
// =============================================================================

type mcpStatusResponse struct {
	Status    string               `json:"status"`
	Version   string               `json:"version"`
	BuildTime string               `json:"buildTime"`
	GitCommit string               `json:"gitCommit"`
	GoVersion string               `json:"goVersion"`
	System    mcpSystemInfoReponse `json:"system"`
	Timestamp int64                `json:"timestamp"`
}

type mcpSystemInfoReponse struct {
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	NumCPUs           int    `json:"numCpus"`
	TotalMemoryMB     uint64 `json:"totalMemoryMb"`
	AvailableMemoryMB uint64 `json:"availableMemoryMb"`
	Uptime            string `json:"uptime"`
}

type mcpVersionResponse struct {
	Version   string `json:"version"`
	BuildTime string `json:"buildTime"`
	GitCommit string `json:"gitCommit"`
	GoVersion string `json:"goVersion"`
}

type mcpListServicesResponse struct {
	Services  []mcpServiceInfoResponse `json:"services"`
	Count     int                      `json:"count"`
	Timestamp int64                    `json:"timestamp"`
}

type mcpServiceInfoResponse struct {
	Name       string `json:"name"`
	Status     string `json:"status"`
	StartedAt  int64  `json:"startedAt,omitempty"`
	Uptime     string `json:"uptime,omitempty"`
	StartCount uint64 `json:"startCount"`
	StopCount  uint64 `json:"stopCount"`
	LastError  string `json:"lastError,omitempty"`
}

type mcpServiceActionResponse struct {
	Service string `json:"service"`
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Message string `json:"message"`
}

type mcpListProtocolsResponse struct {
	Protocols []mcpProtocolInfoResponse `json:"protocols"`
	Timestamp int64                     `json:"timestamp"`
}

type mcpProtocolInfoResponse struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	Status  string `json:"status"`
	TLS     bool   `json:"tls"`
}

// =============================================================================
// Helper Functions
// =============================================================================

func mcpUnixMillisToTime(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.Unix(ms/1000, (ms%1000)*int64(time.Millisecond))
}

// Ensure MCPAdapter implements DaemonCommands interface.
var _ DaemonCommands = (*MCPAdapter)(nil)
