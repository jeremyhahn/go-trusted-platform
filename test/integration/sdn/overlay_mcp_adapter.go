//go:build integration

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

package sdn

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"net/netip"
	"os"
	"sync/atomic"
	"time"
)

// =============================================================================
// MCP Overlay Constants
// =============================================================================

const (
	// DefaultMCPTimeoutOverlay is the default timeout for MCP operations.
	DefaultMCPTimeoutOverlay = 10 * time.Second

	// mcpOverlayProtocolVersion is the MCP protocol version for overlay adapter.
	mcpOverlayProtocolVersion = "2024-11-05"

	// mcpOverlayClientName is the MCP client name for overlay adapter.
	mcpOverlayClientName = "overlay-integration-test"

	// mcpOverlayClientVersion is the MCP client version for overlay adapter.
	mcpOverlayClientVersion = "1.0.0"

	// mcpOverlayJSONRPCInternalError is the JSON-RPC 2.0 internal error code.
	mcpOverlayJSONRPCInternalError = -32603
)

// =============================================================================
// Error Types
// =============================================================================

// ErrMCPOverlayConnectionFailed indicates an MCP connection failure.
type ErrMCPOverlayConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPOverlayConnectionFailed) Error() string {
	return fmt.Sprintf("MCP overlay connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrMCPOverlayConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrMCPOverlayInitializeFailed indicates MCP initialization failure.
type ErrMCPOverlayInitializeFailed struct {
	Err error
}

func (e ErrMCPOverlayInitializeFailed) Error() string {
	return fmt.Sprintf("MCP overlay initialization failed: %v", e.Err)
}

func (e ErrMCPOverlayInitializeFailed) Unwrap() error {
	return e.Err
}

// ErrMCPOverlayToolCallFailed indicates an MCP tool call failure.
type ErrMCPOverlayToolCallFailed struct {
	Tool    string
	Code    int
	Message string
}

func (e ErrMCPOverlayToolCallFailed) Error() string {
	return fmt.Sprintf("MCP overlay tool call %s failed (code %d): %s", e.Tool, e.Code, e.Message)
}

// ErrMCPOverlayResponseParseFailed indicates MCP response parsing failure.
type ErrMCPOverlayResponseParseFailed struct {
	Tool string
	Err  error
}

func (e ErrMCPOverlayResponseParseFailed) Error() string {
	return fmt.Sprintf("MCP overlay response parse failed for %s: %v", e.Tool, e.Err)
}

func (e ErrMCPOverlayResponseParseFailed) Unwrap() error {
	return e.Err
}

// ErrMCPOverlayClientClosed indicates the client is closed.
type ErrMCPOverlayClientClosed struct{}

func (e ErrMCPOverlayClientClosed) Error() string {
	return "MCP overlay client is closed"
}

// ErrMCPOverlayNotImplemented indicates a method is not yet implemented.
type ErrMCPOverlayNotImplemented struct {
	Method string
}

func (e ErrMCPOverlayNotImplemented) Error() string {
	return fmt.Sprintf("MCP overlay method %s not implemented", e.Method)
}

// ErrMCPOverlayInvalidResponse indicates an invalid response from MCP.
type ErrMCPOverlayInvalidResponse struct {
	Tool   string
	Reason string
}

func (e ErrMCPOverlayInvalidResponse) Error() string {
	return fmt.Sprintf("MCP overlay invalid response for %s: %s", e.Tool, e.Reason)
}

// ErrMCPOverlayTimeout indicates an MCP operation timeout.
type ErrMCPOverlayTimeout struct {
	Tool    string
	Timeout time.Duration
}

func (e ErrMCPOverlayTimeout) Error() string {
	return fmt.Sprintf("MCP overlay timeout for %s after %v", e.Tool, e.Timeout)
}

// ErrMCPOverlayRequestFailed indicates an MCP request failed.
type ErrMCPOverlayRequestFailed struct {
	Err error
}

func (e ErrMCPOverlayRequestFailed) Error() string {
	return fmt.Sprintf("MCP overlay request failed: %v", e.Err)
}

func (e ErrMCPOverlayRequestFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// MCP JSON-RPC Types
// =============================================================================

// mcpOverlayJSONRPCRequest represents a JSON-RPC 2.0 request.
type mcpOverlayJSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// mcpOverlayJSONRPCResponse represents a JSON-RPC 2.0 response.
type mcpOverlayJSONRPCResponse struct {
	JSONRPC string              `json:"jsonrpc"`
	Result  json.RawMessage     `json:"result,omitempty"`
	Error   *mcpOverlayRPCError `json:"error,omitempty"`
	ID      int64               `json:"id"`
}

// mcpOverlayRPCError represents a JSON-RPC 2.0 error.
type mcpOverlayRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// mcpOverlayInitializeRequest represents MCP initialize request params.
type mcpOverlayInitializeRequest struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    mcpOverlayCapabilities `json:"capabilities"`
	ClientInfo      mcpOverlayClientInfo   `json:"clientInfo"`
}

// mcpOverlayCapabilities represents MCP client capabilities.
type mcpOverlayCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

// mcpOverlayClientInfo represents MCP client information.
type mcpOverlayClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpOverlayInitializeResult represents the result of an MCP initialize request.
type mcpOverlayInitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      mcpOverlayServerInfo   `json:"serverInfo"`
}

// mcpOverlayServerInfo represents MCP server information.
type mcpOverlayServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpOverlayCallToolParams represents parameters for tools/call.
type mcpOverlayCallToolParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// mcpOverlayCallToolResult represents the result of tools/call.
type mcpOverlayCallToolResult struct {
	Content []mcpOverlayContent `json:"content"`
	IsError bool                `json:"isError,omitempty"`
}

// mcpOverlayContent represents content in an MCP response.
type mcpOverlayContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// =============================================================================
// Overlay MCP Adapter
// =============================================================================

// OverlayMCPAdapter implements OverlayCommands using the MCP protocol over HTTP transport.
// MCP (Model Context Protocol) is designed for AI/LLM integration.
type OverlayMCPAdapter struct {
	endpoint    string
	httpClient  *http.Client
	initialized bool
	requestID   int64
}

// NewOverlayMCPAdapter creates a new MCP adapter for overlay integration testing.
func NewOverlayMCPAdapter() *OverlayMCPAdapter {
	endpoint := os.Getenv(EnvPlatformMCPEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformMCPEndpoint
	}

	return &OverlayMCPAdapter{
		endpoint:   endpoint,
		httpClient: helpers.NewHTTPClient(DefaultMCPTimeoutOverlay),
	}
}

// Name returns the protocol adapter identifier.
func (m *OverlayMCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP connection and performs the initialize handshake.
func (m *OverlayMCPAdapter) Setup(ctx context.Context) error {
	initReq := mcpOverlayInitializeRequest{
		ProtocolVersion: mcpOverlayProtocolVersion,
		Capabilities:    mcpOverlayCapabilities{},
		ClientInfo: mcpOverlayClientInfo{
			Name:    mcpOverlayClientName,
			Version: mcpOverlayClientVersion,
		},
	}

	var result mcpOverlayInitializeResult
	if err := m.sendRequest(ctx, "initialize", initReq, &result); err != nil {
		return ErrMCPOverlayInitializeFailed{Err: err}
	}

	m.initialized = true
	return nil
}

// Teardown closes the MCP connection.
func (m *OverlayMCPAdapter) Teardown() error {
	if m.httpClient != nil {
		m.httpClient.CloseIdleConnections()
	}
	m.initialized = false
	return nil
}

// =============================================================================
// HTTP Transport Layer
// =============================================================================

// nextRequestID atomically increments and returns the next request ID.
func (m *OverlayMCPAdapter) nextRequestID() int64 {
	return atomic.AddInt64(&m.requestID, 1)
}

// sendRequest sends a JSON-RPC request over HTTP and unmarshals the result.
func (m *OverlayMCPAdapter) sendRequest(ctx context.Context, method string, params interface{}, result interface{}) error {
	req := mcpOverlayJSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      m.nextRequestID(),
	}

	reqBody, marshalErr := json.Marshal(req)
	if marshalErr != nil {
		return ErrMCPOverlayRequestFailed{Err: marshalErr}
	}

	httpReq, httpErr := http.NewRequestWithContext(ctx, http.MethodPost, helpers.MCPEndpointURL(m.endpoint), bytes.NewReader(reqBody))
	if httpErr != nil {
		return ErrMCPOverlayRequestFailed{Err: httpErr}
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, doErr := m.httpClient.Do(httpReq)
	if doErr != nil {
		return ErrMCPOverlayConnectionFailed{Endpoint: m.endpoint, Err: doErr}
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return ErrMCPOverlayRequestFailed{Err: readErr}
	}

	var rpcResp mcpOverlayJSONRPCResponse
	if unmarshalErr := json.Unmarshal(respBody, &rpcResp); unmarshalErr != nil {
		return ErrMCPOverlayResponseParseFailed{Tool: method, Err: unmarshalErr}
	}

	if rpcResp.Error != nil {
		return ErrMCPOverlayToolCallFailed{
			Tool:    method,
			Code:    rpcResp.Error.Code,
			Message: rpcResp.Error.Message,
		}
	}

	if result != nil && len(rpcResp.Result) > 0 {
		if unmarshalErr := json.Unmarshal(rpcResp.Result, result); unmarshalErr != nil {
			return ErrMCPOverlayResponseParseFailed{Tool: method, Err: unmarshalErr}
		}
	}

	return nil
}

// callTool calls an MCP tool over HTTP and unmarshals the result.
func (m *OverlayMCPAdapter) callTool(ctx context.Context, toolName string, args map[string]interface{}, result interface{}) error {
	toolReq := mcpOverlayCallToolParams{
		Name:      toolName,
		Arguments: args,
	}

	var rawResult json.RawMessage
	if err := m.sendRequest(ctx, "tools/call", toolReq, &rawResult); err != nil {
		return err
	}

	if result == nil || len(rawResult) == 0 {
		return nil
	}

	// Try MCP content-wrapped format first: {"content":[{"type":"text","text":"..."}],"isError":false}
	var toolResult mcpOverlayCallToolResult
	if unmarshalErr := json.Unmarshal(rawResult, &toolResult); unmarshalErr == nil && len(toolResult.Content) > 0 {
		if toolResult.IsError {
			var errMsg string
			for _, item := range toolResult.Content {
				if item.Type == "text" {
					errMsg = item.Text
					break
				}
			}
			return ErrMCPOverlayToolCallFailed{Tool: toolName, Code: mcpOverlayJSONRPCInternalError, Message: errMsg}
		}

		for _, item := range toolResult.Content {
			if item.Type == "text" && item.Text != "" {
				if parseErr := json.Unmarshal([]byte(item.Text), result); parseErr != nil {
					return ErrMCPOverlayResponseParseFailed{Tool: toolName, Err: parseErr}
				}
				return nil
			}
		}
		return nil
	}

	// Server returned result directly as a raw map (not wrapped in content items).
	if unmarshalErr := json.Unmarshal(rawResult, result); unmarshalErr != nil {
		return ErrMCPOverlayResponseParseFailed{Tool: toolName, Err: unmarshalErr}
	}

	return nil
}

// =============================================================================
// Overlay Status Commands
// =============================================================================

// OverlayStatus retrieves the overlay network status via MCP.
func (m *OverlayMCPAdapter) OverlayStatus(ctx context.Context) (*OverlayStatusResult, error) {
	const toolName = "overlay_status"

	var response struct {
		NodeID          string `json:"node_id"`
		VTEPIP          string `json:"vtep_ip"`
		ControllerState string `json:"controller_state"`
		UnderlayMTU     int    `json:"underlay_mtu"`
		VXLANPort       uint16 `json:"vxlan_port"`
		VNICount        int    `json:"vni_count"`
		VTEPCount       int    `json:"vtep_count"`
		RemoteMACCount  int    `json:"remote_mac_count"`
		TunnelCount     int    `json:"tunnel_count"`
		UptimeSeconds   int64  `json:"uptime_seconds"`
	}

	if err := m.callTool(ctx, toolName, nil, &response); err != nil {
		return nil, err
	}

	vtepIP, _ := netip.ParseAddr(response.VTEPIP)

	return &OverlayStatusResult{
		NodeID:          response.NodeID,
		VTEPIP:          vtepIP,
		ControllerState: response.ControllerState,
		UnderlayMTU:     response.UnderlayMTU,
		VXLANPort:       response.VXLANPort,
		VNICount:        response.VNICount,
		VTEPCount:       response.VTEPCount,
		RemoteMACCount:  response.RemoteMACCount,
		TunnelCount:     response.TunnelCount,
		Uptime:          time.Duration(response.UptimeSeconds) * time.Second,
	}, nil
}

// =============================================================================
// VTEP Commands
// =============================================================================

// VTEPList retrieves the list of VTEPs via MCP.
func (m *OverlayMCPAdapter) VTEPList(ctx context.Context) (*VTEPListResult, error) {
	const toolName = "overlay_vtep_list"

	var response struct {
		VTEPs []struct {
			NodeID     string `json:"node_id"`
			IP         string `json:"ip"`
			Healthy    bool   `json:"healthy"`
			LastSeen   string `json:"last_seen"`
			IsLocal    bool   `json:"is_local"`
			TunnelPort int    `json:"tunnel_port"`
		} `json:"vteps"`
	}

	if err := m.callTool(ctx, toolName, nil, &response); err != nil {
		return nil, err
	}

	vteps := make([]VTEPInfo, 0, len(response.VTEPs))
	for _, v := range response.VTEPs {
		ip, _ := netip.ParseAddr(v.IP)
		lastSeen, _ := time.Parse(time.RFC3339, v.LastSeen)
		vteps = append(vteps, VTEPInfo{
			NodeID:     v.NodeID,
			IP:         ip,
			Healthy:    v.Healthy,
			LastSeen:   lastSeen,
			IsLocal:    v.IsLocal,
			TunnelPort: v.TunnelPort,
		})
	}

	return &VTEPListResult{
		VTEPs:      vteps,
		TotalCount: len(vteps),
	}, nil
}

// VTEPGet retrieves details about a specific VTEP via MCP.
func (m *OverlayMCPAdapter) VTEPGet(ctx context.Context, nodeID string) (*VTEPGetResult, error) {
	const toolName = "overlay_vtep_get"

	args := map[string]interface{}{
		"node_id": nodeID,
	}

	var response struct {
		NodeID     string   `json:"node_id"`
		IP         string   `json:"ip"`
		Healthy    bool     `json:"healthy"`
		LastSeen   string   `json:"last_seen"`
		IsLocal    bool     `json:"is_local"`
		TunnelPort int      `json:"tunnel_port"`
		VNIs       []uint32 `json:"vnis"`
		MACCount   int      `json:"mac_count"`
		BytesSent  uint64   `json:"bytes_sent"`
		BytesRecv  uint64   `json:"bytes_recv"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	ip, _ := netip.ParseAddr(response.IP)
	lastSeen, _ := time.Parse(time.RFC3339, response.LastSeen)

	return &VTEPGetResult{
		VTEPInfo: VTEPInfo{
			NodeID:     response.NodeID,
			IP:         ip,
			Healthy:    response.Healthy,
			LastSeen:   lastSeen,
			IsLocal:    response.IsLocal,
			TunnelPort: response.TunnelPort,
		},
		VNIs:      response.VNIs,
		MACCount:  response.MACCount,
		BytesSent: response.BytesSent,
		BytesRecv: response.BytesRecv,
	}, nil
}

// =============================================================================
// VNI Commands
// =============================================================================

// VNICreate creates a new VNI via MCP.
func (m *OverlayMCPAdapter) VNICreate(ctx context.Context, opts VNICreateOptions) (*VNICreateResult, error) {
	const toolName = "overlay_vni_create"

	args := map[string]interface{}{
		"vni": opts.VNI,
	}
	if opts.VLAN > 0 {
		args["vlan"] = opts.VLAN
	}
	if opts.Name != "" {
		args["name"] = opts.Name
	}

	var response struct {
		VNI       uint32 `json:"vni"`
		VLAN      uint16 `json:"vlan"`
		Name      string `json:"name"`
		CreatedAt string `json:"created_at"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, response.CreatedAt)

	return &VNICreateResult{
		VNI:       response.VNI,
		VLAN:      response.VLAN,
		Name:      response.Name,
		CreatedAt: createdAt,
	}, nil
}

// VNIDelete deletes a VNI via MCP.
func (m *OverlayMCPAdapter) VNIDelete(ctx context.Context, vni uint32) (*VNIDeleteResult, error) {
	const toolName = "overlay_vni_delete"

	args := map[string]interface{}{
		"vni": vni,
	}

	var response struct {
		Success bool `json:"success"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	return &VNIDeleteResult{
		VNI:     vni,
		Deleted: response.Success,
	}, nil
}

// VNIList retrieves the list of VNIs via MCP.
func (m *OverlayMCPAdapter) VNIList(ctx context.Context) (*VNIListResult, error) {
	const toolName = "overlay_vni_list"

	var response struct {
		VNIs []struct {
			VNI        uint32 `json:"vni"`
			VLAN       uint16 `json:"vlan"`
			Name       string `json:"name"`
			MACCount   int    `json:"mac_count"`
			TunnelPort string `json:"tunnel_port"`
			CreatedAt  string `json:"created_at"`
		} `json:"vnis"`
	}

	if err := m.callTool(ctx, toolName, nil, &response); err != nil {
		return nil, err
	}

	vnis := make([]VNIInfo, 0, len(response.VNIs))
	for _, v := range response.VNIs {
		createdAt, _ := time.Parse(time.RFC3339, v.CreatedAt)
		vnis = append(vnis, VNIInfo{
			VNI:        v.VNI,
			VLAN:       v.VLAN,
			Name:       v.Name,
			MACCount:   v.MACCount,
			TunnelPort: v.TunnelPort,
			CreatedAt:  createdAt,
		})
	}

	return &VNIListResult{
		VNIs:       vnis,
		TotalCount: len(vnis),
	}, nil
}

// =============================================================================
// Tunnel Commands
// =============================================================================

// TunnelList retrieves the list of tunnels via MCP.
func (m *OverlayMCPAdapter) TunnelList(ctx context.Context, opts TunnelListOptions) (*TunnelListResult, error) {
	const toolName = "overlay_tunnel_list"

	args := make(map[string]interface{})
	if opts.VNI > 0 {
		args["vni"] = opts.VNI
	}

	var response struct {
		Tunnels []struct {
			LocalVTEP  string `json:"local_vtep"`
			RemoteVTEP string `json:"remote_vtep"`
			VNI        uint32 `json:"vni"`
			Port       string `json:"port"`
			State      string `json:"state"`
			BytesSent  uint64 `json:"bytes_sent"`
			BytesRecv  uint64 `json:"bytes_recv"`
		} `json:"tunnels"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	tunnels := make([]TunnelInfo, 0, len(response.Tunnels))
	for _, t := range response.Tunnels {
		localVTEP, _ := netip.ParseAddr(t.LocalVTEP)
		remoteVTEP, _ := netip.ParseAddr(t.RemoteVTEP)
		tunnels = append(tunnels, TunnelInfo{
			LocalVTEP:  localVTEP,
			RemoteVTEP: remoteVTEP,
			VNI:        t.VNI,
			Port:       t.Port,
			State:      t.State,
			BytesSent:  t.BytesSent,
			BytesRecv:  t.BytesRecv,
		})
	}

	return &TunnelListResult{
		Tunnels:    tunnels,
		TotalCount: len(tunnels),
	}, nil
}

// =============================================================================
// MAC Commands
// =============================================================================

// MACList retrieves the list of remote MACs via MCP.
func (m *OverlayMCPAdapter) MACList(ctx context.Context, opts MACListOptions) (*MACListResult, error) {
	const toolName = "overlay_mac_list"

	args := make(map[string]interface{})
	if opts.VNI > 0 {
		args["vni"] = opts.VNI
	}

	var response struct {
		MACs []struct {
			MAC        string `json:"mac"`
			IP         string `json:"ip"`
			VNI        uint32 `json:"vni"`
			RemoteVTEP string `json:"remote_vtep"`
			Source     string `json:"source"`
			LearnedAt  string `json:"learned_at"`
			ExpiresAt  string `json:"expires_at"`
		} `json:"macs"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	macs := make([]RemoteMACInfo, 0, len(response.MACs))
	for _, mac := range response.MACs {
		hwAddr, _ := net.ParseMAC(mac.MAC)
		ip, _ := netip.ParseAddr(mac.IP)
		remoteVTEP, _ := netip.ParseAddr(mac.RemoteVTEP)
		learnedAt, _ := time.Parse(time.RFC3339, mac.LearnedAt)
		expiresAt, _ := time.Parse(time.RFC3339, mac.ExpiresAt)
		macs = append(macs, RemoteMACInfo{
			MAC:        hwAddr,
			IP:         ip,
			VNI:        mac.VNI,
			RemoteVTEP: remoteVTEP,
			Source:     mac.Source,
			LearnedAt:  learnedAt,
			ExpiresAt:  expiresAt,
		})
	}

	return &MACListResult{
		MACs:       macs,
		TotalCount: len(macs),
	}, nil
}

// MACForget removes a learned MAC address via MCP.
func (m *OverlayMCPAdapter) MACForget(ctx context.Context, mac string, vni uint32) (*MACForgetResult, error) {
	const toolName = "overlay_mac_forget"

	args := map[string]interface{}{
		"mac": mac,
		"vni": vni,
	}

	var response struct {
		Success bool `json:"success"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	return &MACForgetResult{
		MAC:     mac,
		VNI:     vni,
		Deleted: response.Success,
	}, nil
}

// =============================================================================
// Gateway Commands
// =============================================================================

// GatewayStatus retrieves the gateway status via MCP.
func (m *OverlayMCPAdapter) GatewayStatus(ctx context.Context) (*GatewayStatusResult, error) {
	const toolName = "gateway_status"

	var response struct {
		NodeID         string   `json:"node_id"`
		Modes          []string `json:"modes"`
		Tier           string   `json:"tier"`
		Healthy        bool     `json:"healthy"`
		Reputation     float64  `json:"reputation"`
		AgeSeconds     int64    `json:"age_seconds"`
		UptimePct      float64  `json:"uptime_pct"`
		IPv6Pool       string   `json:"ipv6_pool"`
		IPv4Pool       string   `json:"ipv4_pool"`
		BGPEnabled     bool     `json:"bgp_enabled"`
		EVPNEnabled    bool     `json:"evpn_enabled"`
		TransitEnabled bool     `json:"transit_enabled"`
	}

	if err := m.callTool(ctx, toolName, nil, &response); err != nil {
		return nil, err
	}

	return &GatewayStatusResult{
		NodeID:         response.NodeID,
		Modes:          response.Modes,
		Tier:           response.Tier,
		Healthy:        response.Healthy,
		Reputation:     response.Reputation,
		Age:            time.Duration(response.AgeSeconds) * time.Second,
		UptimePct:      response.UptimePct,
		IPv6Pool:       response.IPv6Pool,
		IPv4Pool:       response.IPv4Pool,
		BGPEnabled:     response.BGPEnabled,
		EVPNEnabled:    response.EVPNEnabled,
		TransitEnabled: response.TransitEnabled,
	}, nil
}

// GatewaySetMode sets the gateway mode via MCP.
func (m *OverlayMCPAdapter) GatewaySetMode(ctx context.Context, opts GatewayModeOptions) (*GatewayModeResult, error) {
	const toolName = "gateway_mode_set"

	args := map[string]interface{}{
		"modes": opts.Modes,
	}

	var response struct {
		Modes   []string `json:"modes"`
		Success bool     `json:"success"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	return &GatewayModeResult{
		Modes:   response.Modes,
		Success: response.Success,
	}, nil
}

// =============================================================================
// BGP Commands
// =============================================================================

// BGPStatus retrieves the BGP status via MCP.
func (m *OverlayMCPAdapter) BGPStatus(ctx context.Context) (*BGPStatusResult, error) {
	const toolName = "gateway_bgp_status"

	var response struct {
		Enabled          bool   `json:"enabled"`
		ASN              uint32 `json:"asn"`
		RouterID         string `json:"router_id"`
		State            string `json:"state"`
		PeerCount        int    `json:"peer_count"`
		EstablishedCount int    `json:"established_count"`
		EVPNEnabled      bool   `json:"evpn_enabled"`
		TransitEnabled   bool   `json:"transit_enabled"`
	}

	if err := m.callTool(ctx, toolName, nil, &response); err != nil {
		return nil, err
	}

	return &BGPStatusResult{
		Enabled:          response.Enabled,
		ASN:              response.ASN,
		RouterID:         response.RouterID,
		State:            response.State,
		PeerCount:        response.PeerCount,
		EstablishedCount: response.EstablishedCount,
		EVPNEnabled:      response.EVPNEnabled,
		TransitEnabled:   response.TransitEnabled,
	}, nil
}

// BGPPeers retrieves the list of BGP peers via MCP.
func (m *OverlayMCPAdapter) BGPPeers(ctx context.Context) (*BGPPeersResult, error) {
	const toolName = "gateway_bgp_peers"

	var response struct {
		Peers []struct {
			Address       string `json:"address"`
			RemoteASN     uint32 `json:"remote_asn"`
			State         string `json:"state"`
			UptimeSeconds int64  `json:"uptime_seconds"`
			PrefixesRecv  int    `json:"prefixes_recv"`
			PrefixesSent  int    `json:"prefixes_sent"`
			Description   string `json:"description"`
		} `json:"peers"`
	}

	if err := m.callTool(ctx, toolName, nil, &response); err != nil {
		return nil, err
	}

	peers := make([]BGPPeerInfo, 0, len(response.Peers))
	for _, p := range response.Peers {
		peers = append(peers, BGPPeerInfo{
			Address:      p.Address,
			RemoteASN:    p.RemoteASN,
			State:        p.State,
			Uptime:       time.Duration(p.UptimeSeconds) * time.Second,
			PrefixesRecv: p.PrefixesRecv,
			PrefixesSent: p.PrefixesSent,
			Description:  p.Description,
		})
	}

	return &BGPPeersResult{
		Peers:      peers,
		TotalCount: len(peers),
	}, nil
}

// BGPPrefixes retrieves the list of announced prefixes via MCP.
func (m *OverlayMCPAdapter) BGPPrefixes(ctx context.Context) (*BGPPrefixesResult, error) {
	const toolName = "gateway_bgp_prefixes"

	var response struct {
		Prefixes []struct {
			Prefix      string   `json:"prefix"`
			NextHop     string   `json:"next_hop"`
			Origin      string   `json:"origin"`
			ASPath      string   `json:"as_path"`
			LocalPref   uint32   `json:"local_pref"`
			MED         uint32   `json:"med"`
			Communities []string `json:"communities"`
		} `json:"prefixes"`
	}

	if err := m.callTool(ctx, toolName, nil, &response); err != nil {
		return nil, err
	}

	prefixes := make([]BGPPrefixInfo, 0, len(response.Prefixes))
	for _, p := range response.Prefixes {
		prefixes = append(prefixes, BGPPrefixInfo{
			Prefix:      p.Prefix,
			NextHop:     p.NextHop,
			Origin:      p.Origin,
			ASPath:      p.ASPath,
			LocalPref:   p.LocalPref,
			MED:         p.MED,
			Communities: p.Communities,
		})
	}

	return &BGPPrefixesResult{
		Prefixes:   prefixes,
		TotalCount: len(prefixes),
	}, nil
}

// BGPAnnounce announces a prefix via MCP.
func (m *OverlayMCPAdapter) BGPAnnounce(ctx context.Context, opts BGPAnnounceOptions) (*BGPAnnounceResult, error) {
	const toolName = "gateway_bgp_announce"

	args := map[string]interface{}{
		"prefix": opts.Prefix,
	}
	if opts.NextHop != "" {
		args["next_hop"] = opts.NextHop
	}

	var response struct {
		Success bool `json:"success"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	return &BGPAnnounceResult{
		Prefix:  opts.Prefix,
		Success: response.Success,
	}, nil
}

// BGPWithdraw withdraws a prefix via MCP.
func (m *OverlayMCPAdapter) BGPWithdraw(ctx context.Context, prefix string) (*BGPWithdrawResult, error) {
	const toolName = "gateway_bgp_withdraw"

	args := map[string]interface{}{
		"prefix": prefix,
	}

	var response struct {
		Success bool `json:"success"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	return &BGPWithdrawResult{
		Prefix:  prefix,
		Success: response.Success,
	}, nil
}

// =============================================================================
// IPAM Commands
// =============================================================================

// IPAMPoolList retrieves the list of IPAM pools via MCP.
func (m *OverlayMCPAdapter) IPAMPoolList(ctx context.Context) (*IPAMPoolListResult, error) {
	const toolName = "gateway_ipam_pools"

	var response struct {
		Pools []struct {
			ID                   string   `json:"id"`
			Name                 string   `json:"name"`
			CIDR                 string   `json:"cidr"`
			Gateway              string   `json:"gateway"`
			TotalIPs             int64    `json:"total_ips"`
			AllocatedIPs         int64    `json:"allocated_ips"`
			AvailableIPs         int64    `json:"available_ips"`
			UtilizationPct       float64  `json:"utilization_pct"`
			DNS                  []string `json:"dns"`
			LeaseDurationSeconds int64    `json:"lease_duration_seconds"`
		} `json:"pools"`
	}

	if err := m.callTool(ctx, toolName, nil, &response); err != nil {
		return nil, err
	}

	pools := make([]IPAMPoolInfo, 0, len(response.Pools))
	for _, p := range response.Pools {
		pools = append(pools, IPAMPoolInfo{
			ID:             p.ID,
			Name:           p.Name,
			CIDR:           p.CIDR,
			Gateway:        p.Gateway,
			TotalIPs:       p.TotalIPs,
			AllocatedIPs:   p.AllocatedIPs,
			AvailableIPs:   p.AvailableIPs,
			UtilizationPct: p.UtilizationPct,
			DNS:            p.DNS,
			LeaseDuration:  time.Duration(p.LeaseDurationSeconds) * time.Second,
		})
	}

	return &IPAMPoolListResult{
		Pools:      pools,
		TotalCount: len(pools),
	}, nil
}

// IPAMPoolCreate creates a new IPAM pool via MCP.
func (m *OverlayMCPAdapter) IPAMPoolCreate(ctx context.Context, opts IPAMPoolCreateOptions) (*IPAMPoolCreateResult, error) {
	const toolName = "gateway_ipam_pool_create"

	args := map[string]interface{}{
		"name": opts.Name,
		"cidr": opts.CIDR,
	}
	if opts.Gateway != "" {
		args["gateway"] = opts.Gateway
	}
	if len(opts.DNS) > 0 {
		args["dns"] = opts.DNS
	}
	if opts.LeaseDuration > 0 {
		args["lease_duration_seconds"] = int64(opts.LeaseDuration.Seconds())
	}

	var response struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CIDR      string `json:"cidr"`
		CreatedAt string `json:"created_at"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, response.CreatedAt)

	return &IPAMPoolCreateResult{
		ID:        response.ID,
		Name:      response.Name,
		CIDR:      response.CIDR,
		CreatedAt: createdAt,
	}, nil
}

// IPAMPoolDelete deletes an IPAM pool via MCP.
func (m *OverlayMCPAdapter) IPAMPoolDelete(ctx context.Context, poolID string) (*IPAMPoolDeleteResult, error) {
	const toolName = "gateway_ipam_pool_delete"

	args := map[string]interface{}{
		"pool_id": poolID,
	}

	var response struct {
		Success bool `json:"success"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	return &IPAMPoolDeleteResult{
		ID:      poolID,
		Deleted: response.Success,
	}, nil
}

// IPAMAllocate allocates an IP from a pool via MCP.
func (m *OverlayMCPAdapter) IPAMAllocate(ctx context.Context, opts IPAMAllocateOptions) (*IPAMAllocateResult, error) {
	const toolName = "gateway_ipam_allocate"

	args := map[string]interface{}{
		"pool_id":   opts.PoolID,
		"device_id": opts.DeviceID,
	}
	if opts.Hostname != "" {
		args["hostname"] = opts.Hostname
	}

	var response struct {
		IP          string `json:"ip"`
		PoolID      string `json:"pool_id"`
		DeviceID    string `json:"device_id"`
		Hostname    string `json:"hostname"`
		LeaseExpiry string `json:"lease_expiry"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	ip, _ := netip.ParseAddr(response.IP)
	leaseExpiry, _ := time.Parse(time.RFC3339, response.LeaseExpiry)

	return &IPAMAllocateResult{
		IP:          ip,
		PoolID:      response.PoolID,
		DeviceID:    response.DeviceID,
		Hostname:    response.Hostname,
		LeaseExpiry: leaseExpiry,
	}, nil
}

// IPAMRelease releases an allocated IP via MCP.
func (m *OverlayMCPAdapter) IPAMRelease(ctx context.Context, ip string) (*IPAMReleaseResult, error) {
	const toolName = "gateway_ipam_release"

	args := map[string]interface{}{
		"ip": ip,
	}

	var response struct {
		Success bool `json:"success"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	return &IPAMReleaseResult{
		IP:       ip,
		Released: response.Success,
	}, nil
}

// IPAMList retrieves the list of IPAM allocations via MCP.
func (m *OverlayMCPAdapter) IPAMList(ctx context.Context, opts IPAMListOptions) (*IPAMListResult, error) {
	const toolName = "gateway_ipam_allocations"

	args := make(map[string]interface{})
	if opts.PoolID != "" {
		args["pool_id"] = opts.PoolID
	}

	var response struct {
		Allocations []struct {
			IP          string `json:"ip"`
			PoolID      string `json:"pool_id"`
			DeviceID    string `json:"device_id"`
			Hostname    string `json:"hostname"`
			Status      string `json:"status"`
			AllocatedAt string `json:"allocated_at"`
			LeaseExpiry string `json:"lease_expiry"`
			LastSeen    string `json:"last_seen"`
		} `json:"allocations"`
	}

	if err := m.callTool(ctx, toolName, args, &response); err != nil {
		return nil, err
	}

	allocations := make([]IPAMAllocationInfo, 0, len(response.Allocations))
	for _, a := range response.Allocations {
		ip, _ := netip.ParseAddr(a.IP)
		allocatedAt, _ := time.Parse(time.RFC3339, a.AllocatedAt)
		leaseExpiry, _ := time.Parse(time.RFC3339, a.LeaseExpiry)
		lastSeen, _ := time.Parse(time.RFC3339, a.LastSeen)
		allocations = append(allocations, IPAMAllocationInfo{
			IP:          ip,
			PoolID:      a.PoolID,
			DeviceID:    a.DeviceID,
			Hostname:    a.Hostname,
			Status:      a.Status,
			AllocatedAt: allocatedAt,
			LeaseExpiry: leaseExpiry,
			LastSeen:    lastSeen,
		})
	}

	return &IPAMListResult{
		Allocations: allocations,
		TotalCount:  len(allocations),
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure OverlayMCPAdapter implements OverlayCommands interface.
var _ OverlayCommands = (*OverlayMCPAdapter)(nil)
