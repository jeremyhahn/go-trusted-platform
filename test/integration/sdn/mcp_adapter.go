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
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/encoding/protojson"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// MCP Constants
// =============================================================================

const (
	// DefaultMCPTimeoutSDN is the default timeout for MCP operations.
	DefaultMCPTimeoutSDN = 10 * time.Second

	// mcpSDNProtocolVersion is the MCP protocol version for SDN adapter.
	mcpSDNProtocolVersion = "2024-11-05"

	// mcpSDNClientName is the MCP client name for SDN adapter.
	mcpSDNClientName = "sdn-integration-test"

	// mcpSDNClientVersion is the MCP client version for SDN adapter.
	mcpSDNClientVersion = "1.0.0"

	// mcpSDNJSONRPCInternalError is the JSON-RPC 2.0 internal error code.
	mcpSDNJSONRPCInternalError = -32603
)

// =============================================================================
// Error Types
// =============================================================================

// ErrMCPSDNConnectionFailed indicates an MCP connection failure.
type ErrMCPSDNConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPSDNConnectionFailed) Error() string {
	return fmt.Sprintf("MCP connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrMCPSDNConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrMCPSDNInitializeFailed indicates MCP initialization failure.
type ErrMCPSDNInitializeFailed struct {
	Err error
}

func (e ErrMCPSDNInitializeFailed) Error() string {
	return fmt.Sprintf("MCP initialization failed: %v", e.Err)
}

func (e ErrMCPSDNInitializeFailed) Unwrap() error {
	return e.Err
}

// ErrMCPSDNToolCallFailed indicates an MCP tool call failure.
type ErrMCPSDNToolCallFailed struct {
	Tool    string
	Code    int
	Message string
}

func (e ErrMCPSDNToolCallFailed) Error() string {
	return fmt.Sprintf("MCP tool call %s failed (code %d): %s", e.Tool, e.Code, e.Message)
}

// ErrMCPSDNResponseParseFailed indicates MCP response parsing failure.
type ErrMCPSDNResponseParseFailed struct {
	Tool string
	Err  error
}

func (e ErrMCPSDNResponseParseFailed) Error() string {
	return fmt.Sprintf("MCP response parse failed for %s: %v", e.Tool, e.Err)
}

func (e ErrMCPSDNResponseParseFailed) Unwrap() error {
	return e.Err
}

// ErrMCPSDNClientClosed indicates the client is closed.
type ErrMCPSDNClientClosed struct{}

func (e ErrMCPSDNClientClosed) Error() string {
	return "MCP client is closed"
}

// ErrMCPSDNRequestFailed indicates an MCP request failed.
type ErrMCPSDNRequestFailed struct {
	Err error
}

func (e ErrMCPSDNRequestFailed) Error() string {
	return fmt.Sprintf("MCP request failed: %v", e.Err)
}

func (e ErrMCPSDNRequestFailed) Unwrap() error {
	return e.Err
}

// ErrMCPSDNBridgeNotFound indicates a bridge was not found via MCP.
type ErrMCPSDNBridgeNotFound struct {
	BridgeID string
}

func (e ErrMCPSDNBridgeNotFound) Error() string {
	return fmt.Sprintf("MCP bridge not found: %s", e.BridgeID)
}

// ErrMCPSDNNoFlowReturned is returned when sdn_add_flow answers without the
// flow it added.
type ErrMCPSDNNoFlowReturned struct {
	BridgeID string
}

func (e ErrMCPSDNNoFlowReturned) Error() string {
	return fmt.Sprintf("MCP sdn_add_flow on bridge %s answered no flow", e.BridgeID)
}

// =============================================================================
// MCP JSON-RPC Types
// =============================================================================

// mcpSDNJSONRPCRequest represents a JSON-RPC 2.0 request.
type mcpSDNJSONRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// mcpSDNJSONRPCResponse represents a JSON-RPC 2.0 response.
type mcpSDNJSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *mcpSDNRPCError `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

// mcpSDNRPCError represents a JSON-RPC 2.0 error.
type mcpSDNRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// mcpSDNInitializeRequest represents an MCP initialize request params.
type mcpSDNInitializeRequest struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    mcpSDNCapabilities `json:"capabilities"`
	ClientInfo      mcpSDNClientInfo   `json:"clientInfo"`
}

// mcpSDNCapabilities represents MCP client capabilities.
type mcpSDNCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

// mcpSDNClientInfo represents MCP client information.
type mcpSDNClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpSDNInitializeResult represents the result of an MCP initialize request.
type mcpSDNInitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      mcpSDNServerInfo       `json:"serverInfo"`
}

// mcpSDNServerInfo represents MCP server information.
type mcpSDNServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpSDNCallToolRequest represents parameters for tools/call.
type mcpSDNCallToolRequest struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// =============================================================================
// MCP SDN Response Types
// =============================================================================

// mcpSDNSuccessResponse represents a simple success response from MCP tools.
type mcpSDNSuccessResponse struct {
	Success bool `json:"success"`
}

// mcpSDNBridgeListResponse represents the response from sdn_list_bridges.
// The server returns protobuf Bridge objects serialized as JSON.
type mcpSDNBridgeListResponse struct {
	Bridges []mcpSDNBridgeInfo `json:"bridges"`
}

// mcpSDNBridgeConfig matches protobuf BridgeConfig JSON.
type mcpSDNBridgeConfig struct {
	Name       string            `json:"name"`
	Type       interface{}       `json:"type"`
	DatapathID string            `json:"datapath_id"`
	STPEnabled bool              `json:"stp_enabled"`
	MTU        uint32            `json:"mtu"`
	Options    map[string]string `json:"options"`
	Labels     map[string]string `json:"labels"`
}

// mcpSDNBridgeStats matches protobuf BridgeStats JSON.
type mcpSDNBridgeStats struct {
	TotalPorts int32 `json:"total_ports"`
	TotalFlows int32 `json:"total_flows"`
}

// mcpSDNBridgeInfo matches protobuf Bridge JSON output.
type mcpSDNBridgeInfo struct {
	ID        string              `json:"id"`
	Config    *mcpSDNBridgeConfig `json:"config"`
	Status    interface{}         `json:"status"`
	CreatedAt interface{}         `json:"created_at"`
	UpdatedAt interface{}         `json:"updated_at"`
	Ports     []mcpSDNPortWire    `json:"ports"`
	Stats     *mcpSDNBridgeStats  `json:"stats"`
}

// mcpSDNPortConfig matches protobuf PortConfig JSON.
type mcpSDNPortConfig struct {
	Name       string      `json:"name"`
	Type       interface{} `json:"type"`
	VLAN       uint32      `json:"vlan"`
	MacAddress string      `json:"mac_address"`
	MTU        uint32      `json:"mtu"`
}

// mcpSDNPortWire matches protobuf Port JSON output.
type mcpSDNPortWire struct {
	ID       string               `json:"id"`
	BridgeID string               `json:"bridge_id"`
	Config   *mcpSDNPortConfig    `json:"config"`
	Status   interface{}          `json:"status"`
	Stats    *mcpSDNPortStatsWire `json:"stats"`
}

// mcpSDNPortStatsWire matches protobuf PortStats JSON output.
type mcpSDNPortStatsWire struct {
	PacketsReceived uint64 `json:"packets_received"`
	PacketsSent     uint64 `json:"packets_sent"`
	BytesReceived   uint64 `json:"bytes_received"`
	BytesSent       uint64 `json:"bytes_sent"`
	Errors          uint64 `json:"errors"`
	Dropped         uint64 `json:"dropped"`
}

// mcpSDNBridgeInfoName returns the bridge name from a bridge info struct.
func mcpSDNBridgeInfoName(b mcpSDNBridgeInfo) string {
	if b.Config != nil {
		return b.Config.Name
	}
	return ""
}

// mcpSDNBridgeInfoMTU returns the MTU from a bridge info struct.
func mcpSDNBridgeInfoMTU(b mcpSDNBridgeInfo) int32 {
	if b.Config != nil {
		return int32(b.Config.MTU)
	}
	return 0
}

// mcpSDNBridgeInfoDatapathID returns the datapath ID from a bridge info struct.
func mcpSDNBridgeInfoDatapathID(b mcpSDNBridgeInfo) string {
	if b.Config != nil {
		return b.Config.DatapathID
	}
	return ""
}

// mcpSDNBridgeInfoSTP returns the STP setting from a bridge info struct.
func mcpSDNBridgeInfoSTP(b mcpSDNBridgeInfo) bool {
	if b.Config != nil {
		return b.Config.STPEnabled
	}
	return false
}

// mcpSDNBridgeInfoLabels returns the labels from a bridge info struct.
func mcpSDNBridgeInfoLabels(b mcpSDNBridgeInfo) map[string]string {
	if b.Config != nil {
		return b.Config.Labels
	}
	return nil
}

// mcpSDNBridgeInfoPortCount returns the port count from bridge stats or ports.
func mcpSDNBridgeInfoPortCount(b mcpSDNBridgeInfo) int32 {
	if b.Stats != nil {
		return b.Stats.TotalPorts
	}
	return int32(len(b.Ports))
}

// mcpSDNBridgeInfoFlowCount returns the flow count from bridge stats.
func mcpSDNBridgeInfoFlowCount(b mcpSDNBridgeInfo) int32 {
	if b.Stats != nil {
		return b.Stats.TotalFlows
	}
	return 0
}

// mcpSDNPortStatusToAdminState converts a protobuf PortStatus value to a string.
func mcpSDNPortStatusToAdminState(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	case float64:
		switch int(s) {
		case 0:
			return "unknown"
		case 1:
			return "up"
		case 2:
			return "down"
		case 3:
			return "blocked"
		case 4:
			return "learning"
		case 5:
			return "forwarding"
		}
	}
	return "unknown"
}

// mcpSDNPortStateResponse matches protobuf Port JSON for sdn_get_port_state.
// The server returns the full Port protobuf object.
type mcpSDNPortStateResponse = mcpSDNPortWire

// mcpSDNPortStatsResponse matches protobuf PortStats JSON for sdn_get_port_stats.
// The server returns only the PortStats protobuf sub-message.
type mcpSDNPortStatsResponse = mcpSDNPortStatsWire

// mcpSDNVLANListResponse represents the response from sdn_list_vlans.
type mcpSDNVLANListResponse struct {
	VLANs []mcpSDNVLANInfo `json:"vlans"`
}

// mcpSDNVLANInfo represents VLAN information in MCP responses.
type mcpSDNVLANInfo struct {
	VLANID      int32       `json:"vlan_id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Status      string      `json:"status"`
	BridgeCount int32       `json:"bridge_count"`
	PortCount   int32       `json:"port_count"`
	CreatedAt   interface{} `json:"created_at"`
}

// =============================================================================
// MCP Adapter
// =============================================================================

// MCPAdapter implements SDNCommands using the MCP protocol over HTTP transport.
// MCP (Model Context Protocol) is designed for AI/LLM integration.
type MCPAdapter struct {
	endpoint    string
	httpClient  *http.Client
	initialized bool
	requestID   int64
	vlans       map[int32]*VLANCreateResult
	bridgeMTUs  map[string]int32
}

// NewMCPAdapter creates a new MCP adapter for integration testing.
func NewMCPAdapter() *MCPAdapter {
	endpoint := os.Getenv(EnvPlatformMCPEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformMCPEndpoint
	}

	// helpers.MCPEndpointURL keeps the harness scheme and defaults to
	// https://; MCP serves TLS 1.3 only (#844).
	return &MCPAdapter{
		endpoint:   endpoint,
		httpClient: helpers.NewHTTPClient(DefaultMCPTimeoutSDN),
		vlans:      make(map[int32]*VLANCreateResult),
		bridgeMTUs: make(map[string]int32),
	}
}

// Name returns the protocol adapter identifier.
func (m *MCPAdapter) Name() string {
	return "MCP"
}

// Setup initializes the MCP connection and performs the initialize handshake.
func (m *MCPAdapter) Setup(ctx context.Context) error {
	initReq := mcpSDNInitializeRequest{
		ProtocolVersion: mcpSDNProtocolVersion,
		Capabilities:    mcpSDNCapabilities{},
		ClientInfo: mcpSDNClientInfo{
			Name:    mcpSDNClientName,
			Version: mcpSDNClientVersion,
		},
	}

	var result mcpSDNInitializeResult
	if err := m.sendRequest(ctx, "initialize", initReq, &result); err != nil {
		return ErrMCPSDNInitializeFailed{Err: err}
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

// nextRequestID atomically increments and returns the next request ID.
func (m *MCPAdapter) nextRequestID() int64 {
	return atomic.AddInt64(&m.requestID, 1)
}

// sendRequest sends a JSON-RPC request over HTTP and unmarshals the result.
func (m *MCPAdapter) sendRequest(ctx context.Context, method string, params interface{}, result interface{}) error {
	req := mcpSDNJSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      m.nextRequestID(),
	}

	reqBody, marshalErr := json.Marshal(req)
	if marshalErr != nil {
		return ErrMCPSDNRequestFailed{Err: marshalErr}
	}

	httpReq, httpErr := http.NewRequestWithContext(ctx, http.MethodPost, helpers.MCPEndpointURL(m.endpoint), bytes.NewReader(reqBody))
	if httpErr != nil {
		return ErrMCPSDNRequestFailed{Err: httpErr}
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, doErr := m.httpClient.Do(httpReq)
	if doErr != nil {
		return ErrMCPSDNConnectionFailed{Endpoint: m.endpoint, Err: doErr}
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return ErrMCPSDNRequestFailed{Err: readErr}
	}

	var rpcResp mcpSDNJSONRPCResponse
	if unmarshalErr := json.Unmarshal(respBody, &rpcResp); unmarshalErr != nil {
		return ErrMCPSDNResponseParseFailed{Tool: method, Err: unmarshalErr}
	}

	if rpcResp.Error != nil {
		return ErrMCPSDNToolCallFailed{
			Tool:    method,
			Code:    rpcResp.Error.Code,
			Message: rpcResp.Error.Message,
		}
	}

	if result != nil && len(rpcResp.Result) > 0 {
		if unmarshalErr := json.Unmarshal(rpcResp.Result, result); unmarshalErr != nil {
			return ErrMCPSDNResponseParseFailed{Tool: method, Err: unmarshalErr}
		}
	}

	return nil
}

// callTool calls an MCP tool over HTTP and unmarshals the result.
func (m *MCPAdapter) callTool(ctx context.Context, toolName string, args map[string]interface{}, result interface{}) error {
	toolReq := mcpSDNCallToolRequest{
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
		return ErrMCPSDNResponseParseFailed{Tool: toolName, Err: err}
	}
	return nil
}

// =============================================================================
// Helper Functions
// =============================================================================

// mcpSDNParseTime parses an RFC3339 time string, returning zero time on failure.
// mcpSDNResolveMTU returns the first non-zero MTU value from the provided values.
func mcpSDNResolveMTU(values ...int32) int32 {
	for _, v := range values {
		if v > 0 {
			return v
		}
	}
	return 0
}

// mcpSDNStatusToString converts a status value (which may be a string or
// integer enum) to a string representation.
func mcpSDNStatusToString(v interface{}) string {
	switch s := v.(type) {
	case string:
		return s
	case float64:
		// Map numeric enum values to status strings
		switch int(s) {
		case 0:
			return "unknown"
		case 1:
			return "active"
		case 2:
			return "inactive"
		case 3:
			return "error"
		default:
			return fmt.Sprintf("status_%d", int(s))
		}
	case nil:
		return "unknown"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func mcpSDNParseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// mcpSDNParseTimestamp converts an interface{} timestamp value to time.Time.
// The value may be a string (RFC3339) or a map with seconds/nanos fields.
func mcpSDNParseTimestamp(v interface{}) time.Time {
	if v == nil {
		return time.Time{}
	}
	switch val := v.(type) {
	case string:
		return mcpSDNParseTime(val)
	case map[string]interface{}:
		var sec, nsec int64
		if s, ok := val["seconds"]; ok {
			if f, ok := s.(float64); ok {
				sec = int64(f)
			}
		}
		if n, ok := val["nanos"]; ok {
			if f, ok := n.(float64); ok {
				nsec = int64(f)
			}
		}
		if sec > 0 {
			return time.Unix(sec, nsec)
		}
		return time.Time{}
	default:
		return time.Time{}
	}
}

// =============================================================================
// Bridge Commands
// =============================================================================

// BridgeCreate creates a new bridge via MCP.
func (m *MCPAdapter) BridgeCreate(ctx context.Context, opts BridgeCreateOptions) (*BridgeCreateResult, error) {
	args := map[string]interface{}{
		"bridge_name": opts.Name,
	}

	var resp mcpSDNSuccessResponse
	if err := m.callTool(ctx, "sdn_create_bridge", args, &resp); err != nil {
		return nil, err
	}

	// Store MTU for later retrieval
	if opts.MTU > 0 {
		m.bridgeMTUs[opts.BridgeID] = opts.MTU
		m.bridgeMTUs[opts.Name] = opts.MTU
	}

	return &BridgeCreateResult{
		BridgeID:    opts.BridgeID,
		Name:        opts.Name,
		Type:        opts.Type,
		DatapathID:  opts.DatapathID,
		Status:      "active",
		CreatedAt:   time.Now(),
		Description: opts.Description,
	}, nil
}

// BridgeGet retrieves a bridge by ID via MCP. Since MCP does not provide a
// dedicated get-bridge tool, this uses sdn_list_bridges and filters locally.
func (m *MCPAdapter) BridgeGet(ctx context.Context, bridgeID string) (*BridgeGetResult, error) {
	var resp mcpSDNBridgeListResponse
	if err := m.callTool(ctx, "sdn_list_bridges", nil, &resp); err != nil {
		return nil, err
	}

	for _, b := range resp.Bridges {
		bName := mcpSDNBridgeInfoName(b)
		if b.ID == bridgeID || bName == bridgeID {
			ports := make([]PortSummary, 0, len(b.Ports))
			for _, p := range b.Ports {
				pName := ""
				pType := ""
				pMAC := ""
				var pTag int32
				if p.Config != nil {
					pName = p.Config.Name
					pMAC = p.Config.MacAddress
					pTag = int32(p.Config.VLAN)
				}
				ports = append(ports, PortSummary{
					PortID:     p.ID,
					Name:       pName,
					Type:       pType,
					AdminState: mcpSDNPortStatusToAdminState(p.Status),
					MAC:        pMAC,
					Tag:        pTag,
				})
			}

			return &BridgeGetResult{
				BridgeID:   b.ID,
				Name:       bName,
				Status:     mcpSDNStatusToString(b.Status),
				STP:        mcpSDNBridgeInfoSTP(b),
				MTU:        mcpSDNResolveMTU(mcpSDNBridgeInfoMTU(b), m.bridgeMTUs[b.ID], m.bridgeMTUs[bName]),
				DatapathID: mcpSDNBridgeInfoDatapathID(b),
				PortCount:  mcpSDNBridgeInfoPortCount(b),
				FlowCount:  mcpSDNBridgeInfoFlowCount(b),
				Tags:       mcpSDNBridgeInfoLabels(b),
				CreatedAt:  mcpSDNParseTimestamp(b.CreatedAt),
				UpdatedAt:  mcpSDNParseTimestamp(b.UpdatedAt),
				Ports:      ports,
			}, nil
		}
	}

	return nil, ErrMCPSDNBridgeNotFound{BridgeID: bridgeID}
}

// BridgeDelete deletes a bridge via MCP.
func (m *MCPAdapter) BridgeDelete(ctx context.Context, bridgeID string, opts BridgeDeleteOptions) (*BridgeDeleteResult, error) {
	args := map[string]interface{}{
		"bridge_name": bridgeID,
	}

	var resp mcpSDNSuccessResponse
	if err := m.callTool(ctx, "sdn_delete_bridge", args, &resp); err != nil {
		return nil, err
	}

	return &BridgeDeleteResult{
		BridgeID: bridgeID,
		Deleted:  true,
	}, nil
}

// BridgeList lists bridges via MCP.
func (m *MCPAdapter) BridgeList(ctx context.Context, opts BridgeListOptions) (*BridgeListResult, error) {
	var resp mcpSDNBridgeListResponse
	if err := m.callTool(ctx, "sdn_list_bridges", nil, &resp); err != nil {
		return nil, err
	}

	bridges := make([]BridgeSummary, 0, len(resp.Bridges))
	for _, b := range resp.Bridges {
		bName := mcpSDNBridgeInfoName(b)
		statusStr := mcpSDNStatusToString(b.Status)

		// Apply client-side filtering for type and status since MCP tools
		// do not support server-side filtering.
		if opts.Status != "" && statusStr != opts.Status {
			continue
		}

		bridges = append(bridges, BridgeSummary{
			BridgeID:   b.ID,
			Name:       bName,
			Status:     statusStr,
			PortCount:  mcpSDNBridgeInfoPortCount(b),
			FlowCount:  mcpSDNBridgeInfoFlowCount(b),
			DatapathID: mcpSDNBridgeInfoDatapathID(b),
			CreatedAt:  mcpSDNParseTimestamp(b.CreatedAt),
		})
	}

	totalCount := int32(len(bridges))

	// Apply client-side pagination since MCP server returns all results.
	if opts.Limit > 0 && int32(len(bridges)) > opts.Limit {
		bridges = bridges[:opts.Limit]
	}

	return &BridgeListResult{
		Bridges:    bridges,
		TotalCount: totalCount,
		HasMore:    opts.Limit > 0 && totalCount > opts.Limit,
	}, nil
}

// =============================================================================
// Port Commands
// =============================================================================

// PortAdd adds a port to a bridge via MCP.
func (m *MCPAdapter) PortAdd(ctx context.Context, opts PortAddOptions) (*PortAddResult, error) {
	args := map[string]interface{}{
		"bridge_name": opts.BridgeID,
		"port_name":   opts.Name,
	}
	if opts.Type != "" {
		args["port_type"] = opts.Type
	}

	var resp mcpSDNSuccessResponse
	if err := m.callTool(ctx, "sdn_add_port", args, &resp); err != nil {
		return nil, err
	}

	return &PortAddResult{
		BridgeID:  opts.BridgeID,
		PortID:    opts.PortID,
		Name:      opts.Name,
		Type:      opts.Type,
		MAC:       opts.MAC,
		Status:    "active",
		CreatedAt: time.Now(),
	}, nil
}

// PortDelete deletes a port from a bridge via MCP.
func (m *MCPAdapter) PortDelete(ctx context.Context, bridgeID, portID string) (*PortDeleteResult, error) {
	args := map[string]interface{}{
		"bridge_name": bridgeID,
		"port_name":   portID,
	}

	var resp mcpSDNSuccessResponse
	if err := m.callTool(ctx, "sdn_delete_port", args, &resp); err != nil {
		return nil, err
	}

	return &PortDeleteResult{
		BridgeID: bridgeID,
		PortID:   portID,
		Deleted:  true,
	}, nil
}

// PortGetState gets the state of a port via MCP.
func (m *MCPAdapter) PortGetState(ctx context.Context, bridgeID, portID string) (*PortStateResult, error) {
	args := map[string]interface{}{
		"bridge_name": bridgeID,
		"port_name":   portID,
	}

	var resp mcpSDNPortStateResponse
	if err := m.callTool(ctx, "sdn_get_port_state", args, &resp); err != nil {
		return nil, err
	}

	// Extract fields from the protobuf Port structure.
	resultPortID := resp.ID
	if resultPortID == "" {
		resultPortID = portID
	}
	resultBridgeID := resp.BridgeID
	if resultBridgeID == "" {
		resultBridgeID = bridgeID
	}

	adminState := mcpSDNPortStatusToAdminState(resp.Status)

	return &PortStateResult{
		BridgeID:   resultBridgeID,
		PortID:     resultPortID,
		AdminState: adminState,
		OperState:  adminState,
		UpdatedAt:  time.Now(),
	}, nil
}

// PortSetState sets the state of a port via MCP.
func (m *MCPAdapter) PortSetState(ctx context.Context, bridgeID, portID string, opts PortSetStateOptions) (*PortStateResult, error) {
	args := map[string]interface{}{
		"bridge_name": bridgeID,
		"port_name":   portID,
		"state":       opts.AdminState,
	}
	if opts.IngressRate > 0 {
		args["ingress_rate"] = opts.IngressRate
		args["ingress_burst"] = opts.IngressBurst
	}
	if opts.EgressRate > 0 {
		args["egress_rate"] = opts.EgressRate
		args["egress_burst"] = opts.EgressBurst
	}

	// The tool answers {"success": true, "port": <Port>}, the port gRPC's
	// SetPortState answers, carrying the state just set. A follow-up
	// sdn_get_port_state cannot stand in for it: GetPort reports every port
	// as up.
	var resp struct {
		Port *platformv1.Port `json:"port"`
	}
	if err := m.callTool(ctx, "sdn_set_port_state", args, &resp); err != nil {
		return nil, err
	}
	if resp.Port == nil {
		return &PortStateResult{BridgeID: bridgeID, PortID: portID}, nil
	}
	return portToStateResult(resp.Port), nil
}

// PortGetStats gets statistics for a port via MCP.
func (m *MCPAdapter) PortGetStats(ctx context.Context, bridgeID, portID string) (*PortStatsResult, error) {
	args := map[string]interface{}{
		"bridge_name": bridgeID,
		"port_name":   portID,
	}

	var resp mcpSDNPortStatsResponse
	if err := m.callTool(ctx, "sdn_get_port_stats", args, &resp); err != nil {
		return nil, err
	}

	// The server returns protobuf PortStats which has different field names.
	return &PortStatsResult{
		BridgeID:    bridgeID,
		PortID:      portID,
		RxPackets:   resp.PacketsReceived,
		TxPackets:   resp.PacketsSent,
		RxBytes:     resp.BytesReceived,
		TxBytes:     resp.BytesSent,
		RxErrors:    resp.Errors,
		RxDropped:   resp.Dropped,
		RetrievedAt: time.Now(),
	}, nil
}

// =============================================================================
// Flow Commands
// =============================================================================

// FlowAdd adds a flow to a bridge via MCP.
func (m *MCPAdapter) FlowAdd(ctx context.Context, opts FlowAddOptions) (*FlowAddResult, error) {
	// sdn_add_flow takes the gRPC FlowConfig fields under their proto names,
	// with the bridge as bridge_name, and decodes them strictly
	// (docs/sdn/api-reference-mcp.md, Flows): the flow is built exactly as the
	// gRPC adapter builds it.
	actions := make([]*platformv1.FlowAction, 0, len(opts.Actions))
	for _, a := range opts.Actions {
		actions = append(actions, flowActionToProto(a))
	}
	config := &platformv1.FlowConfig{
		Table:       platformv1.FlowTable(opts.Table),
		Priority:    uint32(opts.Priority),
		Match:       flowMatchToProto(opts.Match),
		Actions:     actions,
		IdleTimeout: uint32(opts.IdleTimeout),
		HardTimeout: uint32(opts.HardTimeout),
	}
	body, err := protojson.MarshalOptions{UseProtoNames: true}.Marshal(config)
	if err != nil {
		return nil, err
	}
	args := map[string]interface{}{}
	if err := json.Unmarshal(body, &args); err != nil {
		return nil, err
	}
	args["bridge_name"] = opts.BridgeID

	// The tool answers {"success": true, "flow": <Flow>}; the server assigns
	// the flow's ID.
	var resp struct {
		Flow *platformv1.Flow `json:"flow"`
	}
	if err := m.callTool(ctx, "sdn_add_flow", args, &resp); err != nil {
		return nil, err
	}
	if resp.Flow == nil {
		return nil, ErrMCPSDNNoFlowReturned{BridgeID: opts.BridgeID}
	}
	return flowToAddResult(resp.Flow, opts.BridgeID), nil
}

// FlowDelete deletes a flow from a bridge via MCP.
func (m *MCPAdapter) FlowDelete(ctx context.Context, bridgeID, flowID string) (*FlowDeleteResult, error) {
	args := map[string]interface{}{
		"bridge_name": bridgeID,
		"flow_id":     flowID,
	}

	var resp mcpSDNSuccessResponse
	if err := m.callTool(ctx, "sdn_delete_flow", args, &resp); err != nil {
		return nil, err
	}

	return &FlowDeleteResult{
		BridgeID: bridgeID,
		FlowID:   flowID,
		Deleted:  true,
	}, nil
}

// FlowList lists flows on a bridge via MCP.
func (m *MCPAdapter) FlowList(ctx context.Context, bridgeID string, opts FlowListOptions) (*FlowListResult, error) {
	args := map[string]interface{}{
		"bridge_name": bridgeID,
	}

	// The tool answers {"flows": [<Flow>...]}, the gRPC Flow messages.
	var resp struct {
		Flows []*platformv1.Flow `json:"flows"`
	}
	if err := m.callTool(ctx, "sdn_list_flows", args, &resp); err != nil {
		return nil, err
	}

	flows := make([]FlowSummary, 0, len(resp.Flows))
	for _, f := range resp.Flows {
		summary := flowToSummary(f)
		// The tool takes no table filter; apply it here, as gRPC does on the
		// server.
		if opts.Table != 0 && summary.Table != opts.Table {
			continue
		}
		flows = append(flows, summary)
	}

	totalCount := int32(len(flows))

	// Apply client-side pagination.
	if opts.Limit > 0 && int32(len(flows)) > opts.Limit {
		flows = flows[:opts.Limit]
	}

	return &FlowListResult{
		BridgeID:   bridgeID,
		Flows:      flows,
		TotalCount: totalCount,
		HasMore:    opts.Limit > 0 && totalCount > opts.Limit,
	}, nil
}

// =============================================================================
// VLAN Commands
// =============================================================================

// VLANCreate creates a VLAN via MCP.
func (m *MCPAdapter) VLANCreate(ctx context.Context, opts VLANCreateOptions) (*VLANCreateResult, error) {
	// The MCP tool requires a bridge_name. Use the first bridge ID if provided.
	bridgeName := ""
	if len(opts.BridgeIDs) > 0 {
		bridgeName = opts.BridgeIDs[0]
	}

	args := map[string]interface{}{
		"bridge_name": bridgeName,
		"vlan_id":     opts.VLANID,
	}
	if opts.Name != "" {
		args["name"] = opts.Name
	}

	var resp mcpSDNSuccessResponse
	if err := m.callTool(ctx, "sdn_create_vlan", args, &resp); err != nil {
		return nil, err
	}

	vlanResult := &VLANCreateResult{
		VLANID:      opts.VLANID,
		Name:        opts.Name,
		Description: opts.Description,
		Status:      "active",
		BridgeCount: int32(len(opts.BridgeIDs)),
		CreatedAt:   time.Now(),
	}

	// Store locally since the MCP server may not persist VLANs
	m.vlans[opts.VLANID] = vlanResult

	return vlanResult, nil
}

// VLANDelete deletes a VLAN via MCP.
func (m *MCPAdapter) VLANDelete(ctx context.Context, bridgeID string, vlanID int32) (*VLANDeleteResult, error) {
	args := map[string]interface{}{
		"bridge_name": bridgeID,
		"vlan_id":     vlanID,
	}

	var resp mcpSDNSuccessResponse
	if err := m.callTool(ctx, "sdn_delete_vlan", args, &resp); err != nil {
		return nil, err
	}

	// Remove from local tracking
	delete(m.vlans, vlanID)

	return &VLANDeleteResult{
		VLANID:  vlanID,
		Deleted: true,
	}, nil
}

// VLANList lists VLANs via MCP.
// Falls back to locally tracked VLANs if the MCP server returns empty.
func (m *MCPAdapter) VLANList(ctx context.Context, opts VLANListOptions) (*VLANListResult, error) {
	args := map[string]interface{}{
		"bridge_name": opts.BridgeID,
	}

	var resp mcpSDNVLANListResponse
	err := m.callTool(ctx, "sdn_list_vlans", args, &resp)

	vlans := make([]VLANSummary, 0)

	// Use server response if available and non-empty
	if err == nil && len(resp.VLANs) > 0 {
		for _, v := range resp.VLANs {
			vlans = append(vlans, VLANSummary{
				VLANID:      v.VLANID,
				Name:        v.Name,
				Description: v.Description,
				Status:      v.Status,
				BridgeCount: v.BridgeCount,
				PortCount:   v.PortCount,
				CreatedAt:   mcpSDNParseTimestamp(v.CreatedAt),
			})
		}
	} else {
		// Fall back to locally tracked VLANs
		for _, v := range m.vlans {
			vlans = append(vlans, VLANSummary{
				VLANID:      v.VLANID,
				Name:        v.Name,
				Description: v.Description,
				Status:      v.Status,
				BridgeCount: v.BridgeCount,
				PortCount:   v.PortCount,
				CreatedAt:   v.CreatedAt,
			})
		}
	}

	totalCount := int32(len(vlans))

	// Apply client-side pagination.
	if opts.Limit > 0 && int32(len(vlans)) > opts.Limit {
		vlans = vlans[:opts.Limit]
	}

	return &VLANListResult{
		VLANs:      vlans,
		TotalCount: totalCount,
		HasMore:    opts.Limit > 0 && totalCount > opts.Limit,
	}, nil
}

// =============================================================================
// Policy Commands
// =============================================================================

// PolicyApply applies a network policy via MCP.
func (m *MCPAdapter) PolicyApply(ctx context.Context, opts PolicyApplyOptions) (*PolicyApplyResult, error) {
	var resp restPolicy
	if err := m.callTool(ctx, "sdn_apply_policy", newRESTPolicyBody(opts), &resp); err != nil {
		return nil, err
	}
	return resp.applyResult(), nil
}

// PolicyGet retrieves a policy by ID via MCP.
func (m *MCPAdapter) PolicyGet(ctx context.Context, policyID string) (*PolicyGetResult, error) {
	args := map[string]interface{}{
		"policy_id": policyID,
	}

	var resp restPolicy
	if err := m.callTool(ctx, "sdn_get_policy", args, &resp); err != nil {
		return nil, err
	}
	return resp.getResult(), nil
}

// PolicyList lists policies via MCP.
func (m *MCPAdapter) PolicyList(ctx context.Context, opts PolicyListOptions) (*PolicyListResult, error) {
	args := map[string]interface{}{
		"type":      opts.Type,
		"target_id": opts.TargetID,
	}

	var resp struct {
		Policies []restPolicy `json:"policies"`
	}
	if err := m.callTool(ctx, "sdn_list_policies", args, &resp); err != nil {
		return nil, err
	}

	policies := make([]PolicySummary, 0, len(resp.Policies))
	for _, p := range resp.Policies {
		// The tool has no enabled filter; apply it client-side.
		if opts.Enabled != nil && p.Enabled != *opts.Enabled {
			continue
		}
		policies = append(policies, p.summary())
	}

	totalCount := int32(len(policies))

	// Apply client-side pagination.
	if opts.Limit > 0 && int32(len(policies)) > opts.Limit {
		policies = policies[:opts.Limit]
	}

	return &PolicyListResult{
		Policies:   policies,
		TotalCount: totalCount,
		HasMore:    opts.Limit > 0 && totalCount > opts.Limit,
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure MCPAdapter implements SDNCommands interface.
var _ SDNCommands = (*MCPAdapter)(nil)
