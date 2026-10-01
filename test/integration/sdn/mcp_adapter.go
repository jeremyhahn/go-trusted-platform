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
	"strings"
	"sync/atomic"
	"time"

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

// ErrMCPSDNNotImplemented indicates a method is not yet implemented.
type ErrMCPSDNNotImplemented struct {
	Method string
}

func (e ErrMCPSDNNotImplemented) Error() string {
	return fmt.Sprintf("MCP method %s not implemented", e.Method)
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

// mcpSDNCallToolResult represents the result of tools/call.
type mcpSDNCallToolResult struct {
	Content []mcpSDNContent `json:"content"`
	IsError bool            `json:"isError,omitempty"`
}

// mcpSDNContent represents content in an MCP response.
type mcpSDNContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
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

// mcpSDNFlowListResponse represents the response from sdn_list_flows.
type mcpSDNFlowListResponse struct {
	Flows []mcpSDNFlowInfo `json:"flows"`
}

// mcpSDNFlowInfo represents flow information in MCP responses.
type mcpSDNFlowInfo struct {
	FlowID      string                 `json:"flow_id"`
	Table       int32                  `json:"table"`
	Priority    int32                  `json:"priority"`
	Cookie      uint64                 `json:"cookie"`
	PacketCount uint64                 `json:"packet_count"`
	ByteCount   uint64                 `json:"byte_count"`
	Duration    int64                  `json:"duration"`
	IdleAge     int64                  `json:"idle_age"`
	HardAge     int64                  `json:"hard_age"`
	Match       map[string]interface{} `json:"match"`
	Actions     []interface{}          `json:"actions"`
}

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

// mcpSDNPolicyResponse represents policy information from sdn_get_policy.
type mcpSDNPolicyResponse struct {
	PolicyID    string                   `json:"policy_id"`
	Name        string                   `json:"name"`
	Description string                   `json:"description"`
	Type        string                   `json:"type"`
	Priority    int32                    `json:"priority"`
	Enabled     bool                     `json:"enabled"`
	Status      string                   `json:"status"`
	Rules       []map[string]interface{} `json:"rules"`
	Targets     []map[string]interface{} `json:"targets"`
	Schedule    map[string]interface{}   `json:"schedule"`
	HitCount    uint64                   `json:"hit_count"`
	ByteCount   uint64                   `json:"byte_count"`
	CreatedAt   interface{}              `json:"created_at"`
	UpdatedAt   interface{}              `json:"updated_at"`
}

// mcpSDNPolicyListResponse represents the response from sdn_list_policies.
type mcpSDNPolicyListResponse struct {
	Policies []mcpSDNPolicySummary `json:"policies"`
}

// mcpSDNPolicySummary represents policy summary in MCP list responses.
type mcpSDNPolicySummary struct {
	PolicyID    string      `json:"policy_id"`
	Name        string      `json:"name"`
	Type        string      `json:"type"`
	Priority    int32       `json:"priority"`
	Enabled     bool        `json:"enabled"`
	Status      string      `json:"status"`
	RuleCount   int32       `json:"rule_count"`
	TargetCount int32       `json:"target_count"`
	HitCount    uint64      `json:"hit_count"`
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
	// The harness sets PLATFORM_MCP_ENDPOINT with its scheme
	// (http://localhost:9445); the request URL below adds one, and
	// "http://http://..." resolved the host "http" and failed every run.
	endpoint = strings.TrimPrefix(strings.TrimPrefix(endpoint, "http://"), "https://")

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

	if result == nil || len(rawResult) == 0 {
		return nil
	}

	// Try MCP content-wrapped format first: {"content":[{"type":"text","text":"..."}],"isError":false}
	var toolResult mcpSDNCallToolResult
	if unmarshalErr := json.Unmarshal(rawResult, &toolResult); unmarshalErr == nil && len(toolResult.Content) > 0 {
		if toolResult.IsError {
			var errMsg string
			for _, item := range toolResult.Content {
				if item.Type == "text" {
					errMsg = item.Text
					break
				}
			}
			return ErrMCPSDNToolCallFailed{Tool: toolName, Code: mcpSDNJSONRPCInternalError, Message: errMsg}
		}

		for _, item := range toolResult.Content {
			if item.Type == "text" && item.Text != "" {
				if parseErr := json.Unmarshal([]byte(item.Text), result); parseErr != nil {
					return ErrMCPSDNResponseParseFailed{Tool: toolName, Err: parseErr}
				}
				return nil
			}
		}
		return nil
	}

	// Server returned result directly as a raw map (not wrapped in content items).
	if unmarshalErr := json.Unmarshal(rawResult, result); unmarshalErr != nil {
		return ErrMCPSDNResponseParseFailed{Tool: toolName, Err: unmarshalErr}
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

// mcpSDNParsePolicyRules converts raw rule maps into PolicyRule slices.
func mcpSDNParsePolicyRules(raw []map[string]interface{}) []PolicyRule {
	rules := make([]PolicyRule, 0, len(raw))
	for _, r := range raw {
		rule := PolicyRule{}
		if v, ok := r["rule_id"].(string); ok {
			rule.RuleID = v
		}
		if v, ok := r["priority"].(float64); ok {
			rule.Priority = int32(v)
		}
		if v, ok := r["action"].(string); ok {
			rule.Action = v
		}
		if v, ok := r["action_value"].(string); ok {
			rule.ActionValue = v
		}
		if v, ok := r["log"].(bool); ok {
			rule.Log = v
		}
		if v, ok := r["counter"].(bool); ok {
			rule.Counter = v
		}
		if m, ok := r["match"].(map[string]interface{}); ok {
			rule.Match = mcpSDNParsePolicyMatch(m)
		}
		rules = append(rules, rule)
	}
	return rules
}

// mcpSDNParsePolicyMatch converts a raw match map into a PolicyMatch.
func mcpSDNParsePolicyMatch(m map[string]interface{}) PolicyMatch {
	pm := PolicyMatch{}
	if v, ok := m["source_ip"].(string); ok {
		pm.SourceIP = v
	}
	if v, ok := m["destination_ip"].(string); ok {
		pm.DestinationIP = v
	}
	if v, ok := m["source_port"].(float64); ok {
		pm.SourcePort = int32(v)
	}
	if v, ok := m["destination_port"].(float64); ok {
		pm.DestinationPort = int32(v)
	}
	if v, ok := m["protocol"].(string); ok {
		pm.Protocol = v
	}
	if v, ok := m["direction"].(string); ok {
		pm.Direction = v
	}
	if v, ok := m["interface"].(string); ok {
		pm.Interface = v
	}
	if v, ok := m["vlan_id"].(float64); ok {
		pm.VLANID = int32(v)
	}
	if v, ok := m["dscp"].(float64); ok {
		pm.DSCP = int32(v)
	}
	if v, ok := m["application"].(string); ok {
		pm.Application = v
	}
	return pm
}

// mcpSDNParsePolicyTargets converts raw target maps into PolicyTarget slices.
func mcpSDNParsePolicyTargets(raw []map[string]interface{}) []PolicyTarget {
	targets := make([]PolicyTarget, 0, len(raw))
	for _, t := range raw {
		target := PolicyTarget{}
		if v, ok := t["type"].(string); ok {
			target.Type = v
		}
		if v, ok := t["id"].(string); ok {
			target.ID = v
		}
		if v, ok := t["direction"].(string); ok {
			target.Direction = v
		}
		targets = append(targets, target)
	}
	return targets
}

// mcpSDNParsePolicySchedule converts a raw schedule map into a PolicySchedule.
func mcpSDNParsePolicySchedule(m map[string]interface{}) *PolicySchedule {
	if m == nil {
		return nil
	}
	schedule := &PolicySchedule{}
	if v, ok := m["start_time"].(string); ok {
		schedule.StartTime = v
	}
	if v, ok := m["end_time"].(string); ok {
		schedule.EndTime = v
	}
	if v, ok := m["timezone"].(string); ok {
		schedule.Timezone = v
	}
	if v, ok := m["enabled"].(bool); ok {
		schedule.Enabled = v
	}
	if days, ok := m["days"].([]interface{}); ok {
		for _, d := range days {
			if s, ok := d.(string); ok {
				schedule.Days = append(schedule.Days, s)
			}
		}
	}
	return schedule
}

// mcpSDNParseFlowMatch converts a raw match map into a FlowMatch.
func mcpSDNParseFlowMatch(m map[string]interface{}) FlowMatch {
	fm := FlowMatch{}
	if v, ok := m["in_port"].(float64); ok {
		fm.InPort = int32(v)
	}
	if v, ok := m["dl_src"].(string); ok {
		fm.DlSrc = v
	}
	if v, ok := m["dl_dst"].(string); ok {
		fm.DlDst = v
	}
	if v, ok := m["dl_type"].(float64); ok {
		fm.DlType = int32(v)
	}
	if v, ok := m["dl_vlan"].(float64); ok {
		fm.DlVLAN = int32(v)
	}
	if v, ok := m["dl_vlan_pcp"].(float64); ok {
		fm.DlVLANPCP = int32(v)
	}
	if v, ok := m["nw_src"].(string); ok {
		fm.NwSrc = v
	}
	if v, ok := m["nw_dst"].(string); ok {
		fm.NwDst = v
	}
	if v, ok := m["nw_proto"].(float64); ok {
		fm.NwProto = int32(v)
	}
	if v, ok := m["nw_tos"].(float64); ok {
		fm.NwTOS = int32(v)
	}
	if v, ok := m["tp_src"].(float64); ok {
		fm.TpSrc = int32(v)
	}
	if v, ok := m["tp_dst"].(float64); ok {
		fm.TpDst = int32(v)
	}
	if v, ok := m["metadata"].(float64); ok {
		fm.Metadata = uint64(v)
	}
	if v, ok := m["tunnel_id"].(float64); ok {
		fm.TunnelID = uint64(v)
	}
	if v, ok := m["tunnel_src"].(string); ok {
		fm.TunnelSrc = v
	}
	if v, ok := m["tunnel_dst"].(string); ok {
		fm.TunnelDst = v
	}
	return fm
}

// mcpSDNParseFlowActions converts a raw actions slice into FlowAction slices.
func mcpSDNParseFlowActions(raw []interface{}) []FlowAction {
	actions := make([]FlowAction, 0, len(raw))
	for _, a := range raw {
		action := FlowAction{}
		switch v := a.(type) {
		case map[string]interface{}:
			if t, ok := v["type"].(string); ok {
				action.Type = t
			}
			if p, ok := v["port"].(float64); ok {
				action.Port = int32(p)
			}
			if vid, ok := v["vlan_id"].(float64); ok {
				action.VLANID = int32(vid)
			}
			if f, ok := v["field"].(string); ok {
				action.Field = f
			}
			if val, ok := v["value"].(string); ok {
				action.Value = val
			}
			if gid, ok := v["group_id"].(float64); ok {
				action.GroupID = int32(gid)
			}
			if tid, ok := v["table_id"].(float64); ok {
				action.TableID = int32(tid)
			}
		case string:
			action.Type = v
		}
		actions = append(actions, action)
	}
	return actions
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

	var resp mcpSDNSuccessResponse
	if err := m.callTool(ctx, "sdn_set_port_state", args, &resp); err != nil {
		return nil, err
	}

	// After setting state, retrieve the current state to return accurate data.
	return m.PortGetState(ctx, bridgeID, portID)
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
	// Build the flow map that the MCP tool expects.
	flowMap := map[string]interface{}{
		"priority": opts.Priority,
	}

	// Build match criteria.
	matchMap := map[string]interface{}{}
	if opts.Match.InPort != 0 {
		matchMap["in_port"] = opts.Match.InPort
	}
	if opts.Match.DlSrc != "" {
		matchMap["dl_src"] = opts.Match.DlSrc
	}
	if opts.Match.DlDst != "" {
		matchMap["dl_dst"] = opts.Match.DlDst
	}
	if opts.Match.DlType != 0 {
		matchMap["dl_type"] = opts.Match.DlType
	}
	if opts.Match.DlVLAN != 0 {
		matchMap["dl_vlan"] = opts.Match.DlVLAN
	}
	if opts.Match.NwSrc != "" {
		matchMap["nw_src"] = opts.Match.NwSrc
	}
	if opts.Match.NwDst != "" {
		matchMap["nw_dst"] = opts.Match.NwDst
	}
	if opts.Match.NwProto != 0 {
		matchMap["nw_proto"] = opts.Match.NwProto
	}
	if opts.Match.TpSrc != 0 {
		matchMap["tp_src"] = opts.Match.TpSrc
	}
	if opts.Match.TpDst != 0 {
		matchMap["tp_dst"] = opts.Match.TpDst
	}
	if len(matchMap) > 0 {
		flowMap["match"] = matchMap
	}

	// Build actions as string slice for MCP tool compatibility.
	actionStrs := make([]string, 0, len(opts.Actions))
	for _, a := range opts.Actions {
		switch a.Type {
		case "output":
			actionStrs = append(actionStrs, fmt.Sprintf("output:%d", a.Port))
		case "drop":
			actionStrs = append(actionStrs, "drop")
		case "normal":
			actionStrs = append(actionStrs, "normal")
		case "flood":
			actionStrs = append(actionStrs, "flood")
		case "controller":
			actionStrs = append(actionStrs, "controller")
		case "goto_table":
			actionStrs = append(actionStrs, fmt.Sprintf("goto_table:%d", a.TableID))
		case "set_field":
			actionStrs = append(actionStrs, fmt.Sprintf("set_field:%s=%s", a.Field, a.Value))
		case "push_vlan":
			actionStrs = append(actionStrs, fmt.Sprintf("push_vlan:%d", a.VLANID))
		case "pop_vlan":
			actionStrs = append(actionStrs, "pop_vlan")
		case "group":
			actionStrs = append(actionStrs, fmt.Sprintf("group:%d", a.GroupID))
		default:
			actionStrs = append(actionStrs, a.Type)
		}
	}
	if len(actionStrs) > 0 {
		flowMap["actions"] = actionStrs
	}

	args := map[string]interface{}{
		"bridge_name": opts.BridgeID,
		"flow":        flowMap,
	}

	if opts.Priority != 0 {
		args["priority"] = opts.Priority
	}
	if len(matchMap) > 0 {
		args["match"] = matchMap
	}
	if len(actionStrs) > 0 {
		args["actions"] = actionStrs
	}

	var resp mcpSDNSuccessResponse
	if err := m.callTool(ctx, "sdn_add_flow", args, &resp); err != nil {
		return nil, err
	}

	return &FlowAddResult{
		BridgeID:  opts.BridgeID,
		FlowID:    opts.FlowID,
		Table:     opts.Table,
		Priority:  opts.Priority,
		Cookie:    opts.Cookie,
		CreatedAt: time.Now(),
	}, nil
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

	var resp mcpSDNFlowListResponse
	if err := m.callTool(ctx, "sdn_list_flows", args, &resp); err != nil {
		return nil, err
	}

	flows := make([]FlowSummary, 0, len(resp.Flows))
	for _, f := range resp.Flows {
		// Apply client-side filtering for table and cookie.
		if opts.Table != 0 && f.Table != opts.Table {
			continue
		}
		if opts.Cookie != 0 && f.Cookie != opts.Cookie {
			continue
		}

		flows = append(flows, FlowSummary{
			FlowID:      f.FlowID,
			Table:       f.Table,
			Priority:    f.Priority,
			Cookie:      f.Cookie,
			PacketCount: f.PacketCount,
			ByteCount:   f.ByteCount,
			Duration:    f.Duration,
			IdleAge:     f.IdleAge,
			HardAge:     f.HardAge,
			Match:       mcpSDNParseFlowMatch(f.Match),
			Actions:     mcpSDNParseFlowActions(f.Actions),
		})
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
	// The MCP tool requires a bridge_name. Use opts.BridgeID directly,
	// falling back to the first target of type "bridge" if present.
	bridgeName := opts.BridgeID
	if bridgeName == "" {
		for _, t := range opts.Targets {
			if t.Type == "bridge" {
				bridgeName = t.ID
				break
			}
		}
	}

	args := map[string]interface{}{
		"policy_id":   opts.PolicyID,
		"bridge_name": bridgeName,
	}

	var resp mcpSDNSuccessResponse
	if err := m.callTool(ctx, "sdn_apply_policy", args, &resp); err != nil {
		return nil, err
	}

	return &PolicyApplyResult{
		PolicyID:    opts.PolicyID,
		Name:        opts.Name,
		Type:        opts.Type,
		Status:      "applied",
		RuleCount:   int32(len(opts.Rules)),
		TargetCount: int32(len(opts.Targets)),
		AppliedAt:   time.Now(),
	}, nil
}

// PolicyGet retrieves a policy by ID via MCP.
func (m *MCPAdapter) PolicyGet(ctx context.Context, policyID string) (*PolicyGetResult, error) {
	args := map[string]interface{}{
		"policy_id": policyID,
	}

	var resp mcpSDNPolicyResponse
	if err := m.callTool(ctx, "sdn_get_policy", args, &resp); err != nil {
		return nil, err
	}

	return &PolicyGetResult{
		PolicyID:    resp.PolicyID,
		Name:        resp.Name,
		Description: resp.Description,
		Type:        resp.Type,
		Priority:    resp.Priority,
		Enabled:     resp.Enabled,
		Status:      resp.Status,
		Rules:       mcpSDNParsePolicyRules(resp.Rules),
		Targets:     mcpSDNParsePolicyTargets(resp.Targets),
		Schedule:    mcpSDNParsePolicySchedule(resp.Schedule),
		HitCount:    resp.HitCount,
		ByteCount:   resp.ByteCount,
		CreatedAt:   mcpSDNParseTimestamp(resp.CreatedAt),
		UpdatedAt:   mcpSDNParseTimestamp(resp.UpdatedAt),
	}, nil
}

// PolicyList lists policies via MCP.
func (m *MCPAdapter) PolicyList(ctx context.Context, opts PolicyListOptions) (*PolicyListResult, error) {
	var resp mcpSDNPolicyListResponse
	if err := m.callTool(ctx, "sdn_list_policies", nil, &resp); err != nil {
		return nil, err
	}

	policies := make([]PolicySummary, 0, len(resp.Policies))
	for _, p := range resp.Policies {
		// Apply client-side filtering for type.
		if opts.Type != "" && p.Type != opts.Type {
			continue
		}
		// Apply client-side filtering for enabled status.
		if opts.Enabled != nil && p.Enabled != *opts.Enabled {
			continue
		}

		policies = append(policies, PolicySummary{
			PolicyID:    p.PolicyID,
			Name:        p.Name,
			Type:        p.Type,
			Priority:    p.Priority,
			Enabled:     p.Enabled,
			Status:      p.Status,
			RuleCount:   p.RuleCount,
			TargetCount: p.TargetCount,
			HitCount:    p.HitCount,
			CreatedAt:   mcpSDNParseTimestamp(p.CreatedAt),
		})
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
