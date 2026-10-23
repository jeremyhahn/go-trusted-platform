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

// Package dns provides integration test adapters for DNS services.
// This file implements the DNSCommands interface using the MCP (Model Context Protocol).

//go:build integration

package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Environment Variables and Constants
// =============================================================================

const (
	// DefaultMCPTimeout is the default timeout for MCP requests.
	DefaultMCPTimeout = 30 * time.Second

	// MCPProtocolVersion is the MCP protocol version supported by this client.
	MCPProtocolVersion = "2024-11-05"

	// MCPClientName is the name of this MCP client.
	MCPClientName = "dns-integration-test"

	// MCPClientVersion is the version of this MCP client.
	MCPClientVersion = "1.0.0"
)

// =============================================================================
// JSON-RPC 2.0 Types
// =============================================================================

// jsonRPCRequest represents a JSON-RPC 2.0 request.
type jsonRPCRequest struct {
	JSONRPC string      `json:"jsonrpc"`
	Method  string      `json:"method"`
	Params  interface{} `json:"params,omitempty"`
	ID      int64       `json:"id"`
}

// jsonRPCResponse represents a JSON-RPC 2.0 response.
type jsonRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError   `json:"error,omitempty"`
	ID      int64           `json:"id"`
}

// jsonRPCError represents a JSON-RPC 2.0 error object.
type jsonRPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// =============================================================================
// MCP Protocol Types
// =============================================================================

// mcpInitializeRequest is the MCP initialize request payload.
type mcpInitializeRequest struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    mcpCapabilities `json:"capabilities"`
	ClientInfo      mcpClientInfo   `json:"clientInfo"`
}

// mcpCapabilities represents MCP client capabilities.
type mcpCapabilities struct {
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

// mcpClientInfo represents MCP client information.
type mcpClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpInitializeResult is the MCP initialize response payload.
type mcpInitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    map[string]interface{} `json:"capabilities"`
	ServerInfo      mcpServerInfo          `json:"serverInfo"`
}

// mcpServerInfo represents MCP server information.
type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// mcpCallToolRequest is the MCP tools/call request payload.
type mcpCallToolRequest struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments,omitempty"`
}

// =============================================================================
// MCP Adapter Implementation
// =============================================================================

// MCPAdapter implements DNSCommands using the MCP (Model Context Protocol).
type MCPAdapter struct {
	endpoint    string
	httpClient  *http.Client
	initialized bool
	requestID   int64
	// ops runs the DNS operations over mcpDNSClient.
	ops *GRPCAdapter
}

// NewMCPAdapter creates a new MCP adapter for integration testing.
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

	m.ops = &GRPCAdapter{dns: mcpDNSClient{adapter: m}}
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

// callTool runs one tools/call. The platform MCP server answers with an
// MCP CallToolResult whose text block holds the tool's output as JSON
// (pkg/api/mcp Server.handleToolsCall); a tool failure is a JSON-RPC error.
func (m *MCPAdapter) callTool(ctx context.Context, toolName string, args map[string]interface{}, result interface{}) error {
	toolReq := mcpCallToolRequest{
		Name:      toolName,
		Arguments: args,
	}

	var rawResult json.RawMessage
	err := m.sendRequest(ctx, "tools/call", toolReq, &rawResult)
	var toolErr ErrMCPToolCallFailed
	if errors.As(err, &toolErr) {
		toolErr.Tool = toolName
		return toolErr
	}
	if err != nil {
		return err
	}

	if result == nil {
		_, err = mcpwire.ToolOutputJSON(rawResult)
	} else {
		err = mcpwire.DecodeToolOutput(rawResult, result)
	}
	if err != nil {
		return ErrMCPResponseParseFailed{Operation: toolName, Err: err}
	}
	return nil
}

// =============================================================================
// DNS Operations
// =============================================================================

// Each daemon dns_* MCP tool takes the arguments of its DNSService RPC request
// and returns the RPC response, both in the proto3 JSON mapping. The adapter
// therefore runs the gRPC adapter's request building and response reading
// over mcpDNSClient, a DNSServiceClient whose calls are those MCP tools.

func (m *MCPAdapter) CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error) {
	return m.ops.CreateZone(ctx, opts)
}

func (m *MCPAdapter) GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error) {
	return m.ops.GetZone(ctx, zoneName)
}

func (m *MCPAdapter) UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error) {
	return m.ops.UpdateZone(ctx, zoneName, opts)
}

func (m *MCPAdapter) DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error) {
	return m.ops.DeleteZone(ctx, zoneName)
}

func (m *MCPAdapter) ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error) {
	return m.ops.ListZones(ctx, opts)
}

func (m *MCPAdapter) AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error) {
	return m.ops.AddRecord(ctx, opts)
}

func (m *MCPAdapter) GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error) {
	return m.ops.GetRecord(ctx, name, recordType)
}

func (m *MCPAdapter) UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error) {
	return m.ops.UpdateRecord(ctx, opts)
}

func (m *MCPAdapter) DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error) {
	return m.ops.DeleteRecord(ctx, name, recordType)
}

func (m *MCPAdapter) ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error) {
	return m.ops.ListRecords(ctx, zoneName, opts)
}

func (m *MCPAdapter) Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error) {
	return m.ops.Resolve(ctx, name, recordType)
}

func (m *MCPAdapter) AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error) {
	return m.ops.AddTLSARecord(ctx, opts)
}

// mcpProtoJSON encodes tool arguments the way the daemon decodes them.
var mcpProtoJSON = protojson.MarshalOptions{UseProtoNames: true}

// mcpDNSClient is the DNSService over the daemon's dns_* MCP tools.
type mcpDNSClient struct {
	adapter *MCPAdapter
}

var _ pb.DNSServiceClient = mcpDNSClient{}

// call runs one tool: the request is its arguments, its result the response.
func (c mcpDNSClient) call(ctx context.Context, tool string, request, response proto.Message) error {
	data, err := mcpProtoJSON.Marshal(request)
	if err != nil {
		return ErrMCPRequestFailed{Err: err}
	}
	args := map[string]interface{}{}
	if err := json.Unmarshal(data, &args); err != nil {
		return ErrMCPRequestFailed{Err: err}
	}
	var result json.RawMessage
	if err := c.adapter.callTool(ctx, tool, args, &result); err != nil {
		return err
	}
	if len(result) == 0 {
		return ErrMCPEmptyResult{Tool: tool}
	}
	if err := protojson.Unmarshal(result, response); err != nil {
		return ErrMCPResponseParseFailed{Operation: tool, Err: err}
	}
	return nil
}

func (c mcpDNSClient) CreateZone(ctx context.Context, in *pb.CreateZoneRequest, _ ...grpc.CallOption) (*pb.CreateZoneResponse, error) {
	out := &pb.CreateZoneResponse{}
	if err := c.call(ctx, "dns_zone_create", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) GetZone(ctx context.Context, in *pb.GetZoneRequest, _ ...grpc.CallOption) (*pb.GetZoneResponse, error) {
	out := &pb.GetZoneResponse{}
	if err := c.call(ctx, "dns_zone_get", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) UpdateZone(ctx context.Context, in *pb.UpdateZoneRequest, _ ...grpc.CallOption) (*pb.UpdateZoneResponse, error) {
	out := &pb.UpdateZoneResponse{}
	if err := c.call(ctx, "dns_zone_update", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) DeleteZone(ctx context.Context, in *pb.DeleteZoneRequest, _ ...grpc.CallOption) (*pb.DeleteZoneResponse, error) {
	out := &pb.DeleteZoneResponse{}
	if err := c.call(ctx, "dns_zone_delete", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) ListZones(ctx context.Context, in *pb.ListZonesRequest, _ ...grpc.CallOption) (*pb.ListZonesResponse, error) {
	out := &pb.ListZonesResponse{}
	if err := c.call(ctx, "dns_zone_list", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) AddRecord(ctx context.Context, in *pb.AddRecordRequest, _ ...grpc.CallOption) (*pb.AddRecordResponse, error) {
	out := &pb.AddRecordResponse{}
	if err := c.call(ctx, "dns_record_create", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) DeleteRecord(ctx context.Context, in *pb.DeleteRecordRequest, _ ...grpc.CallOption) (*pb.DeleteRecordResponse, error) {
	out := &pb.DeleteRecordResponse{}
	if err := c.call(ctx, "dns_record_delete", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) UpdateRecord(ctx context.Context, in *pb.UpdateRecordRequest, _ ...grpc.CallOption) (*pb.UpdateRecordResponse, error) {
	out := &pb.UpdateRecordResponse{}
	if err := c.call(ctx, "dns_record_update", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) ListRecords(ctx context.Context, in *pb.ListRecordsRequest, _ ...grpc.CallOption) (*pb.ListRecordsResponse, error) {
	out := &pb.ListRecordsResponse{}
	if err := c.call(ctx, "dns_record_list", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) SignZone(ctx context.Context, in *pb.SignZoneRequest, _ ...grpc.CallOption) (*pb.SignZoneResponse, error) {
	out := &pb.SignZoneResponse{}
	if err := c.call(ctx, "dns_zone_sign", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) GetDNSSECStatus(ctx context.Context, in *pb.GetDNSSECStatusRequest, _ ...grpc.CallOption) (*pb.GetDNSSECStatusResponse, error) {
	out := &pb.GetDNSSECStatusResponse{}
	if err := c.call(ctx, "dns_zone_dnssec_status", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) Resolve(ctx context.Context, in *pb.ResolveRequest, _ ...grpc.CallOption) (*pb.ResolveResponse, error) {
	out := &pb.ResolveResponse{}
	if err := c.call(ctx, "dns_lookup", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

func (c mcpDNSClient) Register(ctx context.Context, in *pb.RegisterRequest, _ ...grpc.CallOption) (*pb.RegisterResponse, error) {
	out := &pb.RegisterResponse{}
	if err := c.call(ctx, "dns_register", in, out); err != nil {
		return nil, err
	}
	return out, nil
}

// =============================================================================
// Error Types
// =============================================================================

// ErrMCPConnectionFailed indicates the MCP connection failed.
type ErrMCPConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPConnectionFailed) Error() string {
	return fmt.Sprintf("MCP connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrMCPConnectionFailed) Unwrap() error {
	return e.Err
}

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

// ErrMCPToolCallFailed indicates an MCP tool call failed.
type ErrMCPToolCallFailed struct {
	Tool    string
	Code    int
	Message string
}

func (e ErrMCPToolCallFailed) Error() string {
	return fmt.Sprintf("MCP tool %q call failed (code %d): %s", e.Tool, e.Code, e.Message)
}

// ErrMCPEmptyResult indicates an MCP tool answered without a result, which
// would otherwise leave the caller an empty response to dereference.
type ErrMCPEmptyResult struct {
	Tool string
}

func (e ErrMCPEmptyResult) Error() string {
	return fmt.Sprintf("MCP tool %q returned no result", e.Tool)
}

// ErrMCPResponseParseFailed indicates MCP response parsing failed.
type ErrMCPResponseParseFailed struct {
	Operation string
	Err       error
}

func (e ErrMCPResponseParseFailed) Error() string {
	return fmt.Sprintf("failed to parse MCP response for %s: %v", e.Operation, e.Err)
}

func (e ErrMCPResponseParseFailed) Unwrap() error {
	return e.Err
}

// ErrMCPRequestFailed indicates an MCP HTTP request failed.
type ErrMCPRequestFailed struct {
	Err error
}

func (e ErrMCPRequestFailed) Error() string {
	return fmt.Sprintf("MCP request failed: %v", e.Err)
}

func (e ErrMCPRequestFailed) Unwrap() error {
	return e.Err
}

// Ensure MCPAdapter implements DNSCommands interface.
var _ DNSCommands = (*MCPAdapter)(nil)
