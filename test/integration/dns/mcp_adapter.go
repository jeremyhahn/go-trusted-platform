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
	"fmt"
	"io"
	"net/http"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"os"
	"sync/atomic"
	"time"
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

// JSON-RPC 2.0 standard error codes.
const (
	jsonRPCInternalError = -32603
)

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

// mcpCallToolResult is the MCP tools/call response payload.
type mcpCallToolResult struct {
	Content []mcpContentItem `json:"content"`
	IsError bool             `json:"isError,omitempty"`
}

// mcpContentItem represents a content item in a tool result.
type mcpContentItem struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
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

	var toolResult mcpCallToolResult
	if err := m.sendRequest(ctx, "tools/call", toolReq, &toolResult); err != nil {
		return err
	}

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

	if result != nil && len(toolResult.Content) > 0 {
		for _, item := range toolResult.Content {
			if item.Type == "text" && item.Text != "" {
				if err := json.Unmarshal([]byte(item.Text), result); err != nil {
					return ErrMCPResponseParseFailed{Operation: toolName, Err: err}
				}
				break
			}
		}
	}

	return nil
}

// =============================================================================
// Zone Management Operations
// =============================================================================

// CreateZone creates a new DNS zone via MCP tool call.
func (m *MCPAdapter) CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error) {
	args := map[string]interface{}{
		"name": opts.Name,
		"ttl":  opts.TTL,
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}
	if opts.Internal {
		args["internal"] = true
	}
	if opts.SOA != nil {
		args["soa"] = map[string]interface{}{
			"mname":      opts.SOA.MName,
			"rname":      opts.SOA.RName,
			"serial":     opts.SOA.Serial,
			"refresh":    opts.SOA.Refresh,
			"retry":      opts.SOA.Retry,
			"expire":     opts.SOA.Expire,
			"minimumTtl": opts.SOA.MinimumTTL,
		}
	}

	var resp mcpCreateZoneResponse
	if err := m.callTool(ctx, "platform.dns.zone.create", args, &resp); err != nil {
		return nil, err
	}

	return &CreateZoneResult{
		Name:      resp.Name,
		ID:        resp.ID,
		TTL:       resp.TTL,
		Internal:  resp.Internal,
		CreatedAt: mcpUnixMillisToTime(resp.CreatedAt),
	}, nil
}

// GetZone retrieves a DNS zone via MCP tool call.
func (m *MCPAdapter) GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error) {
	args := map[string]interface{}{
		"name": zoneName,
	}

	var resp mcpGetZoneResponse
	if err := m.callTool(ctx, "platform.dns.zone.get", args, &resp); err != nil {
		return nil, err
	}

	result := &GetZoneResult{
		Name:        resp.Name,
		ID:          resp.ID,
		TTL:         resp.TTL,
		Description: resp.Description,
		Internal:    resp.Internal,
		RecordCount: resp.RecordCount,
		CreatedAt:   mcpUnixMillisToTime(resp.CreatedAt),
		UpdatedAt:   mcpUnixMillisToTime(resp.UpdatedAt),
	}

	if resp.SOA != nil {
		result.SOA = &SOARecordInfo{
			Name:       resp.Name,
			MName:      resp.SOA.MName,
			RName:      resp.SOA.RName,
			Serial:     resp.SOA.Serial,
			Refresh:    resp.SOA.Refresh,
			Retry:      resp.SOA.Retry,
			Expire:     resp.SOA.Expire,
			MinimumTTL: resp.SOA.MinimumTTL,
			TTL:        resp.TTL,
		}
	}

	return result, nil
}

// UpdateZone updates a DNS zone via MCP tool call.
func (m *MCPAdapter) UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error) {
	args := map[string]interface{}{
		"name": zoneName,
	}
	if opts.TTL > 0 {
		args["ttl"] = opts.TTL
	}
	if opts.Description != "" {
		args["description"] = opts.Description
	}

	var resp mcpUpdateZoneResponse
	if err := m.callTool(ctx, "platform.dns.zone.update", args, &resp); err != nil {
		return nil, err
	}

	return &UpdateZoneResult{
		Name:      resp.Name,
		TTL:       resp.TTL,
		UpdatedAt: mcpUnixMillisToTime(resp.UpdatedAt),
	}, nil
}

// DeleteZone deletes a DNS zone via MCP tool call.
func (m *MCPAdapter) DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error) {
	args := map[string]interface{}{
		"name": zoneName,
	}

	var resp mcpDeleteZoneResponse
	if err := m.callTool(ctx, "platform.dns.zone.delete", args, &resp); err != nil {
		return nil, err
	}

	return &DeleteZoneResult{
		Name:    zoneName,
		Deleted: resp.Deleted,
	}, nil
}

// ListZones lists DNS zones via MCP tool call.
func (m *MCPAdapter) ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error) {
	args := map[string]interface{}{}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Cursor != "" {
		args["cursor"] = opts.Cursor
	}
	if opts.Internal != nil {
		args["internal"] = *opts.Internal
	}

	var resp mcpListZonesResponse
	if err := m.callTool(ctx, "platform.dns.zone.list", args, &resp); err != nil {
		return nil, err
	}

	zones := make([]ZoneSummary, len(resp.Zones))
	for i, z := range resp.Zones {
		zones[i] = ZoneSummary{
			Name:        z.Name,
			ID:          z.ID,
			TTL:         z.TTL,
			Internal:    z.Internal,
			RecordCount: z.RecordCount,
			CreatedAt:   mcpUnixMillisToTime(z.CreatedAt),
		}
	}

	return &ListZonesResult{
		Zones:      zones,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// =============================================================================
// Record Management Operations
// =============================================================================

// AddRecord adds a DNS record via MCP tool call.
func (m *MCPAdapter) AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error) {
	args := map[string]interface{}{
		"zoneName":   opts.ZoneName,
		"name":       opts.Name,
		"recordType": opts.RecordType,
		"value":      opts.Value,
		"ttl":        opts.TTL,
	}
	if opts.Priority > 0 {
		args["priority"] = opts.Priority
	}
	if opts.Weight > 0 {
		args["weight"] = opts.Weight
	}
	if opts.Port > 0 {
		args["port"] = opts.Port
	}

	var resp mcpAddRecordResponse
	if err := m.callTool(ctx, "platform.dns.record.add", args, &resp); err != nil {
		return nil, err
	}

	return &AddRecordResult{
		Name:       resp.Name,
		RecordType: resp.RecordType,
		Value:      resp.Value,
		TTL:        resp.TTL,
		CreatedAt:  mcpUnixMillisToTime(resp.CreatedAt),
	}, nil
}

// GetRecord retrieves a DNS record via MCP tool call.
func (m *MCPAdapter) GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error) {
	args := map[string]interface{}{
		"name":       name,
		"recordType": recordType,
	}

	var resp mcpGetRecordResponse
	if err := m.callTool(ctx, "platform.dns.record.get", args, &resp); err != nil {
		return nil, err
	}

	return &GetRecordResult{
		Name:       resp.Name,
		RecordType: resp.RecordType,
		Value:      resp.Value,
		TTL:        resp.TTL,
		Priority:   resp.Priority,
		Weight:     resp.Weight,
		Port:       resp.Port,
		CreatedAt:  mcpUnixMillisToTime(resp.CreatedAt),
		UpdatedAt:  mcpUnixMillisToTime(resp.UpdatedAt),
	}, nil
}

// UpdateRecord updates a DNS record via MCP tool call.
func (m *MCPAdapter) UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error) {
	args := map[string]interface{}{
		"zoneName":   opts.ZoneName,
		"name":       opts.Name,
		"recordType": opts.RecordType,
		"value":      opts.Value,
		"ttl":        opts.TTL,
	}
	if opts.Priority > 0 {
		args["priority"] = opts.Priority
	}
	if opts.Weight > 0 {
		args["weight"] = opts.Weight
	}
	if opts.Port > 0 {
		args["port"] = opts.Port
	}

	var resp mcpUpdateRecordResponse
	if err := m.callTool(ctx, "platform.dns.record.update", args, &resp); err != nil {
		return nil, err
	}

	return &UpdateRecordResult{
		Name:       resp.Name,
		RecordType: resp.RecordType,
		Value:      resp.Value,
		TTL:        resp.TTL,
		UpdatedAt:  mcpUnixMillisToTime(resp.UpdatedAt),
	}, nil
}

// DeleteRecord deletes a DNS record via MCP tool call.
func (m *MCPAdapter) DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error) {
	args := map[string]interface{}{
		"name":       name,
		"recordType": recordType,
	}

	var resp mcpDeleteRecordResponse
	if err := m.callTool(ctx, "platform.dns.record.delete", args, &resp); err != nil {
		return nil, err
	}

	return &DeleteRecordResult{
		Name:       name,
		RecordType: recordType,
		Deleted:    resp.Deleted,
	}, nil
}

// ListRecords lists DNS records via MCP tool call.
func (m *MCPAdapter) ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error) {
	args := map[string]interface{}{
		"zoneName": zoneName,
	}
	if opts.RecordType != "" {
		args["recordType"] = opts.RecordType
	}
	if opts.Limit > 0 {
		args["limit"] = opts.Limit
	}
	if opts.Cursor != "" {
		args["cursor"] = opts.Cursor
	}

	var resp mcpListRecordsResponse
	if err := m.callTool(ctx, "platform.dns.record.list", args, &resp); err != nil {
		return nil, err
	}

	records := make([]RecordSummary, len(resp.Records))
	for i, r := range resp.Records {
		records[i] = RecordSummary{
			Name:       r.Name,
			RecordType: r.RecordType,
			Value:      r.Value,
			TTL:        r.TTL,
			Priority:   r.Priority,
		}
	}

	return &ListRecordsResult{
		Records:    records,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// =============================================================================
// Resolution Operations
// =============================================================================

// Resolve performs DNS resolution via MCP tool call.
func (m *MCPAdapter) Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error) {
	args := map[string]interface{}{
		"name":       name,
		"recordType": recordType,
	}

	var resp mcpResolveResponse
	if err := m.callTool(ctx, "platform.dns.resolve", args, &resp); err != nil {
		return nil, err
	}

	return &ResolveResult{
		Name:       resp.Name,
		RecordType: resp.RecordType,
		Values:     resp.Values,
		TTL:        resp.TTL,
		Timestamp:  mcpUnixMillisToTime(resp.Timestamp),
	}, nil
}

// =============================================================================
// TLSA/DANE Operations
// =============================================================================

// AddTLSARecord adds a TLSA record via MCP tool call.
func (m *MCPAdapter) AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error) {
	args := map[string]interface{}{
		"zoneName":     opts.ZoneName,
		"name":         opts.Name,
		"usage":        opts.Usage,
		"selector":     opts.Selector,
		"matchingType": opts.MatchingType,
		"data":         opts.Data,
		"ttl":          opts.TTL,
	}

	var resp mcpAddTLSAResponse
	if err := m.callTool(ctx, "platform.dns.tlsa.add", args, &resp); err != nil {
		return nil, err
	}

	return &AddTLSARecordResult{
		Name:         resp.Name,
		Usage:        resp.Usage,
		Selector:     resp.Selector,
		MatchingType: resp.MatchingType,
		Data:         resp.Data,
		TTL:          resp.TTL,
		CreatedAt:    mcpUnixMillisToTime(resp.CreatedAt),
	}, nil
}

// =============================================================================
// MCP Response Types
// =============================================================================

type mcpCreateZoneResponse struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	TTL       uint32 `json:"ttl"`
	Internal  bool   `json:"internal"`
	CreatedAt int64  `json:"createdAt"`
}

type mcpGetZoneResponse struct {
	Name        string      `json:"name"`
	ID          string      `json:"id"`
	TTL         uint32      `json:"ttl"`
	Description string      `json:"description"`
	Internal    bool        `json:"internal"`
	RecordCount int         `json:"recordCount"`
	SOA         *mcpSOAInfo `json:"soa,omitempty"`
	CreatedAt   int64       `json:"createdAt"`
	UpdatedAt   int64       `json:"updatedAt"`
}

type mcpSOAInfo struct {
	MName      string `json:"mname"`
	RName      string `json:"rname"`
	Serial     uint32 `json:"serial"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	MinimumTTL uint32 `json:"minimumTtl"`
}

type mcpUpdateZoneResponse struct {
	Name      string `json:"name"`
	TTL       uint32 `json:"ttl"`
	UpdatedAt int64  `json:"updatedAt"`
}

type mcpDeleteZoneResponse struct {
	Deleted bool `json:"deleted"`
}

type mcpListZonesResponse struct {
	Zones      []mcpZoneSummary `json:"zones"`
	TotalCount int32            `json:"totalCount"`
	HasMore    bool             `json:"hasMore"`
	NextCursor string           `json:"nextCursor"`
}

type mcpZoneSummary struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	TTL         uint32 `json:"ttl"`
	Internal    bool   `json:"internal"`
	RecordCount int    `json:"recordCount"`
	CreatedAt   int64  `json:"createdAt"`
}

type mcpAddRecordResponse struct {
	Name       string `json:"name"`
	RecordType string `json:"recordType"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
	CreatedAt  int64  `json:"createdAt"`
}

type mcpGetRecordResponse struct {
	Name       string `json:"name"`
	RecordType string `json:"recordType"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
	Priority   uint16 `json:"priority"`
	Weight     uint16 `json:"weight"`
	Port       uint16 `json:"port"`
	CreatedAt  int64  `json:"createdAt"`
	UpdatedAt  int64  `json:"updatedAt"`
}

type mcpUpdateRecordResponse struct {
	Name       string `json:"name"`
	RecordType string `json:"recordType"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
	UpdatedAt  int64  `json:"updatedAt"`
}

type mcpDeleteRecordResponse struct {
	Deleted bool `json:"deleted"`
}

type mcpListRecordsResponse struct {
	Records    []mcpRecordSummary `json:"records"`
	TotalCount int32              `json:"totalCount"`
	HasMore    bool               `json:"hasMore"`
	NextCursor string             `json:"nextCursor"`
}

type mcpRecordSummary struct {
	Name       string `json:"name"`
	RecordType string `json:"recordType"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
	Priority   uint16 `json:"priority"`
}

type mcpResolveResponse struct {
	Name       string   `json:"name"`
	RecordType string   `json:"recordType"`
	Values     []string `json:"values"`
	TTL        uint32   `json:"ttl"`
	Timestamp  int64    `json:"timestamp"`
}

type mcpAddTLSAResponse struct {
	Name         string `json:"name"`
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matchingType"`
	Data         string `json:"data"`
	TTL          uint32 `json:"ttl"`
	CreatedAt    int64  `json:"createdAt"`
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
