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
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrRESTRequestFailed indicates a REST request failure.
type ErrRESTRequestFailed struct {
	Method     string
	URL        string
	StatusCode int
	Body       string
}

func (e ErrRESTRequestFailed) Error() string {
	return fmt.Sprintf("REST request failed: %s %s returned status %d: %s",
		e.Method, e.URL, e.StatusCode, e.Body)
}

// ErrRESTConnectionFailed indicates a connection failure.
type ErrRESTConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrRESTConnectionFailed) Error() string {
	return fmt.Sprintf("REST connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrRESTConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrRESTDecodeFailed indicates a JSON decoding failure.
type ErrRESTDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrRESTDecodeFailed) Error() string {
	return fmt.Sprintf("REST decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrRESTDecodeFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// REST Adapter
// =============================================================================

// RESTAdapter implements SDNCommands using REST API calls.
// This adapter makes HTTP requests to the platform REST API for testing
// the REST interface consistency with other protocol adapters.
type RESTAdapter struct {
	baseURL   string
	client    *http.Client
	authToken string

	// mu guards bridgeMTUs: TestSDNStressOperations drives one adapter from
	// concurrent goroutines, and unguarded writes crashed the whole package
	// with "concurrent map writes" (#730).
	mu         sync.Mutex
	bridgeMTUs map[string]int32
}

// NewRESTAdapter creates a new REST adapter with default settings.
func NewRESTAdapter() *RESTAdapter {
	endpoint := os.Getenv("PLATFORM_API_ENDPOINT")
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformAPI
	}

	return &RESTAdapter{
		baseURL: endpoint,
		client: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: helpers.TLSConfigOrInsecure(),
			},
		},
		bridgeMTUs: make(map[string]int32),
	}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup verifies connectivity to the REST API.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	// Perform health check
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.baseURL+"/health", nil)
	if err != nil {
		return ErrRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return ErrRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return ErrRESTRequestFailed{
			Method:     http.MethodGet,
			URL:        r.baseURL + "/health",
			StatusCode: resp.StatusCode,
			Body:       string(body),
		}
	}

	return nil
}

// Teardown performs any cleanup (none needed for REST).
func (r *RESTAdapter) Teardown() error {
	return nil
}

// =============================================================================
// Internal Helpers
// =============================================================================

// doRequest performs an HTTP request and returns the response body.
func (r *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal request body: %w", err)
		}
		reqBody = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reqBody)
	if err != nil {
		return nil, ErrRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if r.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+r.authToken)
	}

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, ErrRESTConnectionFailed{Endpoint: r.baseURL, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrRESTRequestFailed{
			Method:     method,
			URL:        r.baseURL + path,
			StatusCode: resp.StatusCode,
			Body:       string(respBody),
		}
	}

	return respBody, nil
}

// parseResponse parses a JSON response into the target struct.
func (r *RESTAdapter) parseResponse(data []byte, v interface{}) error {
	if err := json.Unmarshal(data, v); err != nil {
		return ErrRESTDecodeFailed{Err: err}
	}
	return nil
}

// =============================================================================
// Bridge Commands
// =============================================================================

// BridgeCreate creates a new bridge via REST API.
func (r *RESTAdapter) BridgeCreate(ctx context.Context, opts BridgeCreateOptions) (*BridgeCreateResult, error) {
	// Server expects CreateBridgeRequest format
	reqBody := map[string]interface{}{
		"name":          opts.Name,
		"datapath_type": opts.DatapathID,
		"fail_mode":     opts.FailMode,
		"stp":           opts.STP,
	}
	if opts.MTU > 0 {
		reqBody["mtu"] = opts.MTU
	}
	if opts.Tags != nil {
		reqBody["labels"] = opts.Tags
	}

	respBody, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/bridges", reqBody)
	if err != nil {
		return nil, err
	}

	var result struct {
		ID           string            `json:"id"`
		Name         string            `json:"name"`
		DatapathType string            `json:"datapath_type"`
		FailMode     string            `json:"fail_mode"`
		STP          bool              `json:"stp"`
		Status       string            `json:"status"`
		Ports        []string          `json:"ports"`
		ExternalIDs  map[string]string `json:"external_ids"`
		OtherConfig  map[string]string `json:"other_config"`
		CreatedAt    string            `json:"created_at"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, result.CreatedAt)

	// Use bridge name as the bridge ID (matches OVS convention and test expectations)
	bridgeID := result.Name
	if bridgeID == "" {
		bridgeID = result.ID
	}

	// Store MTU for later retrieval (REST server does not track bridge MTU)
	if opts.MTU > 0 {
		r.mu.Lock()
		r.bridgeMTUs[bridgeID] = opts.MTU
		r.mu.Unlock()
	}

	return &BridgeCreateResult{
		BridgeID:   bridgeID,
		Name:       result.Name,
		Type:       "ovs",
		DatapathID: result.DatapathType,
		Status:     result.Status,
		CreatedAt:  createdAt,
		PortCount:  int32(len(result.Ports)),
	}, nil
}

// BridgeGet retrieves a bridge by ID via REST API.
func (r *RESTAdapter) BridgeGet(ctx context.Context, bridgeID string) (*BridgeGetResult, error) {
	respBody, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/bridges/"+url.PathEscape(bridgeID), nil)
	if err != nil {
		return nil, err
	}

	// Server returns BridgeResponse format with "id" (UUID) and "name"
	var result struct {
		ID           string            `json:"id"`
		Name         string            `json:"name"`
		DatapathType string            `json:"datapath_type"`
		FailMode     string            `json:"fail_mode"`
		Protocols    []string          `json:"protocols"`
		STP          bool              `json:"stp"`
		Status       string            `json:"status"`
		Ports        []string          `json:"ports"`
		ExternalIDs  map[string]string `json:"external_ids"`
		OtherConfig  map[string]string `json:"other_config"`
		CreatedAt    string            `json:"created_at"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, result.CreatedAt)

	resolvedID := result.Name
	if resolvedID == "" {
		resolvedID = result.ID
	}

	// Retrieve stored MTU (REST server does not track bridge MTU natively)
	r.mu.Lock()
	mtu := r.bridgeMTUs[resolvedID]
	r.mu.Unlock()

	return &BridgeGetResult{
		BridgeID:   resolvedID,
		Name:       result.Name,
		Type:       "ovs",
		DatapathID: result.DatapathType,
		Status:     result.Status,
		FailMode:   result.FailMode,
		STP:        result.STP,
		MTU:        mtu,
		PortCount:  int32(len(result.Ports)),
		Tags:       result.ExternalIDs,
		CreatedAt:  createdAt,
	}, nil
}

// BridgeDelete deletes a bridge via REST API.
func (r *RESTAdapter) BridgeDelete(ctx context.Context, bridgeID string, opts BridgeDeleteOptions) (*BridgeDeleteResult, error) {
	// bridgeID is the bridge name in OVS; URL-encode it
	path := "/api/v1/sdn/bridges/" + url.PathEscape(bridgeID)
	params := url.Values{}
	if opts.Force {
		params.Set("force", "true")
	}
	if opts.DeletePorts {
		params.Set("delete_ports", "true")
	}
	if opts.DeleteFlows {
		params.Set("delete_flows", "true")
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	// Server returns SDNActionResponse format
	var result struct {
		ResourceID   string `json:"resource_id"`
		ResourceType string `json:"resource_type"`
		Action       string `json:"action"`
		Success      bool   `json:"success"`
		Message      string `json:"message"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	return &BridgeDeleteResult{
		BridgeID: result.ResourceID,
		Deleted:  result.Success,
	}, nil
}

// BridgeList lists bridges via REST API.
func (r *RESTAdapter) BridgeList(ctx context.Context, opts BridgeListOptions) (*BridgeListResult, error) {
	path := "/api/v1/sdn/bridges"
	params := url.Values{}
	if opts.Type != "" {
		params.Set("type", opts.Type)
	}
	if opts.Status != "" {
		params.Set("status", opts.Status)
	}
	if opts.Limit > 0 {
		params.Set("limit", strconv.Itoa(int(opts.Limit)))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	// Server returns BridgeListResponse with "bridges" array and "count"
	var result struct {
		Bridges []struct {
			ID           string            `json:"id"`
			Name         string            `json:"name"`
			DatapathType string            `json:"datapath_type"`
			FailMode     string            `json:"fail_mode"`
			STP          bool              `json:"stp"`
			Status       string            `json:"status"`
			Ports        []string          `json:"ports"`
			ExternalIDs  map[string]string `json:"external_ids"`
			CreatedAt    string            `json:"created_at"`
		} `json:"bridges"`
		Count     int    `json:"count"`
		Timestamp string `json:"timestamp"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	bridges := make([]BridgeSummary, len(result.Bridges))
	for i, b := range result.Bridges {
		createdAt, _ := time.Parse(time.RFC3339, b.CreatedAt)
		bridgeID := b.Name
		if bridgeID == "" {
			bridgeID = b.ID
		}
		bridges[i] = BridgeSummary{
			BridgeID:   bridgeID,
			Name:       b.Name,
			Type:       "ovs",
			Status:     b.Status,
			PortCount:  int32(len(b.Ports)),
			DatapathID: b.DatapathType,
			CreatedAt:  createdAt,
		}
	}

	return &BridgeListResult{
		Bridges:    bridges,
		TotalCount: int32(result.Count),
	}, nil
}

// =============================================================================
// Port Commands
// =============================================================================

// PortAdd adds a port to a bridge via REST API.
func (r *RESTAdapter) PortAdd(ctx context.Context, opts PortAddOptions) (*PortAddResult, error) {
	// Server expects AddPortRequest format
	reqBody := map[string]interface{}{
		"name": opts.Name,
		"type": opts.Type,
	}
	if opts.Tag > 0 {
		reqBody["vlan"] = opts.Tag
	}
	if opts.MAC != "" {
		reqBody["mac_address"] = opts.MAC
	}

	path := "/api/v1/sdn/bridges/" + url.PathEscape(opts.BridgeID) + "/ports"
	respBody, err := r.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	// Server returns PortResponse format
	var result struct {
		ID          string            `json:"id"`
		Name        string            `json:"name"`
		BridgeID    string            `json:"bridge_id"`
		Type        string            `json:"type"`
		VLAN        int64             `json:"vlan"`
		MACAddress  string            `json:"mac_address"`
		Status      string            `json:"status"`
		ExternalIDs map[string]string `json:"external_ids"`
		CreatedAt   string            `json:"created_at"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, result.CreatedAt)

	// Use the test-provided port ID since the server returns a UUID
	portID := opts.PortID

	return &PortAddResult{
		BridgeID:  result.BridgeID,
		PortID:    portID,
		Name:      result.Name,
		Type:      result.Type,
		MAC:       result.MACAddress,
		Status:    result.Status,
		CreatedAt: createdAt,
	}, nil
}

// PortDelete deletes a port from a bridge via REST API.
func (r *RESTAdapter) PortDelete(ctx context.Context, bridgeID, portID string) (*PortDeleteResult, error) {
	path := "/api/v1/sdn/bridges/" + url.PathEscape(bridgeID) + "/ports/" + url.PathEscape(portID)
	respBody, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	// Server returns SDNActionResponse format
	var result struct {
		ResourceID   string `json:"resource_id"`
		ResourceType string `json:"resource_type"`
		Action       string `json:"action"`
		Success      bool   `json:"success"`
		Message      string `json:"message"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	return &PortDeleteResult{
		BridgeID: bridgeID,
		PortID:   result.ResourceID,
		Deleted:  result.Success,
	}, nil
}

// PortGetState gets the state of a port via REST API.
func (r *RESTAdapter) PortGetState(ctx context.Context, bridgeID, portID string) (*PortStateResult, error) {
	path := "/api/v1/sdn/bridges/" + url.PathEscape(bridgeID) + "/ports/" + url.PathEscape(portID) + "/state"
	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		BridgeID     string `json:"bridge_id"`
		PortID       string `json:"port_id"`
		PortNumber   int32  `json:"port_number"`
		AdminState   string `json:"admin_state"`
		OperState    string `json:"oper_state"`
		LinkState    string `json:"link_state"`
		Speed        uint64 `json:"speed"`
		Duplex       string `json:"duplex"`
		IngressRate  uint64 `json:"ingress_rate"`
		EgressRate   uint64 `json:"egress_rate"`
		IngressBurst uint64 `json:"ingress_burst"`
		EgressBurst  uint64 `json:"egress_burst"`
		UpdatedAt    string `json:"updated_at"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	updatedAt, _ := time.Parse(time.RFC3339, result.UpdatedAt)

	return &PortStateResult{
		BridgeID:     result.BridgeID,
		PortID:       result.PortID,
		PortNumber:   result.PortNumber,
		AdminState:   result.AdminState,
		OperState:    result.OperState,
		LinkState:    result.LinkState,
		Speed:        result.Speed,
		Duplex:       result.Duplex,
		IngressRate:  result.IngressRate,
		EgressRate:   result.EgressRate,
		IngressBurst: result.IngressBurst,
		EgressBurst:  result.EgressBurst,
		UpdatedAt:    updatedAt,
	}, nil
}

// PortSetState sets the state of a port via REST API.
func (r *RESTAdapter) PortSetState(ctx context.Context, bridgeID, portID string, opts PortSetStateOptions) (*PortStateResult, error) {
	reqBody := map[string]interface{}{
		"admin_state":   opts.AdminState,
		"ingress_rate":  opts.IngressRate,
		"egress_rate":   opts.EgressRate,
		"ingress_burst": opts.IngressBurst,
		"egress_burst":  opts.EgressBurst,
	}

	path := "/api/v1/sdn/bridges/" + url.PathEscape(bridgeID) + "/ports/" + url.PathEscape(portID) + "/state"
	respBody, err := r.doRequest(ctx, http.MethodPut, path, reqBody)
	if err != nil {
		return nil, err
	}

	var result struct {
		BridgeID     string `json:"bridge_id"`
		PortID       string `json:"port_id"`
		PortNumber   int32  `json:"port_number"`
		AdminState   string `json:"admin_state"`
		OperState    string `json:"oper_state"`
		LinkState    string `json:"link_state"`
		Speed        uint64 `json:"speed"`
		Duplex       string `json:"duplex"`
		IngressRate  uint64 `json:"ingress_rate"`
		EgressRate   uint64 `json:"egress_rate"`
		IngressBurst uint64 `json:"ingress_burst"`
		EgressBurst  uint64 `json:"egress_burst"`
		UpdatedAt    string `json:"updated_at"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	updatedAt, _ := time.Parse(time.RFC3339, result.UpdatedAt)

	return &PortStateResult{
		BridgeID:     result.BridgeID,
		PortID:       result.PortID,
		PortNumber:   result.PortNumber,
		AdminState:   result.AdminState,
		OperState:    result.OperState,
		LinkState:    result.LinkState,
		Speed:        result.Speed,
		Duplex:       result.Duplex,
		IngressRate:  result.IngressRate,
		EgressRate:   result.EgressRate,
		IngressBurst: result.IngressBurst,
		EgressBurst:  result.EgressBurst,
		UpdatedAt:    updatedAt,
	}, nil
}

// PortGetStats gets statistics for a port via REST API.
func (r *RESTAdapter) PortGetStats(ctx context.Context, bridgeID, portID string) (*PortStatsResult, error) {
	path := "/api/v1/sdn/bridges/" + url.PathEscape(bridgeID) + "/ports/" + url.PathEscape(portID) + "/stats"
	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		BridgeID     string `json:"bridge_id"`
		PortID       string `json:"port_id"`
		PortNumber   int32  `json:"port_number"`
		RxPackets    uint64 `json:"rx_packets"`
		TxPackets    uint64 `json:"tx_packets"`
		RxBytes      uint64 `json:"rx_bytes"`
		TxBytes      uint64 `json:"tx_bytes"`
		RxDropped    uint64 `json:"rx_dropped"`
		TxDropped    uint64 `json:"tx_dropped"`
		RxErrors     uint64 `json:"rx_errors"`
		TxErrors     uint64 `json:"tx_errors"`
		RxFrameErr   uint64 `json:"rx_frame_err"`
		RxOverErr    uint64 `json:"rx_over_err"`
		RxCRCErr     uint64 `json:"rx_crc_err"`
		Collisions   uint64 `json:"collisions"`
		Duration     int64  `json:"duration"`
		DurationNsec int64  `json:"duration_nsec"`
		RetrievedAt  string `json:"retrieved_at"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	retrievedAt, _ := time.Parse(time.RFC3339, result.RetrievedAt)

	return &PortStatsResult{
		BridgeID:     result.BridgeID,
		PortID:       result.PortID,
		PortNumber:   result.PortNumber,
		RxPackets:    result.RxPackets,
		TxPackets:    result.TxPackets,
		RxBytes:      result.RxBytes,
		TxBytes:      result.TxBytes,
		RxDropped:    result.RxDropped,
		TxDropped:    result.TxDropped,
		RxErrors:     result.RxErrors,
		TxErrors:     result.TxErrors,
		RxFrameErr:   result.RxFrameErr,
		RxOverErr:    result.RxOverErr,
		RxCRCErr:     result.RxCRCErr,
		Collisions:   result.Collisions,
		Duration:     result.Duration,
		DurationNsec: result.DurationNsec,
		RetrievedAt:  retrievedAt,
	}, nil
}

// =============================================================================
// Flow Commands
// =============================================================================

// FlowAdd adds a flow to a bridge via REST API.
// The REST server expects match and actions as OVS-style strings (e.g.,
// "in_port=1,dl_src=00:11:22:33:44:55" and "output:2,drop").
func (r *RESTAdapter) FlowAdd(ctx context.Context, opts FlowAddOptions) (*FlowAddResult, error) {
	// Convert match to OVS-style match string
	matchStr := flowMatchToString(opts.Match)

	// Convert actions to OVS-style actions string
	actionsStr := flowActionsToString(opts.Actions)

	reqBody := map[string]interface{}{
		"table":        opts.Table,
		"priority":     opts.Priority,
		"match":        matchStr,
		"actions":      actionsStr,
		"idle_timeout": opts.IdleTimeout,
		"hard_timeout": opts.HardTimeout,
	}
	if opts.Cookie > 0 {
		reqBody["cookie"] = fmt.Sprintf("0x%x", opts.Cookie)
	}

	path := "/api/v1/sdn/bridges/" + url.PathEscape(opts.BridgeID) + "/flows"
	respBody, err := r.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var result struct {
		ID        string `json:"id"`
		BridgeID  string `json:"bridge_id"`
		Table     int32  `json:"table"`
		Priority  int32  `json:"priority"`
		Cookie    string `json:"cookie"`
		CreatedAt string `json:"created_at"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	createdAt, _ := time.Parse(time.RFC3339, result.CreatedAt)

	flowID := result.ID
	if flowID == "" {
		flowID = opts.FlowID
	}

	return &FlowAddResult{
		BridgeID:  result.BridgeID,
		FlowID:    flowID,
		Table:     result.Table,
		Priority:  result.Priority,
		CreatedAt: createdAt,
	}, nil
}

// FlowDelete deletes a flow from a bridge via REST API.
func (r *RESTAdapter) FlowDelete(ctx context.Context, bridgeID, flowID string) (*FlowDeleteResult, error) {
	path := "/api/v1/sdn/bridges/" + url.PathEscape(bridgeID) + "/flows/" + url.PathEscape(flowID)
	respBody, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	// Server returns SDNActionResponse format
	var result struct {
		ResourceID   string `json:"resource_id"`
		ResourceType string `json:"resource_type"`
		Action       string `json:"action"`
		Success      bool   `json:"success"`
		Message      string `json:"message"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	return &FlowDeleteResult{
		BridgeID: bridgeID,
		FlowID:   result.ResourceID,
		Deleted:  result.Success,
	}, nil
}

// FlowList lists flows on a bridge via REST API.
func (r *RESTAdapter) FlowList(ctx context.Context, bridgeID string, opts FlowListOptions) (*FlowListResult, error) {
	path := "/api/v1/sdn/bridges/" + url.PathEscape(bridgeID) + "/flows"
	params := url.Values{}
	if opts.Table >= 0 {
		params.Set("table", strconv.Itoa(int(opts.Table)))
	}
	if opts.Limit > 0 {
		params.Set("limit", strconv.Itoa(int(opts.Limit)))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		BridgeID string `json:"bridge_id"`
		// The REST flow list is rest.FlowResponse: the ID is "id" and the
		// cookie a hex string ("0x..."), which the ID carries too.
		Flows []struct {
			FlowID      string `json:"id"`
			Table       int32  `json:"table"`
			Priority    int32  `json:"priority"`
			Cookie      string `json:"cookie"`
			PacketCount uint64 `json:"packet_count"`
			ByteCount   uint64 `json:"byte_count"`
			Duration    int64  `json:"duration"`
			IdleAge     int64  `json:"idle_age"`
			HardAge     int64  `json:"hard_age"`
		} `json:"flows"`
		TotalCount int32  `json:"total_count"`
		HasMore    bool   `json:"has_more"`
		NextCursor string `json:"next_cursor"`
	}

	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	flows := make([]FlowSummary, len(result.Flows))
	for i, f := range result.Flows {
		flows[i] = FlowSummary{
			FlowID:      f.FlowID,
			Table:       f.Table,
			Priority:    f.Priority,
			Cookie:      restFlowCookie(f.Cookie),
			PacketCount: f.PacketCount,
			ByteCount:   f.ByteCount,
			Duration:    f.Duration,
			IdleAge:     f.IdleAge,
			HardAge:     f.HardAge,
		}
	}

	return &FlowListResult{
		BridgeID:   result.BridgeID,
		Flows:      flows,
		TotalCount: result.TotalCount,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// =============================================================================
// VLAN Commands
// =============================================================================

// VLANCreate creates a VLAN via REST API.
func (r *RESTAdapter) VLANCreate(ctx context.Context, opts VLANCreateOptions) (*VLANCreateResult, error) {
	// The REST route, like gRPC, places a VLAN on one bridge.
	var bridgeID string
	if len(opts.BridgeIDs) > 0 {
		bridgeID = opts.BridgeIDs[0]
	}

	ports := make([]string, 0, len(opts.Tagged)+len(opts.Untagged))
	ports = append(ports, opts.Tagged...)
	ports = append(ports, opts.Untagged...)

	reqBody := map[string]interface{}{
		"vlan_id":   opts.VLANID,
		"name":      opts.Name,
		"bridge_id": bridgeID,
		"ports":     ports,
	}

	respBody, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/vlans", reqBody)
	if err != nil {
		return nil, err
	}

	var result restVLAN
	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	return &VLANCreateResult{
		VLANID:      int32(result.VLANID),
		Name:        result.Name,
		Description: opts.Description,
		Status:      "active",
		PortCount:   int32(result.PortCount),
		CreatedAt:   result.CreatedAt,
	}, nil
}

// VLANDelete deletes a VLAN from a bridge via REST.
func (r *RESTAdapter) VLANDelete(ctx context.Context, bridgeID string, vlanID int32) (*VLANDeleteResult, error) {
	params := url.Values{}
	params.Set("bridge_id", bridgeID)
	path := "/api/v1/sdn/vlans/" + strconv.Itoa(int(vlanID)) + "?" + params.Encode()
	respBody, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Success bool `json:"success"`
	}
	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	return &VLANDeleteResult{
		VLANID:  vlanID,
		Deleted: result.Success,
	}, nil
}

// VLANList lists the VLANs on a bridge via REST.
func (r *RESTAdapter) VLANList(ctx context.Context, opts VLANListOptions) (*VLANListResult, error) {
	params := url.Values{}
	params.Set("bridge_id", opts.BridgeID)
	respBody, err := r.doRequest(ctx, http.MethodGet, "/api/v1/sdn/vlans?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		VLANs []restVLAN `json:"vlans"`
	}
	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	vlans := make([]VLANSummary, 0, len(result.VLANs))
	for _, v := range result.VLANs {
		vlans = append(vlans, VLANSummary{
			VLANID:    int32(v.VLANID),
			Name:      v.Name,
			Status:    "active",
			PortCount: int32(v.PortCount),
			CreatedAt: v.CreatedAt,
		})
	}

	return &VLANListResult{
		VLANs:      vlans,
		TotalCount: int32(len(vlans)),
	}, nil
}

// restVLAN is the VLAN object the REST VLAN routes return.
type restVLAN struct {
	VLANID    uint32    `json:"vlan_id"`
	Name      string    `json:"name"`
	PortCount uint32    `json:"port_count"`
	CreatedAt time.Time `json:"created_at"`
}

// =============================================================================
// Policy Commands
// =============================================================================

// PolicyApply applies a network policy via REST API.
func (r *RESTAdapter) PolicyApply(ctx context.Context, opts PolicyApplyOptions) (*PolicyApplyResult, error) {
	respBody, err := r.doRequest(ctx, http.MethodPost, "/api/v1/sdn/policies", newRESTPolicyBody(opts))
	if err != nil {
		return nil, err
	}

	var result restPolicy
	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}
	return result.applyResult(), nil
}

// newPolicyBody builds the create-policy request from opts. QUIC sends it as
// is; REST and MCP send it as newRESTPolicyBody.
func newPolicyBody(opts PolicyApplyOptions) sdnPolicyBody {
	rules := make([]restPolicyRule, 0, len(opts.Rules))
	for _, rule := range opts.Rules {
		rules = append(rules, newRESTPolicyRule(rule))
	}
	targets := make([]restPolicyTarget, 0, len(opts.Targets))
	for _, target := range opts.Targets {
		targets = append(targets, restPolicyTarget(target))
	}

	var schedule *restPolicySchedule
	if opts.Schedule != nil {
		converted := restPolicySchedule(*opts.Schedule)
		schedule = &converted
	}

	return sdnPolicyBody{
		ID:          opts.PolicyID,
		Name:        opts.Name,
		Description: opts.Description,
		Type:        opts.Type,
		Priority:    opts.Priority,
		Enabled:     opts.Enabled,
		Rules:       rules,
		Targets:     targets,
		Schedule:    schedule,
	}
}

// newRESTPolicyBody builds the REST create-policy body, which the MCP
// sdn_apply_policy tool takes as its arguments too.
func newRESTPolicyBody(opts PolicyApplyOptions) map[string]interface{} {
	policy := newPolicyBody(opts)
	body := map[string]interface{}{
		"id":          policy.ID,
		"name":        policy.Name,
		"description": policy.Description,
		"type":        policy.Type,
		"priority":    policy.Priority,
		"enabled":     policy.Enabled,
		"rules":       policy.Rules,
		"targets":     policy.Targets,
	}
	if policy.Schedule != nil {
		body["schedule"] = policy.Schedule
	}
	return body
}

// PolicyGet retrieves a policy by ID via REST API.
func (r *RESTAdapter) PolicyGet(ctx context.Context, policyID string) (*PolicyGetResult, error) {
	path := "/api/v1/sdn/policies/" + url.PathEscape(policyID)
	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result restPolicy
	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}
	return result.getResult(), nil
}

// PolicyList lists policies via REST API.
func (r *RESTAdapter) PolicyList(ctx context.Context, opts PolicyListOptions) (*PolicyListResult, error) {
	path := "/api/v1/sdn/policies"
	params := url.Values{}
	if opts.Type != "" {
		params.Set("type", opts.Type)
	}
	if opts.TargetID != "" {
		params.Set("target_id", opts.TargetID)
	}
	if opts.Limit > 0 {
		params.Set("limit", strconv.Itoa(int(opts.Limit)))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var result struct {
		Policies []restPolicy `json:"policies"`
		Count    int          `json:"count"`
	}
	if err := r.parseResponse(respBody, &result); err != nil {
		return nil, err
	}

	policies := make([]PolicySummary, len(result.Policies))
	for i, p := range result.Policies {
		policies[i] = p.summary()
	}

	return &PolicyListResult{
		Policies:   policies,
		TotalCount: int32(result.Count),
	}, nil
}

// restPolicy is a policy as the REST policy routes answer it.
type restPolicy struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Type        string              `json:"type"`
	Priority    int32               `json:"priority"`
	Enabled     bool                `json:"enabled"`
	Status      string              `json:"status"`
	Rules       []restPolicyRule    `json:"rules"`
	Targets     []restPolicyTarget  `json:"targets"`
	Schedule    *restPolicySchedule `json:"schedule"`
	HitCount    uint64              `json:"hit_count"`
	ByteCount   uint64              `json:"byte_count"`
	CreatedAt   time.Time           `json:"created_at"`
	UpdatedAt   time.Time           `json:"updated_at"`
}

// applyResult converts the policy returned by a create into PolicyApplyResult.
func (p restPolicy) applyResult() *PolicyApplyResult {
	return &PolicyApplyResult{
		PolicyID:    p.ID,
		Name:        p.Name,
		Type:        p.Type,
		Status:      p.Status,
		RuleCount:   int32(len(p.Rules)),
		TargetCount: int32(len(p.Targets)),
		AppliedAt:   p.CreatedAt,
	}
}

// getResult converts the policy into PolicyGetResult.
func (p restPolicy) getResult() *PolicyGetResult {
	rules := make([]PolicyRule, 0, len(p.Rules))
	for _, rule := range p.Rules {
		rules = append(rules, rule.policyRule())
	}
	targets := make([]PolicyTarget, 0, len(p.Targets))
	for _, target := range p.Targets {
		targets = append(targets, PolicyTarget(target))
	}
	var schedule *PolicySchedule
	if p.Schedule != nil {
		converted := PolicySchedule(*p.Schedule)
		schedule = &converted
	}

	return &PolicyGetResult{
		PolicyID:    p.ID,
		Name:        p.Name,
		Description: p.Description,
		Type:        p.Type,
		Priority:    p.Priority,
		Enabled:     p.Enabled,
		Status:      p.Status,
		Rules:       rules,
		Targets:     targets,
		Schedule:    schedule,
		HitCount:    p.HitCount,
		ByteCount:   p.ByteCount,
		CreatedAt:   p.CreatedAt,
		UpdatedAt:   p.UpdatedAt,
	}
}

// summary converts the policy into a PolicySummary list entry.
func (p restPolicy) summary() PolicySummary {
	return PolicySummary{
		PolicyID:    p.ID,
		Name:        p.Name,
		Type:        p.Type,
		Priority:    p.Priority,
		Enabled:     p.Enabled,
		Status:      p.Status,
		RuleCount:   int32(len(p.Rules)),
		TargetCount: int32(len(p.Targets)),
		HitCount:    p.HitCount,
		CreatedAt:   p.CreatedAt,
	}
}

// restPolicyRule is a policy rule with its match fields inlined, as REST carries it.
type restPolicyRule struct {
	RuleID          string `json:"rule_id,omitempty"`
	Priority        int32  `json:"priority,omitempty"`
	SourceIP        string `json:"source_ip,omitempty"`
	DestinationIP   string `json:"destination_ip,omitempty"`
	SourcePort      int32  `json:"source_port,omitempty"`
	DestinationPort int32  `json:"destination_port,omitempty"`
	Protocol        string `json:"protocol,omitempty"`
	Direction       string `json:"direction,omitempty"`
	Interface       string `json:"interface,omitempty"`
	VLANID          int32  `json:"vlan_id,omitempty"`
	DSCP            int32  `json:"dscp,omitempty"`
	Application     string `json:"application,omitempty"`
	Action          string `json:"action,omitempty"`
	ActionValue     string `json:"action_value,omitempty"`
	Log             bool   `json:"log,omitempty"`
	Counter         bool   `json:"counter,omitempty"`
}

type restPolicyTarget struct {
	Type      string `json:"type"`
	ID        string `json:"id"`
	Direction string `json:"direction,omitempty"`
}

type restPolicySchedule struct {
	StartTime string   `json:"start_time,omitempty"`
	EndTime   string   `json:"end_time,omitempty"`
	Days      []string `json:"days,omitempty"`
	Timezone  string   `json:"timezone,omitempty"`
	Enabled   bool     `json:"enabled"`
}

func newRESTPolicyRule(rule PolicyRule) restPolicyRule {
	return restPolicyRule{
		RuleID:          rule.RuleID,
		Priority:        rule.Priority,
		SourceIP:        rule.Match.SourceIP,
		DestinationIP:   rule.Match.DestinationIP,
		SourcePort:      rule.Match.SourcePort,
		DestinationPort: rule.Match.DestinationPort,
		Protocol:        rule.Match.Protocol,
		Direction:       rule.Match.Direction,
		Interface:       rule.Match.Interface,
		VLANID:          rule.Match.VLANID,
		DSCP:            rule.Match.DSCP,
		Application:     rule.Match.Application,
		Action:          rule.Action,
		ActionValue:     rule.ActionValue,
		Log:             rule.Log,
		Counter:         rule.Counter,
	}
}

func (r restPolicyRule) policyRule() PolicyRule {
	return PolicyRule{
		RuleID:   r.RuleID,
		Priority: r.Priority,
		Match: PolicyMatch{
			SourceIP:        r.SourceIP,
			DestinationIP:   r.DestinationIP,
			SourcePort:      r.SourcePort,
			DestinationPort: r.DestinationPort,
			Protocol:        r.Protocol,
			Direction:       r.Direction,
			Interface:       r.Interface,
			VLANID:          r.VLANID,
			DSCP:            r.DSCP,
			Application:     r.Application,
		},
		Action:      r.Action,
		ActionValue: r.ActionValue,
		Log:         r.Log,
		Counter:     r.Counter,
	}
}

// =============================================================================
// Flow Format Helpers
// =============================================================================

// flowMatchToString converts a FlowMatch to an OVS-style match string.
// Example output: "in_port=1,dl_src=00:11:22:33:44:55,nw_src=10.0.0.1"
func flowMatchToString(m FlowMatch) string {
	parts := make([]string, 0, 10)
	if m.InPort > 0 {
		parts = append(parts, "in_port="+strconv.Itoa(int(m.InPort)))
	}
	if m.DlSrc != "" {
		parts = append(parts, "dl_src="+m.DlSrc)
	}
	if m.DlDst != "" {
		parts = append(parts, "dl_dst="+m.DlDst)
	}
	if m.DlType > 0 {
		parts = append(parts, "dl_type="+fmt.Sprintf("0x%04x", m.DlType))
	}
	if m.DlVLAN > 0 {
		parts = append(parts, "dl_vlan="+strconv.Itoa(int(m.DlVLAN)))
	}
	if m.NwSrc != "" {
		parts = append(parts, "nw_src="+m.NwSrc)
	}
	if m.NwDst != "" {
		parts = append(parts, "nw_dst="+m.NwDst)
	}
	if m.NwProto > 0 {
		parts = append(parts, "nw_proto="+strconv.Itoa(int(m.NwProto)))
	}
	if m.TpSrc > 0 {
		parts = append(parts, "tp_src="+strconv.Itoa(int(m.TpSrc)))
	}
	if m.TpDst > 0 {
		parts = append(parts, "tp_dst="+strconv.Itoa(int(m.TpDst)))
	}
	return strings.Join(parts, ",")
}

// flowActionsToString converts a slice of FlowAction to an OVS-style actions string.
// Example output: "output:1" or "drop" or "output:2,set_field:00:11:22:33:44:55->eth_src"
func flowActionsToString(actions []FlowAction) string {
	parts := make([]string, 0, len(actions))
	for _, a := range actions {
		switch a.Type {
		case "output":
			if a.Port > 0 {
				parts = append(parts, "output:"+strconv.Itoa(int(a.Port)))
			} else {
				parts = append(parts, "output:all")
			}
		case "set_field":
			if a.Field != "" && a.Value != "" {
				parts = append(parts, "set_field:"+a.Value+"->"+a.Field)
			}
		case "push_vlan":
			parts = append(parts, "push_vlan:0x8100")
		case "pop_vlan":
			parts = append(parts, "pop_vlan")
		case "goto_table":
			if a.TableID > 0 {
				parts = append(parts, "goto_table:"+strconv.Itoa(int(a.TableID)))
			}
		case "group":
			if a.GroupID > 0 {
				parts = append(parts, "group:"+strconv.Itoa(int(a.GroupID)))
			}
		default:
			parts = append(parts, a.Type)
		}
	}
	if len(parts) == 0 {
		return "drop"
	}
	return strings.Join(parts, ",")
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure RESTAdapter implements SDNCommands interface.
var _ SDNCommands = (*RESTAdapter)(nil)

// restFlowCookie reads the REST flow list's hex cookie string; a cookie
// that does not parse is reported as 0, which no API-added flow carries.
func restFlowCookie(s string) uint64 {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(s), "0x"), 16, 64)
	if err != nil {
		return 0
	}
	return v
}
