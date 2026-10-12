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
// This file implements the DNSCommands interface using HTTP/REST.

//go:build integration

package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrRESTConnectionFailed indicates the REST API connection failed.
type ErrRESTConnectionFailed struct {
	URL string
	Err error
}

func (e ErrRESTConnectionFailed) Error() string {
	return fmt.Sprintf("REST API connection failed to %s: %v", e.URL, e.Err)
}

func (e ErrRESTConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrRESTRequestFailed indicates the HTTP request failed.
type ErrRESTRequestFailed struct {
	Err error
}

func (e ErrRESTRequestFailed) Error() string {
	return fmt.Sprintf("HTTP request failed: %v", e.Err)
}

func (e ErrRESTRequestFailed) Unwrap() error {
	return e.Err
}

// ErrRESTAPIError indicates an error response from the REST API.
type ErrRESTAPIError struct {
	StatusCode int
	Message    string
}

func (e ErrRESTAPIError) Error() string {
	return fmt.Sprintf("REST API error (status %d): %s", e.StatusCode, e.Message)
}

// =============================================================================
// REST Adapter Implementation
// =============================================================================

// RESTAdapter implements DNSCommands using HTTP/REST calls to platformd.
type RESTAdapter struct {
	baseURL    string
	httpClient *http.Client
}

// NewRESTAdapter creates a new REST adapter for integration testing.
func NewRESTAdapter() *RESTAdapter {
	endpoint := os.Getenv(EnvPlatformAPIEndpoint)
	if endpoint == "" {
		endpoint = DefaultPlatformAPIEndpoint
	}

	return &RESTAdapter{
		baseURL: "http://" + endpoint,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST client.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	// Verify connectivity by checking health endpoint
	_, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/dns/health", nil)
	if err != nil {
		return ErrRESTConnectionFailed{URL: r.baseURL, Err: err}
	}
	if statusCode != http.StatusOK {
		return ErrRESTAPIError{StatusCode: statusCode, Message: "health check failed"}
	}

	return nil
}

// Teardown cleans up REST client resources.
func (r *RESTAdapter) Teardown() error {
	if r.httpClient != nil {
		r.httpClient.CloseIdleConnections()
	}
	return nil
}

// =============================================================================
// HTTP Request Helpers
// =============================================================================

// doRequest performs an HTTP request with JSON serialization.
func (r *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, ErrRESTRequestFailed{Err: fmt.Errorf("failed to marshal request: %w", err)}
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reqBody)
	if err != nil {
		return nil, 0, ErrRESTRequestFailed{Err: fmt.Errorf("failed to create request: %w", err)}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, ErrRESTConnectionFailed{URL: r.baseURL, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, ErrRESTRequestFailed{Err: fmt.Errorf("failed to read response: %w", err)}
	}

	return respBody, resp.StatusCode, nil
}

// handleResponse processes the HTTP response and unmarshals into the target.
func (r *RESTAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		return r.parseErrorResponse(respBody, statusCode)
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return ErrRESTRequestFailed{Err: fmt.Errorf("failed to unmarshal response: %w", err)}
		}
	}

	return nil
}

// parseErrorResponse extracts error information from error responses.
func (r *RESTAdapter) parseErrorResponse(respBody []byte, statusCode int) error {
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(respBody, &errResp); err != nil {
		return ErrRESTAPIError{StatusCode: statusCode, Message: string(respBody)}
	}

	msg := errResp.Error
	if msg == "" {
		msg = errResp.Message
	}

	return ErrRESTAPIError{StatusCode: statusCode, Message: msg}
}

// =============================================================================
// Zone Management Commands
// =============================================================================

// CreateZone creates a new DNS zone via REST API.
func (r *RESTAdapter) CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error) {
	reqBody := map[string]interface{}{
		"name": opts.Name,
		"ttl":  opts.TTL,
	}

	if opts.Description != "" {
		reqBody["description"] = opts.Description
	}
	if opts.Internal {
		reqBody["internal"] = true
	}
	if opts.SOA != nil {
		reqBody["soa"] = map[string]interface{}{
			"mname":       opts.SOA.MName,
			"rname":       opts.SOA.RName,
			"serial":      opts.SOA.Serial,
			"refresh":     opts.SOA.Refresh,
			"retry":       opts.SOA.Retry,
			"expire":      opts.SOA.Expire,
			"minimum_ttl": opts.SOA.MinimumTTL,
		}
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/dns/zones", reqBody)
	if err != nil {
		return nil, err
	}

	var resp restCreateZoneResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// GetZone retrieves zone information via REST API.
func (r *RESTAdapter) GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error) {
	path := "/api/v1/dns/zones/" + url.PathEscape(zoneName)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restGetZoneResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// UpdateZone updates a zone via REST API.
func (r *RESTAdapter) UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error) {
	path := "/api/v1/dns/zones/" + url.PathEscape(zoneName)

	reqBody := map[string]interface{}{}
	if opts.TTL > 0 {
		reqBody["ttl"] = opts.TTL
	}
	if opts.Description != "" {
		reqBody["description"] = opts.Description
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp restUpdateZoneResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// DeleteZone deletes a zone via REST API.
func (r *RESTAdapter) DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error) {
	path := "/api/v1/dns/zones/" + url.PathEscape(zoneName)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restDeleteZoneResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// ListZones lists zones via REST API.
func (r *RESTAdapter) ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error) {
	params := url.Values{}
	if opts.Limit > 0 {
		params.Set("limit", strconv.FormatInt(int64(opts.Limit), 10))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}
	if opts.Internal != nil {
		params.Set("internal", strconv.FormatBool(*opts.Internal))
	}

	path := "/api/v1/dns/zones"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restListZonesResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// Record Management Commands
// =============================================================================

// AddRecord adds a DNS record via REST API.
func (r *RESTAdapter) AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error) {
	path := "/api/v1/dns/zones/" + url.PathEscape(opts.ZoneName) + "/records"

	reqBody := map[string]interface{}{
		"name":        opts.Name,
		"record_type": opts.RecordType,
		"value":       opts.Value,
	}

	if opts.TTL > 0 {
		reqBody["ttl"] = opts.TTL
	}
	if opts.Priority > 0 {
		reqBody["priority"] = opts.Priority
	}
	if opts.Weight > 0 {
		reqBody["weight"] = opts.Weight
	}
	if opts.Port > 0 {
		reqBody["port"] = opts.Port
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp restAddRecordResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// GetRecord retrieves a record via REST API.
func (r *RESTAdapter) GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error) {
	path := "/api/v1/dns/records/" + url.PathEscape(name) + "/" + url.PathEscape(recordType)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restGetRecordResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// UpdateRecord updates a record via REST API.
func (r *RESTAdapter) UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error) {
	path := "/api/v1/dns/zones/" + url.PathEscape(opts.ZoneName) + "/records/" +
		url.PathEscape(opts.Name) + "/" + url.PathEscape(opts.RecordType)

	reqBody := map[string]interface{}{}
	if opts.Value != "" {
		reqBody["value"] = opts.Value
	}
	if opts.TTL > 0 {
		reqBody["ttl"] = opts.TTL
	}
	if opts.Priority > 0 {
		reqBody["priority"] = opts.Priority
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp restUpdateRecordResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// DeleteRecord deletes a record via REST API.
func (r *RESTAdapter) DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error) {
	path := "/api/v1/dns/records/" + url.PathEscape(name) + "/" + url.PathEscape(recordType)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restDeleteRecordResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// ListRecords lists records in a zone via REST API.
func (r *RESTAdapter) ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error) {
	params := url.Values{}
	if opts.RecordType != "" {
		params.Set("type", opts.RecordType)
	}
	if opts.Limit > 0 {
		params.Set("limit", strconv.FormatInt(int64(opts.Limit), 10))
	}
	if opts.Cursor != "" {
		params.Set("cursor", opts.Cursor)
	}

	path := "/api/v1/dns/zones/" + url.PathEscape(zoneName) + "/records"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restListRecordsResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// Resolution Commands
// =============================================================================

// Resolve performs DNS resolution via REST API.
func (r *RESTAdapter) Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error) {
	path := "/api/v1/dns/resolve/" + url.PathEscape(name) + "/" + url.PathEscape(recordType)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restResolveResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// TLSA/DANE Commands
// =============================================================================

// AddTLSARecord adds a TLSA record via REST API.
func (r *RESTAdapter) AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error) {
	path := "/api/v1/dns/zones/" + url.PathEscape(opts.ZoneName) + "/tlsa"

	reqBody := map[string]interface{}{
		"name":          opts.Name,
		"usage":         opts.Usage,
		"selector":      opts.Selector,
		"matching_type": opts.MatchingType,
		"data":          opts.Data,
	}

	if opts.TTL > 0 {
		reqBody["ttl"] = opts.TTL
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp restAddTLSARecordResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// REST Response Types and Conversion
// =============================================================================

type restCreateZoneResponse struct {
	Name      string `json:"name"`
	ID        string `json:"id"`
	TTL       uint32 `json:"ttl"`
	Internal  bool   `json:"internal"`
	CreatedAt int64  `json:"created_at"`
}

func (r *restCreateZoneResponse) toResult() *CreateZoneResult {
	return &CreateZoneResult{
		Name:      r.Name,
		ID:        r.ID,
		TTL:       r.TTL,
		Internal:  r.Internal,
		CreatedAt: time.Unix(r.CreatedAt, 0),
	}
}

type restGetZoneResponse struct {
	Name        string         `json:"name"`
	ID          string         `json:"id"`
	TTL         uint32         `json:"ttl"`
	Description string         `json:"description"`
	Internal    bool           `json:"internal"`
	SOA         *restSOARecord `json:"soa"`
	RecordCount int            `json:"record_count"`
	CreatedAt   int64          `json:"created_at"`
	UpdatedAt   int64          `json:"updated_at"`
}

type restSOARecord struct {
	Name       string `json:"name"`
	MName      string `json:"mname"`
	RName      string `json:"rname"`
	Serial     uint32 `json:"serial"`
	Refresh    uint32 `json:"refresh"`
	Retry      uint32 `json:"retry"`
	Expire     uint32 `json:"expire"`
	MinimumTTL uint32 `json:"minimum_ttl"`
	TTL        uint32 `json:"ttl"`
}

func (r *restGetZoneResponse) toResult() *GetZoneResult {
	result := &GetZoneResult{
		Name:        r.Name,
		ID:          r.ID,
		TTL:         r.TTL,
		Description: r.Description,
		Internal:    r.Internal,
		RecordCount: r.RecordCount,
		CreatedAt:   time.Unix(r.CreatedAt, 0),
		UpdatedAt:   time.Unix(r.UpdatedAt, 0),
	}

	if r.SOA != nil {
		result.SOA = &SOARecordInfo{
			Name:       r.SOA.Name,
			MName:      r.SOA.MName,
			RName:      r.SOA.RName,
			Serial:     r.SOA.Serial,
			Refresh:    r.SOA.Refresh,
			Retry:      r.SOA.Retry,
			Expire:     r.SOA.Expire,
			MinimumTTL: r.SOA.MinimumTTL,
			TTL:        r.SOA.TTL,
		}
	}

	return result
}

type restUpdateZoneResponse struct {
	Name      string `json:"name"`
	TTL       uint32 `json:"ttl"`
	UpdatedAt int64  `json:"updated_at"`
}

func (r *restUpdateZoneResponse) toResult() *UpdateZoneResult {
	return &UpdateZoneResult{
		Name:      r.Name,
		TTL:       r.TTL,
		UpdatedAt: time.Unix(r.UpdatedAt, 0),
	}
}

type restDeleteZoneResponse struct {
	Name    string `json:"name"`
	Deleted bool   `json:"deleted"`
}

func (r *restDeleteZoneResponse) toResult() *DeleteZoneResult {
	return &DeleteZoneResult{
		Name:    r.Name,
		Deleted: r.Deleted,
	}
}

type restListZonesResponse struct {
	Zones      []restZoneSummary `json:"zones"`
	TotalCount int32             `json:"total_count"`
	HasMore    bool              `json:"has_more"`
	NextCursor string            `json:"next_cursor"`
}

type restZoneSummary struct {
	Name        string `json:"name"`
	ID          string `json:"id"`
	TTL         uint32 `json:"ttl"`
	Internal    bool   `json:"internal"`
	RecordCount int    `json:"record_count"`
	CreatedAt   int64  `json:"created_at"`
}

func (r *restListZonesResponse) toResult() *ListZonesResult {
	result := &ListZonesResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}

	for _, z := range r.Zones {
		result.Zones = append(result.Zones, ZoneSummary{
			Name:        z.Name,
			ID:          z.ID,
			TTL:         z.TTL,
			Internal:    z.Internal,
			RecordCount: z.RecordCount,
			CreatedAt:   time.Unix(z.CreatedAt, 0),
		})
	}

	return result
}

type restAddRecordResponse struct {
	Name       string `json:"name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
	CreatedAt  int64  `json:"created_at"`
}

func (r *restAddRecordResponse) toResult() *AddRecordResult {
	return &AddRecordResult{
		Name:       r.Name,
		RecordType: r.RecordType,
		Value:      r.Value,
		TTL:        r.TTL,
		CreatedAt:  time.Unix(r.CreatedAt, 0),
	}
}

type restGetRecordResponse struct {
	Name       string `json:"name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
	Priority   uint16 `json:"priority"`
	Weight     uint16 `json:"weight"`
	Port       uint16 `json:"port"`
	CreatedAt  int64  `json:"created_at"`
	UpdatedAt  int64  `json:"updated_at"`
}

func (r *restGetRecordResponse) toResult() *GetRecordResult {
	return &GetRecordResult{
		Name:       r.Name,
		RecordType: r.RecordType,
		Value:      r.Value,
		TTL:        r.TTL,
		Priority:   r.Priority,
		Weight:     r.Weight,
		Port:       r.Port,
		CreatedAt:  time.Unix(r.CreatedAt, 0),
		UpdatedAt:  time.Unix(r.UpdatedAt, 0),
	}
}

type restUpdateRecordResponse struct {
	Name       string `json:"name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
	UpdatedAt  int64  `json:"updated_at"`
}

func (r *restUpdateRecordResponse) toResult() *UpdateRecordResult {
	return &UpdateRecordResult{
		Name:       r.Name,
		RecordType: r.RecordType,
		Value:      r.Value,
		TTL:        r.TTL,
		UpdatedAt:  time.Unix(r.UpdatedAt, 0),
	}
}

type restDeleteRecordResponse struct {
	Name       string `json:"name"`
	RecordType string `json:"record_type"`
	Deleted    bool   `json:"deleted"`
}

func (r *restDeleteRecordResponse) toResult() *DeleteRecordResult {
	return &DeleteRecordResult{
		Name:       r.Name,
		RecordType: r.RecordType,
		Deleted:    r.Deleted,
	}
}

type restListRecordsResponse struct {
	Records    []restRecordSummary `json:"records"`
	TotalCount int32               `json:"total_count"`
	HasMore    bool                `json:"has_more"`
	NextCursor string              `json:"next_cursor"`
}

type restRecordSummary struct {
	Name       string `json:"name"`
	RecordType string `json:"record_type"`
	Value      string `json:"value"`
	TTL        uint32 `json:"ttl"`
	Priority   uint16 `json:"priority"`
}

func (r *restListRecordsResponse) toResult() *ListRecordsResult {
	result := &ListRecordsResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
		NextCursor: r.NextCursor,
	}

	for _, rec := range r.Records {
		result.Records = append(result.Records, RecordSummary{
			Name:       rec.Name,
			RecordType: rec.RecordType,
			Value:      rec.Value,
			TTL:        rec.TTL,
			Priority:   rec.Priority,
		})
	}

	return result
}

type restResolveResponse struct {
	Name       string   `json:"name"`
	RecordType string   `json:"record_type"`
	Values     []string `json:"values"`
	TTL        uint32   `json:"ttl"`
	Timestamp  int64    `json:"timestamp"`
}

func (r *restResolveResponse) toResult() *ResolveResult {
	return &ResolveResult{
		Name:       r.Name,
		RecordType: r.RecordType,
		Values:     r.Values,
		TTL:        r.TTL,
		Timestamp:  time.Unix(r.Timestamp, 0),
	}
}

type restAddTLSARecordResponse struct {
	Name         string `json:"name"`
	Usage        uint8  `json:"usage"`
	Selector     uint8  `json:"selector"`
	MatchingType uint8  `json:"matching_type"`
	Data         string `json:"data"`
	TTL          uint32 `json:"ttl"`
	CreatedAt    int64  `json:"created_at"`
}

func (r *restAddTLSARecordResponse) toResult() *AddTLSARecordResult {
	return &AddTLSARecordResult{
		Name:         r.Name,
		Usage:        r.Usage,
		Selector:     r.Selector,
		MatchingType: r.MatchingType,
		Data:         r.Data,
		TTL:          r.TTL,
		CreatedAt:    time.Unix(r.CreatedAt, 0),
	}
}

// Ensure RESTAdapter implements DNSCommands interface.
var _ DNSCommands = (*RESTAdapter)(nil)
