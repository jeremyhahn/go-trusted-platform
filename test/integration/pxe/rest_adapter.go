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
// This file implements the PXECommands interface using HTTP/REST.

//go:build integration

package pxe

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

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// REST Adapter Implementation
// =============================================================================

// RESTAdapter implements PXECommands using HTTP/REST calls to platformd.
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
		baseURL:    helpers.RESTBaseURL(endpoint),
		httpClient: helpers.NewHTTPClient(30 * time.Second),
	}
}

// Name returns the protocol adapter identifier.
func (r *RESTAdapter) Name() string {
	return "REST"
}

// Setup initializes the REST client.
func (r *RESTAdapter) Setup(ctx context.Context) error {
	_, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/pxe/status", nil)
	if err != nil {
		return ErrConnectionFailed{Protocol: "REST", Endpoint: r.baseURL, Err: err}
	}
	if statusCode != http.StatusOK {
		return ErrAPIError{Protocol: "REST", StatusCode: statusCode, Message: "health check failed"}
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

func (r *RESTAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, ErrRequestFailed{Protocol: "REST", Method: method, Err: fmt.Errorf("failed to marshal request: %w", err)}
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	req, err := http.NewRequestWithContext(ctx, method, r.baseURL+path, reqBody)
	if err != nil {
		return nil, 0, ErrRequestFailed{Protocol: "REST", Method: method, Err: fmt.Errorf("failed to create request: %w", err)}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, 0, ErrConnectionFailed{Protocol: "REST", Endpoint: r.baseURL, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, ErrRequestFailed{Protocol: "REST", Method: method, Err: fmt.Errorf("failed to read response: %w", err)}
	}

	return respBody, resp.StatusCode, nil
}

func (r *RESTAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		return r.parseErrorResponse(respBody, statusCode)
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return ErrRequestFailed{Protocol: "REST", Method: "response", Err: fmt.Errorf("failed to unmarshal response: %w", err)}
		}
	}

	return nil
}

func (r *RESTAdapter) parseErrorResponse(respBody []byte, statusCode int) error {
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(respBody, &errResp); err != nil {
		return ErrAPIError{Protocol: "REST", StatusCode: statusCode, Message: string(respBody)}
	}

	msg := errResp.Error
	if msg == "" {
		msg = errResp.Message
	}

	return ErrAPIError{Protocol: "REST", StatusCode: statusCode, Message: msg}
}

// =============================================================================
// Device Management Commands
// =============================================================================

// RegisterDevice registers a new device via REST API.
func (r *RESTAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	reqBody := map[string]interface{}{
		"mac_address": opts.MACAddress,
		"port_id":     opts.PortID,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, "/api/v1/pxe/devices", reqBody)
	if err != nil {
		return nil, err
	}

	var resp restRegisterDeviceResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// GetDevice retrieves device information via REST API.
func (r *RESTAdapter) GetDevice(ctx context.Context, deviceID string) (*GetDeviceResult, error) {
	path := "/api/v1/pxe/devices/" + url.PathEscape(deviceID)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restGetDeviceResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// GetDeviceByMAC retrieves a device by MAC address via REST API.
func (r *RESTAdapter) GetDeviceByMAC(ctx context.Context, mac string) (*GetDeviceResult, error) {
	path := "/api/v1/pxe/devices/mac/" + url.PathEscape(mac)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restGetDeviceResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// ListDevices lists devices via REST API.
func (r *RESTAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	params := url.Values{}
	if opts.State != "" {
		params.Set("state", opts.State)
	}
	if opts.MACAddress != "" {
		params.Set("mac", opts.MACAddress)
	}
	if opts.VLAN > 0 {
		params.Set("vlan", strconv.FormatUint(uint64(opts.VLAN), 10))
	}
	if opts.Limit > 0 {
		params.Set("limit", strconv.FormatInt(int64(opts.Limit), 10))
	}
	if opts.Offset > 0 {
		params.Set("offset", strconv.FormatInt(int64(opts.Offset), 10))
	}

	path := "/api/v1/pxe/devices"
	if len(params) > 0 {
		path += "?" + params.Encode()
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restListDevicesResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// RemoveDevice removes a device via REST API.
func (r *RESTAdapter) RemoveDevice(ctx context.Context, deviceID string) (*RemoveDeviceResult, error) {
	path := "/api/v1/pxe/devices/" + url.PathEscape(deviceID)

	respBody, statusCode, err := r.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restRemoveDeviceResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// State Management Commands
// =============================================================================

// UpdateDeviceState updates device state via REST API.
func (r *RESTAdapter) UpdateDeviceState(ctx context.Context, opts UpdateStateOptions) (*UpdateStateResult, error) {
	path := "/api/v1/pxe/devices/" + url.PathEscape(opts.DeviceID) + "/state"

	reqBody := map[string]interface{}{
		"state":  opts.State,
		"reason": opts.Reason,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPut, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp restUpdateStateResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// SetDeviceEnrolled sets a device as enrolled via REST API.
func (r *RESTAdapter) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) (*SetEnrolledResult, error) {
	path := "/api/v1/pxe/devices/" + url.PathEscape(deviceID) + "/enrolled"

	reqBody := map[string]interface{}{
		"certificate_serial": certSerial,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp restSetEnrolledResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// AuthorizeDevice authorizes a device via REST API.
func (r *RESTAdapter) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) (*AuthorizeResult, error) {
	path := "/api/v1/pxe/devices/" + url.PathEscape(deviceID) + "/authorize"

	reqBody := map[string]interface{}{
		"target_vlan": targetVLAN,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp restAuthorizeResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// QuarantineDevice quarantines a device via REST API.
func (r *RESTAdapter) QuarantineDevice(ctx context.Context, deviceID, reason string) (*QuarantineResult, error) {
	path := "/api/v1/pxe/devices/" + url.PathEscape(deviceID) + "/quarantine"

	reqBody := map[string]interface{}{
		"reason": reason,
	}

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp restQuarantineResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// RetryDevice retries a device via REST API.
func (r *RESTAdapter) RetryDevice(ctx context.Context, deviceID string) (*RetryResult, error) {
	path := "/api/v1/pxe/devices/" + url.PathEscape(deviceID) + "/retry"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restRetryResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// Event Commands
// =============================================================================

// GetEvents retrieves device events via REST API.
func (r *RESTAdapter) GetEvents(ctx context.Context, deviceID string) (*GetEventsResult, error) {
	path := "/api/v1/pxe/devices/" + url.PathEscape(deviceID) + "/events"

	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp restGetEventsResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// Service Status Commands
// =============================================================================

// GetStatus retrieves service status via REST API.
func (r *RESTAdapter) GetStatus(ctx context.Context) (*GetStatusResult, error) {
	respBody, statusCode, err := r.doRequest(ctx, http.MethodGet, "/api/v1/pxe/status", nil)
	if err != nil {
		return nil, err
	}

	var resp restGetStatusResponse
	if err := r.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// REST Response Types and Conversion
// =============================================================================

type restRegisterDeviceResponse struct {
	ID          string `json:"id"`
	MACAddress  string `json:"mac_address"`
	PortID      string `json:"port_id"`
	State       string `json:"state"`
	StateReason string `json:"state_reason"`
	CurrentVLAN uint16 `json:"current_vlan"`
	CreatedAt   int64  `json:"created_at"`
}

func (r *restRegisterDeviceResponse) toResult() *RegisterDeviceResult {
	return &RegisterDeviceResult{
		ID:          r.ID,
		MACAddress:  r.MACAddress,
		PortID:      r.PortID,
		State:       r.State,
		StateReason: r.StateReason,
		CurrentVLAN: r.CurrentVLAN,
		CreatedAt:   time.Unix(r.CreatedAt, 0),
	}
}

type restGetDeviceResponse struct {
	ID                string `json:"id"`
	MACAddress        string `json:"mac_address"`
	PortID            string `json:"port_id"`
	State             string `json:"state"`
	StateReason       string `json:"state_reason"`
	CertificateSerial string `json:"certificate_serial"`
	CurrentVLAN       uint16 `json:"current_vlan"`
	TargetVLAN        uint16 `json:"target_vlan"`
	RetryCount        int    `json:"retry_count"`
	CreatedAt         int64  `json:"created_at"`
	UpdatedAt         int64  `json:"updated_at"`
	StateChangedAt    int64  `json:"state_changed_at"`
}

func (r *restGetDeviceResponse) toResult() *GetDeviceResult {
	return &GetDeviceResult{
		ID:                r.ID,
		MACAddress:        r.MACAddress,
		PortID:            r.PortID,
		State:             r.State,
		StateReason:       r.StateReason,
		CertificateSerial: r.CertificateSerial,
		CurrentVLAN:       r.CurrentVLAN,
		TargetVLAN:        r.TargetVLAN,
		RetryCount:        r.RetryCount,
		CreatedAt:         time.Unix(r.CreatedAt, 0),
		UpdatedAt:         time.Unix(r.UpdatedAt, 0),
		StateChangedAt:    time.Unix(r.StateChangedAt, 0),
	}
}

type restListDevicesResponse struct {
	Devices    []restDeviceSummary `json:"devices"`
	TotalCount int32               `json:"total_count"`
	HasMore    bool                `json:"has_more"`
}

type restDeviceSummary struct {
	ID          string `json:"id"`
	MACAddress  string `json:"mac_address"`
	PortID      string `json:"port_id"`
	State       string `json:"state"`
	CurrentVLAN uint16 `json:"current_vlan"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

func (r *restListDevicesResponse) toResult() *ListDevicesResult {
	result := &ListDevicesResult{
		TotalCount: r.TotalCount,
		HasMore:    r.HasMore,
	}

	for _, d := range r.Devices {
		result.Devices = append(result.Devices, DeviceSummary{
			ID:          d.ID,
			MACAddress:  d.MACAddress,
			PortID:      d.PortID,
			State:       d.State,
			CurrentVLAN: d.CurrentVLAN,
			CreatedAt:   time.Unix(d.CreatedAt, 0),
			UpdatedAt:   time.Unix(d.UpdatedAt, 0),
		})
	}

	return result
}

type restRemoveDeviceResponse struct {
	ID      string `json:"id"`
	Removed bool   `json:"removed"`
}

func (r *restRemoveDeviceResponse) toResult() *RemoveDeviceResult {
	return &RemoveDeviceResult{
		ID:      r.ID,
		Removed: r.Removed,
	}
}

type restUpdateStateResponse struct {
	ID        string `json:"id"`
	FromState string `json:"from_state"`
	ToState   string `json:"to_state"`
	Reason    string `json:"reason"`
	UpdatedAt int64  `json:"updated_at"`
}

func (r *restUpdateStateResponse) toResult() *UpdateStateResult {
	return &UpdateStateResult{
		ID:        r.ID,
		FromState: r.FromState,
		ToState:   r.ToState,
		Reason:    r.Reason,
		UpdatedAt: time.Unix(r.UpdatedAt, 0),
	}
}

type restSetEnrolledResponse struct {
	ID                string `json:"id"`
	State             string `json:"state"`
	CertificateSerial string `json:"certificate_serial"`
	UpdatedAt         int64  `json:"updated_at"`
}

func (r *restSetEnrolledResponse) toResult() *SetEnrolledResult {
	return &SetEnrolledResult{
		ID:                r.ID,
		State:             r.State,
		CertificateSerial: r.CertificateSerial,
		UpdatedAt:         time.Unix(r.UpdatedAt, 0),
	}
}

type restAuthorizeResponse struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	TargetVLAN uint16 `json:"target_vlan"`
	UpdatedAt  int64  `json:"updated_at"`
}

func (r *restAuthorizeResponse) toResult() *AuthorizeResult {
	return &AuthorizeResult{
		ID:         r.ID,
		State:      r.State,
		TargetVLAN: r.TargetVLAN,
		UpdatedAt:  time.Unix(r.UpdatedAt, 0),
	}
}

type restQuarantineResponse struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Reason      string `json:"reason"`
	CurrentVLAN uint16 `json:"current_vlan"`
	UpdatedAt   int64  `json:"updated_at"`
}

func (r *restQuarantineResponse) toResult() *QuarantineResult {
	return &QuarantineResult{
		ID:          r.ID,
		State:       r.State,
		Reason:      r.Reason,
		CurrentVLAN: r.CurrentVLAN,
		UpdatedAt:   time.Unix(r.UpdatedAt, 0),
	}
}

type restRetryResponse struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	RetryCount int    `json:"retry_count"`
	UpdatedAt  int64  `json:"updated_at"`
}

func (r *restRetryResponse) toResult() *RetryResult {
	return &RetryResult{
		ID:         r.ID,
		State:      r.State,
		RetryCount: r.RetryCount,
		UpdatedAt:  time.Unix(r.UpdatedAt, 0),
	}
}

type restGetEventsResponse struct {
	DeviceID string          `json:"device_id"`
	Events   []restEventInfo `json:"events"`
}

type restEventInfo struct {
	ID        string            `json:"id"`
	DeviceID  string            `json:"device_id"`
	EventType string            `json:"event_type"`
	FromState string            `json:"from_state"`
	ToState   string            `json:"to_state"`
	Details   map[string]string `json:"details"`
	Error     string            `json:"error"`
	Timestamp int64             `json:"timestamp"`
}

func (r *restGetEventsResponse) toResult() *GetEventsResult {
	result := &GetEventsResult{
		DeviceID: r.DeviceID,
	}

	for _, e := range r.Events {
		result.Events = append(result.Events, ProvisioningEventInfo{
			ID:        e.ID,
			DeviceID:  e.DeviceID,
			EventType: e.EventType,
			FromState: e.FromState,
			ToState:   e.ToState,
			Details:   e.Details,
			Error:     e.Error,
			Timestamp: time.Unix(e.Timestamp, 0),
		})
	}

	return result
}

type restGetStatusResponse struct {
	Running          bool   `json:"running"`
	DeviceCount      int    `json:"device_count"`
	StartTime        int64  `json:"start_time"`
	IPXEServerAddr   string `json:"ipxe_server_addr"`
	QuarantineVLAN   uint16 `json:"quarantine_vlan"`
	ProvisioningVLAN uint16 `json:"provisioning_vlan"`
}

func (r *restGetStatusResponse) toResult() *GetStatusResult {
	return &GetStatusResult{
		Running:          r.Running,
		DeviceCount:      r.DeviceCount,
		StartTime:        time.Unix(r.StartTime, 0),
		IPXEServerAddr:   r.IPXEServerAddr,
		QuarantineVLAN:   r.QuarantineVLAN,
		ProvisioningVLAN: r.ProvisioningVLAN,
	}
}

// Ensure RESTAdapter implements PXECommands interface.
var _ PXECommands = (*RESTAdapter)(nil)
