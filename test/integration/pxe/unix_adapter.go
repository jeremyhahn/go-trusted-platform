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
// This file implements the PXECommands interface using Unix sockets.

//go:build integration

package pxe

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"
)

// =============================================================================
// Unix Socket Adapter Implementation
// =============================================================================

// UnixAdapter implements PXECommands using Unix socket calls to platformd.
// This adapter makes Unix socket HTTP calls to the platformd server for testing
// the local IPC transport layer consistency with other protocol adapters.
type UnixAdapter struct {
	socketPath string
	httpClient *http.Client
}

// NewUnixAdapter creates a new Unix socket protocol adapter instance.
func NewUnixAdapter() *UnixAdapter {
	socketPath := os.Getenv(EnvPlatformdSocket)
	if socketPath == "" {
		socketPath = GetServiceEndpoints().PlatformdSocket
	}

	// Create HTTP client with Unix socket transport
	transport := &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		},
	}

	return &UnixAdapter{
		socketPath: socketPath,
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   30 * time.Second,
		},
	}
}

// Name returns the protocol adapter identifier.
func (u *UnixAdapter) Name() string {
	return "Unix"
}

// Setup verifies the Unix socket exists and is accessible.
func (u *UnixAdapter) Setup(ctx context.Context) error {
	// Check if socket file exists
	if _, err := os.Stat(u.socketPath); os.IsNotExist(err) {
		return ErrConnectionFailed{
			Protocol: "Unix",
			Endpoint: u.socketPath,
			Err:      fmt.Errorf("socket file does not exist: %s", u.socketPath),
		}
	}

	// Verify connectivity by checking status endpoint
	_, statusCode, err := u.doRequest(ctx, http.MethodGet, "/api/v1/pxe/status", nil)
	if err != nil {
		return ErrConnectionFailed{Protocol: "Unix", Endpoint: u.socketPath, Err: err}
	}
	if statusCode != http.StatusOK {
		return ErrAPIError{Protocol: "Unix", StatusCode: statusCode, Message: "health check failed"}
	}

	return nil
}

// Teardown cleans up Unix socket client resources.
func (u *UnixAdapter) Teardown() error {
	if u.httpClient != nil {
		u.httpClient.CloseIdleConnections()
	}
	return nil
}

// =============================================================================
// HTTP Request Helpers
// =============================================================================

func (u *UnixAdapter) doRequest(ctx context.Context, method, path string, body interface{}) ([]byte, int, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBytes, err := json.Marshal(body)
		if err != nil {
			return nil, 0, ErrRequestFailed{Protocol: "Unix", Method: method, Err: fmt.Errorf("failed to marshal request: %w", err)}
		}
		reqBody = bytes.NewReader(jsonBytes)
	}

	// Use localhost as host (will be ignored due to Unix socket transport)
	req, err := http.NewRequestWithContext(ctx, method, "http://localhost"+path, reqBody)
	if err != nil {
		return nil, 0, ErrRequestFailed{Protocol: "Unix", Method: method, Err: fmt.Errorf("failed to create request: %w", err)}
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, 0, ErrConnectionFailed{Protocol: "Unix", Endpoint: u.socketPath, Err: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, resp.StatusCode, ErrRequestFailed{Protocol: "Unix", Method: method, Err: fmt.Errorf("failed to read response: %w", err)}
	}

	return respBody, resp.StatusCode, nil
}

func (u *UnixAdapter) handleResponse(respBody []byte, statusCode int, target interface{}) error {
	if statusCode >= 400 {
		return u.parseErrorResponse(respBody, statusCode)
	}

	if target != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, target); err != nil {
			return ErrRequestFailed{Protocol: "Unix", Method: "response", Err: fmt.Errorf("failed to unmarshal response: %w", err)}
		}
	}

	return nil
}

func (u *UnixAdapter) parseErrorResponse(respBody []byte, statusCode int) error {
	var errResp struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}

	if err := json.Unmarshal(respBody, &errResp); err != nil {
		return ErrAPIError{Protocol: "Unix", StatusCode: statusCode, Message: string(respBody)}
	}

	msg := errResp.Error
	if msg == "" {
		msg = errResp.Message
	}

	return ErrAPIError{Protocol: "Unix", StatusCode: statusCode, Message: msg}
}

// =============================================================================
// Device Management Commands
// =============================================================================

// RegisterDevice registers a new device via Unix socket.
func (u *UnixAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	reqBody := map[string]interface{}{
		"mac_address": opts.MACAddress,
		"port_id":     opts.PortID,
	}

	respBody, statusCode, err := u.doRequest(ctx, http.MethodPost, "/api/v1/pxe/devices", reqBody)
	if err != nil {
		return nil, err
	}

	var resp unixRegisterDeviceResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// GetDevice retrieves device information via Unix socket.
func (u *UnixAdapter) GetDevice(ctx context.Context, deviceID string) (*GetDeviceResult, error) {
	path := "/api/v1/pxe/devices/" + deviceID

	respBody, statusCode, err := u.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp unixGetDeviceResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// GetDeviceByMAC retrieves a device by MAC address via Unix socket.
func (u *UnixAdapter) GetDeviceByMAC(ctx context.Context, mac string) (*GetDeviceResult, error) {
	path := "/api/v1/pxe/devices/mac/" + mac

	respBody, statusCode, err := u.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp unixGetDeviceResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// ListDevices lists devices via Unix socket.
func (u *UnixAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	path := "/api/v1/pxe/devices"
	query := ""

	if opts.State != "" {
		query += "&state=" + opts.State
	}
	if opts.MACAddress != "" {
		query += "&mac=" + opts.MACAddress
	}
	if opts.VLAN > 0 {
		query += "&vlan=" + strconv.FormatUint(uint64(opts.VLAN), 10)
	}
	if opts.Limit > 0 {
		query += "&limit=" + strconv.FormatInt(int64(opts.Limit), 10)
	}
	if opts.Offset > 0 {
		query += "&offset=" + strconv.FormatInt(int64(opts.Offset), 10)
	}

	if query != "" {
		path += "?" + query[1:] // Remove leading &
	}

	respBody, statusCode, err := u.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp unixListDevicesResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// RemoveDevice removes a device via Unix socket.
func (u *UnixAdapter) RemoveDevice(ctx context.Context, deviceID string) (*RemoveDeviceResult, error) {
	path := "/api/v1/pxe/devices/" + deviceID

	respBody, statusCode, err := u.doRequest(ctx, http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	var resp unixRemoveDeviceResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// State Management Commands
// =============================================================================

// UpdateDeviceState updates device state via Unix socket.
func (u *UnixAdapter) UpdateDeviceState(ctx context.Context, opts UpdateStateOptions) (*UpdateStateResult, error) {
	path := "/api/v1/pxe/devices/" + opts.DeviceID + "/state"

	reqBody := map[string]interface{}{
		"state":  opts.State,
		"reason": opts.Reason,
	}

	respBody, statusCode, err := u.doRequest(ctx, http.MethodPut, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp unixUpdateStateResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// SetDeviceEnrolled sets a device as enrolled via Unix socket.
func (u *UnixAdapter) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) (*SetEnrolledResult, error) {
	path := "/api/v1/pxe/devices/" + deviceID + "/enrolled"

	reqBody := map[string]interface{}{
		"certificate_serial": certSerial,
	}

	respBody, statusCode, err := u.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp unixSetEnrolledResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// AuthorizeDevice authorizes a device via Unix socket.
func (u *UnixAdapter) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) (*AuthorizeResult, error) {
	path := "/api/v1/pxe/devices/" + deviceID + "/authorize"

	reqBody := map[string]interface{}{
		"target_vlan": targetVLAN,
	}

	respBody, statusCode, err := u.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp unixAuthorizeResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// QuarantineDevice quarantines a device via Unix socket.
func (u *UnixAdapter) QuarantineDevice(ctx context.Context, deviceID, reason string) (*QuarantineResult, error) {
	path := "/api/v1/pxe/devices/" + deviceID + "/quarantine"

	reqBody := map[string]interface{}{
		"reason": reason,
	}

	respBody, statusCode, err := u.doRequest(ctx, http.MethodPost, path, reqBody)
	if err != nil {
		return nil, err
	}

	var resp unixQuarantineResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// RetryDevice retries a device via Unix socket.
func (u *UnixAdapter) RetryDevice(ctx context.Context, deviceID string) (*RetryResult, error) {
	path := "/api/v1/pxe/devices/" + deviceID + "/retry"

	respBody, statusCode, err := u.doRequest(ctx, http.MethodPost, path, nil)
	if err != nil {
		return nil, err
	}

	var resp unixRetryResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// Event Commands
// =============================================================================

// GetEvents retrieves device events via Unix socket.
func (u *UnixAdapter) GetEvents(ctx context.Context, deviceID string) (*GetEventsResult, error) {
	path := "/api/v1/pxe/devices/" + deviceID + "/events"

	respBody, statusCode, err := u.doRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}

	var resp unixGetEventsResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// Service Status Commands
// =============================================================================

// GetStatus retrieves service status via Unix socket.
func (u *UnixAdapter) GetStatus(ctx context.Context) (*GetStatusResult, error) {
	respBody, statusCode, err := u.doRequest(ctx, http.MethodGet, "/api/v1/pxe/status", nil)
	if err != nil {
		return nil, err
	}

	var resp unixGetStatusResponse
	if err := u.handleResponse(respBody, statusCode, &resp); err != nil {
		return nil, err
	}

	return resp.toResult(), nil
}

// =============================================================================
// Unix Response Types and Conversion
// =============================================================================

// Response types mirror REST adapter types - using same JSON structure
type unixRegisterDeviceResponse struct {
	ID          string `json:"id"`
	MACAddress  string `json:"mac_address"`
	PortID      string `json:"port_id"`
	State       string `json:"state"`
	StateReason string `json:"state_reason"`
	CurrentVLAN uint16 `json:"current_vlan"`
	CreatedAt   int64  `json:"created_at"`
}

func (r *unixRegisterDeviceResponse) toResult() *RegisterDeviceResult {
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

type unixGetDeviceResponse struct {
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

func (r *unixGetDeviceResponse) toResult() *GetDeviceResult {
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

type unixListDevicesResponse struct {
	Devices    []unixDeviceSummary `json:"devices"`
	TotalCount int32               `json:"total_count"`
	HasMore    bool                `json:"has_more"`
}

type unixDeviceSummary struct {
	ID          string `json:"id"`
	MACAddress  string `json:"mac_address"`
	PortID      string `json:"port_id"`
	State       string `json:"state"`
	CurrentVLAN uint16 `json:"current_vlan"`
	CreatedAt   int64  `json:"created_at"`
	UpdatedAt   int64  `json:"updated_at"`
}

func (r *unixListDevicesResponse) toResult() *ListDevicesResult {
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

type unixRemoveDeviceResponse struct {
	ID      string `json:"id"`
	Removed bool   `json:"removed"`
}

func (r *unixRemoveDeviceResponse) toResult() *RemoveDeviceResult {
	return &RemoveDeviceResult{
		ID:      r.ID,
		Removed: r.Removed,
	}
}

type unixUpdateStateResponse struct {
	ID        string `json:"id"`
	FromState string `json:"from_state"`
	ToState   string `json:"to_state"`
	Reason    string `json:"reason"`
	UpdatedAt int64  `json:"updated_at"`
}

func (r *unixUpdateStateResponse) toResult() *UpdateStateResult {
	return &UpdateStateResult{
		ID:        r.ID,
		FromState: r.FromState,
		ToState:   r.ToState,
		Reason:    r.Reason,
		UpdatedAt: time.Unix(r.UpdatedAt, 0),
	}
}

type unixSetEnrolledResponse struct {
	ID                string `json:"id"`
	State             string `json:"state"`
	CertificateSerial string `json:"certificate_serial"`
	UpdatedAt         int64  `json:"updated_at"`
}

func (r *unixSetEnrolledResponse) toResult() *SetEnrolledResult {
	return &SetEnrolledResult{
		ID:                r.ID,
		State:             r.State,
		CertificateSerial: r.CertificateSerial,
		UpdatedAt:         time.Unix(r.UpdatedAt, 0),
	}
}

type unixAuthorizeResponse struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	TargetVLAN uint16 `json:"target_vlan"`
	UpdatedAt  int64  `json:"updated_at"`
}

func (r *unixAuthorizeResponse) toResult() *AuthorizeResult {
	return &AuthorizeResult{
		ID:         r.ID,
		State:      r.State,
		TargetVLAN: r.TargetVLAN,
		UpdatedAt:  time.Unix(r.UpdatedAt, 0),
	}
}

type unixQuarantineResponse struct {
	ID          string `json:"id"`
	State       string `json:"state"`
	Reason      string `json:"reason"`
	CurrentVLAN uint16 `json:"current_vlan"`
	UpdatedAt   int64  `json:"updated_at"`
}

func (r *unixQuarantineResponse) toResult() *QuarantineResult {
	return &QuarantineResult{
		ID:          r.ID,
		State:       r.State,
		Reason:      r.Reason,
		CurrentVLAN: r.CurrentVLAN,
		UpdatedAt:   time.Unix(r.UpdatedAt, 0),
	}
}

type unixRetryResponse struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	RetryCount int    `json:"retry_count"`
	UpdatedAt  int64  `json:"updated_at"`
}

func (r *unixRetryResponse) toResult() *RetryResult {
	return &RetryResult{
		ID:         r.ID,
		State:      r.State,
		RetryCount: r.RetryCount,
		UpdatedAt:  time.Unix(r.UpdatedAt, 0),
	}
}

type unixGetEventsResponse struct {
	DeviceID string          `json:"device_id"`
	Events   []unixEventInfo `json:"events"`
}

type unixEventInfo struct {
	ID        string            `json:"id"`
	DeviceID  string            `json:"device_id"`
	EventType string            `json:"event_type"`
	FromState string            `json:"from_state"`
	ToState   string            `json:"to_state"`
	Details   map[string]string `json:"details"`
	Error     string            `json:"error"`
	Timestamp int64             `json:"timestamp"`
}

func (r *unixGetEventsResponse) toResult() *GetEventsResult {
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

type unixGetStatusResponse struct {
	Running          bool   `json:"running"`
	DeviceCount      int    `json:"device_count"`
	StartTime        int64  `json:"start_time"`
	IPXEServerAddr   string `json:"ipxe_server_addr"`
	QuarantineVLAN   uint16 `json:"quarantine_vlan"`
	ProvisioningVLAN uint16 `json:"provisioning_vlan"`
}

func (r *unixGetStatusResponse) toResult() *GetStatusResult {
	return &GetStatusResult{
		Running:          r.Running,
		DeviceCount:      r.DeviceCount,
		StartTime:        time.Unix(r.StartTime, 0),
		IPXEServerAddr:   r.IPXEServerAddr,
		QuarantineVLAN:   r.QuarantineVLAN,
		ProvisioningVLAN: r.ProvisioningVLAN,
	}
}

// Ensure UnixAdapter implements PXECommands interface.
var _ PXECommands = (*UnixAdapter)(nil)
