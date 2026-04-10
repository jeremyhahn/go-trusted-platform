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

package rest

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
)

// =============================================================================
// PXE REST Handler Errors
// =============================================================================

// ErrPXEServiceNotAvailable is returned when the PXE service is not configured
// or unavailable.
type ErrPXEServiceNotAvailable struct{}

func (e ErrPXEServiceNotAvailable) Error() string {
	return "PXE service not available"
}

// ErrPXEServiceNotRunning is returned when the PXE service is not running.
type ErrPXEServiceNotRunning struct{}

func (e ErrPXEServiceNotRunning) Error() string {
	return "PXE service is not running"
}

// ErrInvalidPXEDeviceID is returned when a device ID is invalid or empty.
type ErrInvalidPXEDeviceID struct {
	ID string
}

func (e ErrInvalidPXEDeviceID) Error() string {
	if e.ID == "" {
		return "device ID is required"
	}
	return fmt.Sprintf("invalid device ID: %s", e.ID)
}

// ErrInvalidMACAddressFormat is returned when a MAC address format is invalid.
type ErrInvalidMACAddressFormat struct {
	MACAddress string
	Reason     string
}

func (e ErrInvalidMACAddressFormat) Error() string {
	msg := "invalid MAC address format"
	if e.MACAddress != "" {
		msg = fmt.Sprintf("%s: %s", msg, e.MACAddress)
	}
	if e.Reason != "" {
		msg = fmt.Sprintf("%s (%s)", msg, e.Reason)
	}
	return msg
}

// ErrPXEDeviceNotFound is returned when a device is not found.
type ErrPXEDeviceNotFound struct {
	ID string
}

func (e ErrPXEDeviceNotFound) Error() string {
	return fmt.Sprintf("PXE device not found: %s", e.ID)
}

// ErrPXEDeviceAlreadyExists is returned when a device already exists.
type ErrPXEDeviceAlreadyExists struct {
	MACAddress string
}

func (e ErrPXEDeviceAlreadyExists) Error() string {
	return fmt.Sprintf("PXE device already exists with MAC: %s", e.MACAddress)
}

// ErrPXEInvalidStateTransition is returned when a state transition is invalid.
type ErrPXEInvalidStateTransition struct {
	DeviceID  string
	FromState string
	ToState   string
}

func (e ErrPXEInvalidStateTransition) Error() string {
	return fmt.Sprintf("invalid state transition from %s to %s for device %s",
		e.FromState, e.ToState, e.DeviceID)
}

// ErrPXEOperationFailed is returned when a PXE operation fails.
type ErrPXEOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrPXEOperationFailed) Error() string {
	return fmt.Sprintf("PXE operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrPXEOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrMissingMACAddress is returned when a MAC address is required but not provided.
type ErrMissingMACAddress struct{}

func (e ErrMissingMACAddress) Error() string {
	return "MAC address is required"
}

// =============================================================================
// Request Types
// =============================================================================

// PXERegisterDeviceRequest represents a device registration request.
type PXERegisterDeviceRequest struct {
	MACAddress string `json:"mac_address"`
	PortID     string `json:"port_id"`
}

// PXEUpdateStateRequest represents a device state update request.
type PXEUpdateStateRequest struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

// PXEAuthorizeDeviceRequest represents a device authorization request.
type PXEAuthorizeDeviceRequest struct {
	TargetVLAN uint16 `json:"target_vlan"`
}

// PXEQuarantineDeviceRequest represents a device quarantine request.
type PXEQuarantineDeviceRequest struct {
	Reason string `json:"reason"`
}

// PXESetDeviceEnrolledRequest represents a device enrollment request.
type PXESetDeviceEnrolledRequest struct {
	CertSerial string `json:"cert_serial"`
}

// =============================================================================
// Response Types
// =============================================================================

// PXEDeviceResponse represents a PXE device in API responses.
type PXEDeviceResponse struct {
	ID                string                      `json:"id"`
	MACAddress        string                      `json:"mac_address"`
	PortID            string                      `json:"port_id"`
	State             string                      `json:"state"`
	StateReason       string                      `json:"state_reason,omitempty"`
	CertificateSerial string                      `json:"certificate_serial,omitempty"`
	CurrentVLAN       uint16                      `json:"current_vlan"`
	TargetVLAN        uint16                      `json:"target_vlan"`
	RetryCount        int                         `json:"retry_count"`
	CreatedAt         time.Time                   `json:"created_at"`
	UpdatedAt         time.Time                   `json:"updated_at"`
	StateChangedAt    time.Time                   `json:"state_changed_at"`
	Events            []*PXEProvisioningEventResp `json:"events,omitempty"`
}

// PXEProvisioningEventResp represents a provisioning event in API responses.
type PXEProvisioningEventResp struct {
	ID        string            `json:"id"`
	DeviceID  string            `json:"device_id"`
	Timestamp time.Time         `json:"timestamp"`
	EventType string            `json:"event_type"`
	FromState string            `json:"from_state"`
	ToState   string            `json:"to_state"`
	Details   map[string]string `json:"details,omitempty"`
	Error     string            `json:"error,omitempty"`
}

// PXEListDevicesResponse represents a list of PXE devices.
type PXEListDevicesResponse struct {
	Devices   []PXEDeviceResponse `json:"devices"`
	Total     int                 `json:"total"`
	Limit     int                 `json:"limit"`
	Offset    int                 `json:"offset"`
	Timestamp time.Time           `json:"timestamp"`
}

// PXEEventsResponse represents a list of provisioning events for a device.
type PXEEventsResponse struct {
	DeviceID  string                      `json:"device_id"`
	Events    []*PXEProvisioningEventResp `json:"events"`
	Total     int                         `json:"total"`
	Timestamp time.Time                   `json:"timestamp"`
}

// PXEStatusResponse represents the PXE service status.
type PXEStatusResponse struct {
	Running          bool      `json:"running"`
	DeviceCount      int       `json:"device_count"`
	StartTime        time.Time `json:"start_time,omitempty"`
	IPXEServerAddr   string    `json:"ipxe_server_addr,omitempty"`
	QuarantineVLAN   uint16    `json:"quarantine_vlan"`
	ProvisioningVLAN uint16    `json:"provisioning_vlan"`
	Timestamp        time.Time `json:"timestamp"`
}

// PXEActionResponse represents a PXE action result.
type PXEActionResponse struct {
	DeviceID string `json:"device_id,omitempty"`
	Action   string `json:"action"`
	Success  bool   `json:"success"`
	Message  string `json:"message,omitempty"`
}

// PXEErrorResponse represents a PXE error response.
type PXEErrorResponse struct {
	Error     string    `json:"error"`
	Code      int       `json:"code"`
	Timestamp time.Time `json:"timestamp"`
}

// =============================================================================
// PXE Handlers
// =============================================================================

// PXEHandlers provides REST API handlers for PXE provisioning operations.
type PXEHandlers struct {
	service pxe.Service
	logger  *slog.Logger
}

// NewPXEHandlers creates a new PXEHandlers instance.
func NewPXEHandlers(service pxe.Service, logger *slog.Logger) *PXEHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &PXEHandlers{
		service: service,
		logger:  logger,
	}
}

// RegisterRoutes registers all PXE routes on the provided router.
func (h *PXEHandlers) RegisterRoutes(router *mux.Router) {
	// Device operations
	router.HandleFunc("/api/v1/pxe/devices", h.handleListDevices).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/pxe/devices", h.handleRegisterDevice).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/pxe/devices/mac/{mac}", h.handleGetDeviceByMAC).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/pxe/devices/{id}", h.handleGetDevice).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/pxe/devices/{id}", h.handleRemoveDevice).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/pxe/devices/{id}/state", h.handleUpdateState).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/pxe/devices/{id}/authorize", h.handleAuthorize).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/pxe/devices/{id}/quarantine", h.handleQuarantine).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/pxe/devices/{id}/retry", h.handleRetry).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/pxe/devices/{id}/enrolled", h.handleSetDeviceEnrolled).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/pxe/devices/{id}/events", h.handleGetEvents).Methods(http.MethodGet)

	// Service operations
	router.HandleFunc("/api/v1/pxe/status", h.handleStatus).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/pxe/start", h.handleStart).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/pxe/stop", h.handleStop).Methods(http.MethodPost)

	// Webhook
	router.HandleFunc("/api/v1/pxe/webhook/complete", h.handleWebhookComplete).Methods(http.MethodPost)

	h.logger.Info("PXE REST routes registered")
}

// =============================================================================
// Device Handlers
// =============================================================================

// handleListDevices handles GET /api/v1/pxe/devices
func (h *PXEHandlers) handleListDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	// Parse query parameters
	limit := ParseIntParam(r, "limit", 100)
	offset := ParseIntParam(r, "offset", 0)
	stateFilter := r.URL.Query().Get("state")
	macFilter := r.URL.Query().Get("mac_address")
	vlanFilter := ParseIntParam(r, "vlan", 0)

	filter := &pxe.DeviceFilter{
		Limit:  limit,
		Offset: offset,
	}

	if stateFilter != "" {
		filter.State = pxe.ProvisioningState(stateFilter)
	}
	if macFilter != "" {
		filter.MACAddress = macFilter
	}
	if vlanFilter > 0 {
		filter.VLAN = uint16(vlanFilter)
	}

	devices, err := h.service.ListDevices(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to list devices", "error", err)
		h.writePXEError(w, "list_devices", err)
		return
	}

	responses := make([]PXEDeviceResponse, 0, len(devices))
	for _, device := range devices {
		responses = append(responses, h.deviceToResponse(device))
	}

	resp := PXEListDevicesResponse{
		Devices:   responses,
		Total:     len(responses),
		Limit:     limit,
		Offset:    offset,
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetDevice handles GET /api/v1/pxe/devices/{id}
func (h *PXEHandlers) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	deviceID := vars["id"]
	if deviceID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPXEDeviceID{})
		return
	}

	device, err := h.service.GetDevice(ctx, deviceID)
	if err != nil {
		h.logger.Error("Failed to get device", "error", err, "device_id", deviceID)
		h.writePXEError(w, "get_device", err)
		return
	}

	resp := h.deviceToResponse(device)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetDeviceByMAC handles GET /api/v1/pxe/devices/mac/{mac}
func (h *PXEHandlers) handleGetDeviceByMAC(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	macAddress := vars["mac"]
	if macAddress == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingMACAddress{})
		return
	}

	device, err := h.service.GetDeviceByMAC(ctx, macAddress)
	if err != nil {
		h.logger.Error("Failed to get device by MAC", "error", err, "mac_address", macAddress)
		h.writePXEError(w, "get_device_by_mac", err)
		return
	}

	resp := h.deviceToResponse(device)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleRegisterDevice handles POST /api/v1/pxe/devices
func (h *PXEHandlers) handleRegisterDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	var req PXERegisterDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.MACAddress == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "mac_address"})
		return
	}

	if req.PortID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "port_id"})
		return
	}

	device, err := h.service.RegisterDevice(ctx, req.MACAddress, req.PortID)
	if err != nil {
		h.logger.Error("Failed to register device", "error", err, "mac_address", req.MACAddress)
		h.writePXEError(w, "register_device", err)
		return
	}

	resp := h.deviceToResponse(device)
	h.logger.Info("Device registered", "device_id", device.ID, "mac_address", req.MACAddress)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleRemoveDevice handles DELETE /api/v1/pxe/devices/{id}
func (h *PXEHandlers) handleRemoveDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	deviceID := vars["id"]
	if deviceID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPXEDeviceID{})
		return
	}

	if err := h.service.RemoveDevice(ctx, deviceID); err != nil {
		h.logger.Error("Failed to remove device", "error", err, "device_id", deviceID)
		h.writePXEError(w, "remove_device", err)
		return
	}

	resp := PXEActionResponse{
		DeviceID: deviceID,
		Action:   "remove",
		Success:  true,
		Message:  "device removed successfully",
	}

	h.logger.Info("Device removed", "device_id", deviceID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleUpdateState handles PUT /api/v1/pxe/devices/{id}/state
func (h *PXEHandlers) handleUpdateState(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	deviceID := vars["id"]
	if deviceID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPXEDeviceID{})
		return
	}

	var req PXEUpdateStateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.State == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "state"})
		return
	}

	state := pxe.ProvisioningState(req.State)
	if !state.IsValid() {
		h.writeError(w, http.StatusBadRequest, pxe.ErrInvalidState{
			DeviceID: deviceID,
			State:    req.State,
			Reason:   "unknown state value",
		})
		return
	}

	if err := h.service.UpdateDeviceState(ctx, deviceID, state, req.Reason); err != nil {
		h.logger.Error("Failed to update device state", "error", err, "device_id", deviceID, "state", req.State)
		h.writePXEError(w, "update_state", err)
		return
	}

	resp := PXEActionResponse{
		DeviceID: deviceID,
		Action:   "update_state",
		Success:  true,
		Message:  fmt.Sprintf("state updated to %s", req.State),
	}

	h.logger.Info("Device state updated", "device_id", deviceID, "state", req.State)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleAuthorize handles POST /api/v1/pxe/devices/{id}/authorize
func (h *PXEHandlers) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	deviceID := vars["id"]
	if deviceID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPXEDeviceID{})
		return
	}

	var req PXEAuthorizeDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.TargetVLAN == 0 {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "target_vlan"})
		return
	}

	if err := h.service.AuthorizeDevice(ctx, deviceID, req.TargetVLAN); err != nil {
		h.logger.Error("Failed to authorize device", "error", err, "device_id", deviceID, "target_vlan", req.TargetVLAN)
		h.writePXEError(w, "authorize_device", err)
		return
	}

	resp := PXEActionResponse{
		DeviceID: deviceID,
		Action:   "authorize",
		Success:  true,
		Message:  fmt.Sprintf("device authorized for VLAN %d", req.TargetVLAN),
	}

	h.logger.Info("Device authorized", "device_id", deviceID, "target_vlan", req.TargetVLAN)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleQuarantine handles POST /api/v1/pxe/devices/{id}/quarantine
func (h *PXEHandlers) handleQuarantine(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	deviceID := vars["id"]
	if deviceID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPXEDeviceID{})
		return
	}

	var req PXEQuarantineDeviceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Reason == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "reason"})
		return
	}

	if err := h.service.QuarantineDevice(ctx, deviceID, req.Reason); err != nil {
		h.logger.Error("Failed to quarantine device", "error", err, "device_id", deviceID)
		h.writePXEError(w, "quarantine_device", err)
		return
	}

	resp := PXEActionResponse{
		DeviceID: deviceID,
		Action:   "quarantine",
		Success:  true,
		Message:  "device quarantined",
	}

	h.logger.Info("Device quarantined", "device_id", deviceID, "reason", req.Reason)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleRetry handles POST /api/v1/pxe/devices/{id}/retry
func (h *PXEHandlers) handleRetry(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	deviceID := vars["id"]
	if deviceID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPXEDeviceID{})
		return
	}

	if err := h.service.RetryDevice(ctx, deviceID); err != nil {
		h.logger.Error("Failed to retry device", "error", err, "device_id", deviceID)
		h.writePXEError(w, "retry_device", err)
		return
	}

	resp := PXEActionResponse{
		DeviceID: deviceID,
		Action:   "retry",
		Success:  true,
		Message:  "device retry initiated",
	}

	h.logger.Info("Device retry initiated", "device_id", deviceID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleSetDeviceEnrolled handles POST /api/v1/pxe/devices/{id}/enrolled
func (h *PXEHandlers) handleSetDeviceEnrolled(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	deviceID := vars["id"]
	if deviceID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPXEDeviceID{})
		return
	}

	var req PXESetDeviceEnrolledRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.CertSerial == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "cert_serial"})
		return
	}

	if err := h.service.SetDeviceEnrolled(ctx, deviceID, req.CertSerial); err != nil {
		h.logger.Error("Failed to set device enrolled", "error", err, "device_id", deviceID)
		h.writePXEError(w, "set_device_enrolled", err)
		return
	}

	resp := PXEActionResponse{
		DeviceID: deviceID,
		Action:   "set_enrolled",
		Success:  true,
		Message:  fmt.Sprintf("device enrolled with certificate serial %s", req.CertSerial),
	}

	h.logger.Info("Device enrolled", "device_id", deviceID, "cert_serial", req.CertSerial)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetEvents handles GET /api/v1/pxe/devices/{id}/events
func (h *PXEHandlers) handleGetEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	deviceID := vars["id"]
	if deviceID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidPXEDeviceID{})
		return
	}

	events, err := h.service.GetEvents(ctx, deviceID)
	if err != nil {
		h.logger.Error("Failed to get device events", "error", err, "device_id", deviceID)
		h.writePXEError(w, "get_events", err)
		return
	}

	eventResponses := make([]*PXEProvisioningEventResp, 0, len(events))
	for _, event := range events {
		eventResponses = append(eventResponses, &PXEProvisioningEventResp{
			ID:        event.ID,
			DeviceID:  event.DeviceID,
			Timestamp: event.Timestamp,
			EventType: string(event.EventType),
			FromState: string(event.FromState),
			ToState:   string(event.ToState),
			Details:   event.Details,
			Error:     event.Error,
		})
	}

	resp := PXEEventsResponse{
		DeviceID:  deviceID,
		Events:    eventResponses,
		Total:     len(eventResponses),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Service Handlers
// =============================================================================

// handleStatus handles GET /api/v1/pxe/status
func (h *PXEHandlers) handleStatus(w http.ResponseWriter, r *http.Request) {
	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	status := h.service.Status()

	resp := PXEStatusResponse{
		Running:          status.Running,
		DeviceCount:      status.DeviceCount,
		StartTime:        status.StartTime,
		IPXEServerAddr:   status.IPXEServerAddr,
		QuarantineVLAN:   status.QuarantineVLAN,
		ProvisioningVLAN: status.ProvisioningVLAN,
		Timestamp:        time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleStart handles POST /api/v1/pxe/start
func (h *PXEHandlers) handleStart(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	if h.service.IsRunning() {
		h.writeError(w, http.StatusConflict, pxe.ErrServiceAlreadyRunning{})
		return
	}

	if err := h.service.Start(ctx); err != nil {
		h.logger.Error("Failed to start PXE service", "error", err)
		h.writePXEError(w, "start_service", err)
		return
	}

	resp := PXEActionResponse{
		Action:  "start",
		Success: true,
		Message: "PXE service started",
	}

	h.logger.Info("PXE service started")
	h.writeJSON(w, http.StatusOK, resp)
}

// handleStop handles POST /api/v1/pxe/stop
func (h *PXEHandlers) handleStop(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	if !h.service.IsRunning() {
		h.writeError(w, http.StatusConflict, ErrPXEServiceNotRunning{})
		return
	}

	if err := h.service.Stop(ctx); err != nil {
		h.logger.Error("Failed to stop PXE service", "error", err)
		h.writePXEError(w, "stop_service", err)
		return
	}

	resp := PXEActionResponse{
		Action:  "stop",
		Success: true,
		Message: "PXE service stopped",
	}

	h.logger.Info("PXE service stopped")
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Webhook Handler
// =============================================================================

// handleWebhookComplete handles POST /api/v1/pxe/webhook/complete
func (h *PXEHandlers) handleWebhookComplete(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.service == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotAvailable{})
		return
	}

	if !h.service.IsRunning() {
		h.writeError(w, http.StatusServiceUnavailable, ErrPXEServiceNotRunning{})
		return
	}

	var payload pxe.WebhookPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if payload.MACAddress == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "mac_address"})
		return
	}

	// Find device by MAC address
	device, err := h.service.GetDeviceByMAC(ctx, payload.MACAddress)
	if err != nil {
		h.logger.Error("Webhook: device not found", "error", err, "mac_address", payload.MACAddress)
		h.writePXEError(w, "webhook_complete", err)
		return
	}

	// Determine target state based on webhook success
	var targetState pxe.ProvisioningState
	var reason string
	if payload.Success {
		targetState = pxe.StateInstallComplete
		reason = "installation completed successfully"
		if payload.Message != "" {
			reason = payload.Message
		}
	} else {
		targetState = pxe.StateFailed
		reason = "installation failed"
		if payload.Message != "" {
			reason = payload.Message
		}
	}

	// Update device state
	if err := h.service.UpdateDeviceState(ctx, device.ID, targetState, reason); err != nil {
		h.logger.Error("Webhook: failed to update device state", "error", err, "device_id", device.ID)
		h.writePXEError(w, "webhook_complete", err)
		return
	}

	resp := PXEActionResponse{
		DeviceID: device.ID,
		Action:   "webhook_complete",
		Success:  true,
		Message:  fmt.Sprintf("device state updated to %s", targetState),
	}

	h.logger.Info("Webhook completed", "device_id", device.ID, "mac_address", payload.MACAddress, "success", payload.Success)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// deviceToResponse converts a DeviceInfo to PXEDeviceResponse.
func (h *PXEHandlers) deviceToResponse(device *pxe.DeviceInfo) PXEDeviceResponse {
	resp := PXEDeviceResponse{
		ID:                device.ID,
		MACAddress:        device.MACAddress.String(),
		PortID:            device.PortID,
		State:             string(device.State),
		StateReason:       device.StateReason,
		CertificateSerial: device.CertificateSerial,
		CurrentVLAN:       device.CurrentVLAN,
		TargetVLAN:        device.TargetVLAN,
		RetryCount:        device.RetryCount,
		CreatedAt:         device.CreatedAt,
		UpdatedAt:         device.UpdatedAt,
		StateChangedAt:    device.StateChangedAt,
	}

	if len(device.Events) > 0 {
		resp.Events = make([]*PXEProvisioningEventResp, 0, len(device.Events))
		for _, event := range device.Events {
			resp.Events = append(resp.Events, &PXEProvisioningEventResp{
				ID:        event.ID,
				DeviceID:  event.DeviceID,
				Timestamp: event.Timestamp,
				EventType: string(event.EventType),
				FromState: string(event.FromState),
				ToState:   string(event.ToState),
				Details:   event.Details,
				Error:     event.Error,
			})
		}
	}

	return resp
}

// writeJSON writes a JSON response.
func (h *PXEHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *PXEHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, PXEErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writePXEError maps PXE errors to appropriate HTTP status codes.
func (h *PXEHandlers) writePXEError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch err.(type) {
	case pxe.ErrDeviceNotFound:
		status = http.StatusNotFound
	case pxe.ErrDeviceAlreadyExists:
		status = http.StatusConflict
	case pxe.ErrInvalidMACAddress:
		status = http.StatusBadRequest
	case pxe.ErrInvalidState:
		status = http.StatusBadRequest
	case pxe.ErrInvalidStateTransition:
		status = http.StatusConflict
	case pxe.ErrInvalidConfiguration:
		status = http.StatusBadRequest
	case pxe.ErrServiceNotInitialized:
		status = http.StatusServiceUnavailable
	case pxe.ErrServiceNotRunning:
		status = http.StatusServiceUnavailable
	case pxe.ErrServiceAlreadyRunning:
		status = http.StatusConflict
	case pxe.ErrMaxRetriesExceeded:
		status = http.StatusConflict
	case pxe.ErrVLANTransitionFailed:
		status = http.StatusInternalServerError
	case pxe.ErrProvisioningFailed:
		status = http.StatusInternalServerError
	case pxe.ErrTimeout:
		status = http.StatusGatewayTimeout
	case pxe.ErrWebhookValidationFailed:
		status = http.StatusBadRequest
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrPXEOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}
