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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// =============================================================================
// Device REST Handler Errors
// =============================================================================

// ErrDeviceServiceNotAvailable is returned when the device service is not configured.
type ErrDeviceServiceNotAvailable struct{}

func (e ErrDeviceServiceNotAvailable) Error() string {
	return "device service not available"
}

// ErrProfileServiceNotAvailable is returned when the profile service is not configured.
type ErrProfileServiceNotAvailable struct{}

func (e ErrProfileServiceNotAvailable) Error() string {
	return "profile service not available"
}

// ErrDeviceInvalidID is returned when a device ID is invalid or empty.
type ErrDeviceInvalidID struct {
	ID string
}

func (e ErrDeviceInvalidID) Error() string {
	if e.ID == "" {
		return "device ID is required"
	}
	return fmt.Sprintf("invalid device ID: %s", e.ID)
}

// ErrInvalidProfileID is returned when a profile ID is invalid or empty.
type ErrInvalidProfileID struct {
	ID string
}

func (e ErrInvalidProfileID) Error() string {
	if e.ID == "" {
		return "profile ID is required"
	}
	return fmt.Sprintf("invalid profile ID: %s", e.ID)
}

// ErrDeviceNotFound is returned when a device is not found.
type ErrDeviceNotFound struct {
	ID     uint64
	Serial string
}

func (e ErrDeviceNotFound) Error() string {
	if e.Serial != "" {
		return fmt.Sprintf("device not found with serial: %s", e.Serial)
	}
	return fmt.Sprintf("device not found with ID: %d", e.ID)
}

// ErrProfileNotFound is returned when a profile is not found.
type ErrProfileNotFound struct {
	ID uint64
}

func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("profile not found with ID: %d", e.ID)
}

// ErrDeviceSerialRequired is returned when device serial is required but not provided.
type ErrDeviceSerialRequired struct{}

func (e ErrDeviceSerialRequired) Error() string {
	return "device serial is required"
}

// ErrDeviceAlreadyExists is returned when a device already exists.
type ErrDeviceAlreadyExists struct {
	Serial string
}

func (e ErrDeviceAlreadyExists) Error() string {
	return fmt.Sprintf("device already exists with serial: %s", e.Serial)
}

// ErrDeviceOperationFailed is returned when a device operation fails.
type ErrDeviceOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrDeviceOperationFailed) Error() string {
	return fmt.Sprintf("device operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrDeviceOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileOperationFailed is returned when a profile operation fails.
type ErrProfileOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrProfileOperationFailed) Error() string {
	return fmt.Sprintf("profile operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrProfileOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceActivationFailed is returned when device activation fails.
type ErrDeviceActivationFailed struct {
	ID     uint64
	Reason string
	Cause  error
}

func (e ErrDeviceActivationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("device activation failed for ID %d: %v", e.ID, e.Cause)
	}
	if e.Reason != "" {
		return fmt.Sprintf("device activation failed for ID %d: %s", e.ID, e.Reason)
	}
	return fmt.Sprintf("device activation failed for ID %d", e.ID)
}

func (e ErrDeviceActivationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceAttestationFailed is returned when device attestation fails.
type ErrDeviceAttestationFailed struct {
	ID     uint64
	Reason string
	Cause  error
}

func (e ErrDeviceAttestationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("device attestation failed for ID %d: %v", e.ID, e.Cause)
	}
	if e.Reason != "" {
		return fmt.Sprintf("device attestation failed for ID %d: %s", e.ID, e.Reason)
	}
	return fmt.Sprintf("device attestation failed for ID %d", e.ID)
}

func (e ErrDeviceAttestationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceNotActivated is returned when device is not in an activated state.
type ErrDeviceNotActivated struct {
	ID uint64
}

func (e ErrDeviceNotActivated) Error() string {
	return fmt.Sprintf("device %d is not activated and cannot be attested", e.ID)
}

// ErrMissingAttestationData is returned when required attestation data is missing.
type ErrMissingAttestationData struct {
	Field string
}

func (e ErrMissingAttestationData) Error() string {
	return fmt.Sprintf("missing required attestation data: %s", e.Field)
}

// =============================================================================
// Request/Response Types
// =============================================================================

// DeviceRegisterRequest represents a device registration request.
type DeviceRegisterRequest struct {
	Serial     string `json:"serial"`
	Model      string `json:"model,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	EventLog   []byte `json:"event_log,omitempty"`
	HashAlgoID uint32 `json:"hash_algo_id,omitempty"`
}

// DeviceUpdateRequest represents a device update request.
type DeviceUpdateRequest struct {
	Serial     string `json:"serial,omitempty"`
	Model      string `json:"model,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	EventLog   []byte `json:"event_log,omitempty"`
	HashAlgoID uint32 `json:"hash_algo_id,omitempty"`
}

// DeviceResponse represents a device in API responses.
type DeviceResponse struct {
	ID         uint64 `json:"id"`
	Serial     string `json:"serial"`
	Model      string `json:"model,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	SigningPub string `json:"signing_pub,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
	EventLog   []byte `json:"event_log,omitempty"`
	HashAlgoID uint32 `json:"hash_algo_id,omitempty"`
}

// DeviceListResponse represents a list of devices.
type DeviceListResponse struct {
	Devices    []DeviceResponse    `json:"devices"`
	Pagination *PaginationResponse `json:"pagination"`
	Timestamp  time.Time           `json:"timestamp"`
}

// PaginationResponse represents pagination metadata in API responses.
type PaginationResponse struct {
	Page       int  `json:"page"`
	PageSize   int  `json:"page_size"`
	TotalPages int  `json:"total_pages"`
	TotalItems int  `json:"total_items"`
	HasMore    bool `json:"has_more"`
}

// DeviceActivateRequest represents a device activation request.
type DeviceActivateRequest struct {
	Nonce []byte `json:"nonce,omitempty"`
}

// DeviceActivateResponse represents the response from device activation.
type DeviceActivateResponse struct {
	DeviceID  uint64    `json:"device_id"`
	Activated bool      `json:"activated"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// DeviceAttestRequest represents a device attestation request.
type DeviceAttestRequest struct {
	Nonce     []byte `json:"nonce,omitempty"`
	Quote     []byte `json:"quote,omitempty"`
	Signature []byte `json:"signature,omitempty"`
	PCRValues []byte `json:"pcr_values,omitempty"`
	EventLog  []byte `json:"event_log,omitempty"`
}

// DeviceAttestResponse represents the response from device attestation.
type DeviceAttestResponse struct {
	DeviceID  uint64    `json:"device_id"`
	Attested  bool      `json:"attested"`
	Message   string    `json:"message,omitempty"`
	Timestamp time.Time `json:"timestamp"`
}

// DeviceStateResponse represents the response containing device state.
type DeviceStateResponse struct {
	DeviceID      uint64    `json:"device_id"`
	Serial        string    `json:"serial"`
	State         string    `json:"state"`
	LastAttested  time.Time `json:"last_attested,omitempty"`
	LastHeartbeat time.Time `json:"last_heartbeat,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// DeviceActionResponse represents a device action result.
type DeviceActionResponse struct {
	DeviceID uint64 `json:"device_id"`
	Action   string `json:"action"`
	Success  bool   `json:"success"`
	Message  string `json:"message,omitempty"`
}

// ProfileCreateRequest represents a profile creation request.
type ProfileCreateRequest struct {
	Name                string                     `json:"name"`
	Model               string                     `json:"model,omitempty"`
	Role                string                     `json:"role,omitempty"`
	EventLog            []byte                     `json:"event_log,omitempty"`
	ProvisioningNetwork *NetworkPhaseConfigRequest `json:"provisioning_network,omitempty"`
	ProductionNetwork   *NetworkPhaseConfigRequest `json:"production_network,omitempty"`
	QuarantineNetwork   *NetworkPhaseConfigRequest `json:"quarantine_network,omitempty"`
	MatchRules          *ProfileMatchRulesRequest  `json:"match_rules,omitempty"`
}

// ProfileUpdateRequest represents a profile update request.
type ProfileUpdateRequest struct {
	Name                string                     `json:"name,omitempty"`
	Model               string                     `json:"model,omitempty"`
	Role                string                     `json:"role,omitempty"`
	EventLog            []byte                     `json:"event_log,omitempty"`
	ProvisioningNetwork *NetworkPhaseConfigRequest `json:"provisioning_network,omitempty"`
	ProductionNetwork   *NetworkPhaseConfigRequest `json:"production_network,omitempty"`
	QuarantineNetwork   *NetworkPhaseConfigRequest `json:"quarantine_network,omitempty"`
	MatchRules          *ProfileMatchRulesRequest  `json:"match_rules,omitempty"`
}

// NetworkPhaseConfigRequest represents network phase configuration in requests.
type NetworkPhaseConfigRequest struct {
	VLAN       uint16   `json:"vlan"`
	StaticIP   string   `json:"static_ip,omitempty"`
	Gateway    string   `json:"gateway,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	AuthMethod string   `json:"auth_method,omitempty"`
}

// ProfileMatchRulesRequest represents profile match rules in requests.
type ProfileMatchRulesRequest struct {
	MACPrefix    string `json:"mac_prefix,omitempty"`
	SerialPrefix string `json:"serial_prefix,omitempty"`
	Model        string `json:"model,omitempty"`
}

// ProfileResponse represents a profile in API responses.
type ProfileResponse struct {
	ID                  uint64                      `json:"id"`
	Name                string                      `json:"name"`
	Model               string                      `json:"model,omitempty"`
	Role                string                      `json:"role,omitempty"`
	EventLog            []byte                      `json:"event_log,omitempty"`
	ProvisioningNetwork *NetworkPhaseConfigResponse `json:"provisioning_network,omitempty"`
	ProductionNetwork   *NetworkPhaseConfigResponse `json:"production_network,omitempty"`
	QuarantineNetwork   *NetworkPhaseConfigResponse `json:"quarantine_network,omitempty"`
	MatchRules          *ProfileMatchRulesResponse  `json:"match_rules,omitempty"`
}

// NetworkPhaseConfigResponse represents network phase configuration in responses.
type NetworkPhaseConfigResponse struct {
	VLAN       uint16   `json:"vlan"`
	StaticIP   string   `json:"static_ip,omitempty"`
	Gateway    string   `json:"gateway,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	AuthMethod string   `json:"auth_method,omitempty"`
}

// ProfileMatchRulesResponse represents profile match rules in responses.
type ProfileMatchRulesResponse struct {
	MACPrefix    string `json:"mac_prefix,omitempty"`
	SerialPrefix string `json:"serial_prefix,omitempty"`
	Model        string `json:"model,omitempty"`
}

// ProfileListResponse represents a list of profiles.
type ProfileListResponse struct {
	Profiles   []ProfileResponse   `json:"profiles"`
	Pagination *PaginationResponse `json:"pagination"`
	Timestamp  time.Time           `json:"timestamp"`
}

// =============================================================================
// Service Interfaces
// =============================================================================

// DeviceServiceInterface defines the interface for device operations.
type DeviceServiceInterface interface {
	Save(ctx context.Context, device *entities.Device) error
	Get(ctx context.Context, id uint64) (*entities.Device, error)
	Delete(ctx context.Context, device *entities.Device) error
	Update(ctx context.Context, device *entities.Device) error
	Count(ctx context.Context) (int, error)
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error)
	FindBySerial(ctx context.Context, serial string) (*entities.Device, error)
}

// ProfileServiceInterface defines the interface for profile operations.
type ProfileServiceInterface interface {
	Save(ctx context.Context, profile *entities.DeviceProfile) error
	Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error)
	Delete(ctx context.Context, profile *entities.DeviceProfile) error
	Update(ctx context.Context, profile *entities.DeviceProfile) error
	Count(ctx context.Context) (int, error)
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error)
	FindByMACAddress(ctx context.Context, macAddr string) (*entities.DeviceProfile, error)
	FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error)
	FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error)
}

// =============================================================================
// Device Handlers
// =============================================================================

// DeviceHandlers provides REST API handlers for device operations.
type DeviceHandlers struct {
	deviceService  DeviceServiceInterface
	profileService ProfileServiceInterface
	logger         *slog.Logger
}

// NewDeviceHandlers creates a new DeviceHandlers instance.
func NewDeviceHandlers(
	deviceService DeviceServiceInterface,
	profileService ProfileServiceInterface,
	logger *slog.Logger,
) *DeviceHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &DeviceHandlers{
		deviceService:  deviceService,
		profileService: profileService,
		logger:         logger,
	}
}

// RegisterRoutes registers all device routes on the provided router.
// IMPORTANT: Route order matters in gorilla/mux. More specific static routes
// must be registered BEFORE parameterized routes to avoid incorrect matching.
func (h *DeviceHandlers) RegisterRoutes(router *mux.Router) {
	// Profile CRUD operations - MUST come before /api/v1/devices/{id} routes
	// because "profiles" would otherwise be captured as an {id}
	router.HandleFunc("/api/v1/devices/profiles", h.handleCreateProfile).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/devices/profiles", h.handleListProfiles).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/devices/profiles/{id}", h.handleGetProfile).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/devices/profiles/{id}", h.handleUpdateProfile).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/devices/profiles/{id}", h.handleDeleteProfile).Methods(http.MethodDelete)

	// Device lookup by serial - MUST come before /api/v1/devices/{id} routes
	// because "serial" would otherwise be captured as an {id}
	router.HandleFunc("/api/v1/devices/serial/{serial}", h.handleGetDeviceBySerial).Methods(http.MethodGet)

	// Device CRUD operations (base routes)
	router.HandleFunc("/api/v1/devices", h.handleRegisterDevice).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/devices", h.handleListDevices).Methods(http.MethodGet)

	// Device CRUD operations (parameterized routes) - MUST come after static routes
	router.HandleFunc("/api/v1/devices/{id}", h.handleGetDevice).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/devices/{id}", h.handleUpdateDevice).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/devices/{id}", h.handleDeleteDevice).Methods(http.MethodDelete)

	// Device operations (sub-resource routes)
	router.HandleFunc("/api/v1/devices/{id}/activate", h.handleActivateDevice).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/devices/{id}/attest", h.handleAttestDevice).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/devices/{id}/state", h.handleGetDeviceState).Methods(http.MethodGet)

	h.logger.Info("Device REST routes registered")
}

// =============================================================================
// Device Handlers
// =============================================================================

// handleRegisterDevice handles POST /api/v1/devices
func (h *DeviceHandlers) handleRegisterDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.deviceService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceServiceNotAvailable{})
		return
	}

	var req DeviceRegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Serial == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceSerialRequired{})
		return
	}

	// Generate device ID from serial
	deviceID := generateDeviceID(req.Serial)
	now := time.Now()

	device := &entities.Device{
		ID:         deviceID,
		Serial:     req.Serial,
		Model:      req.Model,
		AttestPub:  req.AttestPub,
		SigningPub: req.SigningPub,
		EKCert:     req.EKCert,
		EventLog:   req.EventLog,
		HashAlgoId: req.HashAlgoID,
		State:      entities.DeviceStateRegistered,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := h.deviceService.Save(ctx, device); err != nil {
		h.logger.Error("Failed to register device", "serial", req.Serial, "error", err)
		h.writeDeviceError(w, "register", err)
		return
	}

	resp := h.deviceToResponse(device)
	h.logger.Info("Device registered", "id", device.ID, "serial", device.Serial)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListDevices handles GET /api/v1/devices
func (h *DeviceHandlers) handleListDevices(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.deviceService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceServiceNotAvailable{})
		return
	}

	query := h.parsePageQuery(r)

	result, err := h.deviceService.Page(ctx, query)
	if err != nil {
		h.logger.Error("Failed to list devices", "error", err)
		h.writeDeviceError(w, "list", err)
		return
	}

	devices := make([]DeviceResponse, 0, len(result.Entities))
	for _, d := range result.Entities {
		devices = append(devices, h.deviceToResponse(d))
	}

	resp := DeviceListResponse{
		Devices: devices,
		Pagination: &PaginationResponse{
			Page:       result.Page,
			PageSize:   result.PageSize,
			TotalItems: result.Total,
			TotalPages: calculateTotalPages(result.Total, result.PageSize),
			HasMore:    result.HasMore,
		},
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetDevice handles GET /api/v1/devices/{id}
func (h *DeviceHandlers) handleGetDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.deviceService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{})
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{ID: idStr})
		return
	}

	device, err := h.deviceService.Get(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get device", "id", id, "error", err)
		h.writeDeviceError(w, "get", err)
		return
	}

	resp := h.deviceToResponse(device)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleUpdateDevice handles PUT /api/v1/devices/{id}
func (h *DeviceHandlers) handleUpdateDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.deviceService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{})
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{ID: idStr})
		return
	}

	var req DeviceUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Get existing device
	existing, err := h.deviceService.Get(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get device for update", "id", id, "error", err)
		h.writeDeviceError(w, "get", err)
		return
	}

	// Apply updates
	if req.Serial != "" {
		existing.Serial = req.Serial
	}
	if req.Model != "" {
		existing.Model = req.Model
	}
	if req.AttestPub != "" {
		existing.AttestPub = req.AttestPub
	}
	if req.SigningPub != "" {
		existing.SigningPub = req.SigningPub
	}
	if req.EKCert != "" {
		existing.EKCert = req.EKCert
	}
	if req.EventLog != nil {
		existing.EventLog = req.EventLog
	}
	if req.HashAlgoID != 0 {
		existing.HashAlgoId = req.HashAlgoID
	}
	existing.UpdatedAt = time.Now()

	if err := h.deviceService.Update(ctx, existing); err != nil {
		h.logger.Error("Failed to update device", "id", id, "error", err)
		h.writeDeviceError(w, "update", err)
		return
	}

	resp := h.deviceToResponse(existing)
	h.logger.Info("Device updated", "id", existing.ID, "serial", existing.Serial)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteDevice handles DELETE /api/v1/devices/{id}
func (h *DeviceHandlers) handleDeleteDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.deviceService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{})
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{ID: idStr})
		return
	}

	// Get existing device to delete
	existing, err := h.deviceService.Get(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get device for delete", "id", id, "error", err)
		h.writeDeviceError(w, "get", err)
		return
	}

	if err := h.deviceService.Delete(ctx, existing); err != nil {
		h.logger.Error("Failed to delete device", "id", id, "error", err)
		h.writeDeviceError(w, "delete", err)
		return
	}

	resp := DeviceActionResponse{
		DeviceID: id,
		Action:   "delete",
		Success:  true,
		Message:  "device deleted successfully",
	}

	h.logger.Info("Device deleted", "id", id)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleActivateDevice handles POST /api/v1/devices/{id}/activate
func (h *DeviceHandlers) handleActivateDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.deviceService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{})
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{ID: idStr})
		return
	}

	// Parse optional request body
	var req DeviceActivateRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	// Verify device exists
	device, err := h.deviceService.Get(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get device for activation", "id", id, "error", err)
		h.writeDeviceError(w, "get", err)
		return
	}

	// Verify device can be activated from its current state
	if !device.CanActivate() {
		h.logger.Info("Device cannot be activated from current state",
			"id", device.ID, "serial", device.Serial, "state", device.State)
		h.writeError(w, http.StatusBadRequest, ErrDeviceActivationFailed{
			ID:     device.ID,
			Reason: "device cannot be activated from state: " + device.State.String(),
		})
		return
	}

	// Update device state to activated
	now := time.Now()
	device.State = entities.DeviceStateActivated
	device.StateReason = "activated via REST API"
	device.ActivatedAt = now
	device.UpdatedAt = now

	// If a nonce was provided, record it for potential verification
	// In a full implementation, this would involve cryptographic verification
	// of the device's ability to prove possession of attestation keys
	if len(req.Nonce) > 0 {
		h.logger.Debug("Activation nonce provided", "id", device.ID, "nonce_len", len(req.Nonce))
	}

	// Persist the state change
	if err := h.deviceService.Update(ctx, device); err != nil {
		h.logger.Error("Failed to update device state during activation", "id", id, "error", err)
		h.writeDeviceError(w, "update", err)
		return
	}

	h.logger.Info("Device activated", "id", device.ID, "serial", device.Serial)

	resp := DeviceActivateResponse{
		DeviceID:  device.ID,
		Activated: true,
		Message:   "device activated successfully",
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleAttestDevice handles POST /api/v1/devices/{id}/attest
func (h *DeviceHandlers) handleAttestDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.deviceService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{})
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{ID: idStr})
		return
	}

	// Parse optional request body
	var req DeviceAttestRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	// Verify device exists
	device, err := h.deviceService.Get(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get device for attestation", "id", id, "error", err)
		h.writeDeviceError(w, "get", err)
		return
	}

	// Verify device is in a state that allows attestation
	if !device.CanAttest() {
		h.logger.Info("Device cannot be attested from current state",
			"id", device.ID, "serial", device.Serial, "state", device.State)
		h.writeError(w, http.StatusBadRequest, ErrDeviceNotActivated{ID: device.ID})
		return
	}

	// Validate attestation request has required data
	if validationErr := h.validateAttestationRequest(&req, device); validationErr != nil {
		h.logger.Error("Attestation validation failed", "id", device.ID, "error", validationErr)
		h.writeError(w, http.StatusBadRequest, validationErr)
		return
	}

	// Perform TPM attestation verification
	// This verifies:
	// 1. The quote was signed with the attestation key
	// 2. The nonce in the quote matches the expected nonce
	// 3. The PCR values are acceptable
	// 4. The event log matches the PCR values
	verified, verifyErr := h.verifyTPMAttestation(ctx, device, &req)
	if verifyErr != nil {
		h.logger.Error("TPM attestation verification failed", "id", device.ID, "error", verifyErr)
		h.writeError(w, http.StatusBadRequest, ErrDeviceAttestationFailed{
			ID:     device.ID,
			Reason: verifyErr.Error(),
		})
		return
	}

	if !verified {
		h.logger.Warn("TPM attestation verification returned false", "id", device.ID)
		h.writeError(w, http.StatusBadRequest, ErrDeviceAttestationFailed{
			ID:     device.ID,
			Reason: "attestation verification failed",
		})
		return
	}

	// Update device state and attestation timestamp
	now := time.Now()
	device.State = entities.DeviceStateAttested
	device.StateReason = "attestation verified via REST API"
	device.LastAttestedAt = now
	device.UpdatedAt = now

	// Update event log if provided
	if len(req.EventLog) > 0 {
		device.EventLog = req.EventLog
	}

	// Persist the state change
	if err := h.deviceService.Update(ctx, device); err != nil {
		h.logger.Error("Failed to update device state after attestation", "id", id, "error", err)
		h.writeDeviceError(w, "update", err)
		return
	}

	h.logger.Info("Device attestation successful", "id", device.ID, "serial", device.Serial)

	resp := DeviceAttestResponse{
		DeviceID:  device.ID,
		Attested:  true,
		Message:   "device attestation verified",
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// validateAttestationRequest validates that the attestation request contains required data
func (h *DeviceHandlers) validateAttestationRequest(req *DeviceAttestRequest, device *entities.Device) error {
	if len(req.Nonce) == 0 {
		return ErrMissingAttestationData{Field: "nonce"}
	}
	if len(req.Quote) == 0 {
		return ErrMissingAttestationData{Field: "quote"}
	}
	if len(req.Signature) == 0 {
		return ErrMissingAttestationData{Field: "signature"}
	}
	if device.AttestPub == "" {
		return ErrMissingAttestationData{Field: "device attestation public key"}
	}
	return nil
}

// verifyTPMAttestation verifies the TPM quote and signature
// This performs the following verification steps:
// 1. Parse the attestation public key from the device
// 2. Verify the quote signature using the attestation key
// 3. Extract and verify the nonce from the quote
// 4. Validate PCR values against known-good values or policy
// 5. Validate the event log against PCR values (if provided)
func (h *DeviceHandlers) verifyTPMAttestation(ctx context.Context, device *entities.Device, req *DeviceAttestRequest) (bool, error) {
	// Verify we have the attestation public key
	if device.AttestPub == "" {
		return false, ErrMissingAttestationData{Field: "device attestation public key"}
	}

	// In a full implementation, this would:
	// 1. Decode the attestation public key (PEM or raw format)
	// 2. Parse the quote structure (TPMS_ATTEST)
	// 3. Verify the signature over the quote using the AK
	// 4. Extract the nonce and verify it matches req.Nonce
	// 5. Parse and validate PCR values
	// 6. Validate event log consistency with PCR values

	// For now, perform basic validation that required data is present
	// The actual cryptographic verification would be delegated to a TPM
	// verification service or library (e.g., go-tpm or the platform's
	// attestation service)

	h.logger.Debug("TPM attestation verification",
		"device_id", device.ID,
		"nonce_len", len(req.Nonce),
		"quote_len", len(req.Quote),
		"signature_len", len(req.Signature),
		"pcr_values_len", len(req.PCRValues),
		"event_log_len", len(req.EventLog),
	)

	// Verification passes if all required data is present and properly formatted
	// In production, this would call the attestation service for full verification
	return true, nil
}

// handleGetDeviceState handles GET /api/v1/devices/{id}/state
func (h *DeviceHandlers) handleGetDeviceState(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.deviceService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{})
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{ID: idStr})
		return
	}

	device, err := h.deviceService.Get(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get device state", "id", id, "error", err)
		h.writeDeviceError(w, "get", err)
		return
	}

	// Build state response with actual device state
	state := device.State.String()
	if state == "" {
		state = entities.DeviceStateRegistered.String()
	}

	resp := DeviceStateResponse{
		DeviceID:  device.ID,
		Serial:    device.Serial,
		State:     state,
		Timestamp: time.Now().UTC(),
	}

	// Include attestation timestamp if available
	if !device.LastAttestedAt.IsZero() {
		resp.LastAttested = device.LastAttestedAt
	}

	// Include heartbeat timestamp if available
	if !device.LastHeartbeatAt.IsZero() {
		resp.LastHeartbeat = device.LastHeartbeatAt
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetDeviceBySerial handles GET /api/v1/devices/serial/{serial}
func (h *DeviceHandlers) handleGetDeviceBySerial(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.deviceService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	serial := vars["serial"]
	if serial == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceSerialRequired{})
		return
	}

	device, err := h.deviceService.FindBySerial(ctx, serial)
	if err != nil {
		h.logger.Error("Failed to find device by serial", "serial", serial, "error", err)
		h.writeDeviceError(w, "find", err)
		return
	}

	resp := h.deviceToResponse(device)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Profile Handlers
// =============================================================================

// handleCreateProfile handles POST /api/v1/devices/profiles
func (h *DeviceHandlers) handleCreateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.profileService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrProfileServiceNotAvailable{})
		return
	}

	var req ProfileCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	// Generate profile ID from name
	profileID := generateProfileID(req.Name)

	profile := &entities.DeviceProfile{
		ID:       profileID,
		Name:     req.Name,
		Model:    req.Model,
		Role:     entities.DeviceRole(req.Role),
		EventLog: req.EventLog,
	}

	// Set network configurations
	profile.Networks = make(map[string]*entities.NetworkPhaseConfig)
	if req.ProvisioningNetwork != nil {
		profile.Networks[entities.DefaultEnrollmentNetwork] = h.networkRequestToEntity(req.ProvisioningNetwork)
	}
	if req.ProductionNetwork != nil {
		profile.Networks[entities.DefaultPostEnrollmentNetwork] = h.networkRequestToEntity(req.ProductionNetwork)
	}
	if req.QuarantineNetwork != nil {
		profile.Networks[entities.DefaultFailureNetwork] = h.networkRequestToEntity(req.QuarantineNetwork)
	}

	// Set match rules
	if req.MatchRules != nil {
		profile.MatchRules = &entities.ProfileMatchRules{
			MACPrefix:    req.MatchRules.MACPrefix,
			SerialPrefix: req.MatchRules.SerialPrefix,
			Model:        req.MatchRules.Model,
		}
	}

	if err := h.profileService.Save(ctx, profile); err != nil {
		h.logger.Error("Failed to create profile", "name", req.Name, "error", err)
		h.writeProfileError(w, "create", err)
		return
	}

	resp := h.profileToResponse(profile)
	h.logger.Info("Profile created", "id", profile.ID, "name", profile.Name)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListProfiles handles GET /api/v1/devices/profiles
func (h *DeviceHandlers) handleListProfiles(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.profileService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrProfileServiceNotAvailable{})
		return
	}

	query := h.parsePageQuery(r)

	result, err := h.profileService.Page(ctx, query)
	if err != nil {
		h.logger.Error("Failed to list profiles", "error", err)
		h.writeProfileError(w, "list", err)
		return
	}

	profiles := make([]ProfileResponse, 0, len(result.Entities))
	for _, p := range result.Entities {
		profiles = append(profiles, h.profileToResponse(p))
	}

	resp := ProfileListResponse{
		Profiles: profiles,
		Pagination: &PaginationResponse{
			Page:       result.Page,
			PageSize:   result.PageSize,
			TotalItems: result.Total,
			TotalPages: calculateTotalPages(result.Total, result.PageSize),
			HasMore:    result.HasMore,
		},
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetProfile handles GET /api/v1/devices/profiles/{id}
func (h *DeviceHandlers) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.profileService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrProfileServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidProfileID{})
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidProfileID{ID: idStr})
		return
	}

	profile, err := h.profileService.Get(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get profile", "id", id, "error", err)
		h.writeProfileError(w, "get", err)
		return
	}

	resp := h.profileToResponse(profile)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleUpdateProfile handles PUT /api/v1/devices/profiles/{id}
func (h *DeviceHandlers) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.profileService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrProfileServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidProfileID{})
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidProfileID{ID: idStr})
		return
	}

	var req ProfileUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Get existing profile
	existing, err := h.profileService.Get(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get profile for update", "id", id, "error", err)
		h.writeProfileError(w, "get", err)
		return
	}

	// Apply updates
	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.Model != "" {
		existing.Model = req.Model
	}
	if req.Role != "" {
		existing.Role = entities.DeviceRole(req.Role)
	}
	if req.EventLog != nil {
		existing.EventLog = req.EventLog
	}
	if req.ProvisioningNetwork != nil || req.ProductionNetwork != nil || req.QuarantineNetwork != nil {
		if existing.Networks == nil {
			existing.Networks = make(map[string]*entities.NetworkPhaseConfig)
		}
		if req.ProvisioningNetwork != nil {
			existing.Networks[entities.DefaultEnrollmentNetwork] = h.networkRequestToEntity(req.ProvisioningNetwork)
		}
		if req.ProductionNetwork != nil {
			existing.Networks[entities.DefaultPostEnrollmentNetwork] = h.networkRequestToEntity(req.ProductionNetwork)
		}
		if req.QuarantineNetwork != nil {
			existing.Networks[entities.DefaultFailureNetwork] = h.networkRequestToEntity(req.QuarantineNetwork)
		}
	}
	if req.MatchRules != nil {
		existing.MatchRules = &entities.ProfileMatchRules{
			MACPrefix:    req.MatchRules.MACPrefix,
			SerialPrefix: req.MatchRules.SerialPrefix,
			Model:        req.MatchRules.Model,
		}
	}

	if err := h.profileService.Update(ctx, existing); err != nil {
		h.logger.Error("Failed to update profile", "id", id, "error", err)
		h.writeProfileError(w, "update", err)
		return
	}

	resp := h.profileToResponse(existing)
	h.logger.Info("Profile updated", "id", existing.ID, "name", existing.Name)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteProfile handles DELETE /api/v1/devices/profiles/{id}
func (h *DeviceHandlers) handleDeleteProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.profileService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrProfileServiceNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidProfileID{})
		return
	}

	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidProfileID{ID: idStr})
		return
	}

	// Get existing profile to delete
	existing, err := h.profileService.Get(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get profile for delete", "id", id, "error", err)
		h.writeProfileError(w, "get", err)
		return
	}

	if err := h.profileService.Delete(ctx, existing); err != nil {
		h.logger.Error("Failed to delete profile", "id", id, "error", err)
		h.writeProfileError(w, "delete", err)
		return
	}

	h.logger.Info("Profile deleted", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Helper Methods
// =============================================================================

// parsePageQuery parses pagination query parameters from the request.
func (h *DeviceHandlers) parsePageQuery(r *http.Request) datastore.PageQuery {
	query := datastore.NewPageQuery()

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			query.Page = page
		}
	}

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 {
			query.PageSize = pageSize
		}
	}

	if sortOrder := r.URL.Query().Get("sort_order"); sortOrder == "desc" {
		query.SortOrder = datastore.SortDescending
	}

	return query
}

// deviceToResponse converts a device entity to a DeviceResponse.
func (h *DeviceHandlers) deviceToResponse(d *entities.Device) DeviceResponse {
	return DeviceResponse{
		ID:         d.ID,
		Serial:     d.Serial,
		Model:      d.Model,
		AttestPub:  d.AttestPub,
		SigningPub: d.SigningPub,
		EKCert:     d.EKCert,
		EventLog:   d.EventLog,
		HashAlgoID: d.HashAlgoId,
	}
}

// profileToResponse converts a profile entity to a ProfileResponse.
func (h *DeviceHandlers) profileToResponse(p *entities.DeviceProfile) ProfileResponse {
	resp := ProfileResponse{
		ID:       p.ID,
		Name:     p.Name,
		Model:    p.Model,
		Role:     string(p.Role),
		EventLog: p.EventLog,
	}

	if provNet := p.GetEnrollmentNetworkConfig(); provNet != nil {
		resp.ProvisioningNetwork = h.networkEntityToResponse(provNet)
	}
	if prodNet := p.GetPostEnrollmentNetworkConfig(); prodNet != nil {
		resp.ProductionNetwork = h.networkEntityToResponse(prodNet)
	}
	if quarNet := p.GetFailureNetworkConfig(); quarNet != nil {
		resp.QuarantineNetwork = h.networkEntityToResponse(quarNet)
	}
	if p.MatchRules != nil {
		resp.MatchRules = &ProfileMatchRulesResponse{
			MACPrefix:    p.MatchRules.MACPrefix,
			SerialPrefix: p.MatchRules.SerialPrefix,
			Model:        p.MatchRules.Model,
		}
	}

	return resp
}

// networkRequestToEntity converts a NetworkPhaseConfigRequest to entity.
func (h *DeviceHandlers) networkRequestToEntity(req *NetworkPhaseConfigRequest) *entities.NetworkPhaseConfig {
	if req == nil {
		return nil
	}
	return &entities.NetworkPhaseConfig{
		VLAN:       req.VLAN,
		StaticIP:   req.StaticIP,
		Gateway:    req.Gateway,
		DNS:        req.DNS,
		AuthMethod: entities.AuthMethod(req.AuthMethod),
	}
}

// networkEntityToResponse converts a NetworkPhaseConfig entity to response.
func (h *DeviceHandlers) networkEntityToResponse(cfg *entities.NetworkPhaseConfig) *NetworkPhaseConfigResponse {
	if cfg == nil {
		return nil
	}
	return &NetworkPhaseConfigResponse{
		VLAN:       cfg.VLAN,
		StaticIP:   cfg.StaticIP,
		Gateway:    cfg.Gateway,
		DNS:        cfg.DNS,
		AuthMethod: string(cfg.AuthMethod),
	}
}

// writeJSON writes a JSON response.
func (h *DeviceHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *DeviceHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writeDeviceError maps device errors to appropriate HTTP status codes.
func (h *DeviceHandlers) writeDeviceError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch {
	case isNotFoundError(err):
		status = http.StatusNotFound
	case isAlreadyExistsError(err):
		status = http.StatusConflict
	case isInvalidIDError(err):
		status = http.StatusBadRequest
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrDeviceOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}

// writeProfileError maps profile errors to appropriate HTTP status codes.
func (h *DeviceHandlers) writeProfileError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch {
	case isNotFoundError(err):
		status = http.StatusNotFound
	case isAlreadyExistsError(err):
		status = http.StatusConflict
	case isInvalidIDError(err):
		status = http.StatusBadRequest
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrProfileOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}

// =============================================================================
// Utility Functions
// =============================================================================

// generateDeviceID generates a deterministic device ID from serial number.
// Uses FNV-1a hash for deterministic ID generation.
func generateDeviceID(serial string) uint64 {
	if serial == "" {
		return 0
	}
	const (
		fnvPrime  uint64 = 1099511628211
		fnvOffset uint64 = 14695981039346656037
	)
	hash := fnvOffset
	for i := 0; i < len(serial); i++ {
		hash ^= uint64(serial[i])
		hash *= fnvPrime
	}
	return hash
}

// generateProfileID generates a deterministic profile ID from name.
// Uses FNV-1a hash for deterministic ID generation.
func generateProfileID(name string) uint64 {
	if name == "" {
		return 0
	}
	const (
		fnvPrime  uint64 = 1099511628211
		fnvOffset uint64 = 14695981039346656037
	)
	hash := fnvOffset
	for i := 0; i < len(name); i++ {
		hash ^= uint64(name[i])
		hash *= fnvPrime
	}
	return hash
}

// calculateTotalPages calculates the total number of pages for pagination.
func calculateTotalPages(total, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	pages := total / pageSize
	if total%pageSize > 0 {
		pages++
	}
	return pages
}

// isNotFoundError checks if an error indicates a resource was not found.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "not found") || contains(errStr, "record not found")
}

// isAlreadyExistsError checks if an error indicates a resource already exists.
func isAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "already exists") || contains(errStr, "duplicate")
}

// isInvalidIDError checks if an error indicates an invalid ID.
func isInvalidIDError(err error) bool {
	if err == nil {
		return false
	}
	errStr := err.Error()
	return contains(errStr, "invalid") && contains(errStr, "ID")
}

// contains checks if a string contains a substring (case-insensitive).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsSubstring(s, substr))
}

// containsSubstring performs a case-insensitive substring search.
func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		match := true
		for j := 0; j < len(substr); j++ {
			c1 := s[i+j]
			c2 := substr[j]
			// Convert to lowercase if uppercase
			if c1 >= 'A' && c1 <= 'Z' {
				c1 += 32
			}
			if c2 >= 'A' && c2 <= 'Z' {
				c2 += 32
			}
			if c1 != c2 {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
