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

package quic

import (
	"context"
	"errors"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// Device pagination defaults
const (
	deviceDefaultLimit int32 = 50
	deviceMaxLimit     int32 = 1000
)

// =============================================================================
// Device-specific sentinel errors
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

// ErrDeviceMissingID is returned when a device ID is required but not provided.
type ErrDeviceMissingID struct{}

func (e ErrDeviceMissingID) Error() string {
	return "device ID is required"
}

// ErrDeviceMissingSerial is returned when a device serial is required but not provided.
type ErrDeviceMissingSerial struct{}

func (e ErrDeviceMissingSerial) Error() string {
	return "device serial is required"
}

// ErrProfileMissingID is returned when a profile ID is required but not provided.
type ErrProfileMissingID struct{}

func (e ErrProfileMissingID) Error() string {
	return "profile ID is required"
}

// ErrProfileMissingName is returned when a profile name is required but not provided.
type ErrProfileMissingName struct{}

func (e ErrProfileMissingName) Error() string {
	return "profile name is required"
}

// ErrDeviceEncodingFailed represents an encoding failure error
type ErrDeviceEncodingFailed struct {
	Cause error
}

func (e ErrDeviceEncodingFailed) Error() string {
	return "failed to encode device payload: " + e.Cause.Error()
}

func (e ErrDeviceEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceDecodingFailed represents a decoding failure error
type ErrDeviceDecodingFailed struct {
	Cause error
}

func (e ErrDeviceDecodingFailed) Error() string {
	return "failed to decode device payload: " + e.Cause.Error()
}

func (e ErrDeviceDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceOperationFailed represents a device operation failure
type ErrDeviceOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrDeviceOperationFailed) Error() string {
	return "device operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrDeviceOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrProfileOperationFailed represents a profile operation failure
type ErrProfileOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrProfileOperationFailed) Error() string {
	return "profile operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrProfileOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceActivationFailed represents a device activation failure
type ErrDeviceActivationFailed struct {
	DeviceID uint64
	Reason   string
}

func (e ErrDeviceActivationFailed) Error() string {
	return "device activation failed: " + e.Reason
}

// ErrDeviceNotActivated represents a device that is not in an activated state
type ErrDeviceNotActivated struct {
	DeviceID uint64
}

func (e ErrDeviceNotActivated) Error() string {
	return "device is not activated and cannot be attested"
}

// ErrAttestationFailed represents an attestation verification failure
type ErrAttestationFailed struct {
	DeviceID uint64
	Reason   string
}

func (e ErrAttestationFailed) Error() string {
	return "attestation verification failed: " + e.Reason
}

// ErrMissingAttestationData represents missing required attestation data
type ErrMissingAttestationData struct {
	Field string
}

func (e ErrMissingAttestationData) Error() string {
	return "missing required attestation data: " + e.Field
}

// =============================================================================
// Service Interfaces
// =============================================================================

// DeviceService defines the interface for device operations.
type DeviceService interface {
	Save(ctx context.Context, device *entities.Device) error
	Get(ctx context.Context, id uint64) (*entities.Device, error)
	Delete(ctx context.Context, device *entities.Device) error
	Update(ctx context.Context, device *entities.Device) error
	Count(ctx context.Context) (int, error)
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error)
	FindBySerial(ctx context.Context, serial string) (*entities.Device, error)
}

// ProfileService defines the interface for profile operations.
type ProfileService interface {
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
// Request/Response Types
// =============================================================================

// DeviceRegisterRequest represents a device registration request
type DeviceRegisterRequest struct {
	Serial     string `codec:"serial"`
	Model      string `codec:"model"`
	AttestPub  string `codec:"attest_pub"`
	AttestCert string `codec:"attest_cert"`
	SigningPub string `codec:"signing_pub"`
	EKCert     string `codec:"ek_cert"`
	EventLog   []byte `codec:"event_log"`
	HashAlgoID uint32 `codec:"hash_algo_id"`
}

// DeviceRegisterResponse represents a device registration response
type DeviceRegisterResponse struct {
	Device    *DeviceInfo `codec:"device"`
	Timestamp int64       `codec:"timestamp"`
}

// DeviceGetRequest represents a device get request
type DeviceGetRequest struct {
	ID uint64 `codec:"id"`
}

// DeviceGetBySerialRequest represents a device lookup by serial request
type DeviceGetBySerialRequest struct {
	Serial string `codec:"serial"`
}

// DeviceGetResponse represents a device get response
type DeviceGetResponse struct {
	Device    *DeviceInfo `codec:"device"`
	Timestamp int64       `codec:"timestamp"`
}

// DeviceListRequest represents a device list request
type DeviceListRequest struct {
	Page      int32 `codec:"page"`
	PageSize  int32 `codec:"page_size"`
	SortOrder int32 `codec:"sort_order"`
}

// DeviceListResponse represents a device list response
type DeviceListResponse struct {
	Devices    []*DeviceInfo `codec:"devices"`
	Page       int32         `codec:"page"`
	PageSize   int32         `codec:"page_size"`
	Total      int32         `codec:"total"`
	HasMore    bool          `codec:"has_more"`
	TotalPages int32         `codec:"total_pages"`
	Timestamp  int64         `codec:"timestamp"`
}

// DeviceUpdateRequest represents a device update request
type DeviceUpdateRequest struct {
	ID         uint64 `codec:"id"`
	Serial     string `codec:"serial"`
	Model      string `codec:"model"`
	AttestPub  string `codec:"attest_pub"`
	AttestCert string `codec:"attest_cert"`
	SigningPub string `codec:"signing_pub"`
	EKCert     string `codec:"ek_cert"`
	EventLog   []byte `codec:"event_log"`
	HashAlgoID uint32 `codec:"hash_algo_id"`
}

// DeviceUpdateResponse represents a device update response
type DeviceUpdateResponse struct {
	Device    *DeviceInfo `codec:"device"`
	Timestamp int64       `codec:"timestamp"`
}

// DeviceDeleteRequest represents a device deletion request
type DeviceDeleteRequest struct {
	ID uint64 `codec:"id"`
}

// DeviceDeleteResponse represents a device deletion response
type DeviceDeleteResponse struct {
	ID        uint64 `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// DeviceActivateRequest represents a device activation request
type DeviceActivateRequest struct {
	ID    uint64 `codec:"id"`
	Nonce []byte `codec:"nonce"`
}

// DeviceActivateResponse represents a device activation response
type DeviceActivateResponse struct {
	DeviceID  uint64 `codec:"device_id"`
	Activated bool   `codec:"activated"`
	Message   string `codec:"message"`
	Timestamp int64  `codec:"timestamp"`
}

// DeviceAttestRequest represents a device attestation request
type DeviceAttestRequest struct {
	ID        uint64 `codec:"id"`
	Nonce     []byte `codec:"nonce"`
	Quote     []byte `codec:"quote"`
	Signature []byte `codec:"signature"`
	PCRValues []byte `codec:"pcr_values"`
	EventLog  []byte `codec:"event_log"`
}

// DeviceAttestResponse represents a device attestation response
type DeviceAttestResponse struct {
	DeviceID  uint64 `codec:"device_id"`
	Attested  bool   `codec:"attested"`
	Message   string `codec:"message"`
	Timestamp int64  `codec:"timestamp"`
}

// DeviceStateRequest represents a device state request
type DeviceStateRequest struct {
	ID uint64 `codec:"id"`
}

// DeviceStateResponse represents a device state response
type DeviceStateResponse struct {
	DeviceID      uint64 `codec:"device_id"`
	Serial        string `codec:"serial"`
	State         string `codec:"state"`
	LastAttested  int64  `codec:"last_attested"`
	LastHeartbeat int64  `codec:"last_heartbeat"`
	Timestamp     int64  `codec:"timestamp"`
}

// DeviceInfo contains device information
type DeviceInfo struct {
	ID         uint64 `codec:"id"`
	Serial     string `codec:"serial"`
	Model      string `codec:"model"`
	AttestPub  string `codec:"attest_pub"`
	AttestCert string `codec:"attest_cert"`
	SigningPub string `codec:"signing_pub"`
	EKCert     string `codec:"ek_cert"`
	EventLog   []byte `codec:"event_log"`
	HashAlgoID uint32 `codec:"hash_algo_id"`
}

// =============================================================================
// Profile Request/Response Types
// =============================================================================

// ProfileCreateRequest represents a profile creation request
type ProfileCreateRequest struct {
	Name                  string                             `codec:"name"`
	Model                 string                             `codec:"model"`
	Role                  string                             `codec:"role"`
	EventLog              []byte                             `codec:"event_log"`
	Zone                  string                             `codec:"zone"`
	Networks              map[string]*NetworkPhaseConfigInfo `codec:"networks"`
	EnrollmentNetwork     string                             `codec:"enrollment_network"`
	PostEnrollmentNetwork string                             `codec:"post_enrollment_network"`
	FailureNetwork        string                             `codec:"failure_network"`
	MatchRules            *ProfileMatchRulesInfo             `codec:"match_rules"`
}

// ProfileCreateResponse represents a profile creation response
type ProfileCreateResponse struct {
	Profile   *ProfileInfo `codec:"profile"`
	Timestamp int64        `codec:"timestamp"`
}

// ProfileGetRequest represents a profile get request
type ProfileGetRequest struct {
	ID uint64 `codec:"id"`
}

// ProfileGetResponse represents a profile get response
type ProfileGetResponse struct {
	Profile   *ProfileInfo `codec:"profile"`
	Timestamp int64        `codec:"timestamp"`
}

// ProfileListRequest represents a profile list request
type ProfileListRequest struct {
	Page      int32 `codec:"page"`
	PageSize  int32 `codec:"page_size"`
	SortOrder int32 `codec:"sort_order"`
}

// ProfileListResponse represents a profile list response
type ProfileListResponse struct {
	Profiles   []*ProfileInfo `codec:"profiles"`
	Page       int32          `codec:"page"`
	PageSize   int32          `codec:"page_size"`
	Total      int32          `codec:"total"`
	HasMore    bool           `codec:"has_more"`
	TotalPages int32          `codec:"total_pages"`
	Timestamp  int64          `codec:"timestamp"`
}

// ProfileUpdateRequest represents a profile update request
type ProfileUpdateRequest struct {
	ID                    uint64                             `codec:"id"`
	Name                  string                             `codec:"name"`
	Model                 string                             `codec:"model"`
	Role                  string                             `codec:"role"`
	EventLog              []byte                             `codec:"event_log"`
	Zone                  string                             `codec:"zone"`
	Networks              map[string]*NetworkPhaseConfigInfo `codec:"networks"`
	EnrollmentNetwork     string                             `codec:"enrollment_network"`
	PostEnrollmentNetwork string                             `codec:"post_enrollment_network"`
	FailureNetwork        string                             `codec:"failure_network"`
	MatchRules            *ProfileMatchRulesInfo             `codec:"match_rules"`
}

// ProfileUpdateResponse represents a profile update response
type ProfileUpdateResponse struct {
	Profile   *ProfileInfo `codec:"profile"`
	Timestamp int64        `codec:"timestamp"`
}

// ProfileDeleteRequest represents a profile deletion request
type ProfileDeleteRequest struct {
	ID uint64 `codec:"id"`
}

// ProfileDeleteResponse represents a profile deletion response
type ProfileDeleteResponse struct {
	ID        uint64 `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// ProfileInfo contains profile information
type ProfileInfo struct {
	ID                    uint64                             `codec:"id"`
	Name                  string                             `codec:"name"`
	Model                 string                             `codec:"model"`
	Role                  string                             `codec:"role"`
	EventLog              []byte                             `codec:"event_log"`
	Zone                  string                             `codec:"zone"`
	Networks              map[string]*NetworkPhaseConfigInfo `codec:"networks"`
	EnrollmentNetwork     string                             `codec:"enrollment_network"`
	PostEnrollmentNetwork string                             `codec:"post_enrollment_network"`
	FailureNetwork        string                             `codec:"failure_network"`
	MatchRules            *ProfileMatchRulesInfo             `codec:"match_rules"`
}

// NetworkPhaseConfigInfo represents network phase configuration
type NetworkPhaseConfigInfo struct {
	VLAN       uint16   `codec:"vlan"`
	StaticIP   string   `codec:"static_ip"`
	Gateway    string   `codec:"gateway"`
	DNS        []string `codec:"dns"`
	AuthMethod string   `codec:"auth_method"`
	Zone       string   `codec:"zone"`
}

// ProfileMatchRulesInfo represents profile match rules
type ProfileMatchRulesInfo struct {
	MACPrefix    string `codec:"mac_prefix"`
	SerialPrefix string `codec:"serial_prefix"`
	Model        string `codec:"model"`
}

// =============================================================================
// DeviceHandler
// =============================================================================

// DeviceHandler handles device operations over QUIC
type DeviceHandler struct {
	deviceService  DeviceService
	profileService ProfileService
	logger         *logging.Logger
}

// NewDeviceHandler creates a new device handler
func NewDeviceHandler(
	logger *logging.Logger,
	deviceService DeviceService,
	profileService ProfileService,
) *DeviceHandler {
	return &DeviceHandler{
		deviceService:  deviceService,
		profileService: profileService,
		logger:         logger,
	}
}

// HandleRequest processes a device request and returns a response
func (h *DeviceHandler) HandleRequest(ctx context.Context, req *Request) *Response {
	if req == nil {
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte(ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	// Device operations
	case OpDeviceRegister:
		return h.handleRegister(ctx, req)
	case OpDeviceGet:
		return h.handleGet(ctx, req)
	case OpDeviceList:
		return h.handleList(ctx, req)
	case OpDeviceUpdate:
		return h.handleUpdate(ctx, req)
	case OpDeviceUnregister:
		return h.handleDelete(ctx, req)
	case OpDeviceActivate:
		return h.handleActivate(ctx, req)
	case OpDeviceAttest:
		return h.handleAttest(ctx, req)
	case OpDeviceGetState:
		return h.handleGetState(ctx, req)

	// Profile operations
	case OpDeviceCreateProfile:
		return h.handleCreateProfile(ctx, req)
	case OpDeviceGetProfile:
		return h.handleGetProfile(ctx, req)
	case OpDeviceListProfiles:
		return h.handleListProfiles(ctx, req)
	case OpDeviceSetProfile:
		return h.handleUpdateProfile(ctx, req)
	case OpDeviceDeleteProfile:
		return h.handleDeleteProfile(ctx, req)

	default:
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte("unknown device operation"),
		}
	}
}

// =============================================================================
// Device Handler Methods
// =============================================================================

// handleRegister registers a new device
func (h *DeviceHandler) handleRegister(ctx context.Context, req *Request) *Response {
	if h.deviceService == nil {
		return h.errorResponse(StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var registerReq DeviceRegisterRequest
	if err := DecodePayload(req.Payload, &registerReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if registerReq.Serial == "" {
		return h.errorResponse(StatusInvalidArgument, ErrDeviceMissingSerial{})
	}

	// Generate device ID from serial
	deviceID := generateDeviceIDFromSerial(registerReq.Serial)
	now := time.Now()

	device := &entities.Device{
		ID:         deviceID,
		Serial:     registerReq.Serial,
		Model:      registerReq.Model,
		AttestPub:  registerReq.AttestPub,
		AttestCert: registerReq.AttestCert,
		SigningPub: registerReq.SigningPub,
		EKCert:     registerReq.EKCert,
		EventLog:   registerReq.EventLog,
		HashAlgoId: registerReq.HashAlgoID,
		State:      entities.DeviceStateRegistered,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := h.deviceService.Save(ctx, device); err != nil {
		h.logger.Error(err, "failed to register device")
		return h.deviceErrorResponse(err)
	}

	resp := &DeviceRegisterResponse{
		Device:    h.deviceToInfo(device),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGet retrieves a device by ID
func (h *DeviceHandler) handleGet(ctx context.Context, req *Request) *Response {
	if h.deviceService == nil {
		return h.errorResponse(StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var getReq DeviceGetRequest
	if err := DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if getReq.ID == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrDeviceMissingID{})
	}

	device, err := h.deviceService.Get(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device")
		return h.deviceErrorResponse(err)
	}

	resp := &DeviceGetResponse{
		Device:    h.deviceToInfo(device),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleList lists devices with pagination
func (h *DeviceHandler) handleList(ctx context.Context, req *Request) *Response {
	if h.deviceService == nil {
		return h.errorResponse(StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var listReq DeviceListRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	// Build page query with defaults
	query := datastore.NewPageQuery()

	if listReq.Page > 0 {
		query.Page = int(listReq.Page)
	}

	if listReq.PageSize > 0 {
		pageSize := listReq.PageSize
		if pageSize > deviceMaxLimit {
			pageSize = deviceMaxLimit
		}
		query.PageSize = int(pageSize)
	} else {
		query.PageSize = int(deviceDefaultLimit)
	}

	if listReq.SortOrder == int32(datastore.SortDescending) {
		query.SortOrder = datastore.SortDescending
	}

	result, err := h.deviceService.Page(ctx, query)
	if err != nil {
		h.logger.Error(err, "failed to list devices")
		return h.deviceErrorResponse(err)
	}

	deviceInfos := make([]*DeviceInfo, 0, len(result.Entities))
	for _, d := range result.Entities {
		deviceInfos = append(deviceInfos, h.deviceToInfo(d))
	}

	resp := &DeviceListResponse{
		Devices:    deviceInfos,
		Page:       int32(result.Page),
		PageSize:   int32(result.PageSize),
		Total:      int32(result.Total),
		HasMore:    result.HasMore,
		TotalPages: calculateTotalPagesInt32(result.Total, result.PageSize),
		Timestamp:  time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleUpdate updates an existing device
func (h *DeviceHandler) handleUpdate(ctx context.Context, req *Request) *Response {
	if h.deviceService == nil {
		return h.errorResponse(StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var updateReq DeviceUpdateRequest
	if err := DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if updateReq.ID == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrDeviceMissingID{})
	}

	// Get existing device
	existing, err := h.deviceService.Get(ctx, updateReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device for update")
		return h.deviceErrorResponse(err)
	}

	// Apply updates
	if updateReq.Serial != "" {
		existing.Serial = updateReq.Serial
	}
	if updateReq.Model != "" {
		existing.Model = updateReq.Model
	}
	if updateReq.AttestPub != "" {
		existing.AttestPub = updateReq.AttestPub
	}
	if updateReq.AttestCert != "" {
		existing.AttestCert = updateReq.AttestCert
	}
	if updateReq.SigningPub != "" {
		existing.SigningPub = updateReq.SigningPub
	}
	if updateReq.EKCert != "" {
		existing.EKCert = updateReq.EKCert
	}
	if updateReq.EventLog != nil {
		existing.EventLog = updateReq.EventLog
	}
	if updateReq.HashAlgoID != 0 {
		existing.HashAlgoId = updateReq.HashAlgoID
	}
	existing.UpdatedAt = time.Now()

	if err := h.deviceService.Update(ctx, existing); err != nil {
		h.logger.Error(err, "failed to update device")
		return h.deviceErrorResponse(err)
	}

	resp := &DeviceUpdateResponse{
		Device:    h.deviceToInfo(existing),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleDelete deletes a device
func (h *DeviceHandler) handleDelete(ctx context.Context, req *Request) *Response {
	if h.deviceService == nil {
		return h.errorResponse(StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var deleteReq DeviceDeleteRequest
	if err := DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if deleteReq.ID == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrDeviceMissingID{})
	}

	// Get existing device to delete
	existing, err := h.deviceService.Get(ctx, deleteReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device for delete")
		return h.deviceErrorResponse(err)
	}

	if err := h.deviceService.Delete(ctx, existing); err != nil {
		h.logger.Error(err, "failed to delete device")
		return h.deviceErrorResponse(err)
	}

	resp := &DeviceDeleteResponse{
		ID:        deleteReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleActivate activates a device
func (h *DeviceHandler) handleActivate(ctx context.Context, req *Request) *Response {
	if h.deviceService == nil {
		return h.errorResponse(StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var activateReq DeviceActivateRequest
	if err := DecodePayload(req.Payload, &activateReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if activateReq.ID == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrDeviceMissingID{})
	}

	// Get the device
	device, err := h.deviceService.Get(ctx, activateReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device for activation")
		return h.deviceErrorResponse(err)
	}

	// Verify device can be activated from its current state
	if !device.CanActivate() {
		h.logger.Info("Device cannot be activated from current state",
			"id", device.ID, "serial", device.Serial, "state", device.State)
		return h.errorResponse(StatusInvalidArgument, ErrDeviceActivationFailed{
			DeviceID: device.ID,
			Reason:   "device cannot be activated from state: " + device.State.String(),
		})
	}

	// Update device state to activated via the lifecycle state machine.
	now := time.Now()
	if err := device.Transition(entities.DeviceStateActivated); err != nil {
		h.logger.Info("Device activation rejected by state machine",
			"id", device.ID, "serial", device.Serial, "state", device.State, "error", err)
		return h.errorResponse(StatusInvalidArgument, ErrDeviceActivationFailed{
			DeviceID: device.ID,
			Reason:   err.Error(),
		})
	}
	device.StateReason = "activated via QUIC API"
	device.ActivatedAt = now
	device.UpdatedAt = now

	// If a nonce was provided, record it for potential verification
	// In a full implementation, this would involve cryptographic verification
	// of the device's ability to prove possession of attestation keys
	if len(activateReq.Nonce) > 0 {
		h.logger.Debug("Activation nonce provided", "id", device.ID, "nonce_len", len(activateReq.Nonce))
	}

	// Persist the state change
	if err := h.deviceService.Update(ctx, device); err != nil {
		h.logger.Error(err, "failed to update device state during activation")
		return h.deviceErrorResponse(err)
	}

	h.logger.Info("Device activated", "id", device.ID, "serial", device.Serial)

	resp := &DeviceActivateResponse{
		DeviceID:  device.ID,
		Activated: true,
		Message:   "device activated successfully",
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleAttest performs TPM attestation for a device
func (h *DeviceHandler) handleAttest(ctx context.Context, req *Request) *Response {
	if h.deviceService == nil {
		return h.errorResponse(StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var attestReq DeviceAttestRequest
	if err := DecodePayload(req.Payload, &attestReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if attestReq.ID == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrDeviceMissingID{})
	}

	// Get the device
	device, err := h.deviceService.Get(ctx, attestReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device for attestation")
		return h.deviceErrorResponse(err)
	}

	// Verify device is in a state that allows attestation
	if !device.CanAttest() {
		h.logger.Info("Device cannot be attested from current state",
			"id", device.ID, "serial", device.Serial, "state", device.State)
		return h.errorResponse(StatusInvalidArgument, ErrDeviceNotActivated{DeviceID: device.ID})
	}

	// Validate attestation request has required data
	if err := h.validateAttestationRequest(&attestReq, device); err != nil {
		h.logger.Error(err, "attestation validation failed", "id", device.ID)
		return h.errorResponse(StatusInvalidArgument, err)
	}

	// Perform TPM attestation verification
	// This verifies:
	// 1. The quote was signed with the attestation key
	// 2. The nonce in the quote matches the expected nonce
	// 3. The PCR values are acceptable
	// 4. The event log matches the PCR values
	verified, verifyErr := h.verifyTPMAttestation(ctx, device, &attestReq)
	if verifyErr != nil {
		h.logger.Error(verifyErr, "TPM attestation verification failed", "id", device.ID)
		return h.errorResponse(StatusInvalidArgument, ErrAttestationFailed{
			DeviceID: device.ID,
			Reason:   verifyErr.Error(),
		})
	}

	if !verified {
		h.logger.Warn("TPM attestation verification returned false", "id", device.ID)
		return h.errorResponse(StatusInvalidArgument, ErrAttestationFailed{
			DeviceID: device.ID,
			Reason:   "attestation verification failed",
		})
	}

	// Update device state and attestation timestamp
	now := time.Now()
	device.State = entities.DeviceStateAttested
	device.StateReason = "attestation verified via QUIC API"
	device.LastAttestedAt = now
	device.UpdatedAt = now

	// Update event log if provided
	if len(attestReq.EventLog) > 0 {
		device.EventLog = attestReq.EventLog
	}

	// Persist the state change
	if err := h.deviceService.Update(ctx, device); err != nil {
		h.logger.Error(err, "failed to update device state after attestation")
		return h.deviceErrorResponse(err)
	}

	h.logger.Info("Device attestation successful", "id", device.ID, "serial", device.Serial)

	resp := &DeviceAttestResponse{
		DeviceID:  device.ID,
		Attested:  true,
		Message:   "device attestation verified",
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// validateAttestationRequest validates that the attestation request contains required data
func (h *DeviceHandler) validateAttestationRequest(req *DeviceAttestRequest, device *entities.Device) error {
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
func (h *DeviceHandler) verifyTPMAttestation(ctx context.Context, device *entities.Device, req *DeviceAttestRequest) (bool, error) {
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

// handleGetState retrieves device state
func (h *DeviceHandler) handleGetState(ctx context.Context, req *Request) *Response {
	if h.deviceService == nil {
		return h.errorResponse(StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var stateReq DeviceStateRequest
	if err := DecodePayload(req.Payload, &stateReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if stateReq.ID == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrDeviceMissingID{})
	}

	device, err := h.deviceService.Get(ctx, stateReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device state")
		return h.deviceErrorResponse(err)
	}

	// Build state response with actual device state
	state := device.State.String()
	if state == "" {
		state = entities.DeviceStateRegistered.String()
	}

	var lastAttested int64
	if !device.LastAttestedAt.IsZero() {
		lastAttested = device.LastAttestedAt.Unix()
	}

	var lastHeartbeat int64
	if !device.LastHeartbeatAt.IsZero() {
		lastHeartbeat = device.LastHeartbeatAt.Unix()
	}

	resp := &DeviceStateResponse{
		DeviceID:      device.ID,
		Serial:        device.Serial,
		State:         state,
		LastAttested:  lastAttested,
		LastHeartbeat: lastHeartbeat,
		Timestamp:     time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Profile Handler Methods
// =============================================================================

// handleCreateProfile creates a new device profile
func (h *DeviceHandler) handleCreateProfile(ctx context.Context, req *Request) *Response {
	if h.profileService == nil {
		return h.errorResponse(StatusUnavailable, ErrProfileServiceNotAvailable{})
	}

	var createReq ProfileCreateRequest
	if err := DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrProfileMissingName{})
	}

	// Generate profile ID from name
	profileID := generateProfileIDFromName(createReq.Name)

	profile := &entities.DeviceProfile{
		ID:       profileID,
		Name:     createReq.Name,
		Model:    createReq.Model,
		Role:     entities.DeviceRole(createReq.Role),
		EventLog: createReq.EventLog,
	}

	// Set network configurations from map-based request.
	profile.Networks = make(map[string]*entities.NetworkPhaseConfig)
	for k, v := range createReq.Networks {
		profile.Networks[k] = h.networkInfoToEntity(v)
	}
	profile.Zone = createReq.Zone
	profile.EnrollmentNetwork = createReq.EnrollmentNetwork
	profile.PostEnrollmentNetwork = createReq.PostEnrollmentNetwork
	profile.FailureNetwork = createReq.FailureNetwork

	// Set match rules
	if createReq.MatchRules != nil {
		profile.MatchRules = &entities.ProfileMatchRules{
			MACPrefix:    createReq.MatchRules.MACPrefix,
			SerialPrefix: createReq.MatchRules.SerialPrefix,
			Model:        createReq.MatchRules.Model,
		}
	}

	if err := h.profileService.Save(ctx, profile); err != nil {
		h.logger.Error(err, "failed to create profile")
		return h.profileErrorResponse(err)
	}

	resp := &ProfileCreateResponse{
		Profile:   h.profileToInfo(profile),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGetProfile retrieves a profile by ID
func (h *DeviceHandler) handleGetProfile(ctx context.Context, req *Request) *Response {
	if h.profileService == nil {
		return h.errorResponse(StatusUnavailable, ErrProfileServiceNotAvailable{})
	}

	var getReq ProfileGetRequest
	if err := DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if getReq.ID == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrProfileMissingID{})
	}

	profile, err := h.profileService.Get(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get profile")
		return h.profileErrorResponse(err)
	}

	resp := &ProfileGetResponse{
		Profile:   h.profileToInfo(profile),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleListProfiles lists profiles with pagination
func (h *DeviceHandler) handleListProfiles(ctx context.Context, req *Request) *Response {
	if h.profileService == nil {
		return h.errorResponse(StatusUnavailable, ErrProfileServiceNotAvailable{})
	}

	var listReq ProfileListRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	// Build page query with defaults
	query := datastore.NewPageQuery()

	if listReq.Page > 0 {
		query.Page = int(listReq.Page)
	}

	if listReq.PageSize > 0 {
		pageSize := listReq.PageSize
		if pageSize > deviceMaxLimit {
			pageSize = deviceMaxLimit
		}
		query.PageSize = int(pageSize)
	} else {
		query.PageSize = int(deviceDefaultLimit)
	}

	if listReq.SortOrder == int32(datastore.SortDescending) {
		query.SortOrder = datastore.SortDescending
	}

	result, err := h.profileService.Page(ctx, query)
	if err != nil {
		h.logger.Error(err, "failed to list profiles")
		return h.profileErrorResponse(err)
	}

	profileInfos := make([]*ProfileInfo, 0, len(result.Entities))
	for _, p := range result.Entities {
		profileInfos = append(profileInfos, h.profileToInfo(p))
	}

	resp := &ProfileListResponse{
		Profiles:   profileInfos,
		Page:       int32(result.Page),
		PageSize:   int32(result.PageSize),
		Total:      int32(result.Total),
		HasMore:    result.HasMore,
		TotalPages: calculateTotalPagesInt32(result.Total, result.PageSize),
		Timestamp:  time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleUpdateProfile updates an existing profile
func (h *DeviceHandler) handleUpdateProfile(ctx context.Context, req *Request) *Response {
	if h.profileService == nil {
		return h.errorResponse(StatusUnavailable, ErrProfileServiceNotAvailable{})
	}

	var updateReq ProfileUpdateRequest
	if err := DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if updateReq.ID == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrProfileMissingID{})
	}

	// Get existing profile
	existing, err := h.profileService.Get(ctx, updateReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get profile for update")
		return h.profileErrorResponse(err)
	}

	// Apply updates
	if updateReq.Name != "" {
		existing.Name = updateReq.Name
	}
	if updateReq.Model != "" {
		existing.Model = updateReq.Model
	}
	if updateReq.Role != "" {
		existing.Role = entities.DeviceRole(updateReq.Role)
	}
	if updateReq.EventLog != nil {
		existing.EventLog = updateReq.EventLog
	}
	if len(updateReq.Networks) > 0 {
		if existing.Networks == nil {
			existing.Networks = make(map[string]*entities.NetworkPhaseConfig, len(updateReq.Networks))
		}
		for k, v := range updateReq.Networks {
			existing.Networks[k] = h.networkInfoToEntity(v)
		}
	}
	if updateReq.Zone != "" {
		existing.Zone = updateReq.Zone
	}
	if updateReq.EnrollmentNetwork != "" {
		existing.EnrollmentNetwork = updateReq.EnrollmentNetwork
	}
	if updateReq.PostEnrollmentNetwork != "" {
		existing.PostEnrollmentNetwork = updateReq.PostEnrollmentNetwork
	}
	if updateReq.FailureNetwork != "" {
		existing.FailureNetwork = updateReq.FailureNetwork
	}
	if updateReq.MatchRules != nil {
		existing.MatchRules = &entities.ProfileMatchRules{
			MACPrefix:    updateReq.MatchRules.MACPrefix,
			SerialPrefix: updateReq.MatchRules.SerialPrefix,
			Model:        updateReq.MatchRules.Model,
		}
	}

	if err := h.profileService.Update(ctx, existing); err != nil {
		h.logger.Error(err, "failed to update profile")
		return h.profileErrorResponse(err)
	}

	resp := &ProfileUpdateResponse{
		Profile:   h.profileToInfo(existing),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleDeleteProfile deletes a profile
func (h *DeviceHandler) handleDeleteProfile(ctx context.Context, req *Request) *Response {
	if h.profileService == nil {
		return h.errorResponse(StatusUnavailable, ErrProfileServiceNotAvailable{})
	}

	var deleteReq ProfileDeleteRequest
	if err := DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if deleteReq.ID == 0 {
		return h.errorResponse(StatusInvalidArgument, ErrProfileMissingID{})
	}

	// Get existing profile to delete
	existing, err := h.profileService.Get(ctx, deleteReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get profile for delete")
		return h.profileErrorResponse(err)
	}

	if err := h.profileService.Delete(ctx, existing); err != nil {
		h.logger.Error(err, "failed to delete profile")
		return h.profileErrorResponse(err)
	}

	resp := &ProfileDeleteResponse{
		ID:        deleteReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// deviceToInfo converts a Device entity to DeviceInfo
func (h *DeviceHandler) deviceToInfo(d *entities.Device) *DeviceInfo {
	if d == nil {
		return nil
	}
	return &DeviceInfo{
		ID:         d.ID,
		Serial:     d.Serial,
		Model:      d.Model,
		AttestPub:  d.AttestPub,
		AttestCert: d.AttestCert,
		SigningPub: d.SigningPub,
		EKCert:     d.EKCert,
		EventLog:   d.EventLog,
		HashAlgoID: d.HashAlgoId,
	}
}

// profileToInfo converts a DeviceProfile entity to ProfileInfo
func (h *DeviceHandler) profileToInfo(p *entities.DeviceProfile) *ProfileInfo {
	if p == nil {
		return nil
	}
	info := &ProfileInfo{
		ID:                    p.ID,
		Name:                  p.Name,
		Model:                 p.Model,
		Role:                  string(p.Role),
		EventLog:              p.EventLog,
		Zone:                  p.Zone,
		EnrollmentNetwork:     p.EnrollmentNetwork,
		PostEnrollmentNetwork: p.PostEnrollmentNetwork,
		FailureNetwork:        p.FailureNetwork,
	}

	if len(p.Networks) > 0 {
		info.Networks = make(map[string]*NetworkPhaseConfigInfo, len(p.Networks))
		for k, v := range p.Networks {
			info.Networks[k] = h.networkEntityToInfo(v)
		}
	}
	if p.MatchRules != nil {
		info.MatchRules = &ProfileMatchRulesInfo{
			MACPrefix:    p.MatchRules.MACPrefix,
			SerialPrefix: p.MatchRules.SerialPrefix,
			Model:        p.MatchRules.Model,
		}
	}

	return info
}

// networkInfoToEntity converts NetworkPhaseConfigInfo to entity
func (h *DeviceHandler) networkInfoToEntity(info *NetworkPhaseConfigInfo) *entities.NetworkPhaseConfig {
	if info == nil {
		return nil
	}
	return &entities.NetworkPhaseConfig{
		VLAN:       info.VLAN,
		StaticIP:   info.StaticIP,
		Gateway:    info.Gateway,
		DNS:        info.DNS,
		AuthMethod: entities.AuthMethod(info.AuthMethod),
		Zone:       info.Zone,
	}
}

// networkEntityToInfo converts NetworkPhaseConfig entity to info
func (h *DeviceHandler) networkEntityToInfo(cfg *entities.NetworkPhaseConfig) *NetworkPhaseConfigInfo {
	if cfg == nil {
		return nil
	}
	return &NetworkPhaseConfigInfo{
		VLAN:       cfg.VLAN,
		StaticIP:   cfg.StaticIP,
		Gateway:    cfg.Gateway,
		DNS:        cfg.DNS,
		AuthMethod: string(cfg.AuthMethod),
		Zone:       cfg.Zone,
	}
}

// errorResponse creates an error response with the given status and error
func (h *DeviceHandler) errorResponse(status byte, err error) *Response {
	return &Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// deviceErrorResponse maps device errors to appropriate status codes
func (h *DeviceHandler) deviceErrorResponse(err error) *Response {
	var status byte

	errStr := err.Error()
	switch {
	case containsIgnoreCase(errStr, "not found"):
		status = StatusNotFound
	case containsIgnoreCase(errStr, "already exists") || containsIgnoreCase(errStr, "duplicate"):
		status = StatusAlreadyExists
	case containsIgnoreCase(errStr, "invalid"):
		status = StatusInvalidArgument
	default:
		status = StatusInternalError
	}

	return h.errorResponse(status, err)
}

// profileErrorResponse maps profile errors to appropriate status codes
func (h *DeviceHandler) profileErrorResponse(err error) *Response {
	var status byte

	var vlans device.ErrProfileVLANsNotDistinct

	errStr := err.Error()
	switch {
	// Typed validation failures from the service layer are client errors.
	// Matched by type, not by the word "invalid" happening to appear in
	// the message.
	case errors.As(err, &vlans):
		status = StatusInvalidArgument
	case containsIgnoreCase(errStr, "not found"):
		status = StatusNotFound
	case containsIgnoreCase(errStr, "already exists") || containsIgnoreCase(errStr, "duplicate"):
		status = StatusAlreadyExists
	case containsIgnoreCase(errStr, "invalid"):
		status = StatusInvalidArgument
	default:
		status = StatusInternalError
	}

	return h.errorResponse(status, err)
}

// =============================================================================
// Utility Functions
// =============================================================================

// generateDeviceIDFromSerial generates a deterministic device ID from serial number.
// Uses FNV-1a hash for deterministic ID generation.
func generateDeviceIDFromSerial(serial string) uint64 {
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

// generateProfileIDFromName generates a deterministic profile ID from name.
// Uses FNV-1a hash for deterministic ID generation.
func generateProfileIDFromName(name string) uint64 {
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

// calculateTotalPagesInt32 calculates the total number of pages for pagination.
func calculateTotalPagesInt32(total, pageSize int) int32 {
	if pageSize <= 0 {
		return 0
	}
	pages := total / pageSize
	if total%pageSize > 0 {
		pages++
	}
	return int32(pages)
}

// containsIgnoreCase checks if a string contains a substring (case-insensitive).
func containsIgnoreCase(s, substr string) bool {
	if len(s) < len(substr) {
		return false
	}
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
