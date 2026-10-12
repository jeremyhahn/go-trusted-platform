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
	"encoding/hex"
	"errors"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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

// ErrDeviceAttestationUnavailable is returned when OpDeviceAttest is reached
// on a handler with no device attestation service wired. It is distinct from
// a verification failure: nothing was evaluated.
type ErrDeviceAttestationUnavailable struct{}

func (e ErrDeviceAttestationUnavailable) Error() string {
	return "device attestation service is not available"
}

// ErrDeviceAttestationRejected is returned when the verifier could not
// evaluate the request at all - malformed evidence, an unknown device, or a
// missing dependency. A quote that verifies to false is NOT this error: it
// is a successful evaluation with a negative verdict.
type ErrDeviceAttestationRejected struct {
	Reason string
}

func (e ErrDeviceAttestationRejected) Error() string {
	if e.Reason == "" {
		return "device attestation could not be evaluated"
	}
	return "device attestation could not be evaluated: " + e.Reason
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

// DeviceAttestRequest is the attestation request on the wire.
//
// Evidence is the JSON-encoded device quote evidence every other transport
// carries, so the contract does not fork per transport and one verifier
// decides every verdict. The previous per-field shape (nonce / quote /
// signature / pcr_values / event_log) was consumed by a handler-local stub
// that returned true unconditionally; it is gone (#403).
type DeviceAttestRequest struct {
	ID       uint64 `codec:"id"`
	Evidence []byte `codec:"evidence"`
}

// DeviceAttestResponse reports what was verified, not merely that the call
// succeeded, mirroring the field set every other transport returns.
type DeviceAttestResponse struct {
	DeviceID              uint64 `codec:"device_id"`
	Serial                string `codec:"serial"`
	Model                 string `codec:"model"`
	Verified              bool   `codec:"verified"`
	SignatureValid        bool   `codec:"signature_valid"`
	NonceValid            bool   `codec:"nonce_valid"`
	PCRsValid             bool   `codec:"pcrs_valid"`
	AKCertificateVerified bool   `codec:"ak_certificate_verified"`
	AttestationStatus     string `codec:"attestation_status"`
	Message               string `codec:"message"`
	AttestedAt            int64  `codec:"attested_at"`
	PCRBaselineSource     string `codec:"pcr_baseline_source"`
	PCRBaselineRecordedAt int64  `codec:"pcr_baseline_recorded_at"`
	PCRBaselineCaptured   bool   `codec:"pcr_baseline_captured"`
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
	// TLSServerName is the certificate name the attestation collector
	// verifies a node of this profile against (#430). Empty means the
	// device's own FQDN. There is deliberately no pcr_baseline request
	// field: the baseline is read-only (#373, #448).
	TLSServerName string `codec:"tls_server_name"`
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
	// TLSServerName replaces the stored collector server name when
	// non-empty; omitted, the stored value is kept.
	TLSServerName string `codec:"tls_server_name"`
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
	// TLSServerName is the certificate name the attestation collector
	// verifies a node of this profile against (#430).
	TLSServerName string `codec:"tls_server_name"`
	// PCRBaseline is the expected measured state devices on this profile
	// are verified against (#373). Read-only: reported here, never accepted
	// on create or update (#448).
	PCRBaseline *PCRBaselineInfo `codec:"pcr_baseline"`
}

// PCRBaselineInfo is the wire form of the profile's recorded PCR baseline.
// Digests are hex, keyed by the PCR index as a string, mirroring the live
// REST ProfileFullResponse so one client shape reads both; RecordedAt is a
// Unix timestamp like every other time on this handler's wire.
type PCRBaselineInfo struct {
	Values               map[string]string `codec:"values"`
	Source               string            `codec:"source"`
	RecordedAt           int64             `codec:"recorded_at"`
	RecordedFromDeviceID uint64            `codec:"recorded_from_device_id"`
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
	// attestService is the in-process DeviceService gRPC implementation
	// that owns the platform's single device quote verifier. This package
	// holds no verifier of its own, so QUIC cannot form its own opinion
	// about whether a device attested.
	attestService platformv1.DeviceServiceServer
	logger        *logging.Logger
}

// DeviceHandlerOption configures optional DeviceHandler dependencies.
type DeviceHandlerOption func(*DeviceHandler)

// WithDeviceAttestService supplies the in-process DeviceService
// implementation that verifies device quotes. Without it OpDeviceAttest
// fails closed with StatusUnavailable rather than answering a verdict
// nothing computed.
func WithDeviceAttestService(service platformv1.DeviceServiceServer) DeviceHandlerOption {
	return func(h *DeviceHandler) {
		h.attestService = service
	}
}

// NewDeviceHandler creates a new device handler
func NewDeviceHandler(
	logger *logging.Logger,
	deviceService DeviceService,
	profileService ProfileService,
	opts ...DeviceHandlerOption,
) *DeviceHandler {
	h := &DeviceHandler{
		deviceService:  deviceService,
		profileService: profileService,
		logger:         logger,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// HandleRequest processes a device request and returns a response
func (h *DeviceHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte(quicwire.ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	// Device operations
	case quicwire.OpDeviceRegister:
		return h.handleRegister(ctx, req)
	case quicwire.OpDeviceGet:
		return h.handleGet(ctx, req)
	case quicwire.OpDeviceList:
		return h.handleList(ctx, req)
	case quicwire.OpDeviceUpdate:
		return h.handleUpdate(ctx, req)
	case quicwire.OpDeviceUnregister:
		return h.handleDelete(ctx, req)
	case quicwire.OpDeviceActivate:
		return h.handleActivate(ctx, req)
	case quicwire.OpDeviceAttest:
		return h.handleAttest(ctx, req)
	case quicwire.OpDeviceGetState:
		return h.handleGetState(ctx, req)

	// Profile operations
	case quicwire.OpDeviceCreateProfile:
		return h.handleCreateProfile(ctx, req)
	case quicwire.OpDeviceGetProfile:
		return h.handleGetProfile(ctx, req)
	case quicwire.OpDeviceListProfiles:
		return h.handleListProfiles(ctx, req)
	case quicwire.OpDeviceSetProfile:
		return h.handleUpdateProfile(ctx, req)
	case quicwire.OpDeviceDeleteProfile:
		return h.handleDeleteProfile(ctx, req)

	default:
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte("unknown device operation"),
		}
	}
}

// =============================================================================
// Device Handler Methods
// =============================================================================

// handleRegister registers a new device
func (h *DeviceHandler) handleRegister(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.deviceService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var registerReq DeviceRegisterRequest
	if err := quicwire.DecodePayload(req.Payload, &registerReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if registerReq.Serial == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrDeviceMissingSerial{})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGet retrieves a device by ID
func (h *DeviceHandler) handleGet(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.deviceService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var getReq DeviceGetRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if getReq.ID == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrDeviceMissingID{})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleList lists devices with pagination
func (h *DeviceHandler) handleList(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.deviceService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var listReq DeviceListRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleUpdate updates an existing device
func (h *DeviceHandler) handleUpdate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.deviceService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var updateReq DeviceUpdateRequest
	if err := quicwire.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if updateReq.ID == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrDeviceMissingID{})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDelete deletes a device
func (h *DeviceHandler) handleDelete(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.deviceService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var deleteReq DeviceDeleteRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if deleteReq.ID == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrDeviceMissingID{})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleActivate activates a device
func (h *DeviceHandler) handleActivate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.deviceService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var activateReq DeviceActivateRequest
	if err := quicwire.DecodePayload(req.Payload, &activateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if activateReq.ID == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrDeviceMissingID{})
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
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrDeviceActivationFailed{
			DeviceID: device.ID,
			Reason:   "device cannot be activated from state: " + device.State.String(),
		})
	}

	// Update device state to activated via the lifecycle state machine.
	now := time.Now()
	if err := device.Transition(entities.DeviceStateActivated); err != nil {
		h.logger.Info("Device activation rejected by state machine",
			"id", device.ID, "serial", device.Serial, "state", device.State, "error", err)
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrDeviceActivationFailed{
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleAttest verifies TPM quote evidence submitted for a device.
//
// The handler binds the wire and nothing else: the verdict comes from the
// in-process DeviceService implementation, the same single verifier gRPC,
// Unix, REST and MCP answer from. This opcode previously carried its own
// "verifier" that logged the evidence lengths and returned true for any
// input, so any request with a non-empty nonce, quote and signature moved
// the device to Attested (#403).
//
// A failed verification is StatusOK carrying a negative verdict, not an
// error status: the caller asked whether the device attests, and "no" is a
// successful answer. Error statuses are reserved for requests that could
// not be evaluated.
func (h *DeviceHandler) handleAttest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.attestService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceAttestationUnavailable{})
	}

	var attestReq DeviceAttestRequest
	if err := quicwire.DecodePayload(req.Payload, &attestReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}
	if attestReq.ID == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrDeviceMissingID{})
	}
	if len(attestReq.Evidence) == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrMissingAttestationData{Field: "evidence"})
	}

	attestResp, err := h.attestService.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId: strconv.FormatUint(attestReq.ID, 10),
		Evidence: attestReq.Evidence,
	})
	if err != nil {
		h.logger.Error(err, "device attestation could not be evaluated", "id", attestReq.ID)
		return h.attestErrorResponse(err)
	}

	h.logger.Info("device attestation evaluated",
		"id", attestResp.GetDeviceId(),
		"serial", attestResp.GetSerial(),
		"verified", attestResp.GetVerified(),
	)

	payload, err := quicwire.EncodePayload(attestResponseFromProto(attestResp))
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// attestResponseFromProto maps the gRPC attestation reply onto the QUIC
// wire form. Every check the verifier reported is carried through, so QUIC
// and gRPC callers see the same verdict detail.
func attestResponseFromProto(resp *platformv1.AttestDeviceResponse) *DeviceAttestResponse {
	out := &DeviceAttestResponse{
		DeviceID:              resp.GetDeviceId(),
		Serial:                resp.GetSerial(),
		Model:                 resp.GetModel(),
		Verified:              resp.GetVerified(),
		SignatureValid:        resp.GetSignatureValid(),
		NonceValid:            resp.GetNonceValid(),
		PCRsValid:             resp.GetPcrsValid(),
		AKCertificateVerified: resp.GetAkCertificateVerified(),
		AttestationStatus:     resp.GetAttestationStatus(),
		Message:               resp.GetMessage(),
		PCRBaselineSource:     resp.GetPcrBaselineSource(),
		PCRBaselineCaptured:   resp.GetPcrBaselineCaptured(),
	}
	if ts := resp.GetAttestedAt(); ts != nil {
		out.AttestedAt = ts.AsTime().Unix()
	}
	if ts := resp.GetPcrBaselineRecordedAt(); ts != nil {
		out.PCRBaselineRecordedAt = ts.AsTime().Unix()
	}
	return out
}

// attestErrorResponse maps a verifier error onto a QUIC status. The verifier
// returns an error only when the request could not be evaluated, so these
// are all caller-correctable except an unconfigured dependency.
func (h *DeviceHandler) attestErrorResponse(err error) *quicwire.Response {
	reason := err.Error()
	if s, ok := status.FromError(err); ok {
		reason = s.Message()
	}
	rejected := ErrDeviceAttestationRejected{Reason: reason}
	switch status.Code(err) {
	case codes.NotFound:
		return h.errorResponse(quicwire.StatusNotFound, rejected)
	case codes.InvalidArgument, codes.FailedPrecondition:
		return h.errorResponse(quicwire.StatusInvalidArgument, rejected)
	case codes.Unavailable:
		return h.errorResponse(quicwire.StatusUnavailable, rejected)
	default:
		return h.errorResponse(quicwire.StatusInternalError, rejected)
	}
}

// handleGetState retrieves device state
func (h *DeviceHandler) handleGetState(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.deviceService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceServiceNotAvailable{})
	}

	var stateReq DeviceStateRequest
	if err := quicwire.DecodePayload(req.Payload, &stateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if stateReq.ID == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrDeviceMissingID{})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Profile Handler Methods
// =============================================================================

// handleCreateProfile creates a new device profile
func (h *DeviceHandler) handleCreateProfile(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrProfileServiceNotAvailable{})
	}

	var createReq ProfileCreateRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrProfileMissingName{})
	}

	// Generate profile ID from name
	profileID := generateProfileIDFromName(createReq.Name)

	profile := &entities.DeviceProfile{
		ID:            profileID,
		Name:          createReq.Name,
		Model:         createReq.Model,
		Role:          entities.DeviceRole(createReq.Role),
		EventLog:      createReq.EventLog,
		TLSServerName: createReq.TLSServerName,
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetProfile retrieves a profile by ID
func (h *DeviceHandler) handleGetProfile(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrProfileServiceNotAvailable{})
	}

	var getReq ProfileGetRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if getReq.ID == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrProfileMissingID{})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListProfiles lists profiles with pagination
func (h *DeviceHandler) handleListProfiles(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrProfileServiceNotAvailable{})
	}

	var listReq ProfileListRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleUpdateProfile updates an existing profile
func (h *DeviceHandler) handleUpdateProfile(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrProfileServiceNotAvailable{})
	}

	var updateReq ProfileUpdateRequest
	if err := quicwire.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if updateReq.ID == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrProfileMissingID{})
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
	if updateReq.TLSServerName != "" {
		existing.TLSServerName = updateReq.TLSServerName
	}

	if err := h.profileService.Update(ctx, existing); err != nil {
		h.logger.Error(err, "failed to update profile")
		return h.profileErrorResponse(err)
	}

	resp := &ProfileUpdateResponse{
		Profile:   h.profileToInfo(existing),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDeleteProfile deletes a profile
func (h *DeviceHandler) handleDeleteProfile(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrProfileServiceNotAvailable{})
	}

	var deleteReq ProfileDeleteRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrDeviceDecodingFailed{Cause: err})
	}

	if deleteReq.ID == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrProfileMissingID{})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrDeviceEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
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
		TLSServerName:         p.TLSServerName,
		PCRBaseline:           pcrBaselineEntityToInfo(p.PCRBaseline),
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

// pcrBaselineEntityToInfo maps the profile's recorded baseline for the read
// side only; there is no request-side counterpart on purpose (#373, #448).
// A nil baseline maps to nil so an absent baseline is absent on the wire.
func pcrBaselineEntityToInfo(b *entities.PCRBaseline) *PCRBaselineInfo {
	if b == nil {
		return nil
	}
	values := make(map[string]string, len(b.Values))
	for idx, digest := range b.Values {
		values[strconv.Itoa(idx)] = hex.EncodeToString(digest)
	}
	info := &PCRBaselineInfo{
		Values:               values,
		Source:               string(b.Source),
		RecordedFromDeviceID: b.RecordedFromDeviceID,
	}
	if !b.RecordedAt.IsZero() {
		info.RecordedAt = b.RecordedAt.Unix()
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
func (h *DeviceHandler) errorResponse(status byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// deviceErrorResponse maps device errors to appropriate status codes
func (h *DeviceHandler) deviceErrorResponse(err error) *quicwire.Response {
	var status byte

	errStr := err.Error()
	switch {
	case containsIgnoreCase(errStr, "not found"):
		status = quicwire.StatusNotFound
	case containsIgnoreCase(errStr, "already exists") || containsIgnoreCase(errStr, "duplicate"):
		status = quicwire.StatusAlreadyExists
	case containsIgnoreCase(errStr, "invalid"):
		status = quicwire.StatusInvalidArgument
	default:
		status = quicwire.StatusInternalError
	}

	return h.errorResponse(status, err)
}

// profileErrorResponse maps profile errors to appropriate status codes
func (h *DeviceHandler) profileErrorResponse(err error) *quicwire.Response {
	var status byte

	var vlans device.ErrProfileVLANsNotDistinct

	errStr := err.Error()
	switch {
	// Typed validation failures from the service layer are client errors.
	// Matched by type, not by the word "invalid" happening to appear in
	// the message.
	case errors.As(err, &vlans):
		status = quicwire.StatusInvalidArgument
	case containsIgnoreCase(errStr, "not found"):
		status = quicwire.StatusNotFound
	case containsIgnoreCase(errStr, "already exists") || containsIgnoreCase(errStr, "duplicate"):
		status = quicwire.StatusAlreadyExists
	case containsIgnoreCase(errStr, "invalid"):
		status = quicwire.StatusInvalidArgument
	default:
		status = quicwire.StatusInternalError
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
