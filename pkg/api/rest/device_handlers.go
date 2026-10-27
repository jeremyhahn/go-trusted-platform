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
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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

// ErrDeviceAttestationUnavailable is returned when the attest route is
// reached on a daemon with no device attestation service wired. It is a
// distinct error from a verification failure: nothing was evaluated.
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

// DeviceResponse represents a device in API responses.
type DeviceResponse struct {
	ID         uint64 `json:"id"`
	Serial     string `json:"serial"`
	Model      string `json:"model,omitempty"`
	AttestPub  string `json:"attest_pub,omitempty"`
	AttestCert string `json:"attest_cert,omitempty"`
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

// DeviceAttestRequest is the body of POST /api/v1/devices/{id}/attest.
//
// Evidence is the JSON-encoded device quote evidence every other transport
// carries (base64 in JSON), so the wire contract does not fork per transport
// and one verifier decides every verdict. The previous per-field shape
// (nonce / quote / signature / pcr_values / event_log) was verified by a
// handler-local stub that returned true unconditionally; it is gone.
type DeviceAttestRequest struct {
	Evidence []byte `json:"evidence"`
}

// DeviceAttestResponse reports what was verified, not merely that the call
// succeeded. The individual checks travel alongside the verdict so a console
// can say WHY a device failed rather than only that it did. The field set
// mirrors the attestation response every other transport returns.
type DeviceAttestResponse struct {
	DeviceID          uint64    `json:"device_id"`
	Serial            string    `json:"serial,omitempty"`
	Model             string    `json:"model,omitempty"`
	Verified          bool      `json:"verified"`
	SignatureValid    bool      `json:"signature_valid"`
	NonceValid        bool      `json:"nonce_valid"`
	PCRsValid         bool      `json:"pcrs_valid"`
	AttestationStatus string    `json:"attestation_status,omitempty"`
	Message           string    `json:"message,omitempty"`
	AttestedAt        time.Time `json:"attested_at"`
	// AKCertificateVerified reports the TCG DevID 8.2 check: the enrolled
	// attestation certificate chains to the platform CA and carries
	// tcg-cap-verifiedTPMRestricted.
	AKCertificateVerified bool `json:"ak_certificate_verified"`
	// PCRBaselineSource is "signed" or "tofu"; empty when no baseline was
	// evaluated. PCRBaselineRecordedAt is when it was recorded.
	PCRBaselineSource     string     `json:"pcr_baseline_source,omitempty"`
	PCRBaselineRecordedAt *time.Time `json:"pcr_baseline_recorded_at,omitempty"`
	// PCRBaselineCaptured is true when this call captured the profile's
	// trust-on-first-use baseline.
	PCRBaselineCaptured bool `json:"pcr_baseline_captured"`
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
	Name                  string                                `json:"name"`
	Model                 string                                `json:"model,omitempty"`
	Role                  string                                `json:"role,omitempty"`
	EventLog              []byte                                `json:"event_log,omitempty"`
	Zone                  string                                `json:"zone,omitempty"`
	Networks              map[string]*NetworkPhaseConfigRequest `json:"networks,omitempty"`
	EnrollmentNetwork     string                                `json:"enrollment_network,omitempty"`
	PostEnrollmentNetwork string                                `json:"post_enrollment_network,omitempty"`
	FailureNetwork        string                                `json:"failure_network,omitempty"`
	MatchRules            *ProfileMatchRulesRequest             `json:"match_rules,omitempty"`

	// EKSerial is the exact TPM EK certificate serial number used for
	// device identity resolution at boot time.
	EKSerial string `json:"ek_serial,omitempty"`
	// EKCert prestages the PEM-encoded TPM EK certificate that binds
	// pre-enrollment config delivery and remote UKI signing to the
	// device's hardware EK. A non-empty value must parse as a PEM
	// X.509 certificate or the request is rejected with 400.
	EKCert string `json:"ek_cert,omitempty"`
	// MACAddress is the exact MAC address for non-TPM device identification.
	MACAddress string `json:"mac_address,omitempty"`
	// Config is the full merged platform config delivered to the device.
	Config any `json:"config,omitempty"`
	// Assigned marks the profile as bound to a specific device.
	Assigned bool `json:"assigned,omitempty"`
	// AssignedAt is the timestamp of the device assignment.
	AssignedAt time.Time `json:"assigned_at,omitempty"`
	// TLSServerName is the certificate name the attestation collector
	// verifies a node of this profile against (#430). Empty means the
	// device's own FQDN. There is deliberately no pcr_baseline request
	// field: the baseline is read-only (#373, #448).
	TLSServerName string `json:"tls_server_name,omitempty"`
}

// ProfileUpdateRequest represents a profile update request. All fields are
// optional; only supplied fields are applied to the existing profile. The
// assignment fields use pointer types so "not sent" and "set to the zero
// value" are distinguishable (tri-state partial update).
type ProfileUpdateRequest struct {
	Name                  string                                `json:"name,omitempty"`
	Model                 string                                `json:"model,omitempty"`
	Role                  string                                `json:"role,omitempty"`
	EventLog              []byte                                `json:"event_log,omitempty"`
	Zone                  string                                `json:"zone,omitempty"`
	Networks              map[string]*NetworkPhaseConfigRequest `json:"networks,omitempty"`
	EnrollmentNetwork     string                                `json:"enrollment_network,omitempty"`
	PostEnrollmentNetwork string                                `json:"post_enrollment_network,omitempty"`
	FailureNetwork        string                                `json:"failure_network,omitempty"`
	MatchRules            *ProfileMatchRulesRequest             `json:"match_rules,omitempty"`

	// EKSerial replaces the profile's EK serial when non-empty.
	EKSerial string `json:"ek_serial,omitempty"`
	// EKCert replaces the prestaged PEM EK certificate when non-empty.
	// It must parse as a PEM X.509 certificate.
	EKCert string `json:"ek_cert,omitempty"`
	// MACAddress replaces the profile's MAC address when non-empty.
	MACAddress string `json:"mac_address,omitempty"`
	// Config replaces the profile's full platform config when non-nil.
	Config any `json:"config,omitempty"`
	// Assigned updates the assignment flag when present.
	Assigned *bool `json:"assigned,omitempty"`
	// AssignedAt updates the assignment timestamp when present.
	AssignedAt *time.Time `json:"assigned_at,omitempty"`
	// TLSServerName is tri-state like Assigned: omitted keeps the stored
	// collector server name, a value replaces it, and "" clears it so the
	// collector verifies against each device's own FQDN again (#462).
	TLSServerName *string `json:"tls_server_name,omitempty"`
}

// NetworkPhaseConfigRequest represents network phase configuration in requests.
type NetworkPhaseConfigRequest struct {
	VLAN       uint16   `json:"vlan"`
	StaticIP   string   `json:"static_ip,omitempty"`
	Gateway    string   `json:"gateway,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	AuthMethod string   `json:"auth_method,omitempty"`
	Zone       string   `json:"zone,omitempty"`
}

// ProfileMatchRulesRequest represents profile match rules in requests.
type ProfileMatchRulesRequest struct {
	MACPrefix    string `json:"mac_prefix,omitempty"`
	SerialPrefix string `json:"serial_prefix,omitempty"`
	Model        string `json:"model,omitempty"`
}

// ProfileResponse represents a profile in API responses.
type ProfileResponse struct {
	ID                    uint64                                 `json:"id"`
	Name                  string                                 `json:"name"`
	Model                 string                                 `json:"model,omitempty"`
	Role                  string                                 `json:"role,omitempty"`
	EventLog              []byte                                 `json:"event_log,omitempty"`
	Zone                  string                                 `json:"zone,omitempty"`
	Networks              map[string]*NetworkPhaseConfigResponse `json:"networks,omitempty"`
	EnrollmentNetwork     string                                 `json:"enrollment_network,omitempty"`
	PostEnrollmentNetwork string                                 `json:"post_enrollment_network,omitempty"`
	FailureNetwork        string                                 `json:"failure_network,omitempty"`
	MatchRules            *ProfileMatchRulesResponse             `json:"match_rules,omitempty"`

	// EKSerial is the exact TPM EK certificate serial bound to this profile.
	EKSerial string `json:"ek_serial,omitempty"`
	// EKCert is the prestaged PEM-encoded TPM EK certificate. It is
	// echoed back deliberately: an EK certificate is public key material
	// (an X.509 certificate carrying no secrets), so exposing it lets
	// operators audit which certificate is prestaged.
	EKCert string `json:"ek_cert,omitempty"`
	// MACAddress is the exact MAC address bound to this profile.
	MACAddress string `json:"mac_address,omitempty"`
	// Config is the full merged platform config for this device.
	Config any `json:"config,omitempty"`
	// Assigned reports whether the profile is bound to a device.
	Assigned bool `json:"assigned"`
	// AssignedAt is the timestamp of the device assignment (zero when
	// unassigned).
	AssignedAt time.Time `json:"assigned_at,omitempty"`
	// TLSServerName is the certificate name the attestation collector
	// verifies a node of this profile against (#430).
	TLSServerName string `json:"tls_server_name,omitempty"`
	// PCRBaseline is the expected measured state devices on this profile
	// are verified against (#373). Read-only: reported here, never accepted
	// on create or update (#448).
	PCRBaseline *PCRBaselineResponse `json:"pcr_baseline,omitempty"`
}

// PCRBaselineResponse is the wire form of the profile's recorded PCR
// baseline: hex digests keyed by the PCR index as a string (JSON object keys
// are strings), the source, the recording time and the seeding device. It
// mirrors the live REST ProfileFullResponse so one client shape reads both.
type PCRBaselineResponse struct {
	Values               map[string]string `json:"values"`
	Source               string            `json:"source"`
	RecordedAt           time.Time         `json:"recorded_at"`
	RecordedFromDeviceID uint64            `json:"recorded_from_device_id,omitempty"`
}

// NetworkPhaseConfigResponse represents network phase configuration in responses.
type NetworkPhaseConfigResponse struct {
	VLAN       uint16   `json:"vlan"`
	StaticIP   string   `json:"static_ip,omitempty"`
	Gateway    string   `json:"gateway,omitempty"`
	DNS        []string `json:"dns,omitempty"`
	AuthMethod string   `json:"auth_method,omitempty"`
	Zone       string   `json:"zone,omitempty"`
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
	Create(ctx context.Context, device *entities.Device) error
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
	Update(ctx context.Context, profile *entities.DeviceProfile, opts ...device.ProfileUpdateOption) error
	Count(ctx context.Context) (int, error)
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error)
	FindByMACAddress(ctx context.Context, macAddr string) (*entities.DeviceProfile, error)
	FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error)
	FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error)

	// AssignToDeviceWithEK binds a profile to a device identity (EK serial
	// and/or MAC address), optionally prestaging the device's PEM-encoded
	// EK certificate, and marks the profile assigned.
	AssignToDeviceWithEK(ctx context.Context, profileID uint64, ekSerial, mac, ekCertPEM string) error

	// UnassignFromDevice clears a profile's device binding.
	UnassignFromDevice(ctx context.Context, profileID uint64) error
}

// =============================================================================
// Device Handlers
// =============================================================================

// maxAttestEvidenceBytes bounds the attestation evidence body. A TPM quote
// plus its signature and PCR policy is a few kilobytes; the cap exists so an
// unbounded body cannot be used to exhaust memory on an authenticated but
// hostile request. It matches the cap the platform web service applies to
// the same route.
const maxAttestEvidenceBytes = 1 << 20 // 1 MiB

// DeviceHandlers provides REST API handlers for device operations.
type DeviceHandlers struct {
	deviceService  DeviceServiceInterface
	profileService ProfileServiceInterface
	// attestService is the in-process DeviceService gRPC implementation the
	// attest route delegates to. It is the platform's single device quote
	// verifier; this package holds no verifier of its own, so REST cannot
	// form its own opinion about whether a device attested.
	attestService platformv1.DeviceServiceServer
	logger        *slog.Logger
}

// DeviceHandlerOption configures optional DeviceHandlers dependencies.
type DeviceHandlerOption func(*DeviceHandlers)

// WithDeviceAttestService supplies the in-process DeviceService
// implementation that verifies device quotes. Without it the attest route is
// not registered at all, rather than registered and answering 503 - an
// absent capability should not look like a broken one.
func WithDeviceAttestService(service platformv1.DeviceServiceServer) DeviceHandlerOption {
	return func(h *DeviceHandlers) {
		h.attestService = service
	}
}

// NewDeviceHandlers creates a new DeviceHandlers instance.
func NewDeviceHandlers(
	deviceService DeviceServiceInterface,
	profileService ProfileServiceInterface,
	logger *slog.Logger,
	opts ...DeviceHandlerOption,
) *DeviceHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	h := &DeviceHandlers{
		deviceService:  deviceService,
		profileService: profileService,
		logger:         logger,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
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
	router.HandleFunc("/api/v1/devices/{id}/state", h.handleGetDeviceState).Methods(http.MethodGet)

	// Attestation is registered only when the verifier is wired. A route
	// that answers without a verifier is exactly the defect #403 filed:
	// the endpoint existed and reported success without verifying anything.
	if h.attestService != nil {
		router.HandleFunc("/api/v1/devices/{id}/attest", h.handleAttestDevice).Methods(http.MethodPost)
	}

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

	// The webservice listener serves this route with the same decoder and
	// validator (#484), so a body is accepted or refused alike on both.
	newDevice, err := device.DecodeCreateRequest(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.deviceService.Create(ctx, newDevice); err != nil {
		h.logger.Error("Failed to register device", "serial", newDevice.Serial, "error", err)
		h.writeDeviceError(w, "register", err)
		return
	}

	resp := h.deviceToResponse(newDevice)
	h.logger.Info("Device registered", "id", newDevice.ID, "serial", newDevice.Serial)
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

	// The same decoder the create path and the webservice listener use
	// (#484). This listener patches: only the fields the body sets change.
	req, err := device.DecodeRequest(r.Body)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	// Get existing device
	existing, err := h.deviceService.Get(ctx, id)
	if err != nil {
		h.logger.Error("Failed to get device for update", "id", id, "error", err)
		h.writeDeviceError(w, "get", err)
		return
	}

	applyDevicePatch(existing, req)
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

	// Update device state to activated via the lifecycle state machine.
	now := time.Now()
	if err := device.Transition(entities.DeviceStateActivated); err != nil {
		h.logger.Info("Device activation rejected by state machine",
			"id", device.ID, "serial", device.Serial, "state", device.State, "error", err)
		h.writeError(w, http.StatusBadRequest, ErrDeviceActivationFailed{
			ID:     device.ID,
			Reason: err.Error(),
		})
		return
	}
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

// handleAttestDevice handles POST /api/v1/devices/{id}/attest.
//
// The handler binds HTTP and nothing else: the verdict comes from the
// in-process DeviceService implementation, which is the platform's single
// device quote verifier and the same one gRPC, Unix, QUIC and MCP answer
// from. This route previously carried its own verifier that logged the
// evidence lengths and returned true for any input, so any body with a
// non-empty nonce, quote and signature moved the device to Attested (#403).
//
// A failed verification is a 200 carrying a negative verdict, not an error
// status: the caller asked whether the device attests, and "no" is a
// successful answer. Error statuses are reserved for requests that could not
// be evaluated - unparseable evidence, an unknown device, or a device with
// no trustworthy attestation key.
func (h *DeviceHandlers) handleAttestDevice(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.attestService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceAttestationUnavailable{})
		return
	}

	idStr := mux.Vars(r)["id"]
	if idStr == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceInvalidID{})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxAttestEvidenceBytes))
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	var req DeviceAttestRequest
	if len(body) > 0 {
		if err := json.Unmarshal(body, &req); err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}
	if len(req.Evidence) == 0 {
		h.writeError(w, http.StatusBadRequest, ErrMissingAttestationData{Field: "evidence"})
		return
	}

	resp, err := h.attestService.AttestDevice(ctx, &platformv1.AttestDeviceRequest{
		DeviceId: idStr,
		Evidence: req.Evidence,
	})
	if err != nil {
		h.logger.Error("Device attestation could not be evaluated", "id", idStr, "error", err)
		h.writeAttestationError(w, err)
		return
	}

	h.logger.Info("Device attestation evaluated",
		"id", resp.GetDeviceId(),
		"serial", resp.GetSerial(),
		"verified", resp.GetVerified(),
	)

	h.writeJSON(w, http.StatusOK, attestResponseFromProto(resp))
}

// attestResponseFromProto maps the gRPC attestation reply onto the REST
// body. Every check the verifier reported is carried through; nothing is
// summarised away, so REST and gRPC callers see the same verdict detail.
func attestResponseFromProto(resp *platformv1.AttestDeviceResponse) DeviceAttestResponse {
	out := DeviceAttestResponse{
		DeviceID:              resp.GetDeviceId(),
		Serial:                resp.GetSerial(),
		Model:                 resp.GetModel(),
		Verified:              resp.GetVerified(),
		SignatureValid:        resp.GetSignatureValid(),
		NonceValid:            resp.GetNonceValid(),
		PCRsValid:             resp.GetPcrsValid(),
		AttestationStatus:     resp.GetAttestationStatus(),
		Message:               resp.GetMessage(),
		AKCertificateVerified: resp.GetAkCertificateVerified(),
		PCRBaselineSource:     resp.GetPcrBaselineSource(),
		PCRBaselineCaptured:   resp.GetPcrBaselineCaptured(),
	}
	if ts := resp.GetAttestedAt(); ts != nil {
		out.AttestedAt = ts.AsTime()
	}
	if ts := resp.GetPcrBaselineRecordedAt(); ts != nil {
		recorded := ts.AsTime()
		out.PCRBaselineRecordedAt = &recorded
	}
	return out
}

// writeAttestationError maps a verifier error onto an HTTP status. The
// verifier returns an error only when the request could not be evaluated, so
// these are all client-correctable except an unconfigured dependency.
func (h *DeviceHandlers) writeAttestationError(w http.ResponseWriter, err error) {
	switch status.Code(err) {
	case codes.NotFound:
		h.writeError(w, http.StatusNotFound, ErrDeviceAttestationRejected{Reason: statusMessage(err)})
	case codes.InvalidArgument:
		h.writeError(w, http.StatusBadRequest, ErrDeviceAttestationRejected{Reason: statusMessage(err)})
	case codes.FailedPrecondition:
		h.writeError(w, http.StatusConflict, ErrDeviceAttestationRejected{Reason: statusMessage(err)})
	case codes.Unavailable:
		h.writeError(w, http.StatusServiceUnavailable, ErrDeviceAttestationRejected{Reason: statusMessage(err)})
	default:
		h.writeError(w, http.StatusInternalServerError, ErrDeviceAttestationRejected{Reason: statusMessage(err)})
	}
}

// statusMessage returns the gRPC status message when there is one, falling
// back to the error text for a plain error.
func statusMessage(err error) string {
	if s, ok := status.FromError(err); ok {
		return s.Message()
	}
	return err.Error()
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
		h.writeError(w, http.StatusBadRequest, device.ErrDeviceSerialRequired{})
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

	// A prestaged EK certificate binds config delivery and remote UKI
	// signing to the hardware EK; an unparseable value can never match a
	// presented certificate, so reject it at the boundary.
	if err := entities.ValidateEKCertPEM(req.EKCert); err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	profile := &entities.DeviceProfile{
		ID:            profileID,
		Name:          req.Name,
		Model:         req.Model,
		Role:          entities.DeviceRole(req.Role),
		EventLog:      req.EventLog,
		EKSerial:      req.EKSerial,
		EKCert:        req.EKCert,
		MACAddress:    req.MACAddress,
		Config:        req.Config,
		Assigned:      req.Assigned,
		AssignedAt:    req.AssignedAt,
		TLSServerName: req.TLSServerName,
	}

	// Set network configurations from map-based request.
	profile.Networks = make(map[string]*entities.NetworkPhaseConfig)
	for k, v := range req.Networks {
		profile.Networks[k] = h.networkRequestToEntity(v)
	}
	profile.Zone = req.Zone
	profile.EnrollmentNetwork = req.EnrollmentNetwork
	profile.PostEnrollmentNetwork = req.PostEnrollmentNetwork
	profile.FailureNetwork = req.FailureNetwork

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
	if len(req.Networks) > 0 {
		if existing.Networks == nil {
			existing.Networks = make(map[string]*entities.NetworkPhaseConfig, len(req.Networks))
		}
		for k, v := range req.Networks {
			existing.Networks[k] = h.networkRequestToEntity(v)
		}
	}
	if req.Zone != "" {
		existing.Zone = req.Zone
	}
	if req.EnrollmentNetwork != "" {
		existing.EnrollmentNetwork = req.EnrollmentNetwork
	}
	if req.PostEnrollmentNetwork != "" {
		existing.PostEnrollmentNetwork = req.PostEnrollmentNetwork
	}
	if req.FailureNetwork != "" {
		existing.FailureNetwork = req.FailureNetwork
	}
	if req.MatchRules != nil {
		existing.MatchRules = &entities.ProfileMatchRules{
			MACPrefix:    req.MatchRules.MACPrefix,
			SerialPrefix: req.MatchRules.SerialPrefix,
			Model:        req.MatchRules.Model,
		}
	}
	if req.EKSerial != "" {
		existing.EKSerial = req.EKSerial
	}
	if req.EKCert != "" {
		// Same EK-certificate boundary validation as handleCreateProfile.
		if err := entities.ValidateEKCertPEM(req.EKCert); err != nil {
			h.writeError(w, http.StatusBadRequest, err)
			return
		}
		existing.EKCert = req.EKCert
	}
	if req.MACAddress != "" {
		existing.MACAddress = req.MACAddress
	}
	if req.Config != nil {
		existing.Config = req.Config
	}
	if req.Assigned != nil {
		existing.Assigned = *req.Assigned
	}
	if req.AssignedAt != nil {
		existing.AssignedAt = *req.AssignedAt
	}
	// tls_server_name is tri-state too; "" clears it explicitly (#462).
	opts := device.ApplyTLSServerName(existing, req.TLSServerName)

	if err := h.profileService.Update(ctx, existing, opts...); err != nil {
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
		AttestCert: d.AttestCert,
		SigningPub: d.SigningPub,
		EKCert:     d.EKCert,
		EventLog:   d.EventLog,
		HashAlgoID: d.HashAlgoId,
	}
}

// profileToResponse converts a profile entity to a ProfileResponse.
func (h *DeviceHandlers) profileToResponse(p *entities.DeviceProfile) ProfileResponse {
	resp := ProfileResponse{
		ID:                    p.ID,
		Name:                  p.Name,
		Model:                 p.Model,
		Role:                  string(p.Role),
		EventLog:              p.EventLog,
		Zone:                  p.Zone,
		EnrollmentNetwork:     p.EnrollmentNetwork,
		PostEnrollmentNetwork: p.PostEnrollmentNetwork,
		FailureNetwork:        p.FailureNetwork,
		EKSerial:              p.EKSerial,
		EKCert:                p.EKCert,
		MACAddress:            p.MACAddress,
		Config:                p.Config,
		Assigned:              p.Assigned,
		AssignedAt:            p.AssignedAt,
		TLSServerName:         p.TLSServerName,
		PCRBaseline:           pcrBaselineEntityToResponse(p.PCRBaseline),
	}

	if len(p.Networks) > 0 {
		resp.Networks = make(map[string]*NetworkPhaseConfigResponse, len(p.Networks))
		for k, v := range p.Networks {
			resp.Networks[k] = h.networkEntityToResponse(v)
		}
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

// pcrBaselineEntityToResponse maps the profile's recorded baseline for the
// read side only; there is no request-side counterpart on purpose (#373,
// #448). A nil baseline maps to nil so an absent baseline is omitted.
func pcrBaselineEntityToResponse(b *entities.PCRBaseline) *PCRBaselineResponse {
	if b == nil {
		return nil
	}
	values := make(map[string]string, len(b.Values))
	for idx, digest := range b.Values {
		values[strconv.Itoa(idx)] = hex.EncodeToString(digest)
	}
	return &PCRBaselineResponse{
		Values:               values,
		Source:               string(b.Source),
		RecordedAt:           b.RecordedAt,
		RecordedFromDeviceID: b.RecordedFromDeviceID,
	}
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
		Zone:       req.Zone,
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
		Zone:       cfg.Zone,
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

	var vlans device.ErrProfileVLANsNotDistinct

	switch {
	// Typed validation failures from the service layer are client errors.
	case errors.As(err, &vlans):
		status = http.StatusBadRequest
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

// applyDevicePatch copies onto existing every field the update request set,
// leaving the rest as stored.
func applyDevicePatch(existing, patch *entities.Device) {
	if patch.Serial != "" {
		existing.Serial = patch.Serial
	}
	if patch.Model != "" {
		existing.Model = patch.Model
	}
	if patch.AttestPub != "" {
		existing.AttestPub = patch.AttestPub
	}
	if patch.AttestCert != "" {
		existing.AttestCert = patch.AttestCert
	}
	if patch.SigningPub != "" {
		existing.SigningPub = patch.SigningPub
	}
	if patch.EKCert != "" {
		existing.EKCert = patch.EKCert
	}
	if patch.EventLog != nil {
		existing.EventLog = patch.EventLog
	}
	if patch.HashAlgoId != 0 {
		existing.HashAlgoId = patch.HashAlgoId
	}
	if patch.SwitchName != "" {
		existing.SwitchName = patch.SwitchName
	}
	if patch.SwitchPort != "" {
		existing.SwitchPort = patch.SwitchPort
	}
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
	var serialTaken device.ErrDeviceSerialExists
	if errors.As(err, &serialTaken) {
		return true
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
