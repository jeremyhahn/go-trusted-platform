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

package device

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	defaultPage     = 1
	defaultPageSize = 25
	maxPageSize     = 100
)

// DeviceCRUDHandler provides REST handlers for device CRUD operations.
// All operations delegate to the DeviceService interface (service layer).
type DeviceCRUDHandler interface {
	// Device operations
	CreateDevice(w http.ResponseWriter, r *http.Request)
	GetDevice(w http.ResponseWriter, r *http.Request)
	UpdateDevice(w http.ResponseWriter, r *http.Request)
	DeleteDevice(w http.ResponseWriter, r *http.Request)
	ListDevices(w http.ResponseWriter, r *http.Request)
	FindDeviceBySerial(w http.ResponseWriter, r *http.Request)
	CountDevices(w http.ResponseWriter, r *http.Request)

	// Profile operations
	CreateProfile(w http.ResponseWriter, r *http.Request)
	GetProfileByID(w http.ResponseWriter, r *http.Request)
	UpdateProfile(w http.ResponseWriter, r *http.Request)
	DeleteProfile(w http.ResponseWriter, r *http.Request)
	ListProfiles(w http.ResponseWriter, r *http.Request)
	FindProfileByMAC(w http.ResponseWriter, r *http.Request)
	FindProfileBySerial(w http.ResponseWriter, r *http.Request)
	FindMatchingProfile(w http.ResponseWriter, r *http.Request)
	CountProfiles(w http.ResponseWriter, r *http.Request)

	// Activation
	ActivateDevice(w http.ResponseWriter, r *http.Request)
}

// CRUDHandler implements DeviceCRUDHandler
type CRUDHandler struct {
	logger         *logging.Logger
	responseWriter response.HttpWriter
	deviceService  device.DeviceService
	profileService device.DeviceProfileService
}

// NewCRUDHandler creates a new CRUDHandler.
func NewCRUDHandler(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	deviceService device.DeviceService,
	profileService device.DeviceProfileService,
) DeviceCRUDHandler {
	return &CRUDHandler{
		logger:         logger,
		responseWriter: responseWriter,
		deviceService:  deviceService,
		profileService: profileService,
	}
}

// CreateDevice handles POST /api/v1/devices
func (h *CRUDHandler) CreateDevice(w http.ResponseWriter, r *http.Request) {
	if h.deviceService == nil {
		h.responseWriter.Error500(w, r, ErrDeviceServiceNotInitialized{})
		return
	}

	var req DeviceRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	deviceEntity := h.requestToDevice(&req)
	// Identity assignment lives in DeviceService.Create now, not here
	// (#525): this handler minted its own ID because Save rejects a zero
	// one, and every other transport's create verb did not, so every one
	// of them was refused. Callers that supply an explicit ID still win —
	// Create honours a non-zero ID exactly as this code did.
	if deviceEntity.Serial == "" {
		// The device service does not require a serial, but the dashboard
		// list page can't render rows without one. Default to the
		// generated ID so the row is identifiable until the user updates
		// it. That needs the ID before the write, so this one branch
		// assigns it ahead of Create, from the same NewID() allocator
		// Create would have used.
		if deviceEntity.ID == 0 {
			deviceEntity.ID = device.NewID()
		}
		deviceEntity.Serial = fmt.Sprintf("dev-%d", deviceEntity.ID)
	}

	if err := h.deviceService.Create(r.Context(), deviceEntity); err != nil {
		h.logger.Errorf("failed to create device: %v", err)
		h.handleServiceError(w, r, err)
		return
	}

	h.logger.Infof("device created: id=%d serial=%s", deviceEntity.ID, deviceEntity.Serial)
	h.responseWriter.Success201(w, r, h.deviceToResponse(deviceEntity))
}

// GetDevice handles GET /api/v1/devices/{id}
func (h *CRUDHandler) GetDevice(w http.ResponseWriter, r *http.Request) {
	if h.deviceService == nil {
		h.responseWriter.Error500(w, r, ErrDeviceServiceNotInitialized{})
		return
	}

	id, err := h.getDeviceID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidDeviceID{})
		return
	}

	deviceEntity, err := h.deviceService.Get(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, h.deviceToResponse(deviceEntity))
}

// UpdateDevice handles PUT /api/v1/devices/{id}
func (h *CRUDHandler) UpdateDevice(w http.ResponseWriter, r *http.Request) {
	if h.deviceService == nil {
		h.responseWriter.Error500(w, r, ErrDeviceServiceNotInitialized{})
		return
	}

	id, err := h.getDeviceID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidDeviceID{})
		return
	}

	var req DeviceRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	req.ID = ID(id)
	deviceEntity := h.requestToDevice(&req)

	if err := h.deviceService.Update(r.Context(), deviceEntity); err != nil {
		h.logger.Errorf("failed to update device: id=%d error=%v", id, err)
		h.handleServiceError(w, r, err)
		return
	}

	h.logger.Infof("device updated: id=%d", id)
	h.responseWriter.Success200(w, r, h.deviceToResponse(deviceEntity))
}

// DeleteDevice handles DELETE /api/v1/devices/{id}
func (h *CRUDHandler) DeleteDevice(w http.ResponseWriter, r *http.Request) {
	if h.deviceService == nil {
		h.responseWriter.Error500(w, r, ErrDeviceServiceNotInitialized{})
		return
	}

	id, err := h.getDeviceID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidDeviceID{})
		return
	}

	deviceEntity, err := h.deviceService.Get(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	if err := h.deviceService.Delete(r.Context(), deviceEntity); err != nil {
		h.logger.Errorf("failed to delete device: id=%d error=%v", id, err)
		h.handleServiceError(w, r, err)
		return
	}

	h.logger.Infof("device deleted: id=%d", id)
	w.WriteHeader(http.StatusNoContent)
}

// ListDevices handles GET /api/v1/devices
func (h *CRUDHandler) ListDevices(w http.ResponseWriter, r *http.Request) {
	if h.deviceService == nil {
		h.responseWriter.Error500(w, r, ErrDeviceServiceNotInitialized{})
		return
	}

	query := h.getPaginationQuery(r)

	result, err := h.deviceService.Page(r.Context(), query)
	if err != nil {
		h.logger.Errorf("failed to list devices: %v", err)
		h.handleServiceError(w, r, err)
		return
	}

	devices := make([]DeviceResponse, 0, len(result.Entities))
	for _, d := range result.Entities {
		devices = append(devices, *h.deviceToResponse(d))
	}

	resp := DeviceListResponse{
		Devices: devices,
		Pagination: PaginationResponse{
			Page:       result.Page,
			PageSize:   result.PageSize,
			Total:      result.Total,
			TotalPages: h.calculateTotalPages(result.Total, result.PageSize),
			HasMore:    result.HasMore,
		},
	}

	h.responseWriter.Success200(w, r, resp)
}

// FindDeviceBySerial handles GET /api/v1/devices/serial/{serial}
func (h *CRUDHandler) FindDeviceBySerial(w http.ResponseWriter, r *http.Request) {
	if h.deviceService == nil {
		h.responseWriter.Error500(w, r, ErrDeviceServiceNotInitialized{})
		return
	}

	serial := mux.Vars(r)["serial"]
	if serial == "" {
		h.responseWriter.Error400(w, r, ErrMissingSerialNumber{})
		return
	}

	deviceEntity, err := h.deviceService.FindBySerial(r.Context(), serial)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, h.deviceToResponse(deviceEntity))
}

// CountDevices handles GET /api/v1/devices/count
func (h *CRUDHandler) CountDevices(w http.ResponseWriter, r *http.Request) {
	if h.deviceService == nil {
		h.responseWriter.Error500(w, r, ErrDeviceServiceNotInitialized{})
		return
	}

	count, err := h.deviceService.Count(r.Context())
	if err != nil {
		h.logger.Errorf("failed to count devices: %v", err)
		h.handleServiceError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, CountResponse{Count: count})
}

// CreateProfile handles POST /api/v1/device/profiles
func (h *CRUDHandler) CreateProfile(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	var req ProfileRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// A prestaged EK certificate binds config delivery and remote UKI
	// signing to the hardware EK; an unparseable value can never match
	// a presented certificate, so reject it at the boundary.
	if err := entities.ValidateEKCertPEM(req.EKCert); err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	// Auto-generate the profile ID when the client doesn't supply
	// one. The WebUI Create Profile dialog has no way to know a valid
	// ID up-front; rejecting on missing ID makes profile creation
	// impossible from the dashboard.
	if req.ID == 0 {
		req.ID = ID(device.NewID())
	}

	profileEntity, err := profileRequestToEntity(&req)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	if err := h.profileService.Save(r.Context(), profileEntity); err != nil {
		h.logger.Errorf("failed to create profile: %v", err)
		h.handleServiceError(w, r, err)
		return
	}

	h.logger.Infof("profile created: id=%d name=%s", profileEntity.ID, profileEntity.Name)
	h.responseWriter.Success201(w, r, profileToResponse(profileEntity))
}

// GetProfileByID handles GET /api/v1/device/profiles/{id}
func (h *CRUDHandler) GetProfileByID(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	id, err := h.getProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidProfileID{})
		return
	}

	profileEntity, err := h.profileService.Get(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, profileToResponse(profileEntity))
}

// UpdateProfile handles PUT /api/v1/device/profiles/{id}
func (h *CRUDHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	id, err := h.getProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidProfileID{})
		return
	}

	var req ProfileRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Same EK-certificate boundary validation as CreateProfile.
	if err := entities.ValidateEKCertPEM(req.EKCert); err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	req.ID = ID(id)
	profileEntity, err := profileRequestToEntity(&req)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	// An explicit "" clears the stored TLS server name; an omitted one keeps it.
	opts := device.ApplyTLSServerName(profileEntity, req.TLSServerName)
	if err := h.profileService.Update(r.Context(), profileEntity, opts...); err != nil {
		h.logger.Errorf("failed to update profile: id=%d error=%v", id, err)
		h.handleServiceError(w, r, err)
		return
	}

	h.logger.Infof("profile updated: id=%d", id)
	h.responseWriter.Success200(w, r, profileToResponse(profileEntity))
}

// DeleteProfile handles DELETE /api/v1/device/profiles/{id}
func (h *CRUDHandler) DeleteProfile(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	id, err := h.getProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidProfileID{})
		return
	}

	profileEntity, err := h.profileService.Get(r.Context(), id)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	if err := h.profileService.Delete(r.Context(), profileEntity); err != nil {
		h.logger.Errorf("failed to delete profile: id=%d error=%v", id, err)
		h.handleServiceError(w, r, err)
		return
	}

	h.logger.Infof("profile deleted: id=%d", id)
	w.WriteHeader(http.StatusNoContent)
}

// ListProfiles handles GET /api/v1/device/profiles
func (h *CRUDHandler) ListProfiles(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	query := h.getPaginationQuery(r)

	result, err := h.profileService.Page(r.Context(), query)
	if err != nil {
		h.logger.Errorf("failed to list profiles: %v", err)
		h.handleServiceError(w, r, err)
		return
	}

	profiles := make([]ProfileFullResponse, 0, len(result.Entities))
	for _, p := range result.Entities {
		profiles = append(profiles, *profileToResponse(p))
	}

	resp := ProfileListResponse{
		Profiles: profiles,
		Pagination: PaginationResponse{
			Page:       result.Page,
			PageSize:   result.PageSize,
			Total:      result.Total,
			TotalPages: h.calculateTotalPages(result.Total, result.PageSize),
			HasMore:    result.HasMore,
		},
	}

	h.responseWriter.Success200(w, r, resp)
}

// FindProfileByMAC handles GET /api/v1/device/profiles/mac/{mac}
func (h *CRUDHandler) FindProfileByMAC(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	mac := mux.Vars(r)["mac"]
	if mac == "" {
		h.responseWriter.Error400(w, r, ErrMissingMACAddress{})
		return
	}

	profileEntity, err := h.profileService.FindByMACAddress(r.Context(), mac)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, profileToResponse(profileEntity))
}

// FindProfileBySerial handles GET /api/v1/device/profiles/serial/{serial}
func (h *CRUDHandler) FindProfileBySerial(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	serial := mux.Vars(r)["serial"]
	if serial == "" {
		h.responseWriter.Error400(w, r, ErrMissingSerialNumber{})
		return
	}

	profileEntity, err := h.profileService.FindBySerial(r.Context(), serial)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, profileToResponse(profileEntity))
}

// FindMatchingProfile handles POST /api/v1/device/profiles/match
func (h *CRUDHandler) FindMatchingProfile(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	var req FindMatchingProfileRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	profileEntity, err := h.profileService.FindMatchingProfile(
		r.Context(),
		req.MACAddress,
		req.Serial,
		req.Model,
	)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, profileToResponse(profileEntity))
}

// CountProfiles handles GET /api/v1/device/profiles/count
func (h *CRUDHandler) CountProfiles(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	count, err := h.profileService.Count(r.Context())
	if err != nil {
		h.logger.Errorf("failed to count profiles: %v", err)
		h.handleServiceError(w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, CountResponse{Count: count})
}

// ActivateDevice handles POST /api/v1/device/activate
func (h *CRUDHandler) ActivateDevice(w http.ResponseWriter, r *http.Request) {
	if h.deviceService == nil {
		h.responseWriter.Error500(w, r, ErrDeviceServiceNotInitialized{})
		return
	}
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	var req ActivationRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Serial == "" {
		h.responseWriter.Error400(w, r, ErrMissingSerialNumber{})
		return
	}

	// Find device
	deviceEntity, err := h.deviceService.FindBySerial(r.Context(), req.Serial)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	// Find matching profile
	profileEntity, err := h.profileService.FindMatchingProfile(
		r.Context(),
		req.MACAddress,
		req.Serial,
		deviceEntity.Model,
	)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	// Get admitted VLAN
	var vlan uint16
	if prodNet := profileEntity.GetPostEnrollmentNetworkConfig(); prodNet != nil {
		vlan = prodNet.VLAN
	}

	h.logger.Infof("device activated: serial=%s vlan=%d", req.Serial, vlan)

	resp := ActivationResponse{
		Status:         "activated",
		VLAN:           vlan,
		TransitionedAt: time.Now().UTC(),
	}

	h.responseWriter.Success200(w, r, resp)
}

// Helper methods

func (h *CRUDHandler) decodeJSON(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	return decoder.Decode(v)
}

func (h *CRUDHandler) getDeviceID(r *http.Request) (uint64, error) {
	idStr := mux.Vars(r)["id"]
	return strconv.ParseUint(idStr, 10, 64)
}

func (h *CRUDHandler) getProfileID(r *http.Request) (uint64, error) {
	idStr := mux.Vars(r)["id"]
	return strconv.ParseUint(idStr, 10, 64)
}

func (h *CRUDHandler) getPaginationQuery(r *http.Request) datastore.PageQuery {
	query := datastore.NewPageQuery()

	if pageStr := r.URL.Query().Get("page"); pageStr != "" {
		if page, err := strconv.Atoi(pageStr); err == nil && page > 0 {
			query.Page = page
		}
	}

	if pageSizeStr := r.URL.Query().Get("page_size"); pageSizeStr != "" {
		if pageSize, err := strconv.Atoi(pageSizeStr); err == nil && pageSize > 0 {
			if pageSize > maxPageSize {
				pageSize = maxPageSize
			}
			query.PageSize = pageSize
		}
	}

	if sortOrder := r.URL.Query().Get("sort_order"); sortOrder != "" {
		if strings.ToLower(sortOrder) == "desc" || strings.ToLower(sortOrder) == "descending" {
			query.SortOrder = datastore.SortDescending
		} else {
			query.SortOrder = datastore.SortAscending
		}
	}

	return query
}

func (h *CRUDHandler) calculateTotalPages(total, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	pages := total / pageSize
	if total%pageSize > 0 {
		pages++
	}
	return pages
}

func (h *CRUDHandler) handleServiceError(w http.ResponseWriter, r *http.Request, err error) {
	// Typed validation failures from the service layer are client errors.
	var vlans device.ErrProfileVLANsNotDistinct
	if errors.As(err, &vlans) {
		h.responseWriter.Error400(w, r, err)
		return
	}

	errStr := err.Error()

	switch {
	case strings.Contains(errStr, "invalid device ID") || strings.Contains(errStr, "invalid profile ID"):
		h.responseWriter.Error400(w, r, err)
	case strings.Contains(errStr, "not found") || strings.Contains(errStr, "failed to get"):
		h.responseWriter.Error404(w, r, err)
	default:
		h.responseWriter.Error500(w, r, err)
	}
}

func (h *CRUDHandler) requestToDevice(req *DeviceRequest) *entities.Device {
	// Start with the flat fields and overlay anything carried in the
	// nested {device: {...}} envelope so callers using either contract
	// reach the same entity.
	d := &entities.Device{
		ID:         uint64(req.ID),
		AttestPub:  req.AttestPub,
		AttestCert: req.AttestCert,
		EKCert:     req.EKCert,
		EventLog:   req.EventLog,
		HashAlgoId: req.HashAlgoID,
		Model:      req.Model,
		Serial:     req.Serial,
		SigningPub: req.SigningPub,
		SwitchName: req.SwitchName,
		SwitchPort: req.SwitchPort,
	}
	if req.Device != nil {
		if req.Device.ID != 0 {
			d.ID = uint64(req.Device.ID)
		}
		if req.Device.AttestPub != "" {
			d.AttestPub = req.Device.AttestPub
		}
		if req.Device.AttestCert != "" {
			d.AttestCert = req.Device.AttestCert
		}
		if req.Device.EKCert != "" {
			d.EKCert = req.Device.EKCert
		}
		if len(req.Device.EventLog) > 0 {
			d.EventLog = req.Device.EventLog
		}
		if req.Device.HashAlgoID != 0 {
			d.HashAlgoId = req.Device.HashAlgoID
		}
		if req.Device.Model != "" {
			d.Model = req.Device.Model
		}
		if req.Device.Serial != "" {
			d.Serial = req.Device.Serial
		}
		if req.Device.SigningPub != "" {
			d.SigningPub = req.Device.SigningPub
		}
		if req.Device.SwitchName != "" {
			d.SwitchName = req.Device.SwitchName
		}
		if req.Device.SwitchPort != "" {
			d.SwitchPort = req.Device.SwitchPort
		}
	}
	if d.Model == "" && req.Manufacturer != "" {
		d.Model = req.Manufacturer
	}
	// req.Name is deliberately not mapped. entities.Device has no name,
	// and this function used to reuse the name as the Serial when none
	// was supplied. The console's serial field is optional and its name
	// is required, so the ordinary registration wrote a display string
	// into the serial: a row that can never match a TPM serial at
	// enrollment, and that RecordHeartbeat cannot resolve because it
	// matches on Serial or Hostname. On the update path it was worse —
	// the service layer preserves an existing serial only when the
	// incoming one is empty, so a PUT carrying just a name overwrote a
	// real serial. CreateDevice synthesises a visibly-synthetic
	// "dev-<id>" instead. Whether a device gains a real display name is
	// open on #455.
	return d
}

func (h *CRUDHandler) deviceToResponse(d *entities.Device) *DeviceResponse {
	if d == nil {
		return nil
	}
	resp := &DeviceResponse{
		ID:         ID(d.ID),
		AttestPub:  d.AttestPub,
		AttestCert: d.AttestCert,
		EKCert:     d.EKCert,
		EventLog:   d.EventLog,
		HashAlgoID: d.HashAlgoId,
		Model:      d.Model,
		Serial:     d.Serial,
		SigningPub: d.SigningPub,
		SwitchName: d.SwitchName,
		SwitchPort: d.SwitchPort,
		State:      string(d.State),

		LastHeartbeatAddr: d.LastHeartbeatAddr,
	}
	if !d.CreatedAt.IsZero() {
		t := d.CreatedAt
		resp.CreatedAt = &t
	}
	if !d.UpdatedAt.IsZero() {
		t := d.UpdatedAt
		resp.UpdatedAt = &t
	}
	if !d.LastHeartbeatAt.IsZero() {
		t := d.LastHeartbeatAt
		resp.LastHeartbeatAt = &t
	}
	return resp
}
