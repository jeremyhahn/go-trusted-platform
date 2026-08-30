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
	// The device service rejects a zero ID. The WebUI's Register Device
	// form doesn't supply one, so synthesise a non-zero unique ID from
	// the request time + a counter so the platform owns identity
	// assignment. Callers that supply an explicit ID still win.
	if deviceEntity.ID == 0 {
		deviceEntity.ID = device.NewID()
	}
	if deviceEntity.Serial == "" {
		// The device service does not require a serial, but the dashboard
		// list page can't render rows without one. Default to the
		// generated ID so the row is identifiable until the user updates
		// it.
		deviceEntity.Serial = fmt.Sprintf("dev-%d", deviceEntity.ID)
	}

	if err := h.deviceService.Save(r.Context(), deviceEntity); err != nil {
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

	req.ID = id
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
		req.ID = device.NewID()
	}

	profileEntity, err := h.requestToProfile(&req)
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
	h.responseWriter.Success201(w, r, h.profileToResponse(profileEntity))
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

	h.responseWriter.Success200(w, r, h.profileToResponse(profileEntity))
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

	req.ID = id
	profileEntity, err := h.requestToProfile(&req)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}

	if err := h.profileService.Update(r.Context(), profileEntity); err != nil {
		h.logger.Errorf("failed to update profile: id=%d error=%v", id, err)
		h.handleServiceError(w, r, err)
		return
	}

	h.logger.Infof("profile updated: id=%d", id)
	h.responseWriter.Success200(w, r, h.profileToResponse(profileEntity))
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
		profiles = append(profiles, *h.profileToResponse(p))
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

	h.responseWriter.Success200(w, r, h.profileToResponse(profileEntity))
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

	h.responseWriter.Success200(w, r, h.profileToResponse(profileEntity))
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

	h.responseWriter.Success200(w, r, h.profileToResponse(profileEntity))
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

	// Get trusted VLAN
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
		ID:         req.ID,
		AttestPub:  req.AttestPub,
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
			d.ID = req.Device.ID
		}
		if req.Device.AttestPub != "" {
			d.AttestPub = req.Device.AttestPub
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
		// When the WebUI form posts a name but no serial, reuse name as
		// the serial so the entity has a non-empty identifier.
		if d.Serial == "" && req.Device.Name != "" {
			d.Serial = req.Device.Name
		}
	}
	if d.Model == "" && req.Manufacturer != "" {
		d.Model = req.Manufacturer
	}
	if d.Serial == "" && req.Name != "" {
		d.Serial = req.Name
	}
	return d
}

func (h *CRUDHandler) deviceToResponse(d *entities.Device) *DeviceResponse {
	if d == nil {
		return nil
	}
	return &DeviceResponse{
		ID:         d.ID,
		AttestPub:  d.AttestPub,
		EKCert:     d.EKCert,
		EventLog:   d.EventLog,
		HashAlgoID: d.HashAlgoId,
		Model:      d.Model,
		Serial:     d.Serial,
		SigningPub: d.SigningPub,
		SwitchName: d.SwitchName,
		SwitchPort: d.SwitchPort,
	}
}

func (h *CRUDHandler) requestToProfile(req *ProfileRequest) (*entities.DeviceProfile, error) {
	role, err := entities.ParseDeviceRole(req.Role)
	if err != nil {
		return nil, err
	}
	profile := &entities.DeviceProfile{
		ID:         req.ID,
		Name:       req.Name,
		Model:      req.Model,
		Role:       role,
		EventLog:   req.EventLog,
		EKSerial:   req.EKSerial,
		EKCert:     req.EKCert,
		MACAddress: req.MACAddress,
		Config:     req.Config,
		Assigned:   req.Assigned,
		AssignedAt: req.AssignedAt,
	}

	profile.Zone = req.Zone
	profile.EnrollmentNetwork = req.EnrollmentNetwork
	profile.PostEnrollmentNetwork = req.PostEnrollmentNetwork
	profile.FailureNetwork = req.FailureNetwork
	if len(req.Networks) > 0 {
		profile.Networks = make(map[string]*entities.NetworkPhaseConfig, len(req.Networks))
		for name, n := range req.Networks {
			if n != nil {
				profile.Networks[name] = h.networkPhaseRequestToEntity(n)
			}
		}
	} else {
		profile.Networks = make(map[string]*entities.NetworkPhaseConfig)
	}
	if req.PlatformdConfig != nil {
		profile.PlatformdConfig = &entities.PlatformdConfigRef{
			ConfigType: req.PlatformdConfig.ConfigType,
			Reference:  req.PlatformdConfig.Reference,
			ConfigName: req.PlatformdConfig.ConfigName,
			ConfigPath: req.PlatformdConfig.ConfigPath,
			Version:    req.PlatformdConfig.Version,
		}
	}
	if req.MatchRules != nil {
		profile.MatchRules = &entities.ProfileMatchRules{
			MACPrefix:         req.MatchRules.MACPrefix,
			SerialPrefix:      req.MatchRules.SerialPrefix,
			Model:             req.MatchRules.Model,
			ModelPattern:      req.MatchRules.ModelPattern,
			SerialPattern:     req.MatchRules.SerialPattern,
			ManufacturerMatch: req.MatchRules.ManufacturerMatch,
			TPMVendor:         req.MatchRules.TPMVendor,
			CustomAttributes:  req.MatchRules.CustomAttributes,
		}
	}

	return profile, nil
}

func (h *CRUDHandler) networkPhaseRequestToEntity(req *NetworkPhaseRequest) *entities.NetworkPhaseConfig {
	config := &entities.NetworkPhaseConfig{
		VLAN:       req.VLAN,
		StaticIP:   req.StaticIP,
		Gateway:    req.Gateway,
		DNS:        req.DNS,
		AuthMethod: h.stringToAuthMethod(req.AuthMethod),
		Subnet:     req.Subnet,
		DNSServers: req.DNSServers,
		DHCP:       req.DHCP,
		Zone:       req.Zone,
	}

	if req.DHCPPool != nil {
		config.DHCPPool = &entities.DHCPPoolConfig{
			Network:    req.DHCPPool.Network,
			RangeStart: req.DHCPPool.RangeStart,
			RangeEnd:   req.DHCPPool.RangeEnd,
			LeaseTime:  req.DHCPPool.LeaseTime,
		}
	}

	for _, acl := range req.ACLs {
		config.ACLs = append(config.ACLs, entities.ACLConfig{
			Priority: acl.Priority,
			Protocol: acl.Protocol,
			SrcIP:    acl.SrcIP,
			DstIP:    acl.DstIP,
			SrcPort:  acl.SrcPort,
			DstPort:  acl.DstPort,
			Action:   acl.Action,
		})
	}

	return config
}

func (h *CRUDHandler) profileToResponse(p *entities.DeviceProfile) *ProfileFullResponse {
	if p == nil {
		return nil
	}

	resp := &ProfileFullResponse{
		ID:         p.ID,
		Name:       p.Name,
		Model:      p.Model,
		Role:       string(p.Role),
		EventLog:   p.EventLog,
		EKSerial:   p.EKSerial,
		EKCert:     p.EKCert,
		MACAddress: p.MACAddress,
		Config:     p.Config,
		Assigned:   p.Assigned,
		AssignedAt: p.AssignedAt,
	}

	resp.Zone = p.Zone
	resp.EnrollmentNetwork = p.EnrollmentNetwork
	resp.PostEnrollmentNetwork = p.PostEnrollmentNetwork
	resp.FailureNetwork = p.FailureNetwork
	if len(p.Networks) > 0 {
		resp.Networks = make(map[string]*NetworkPhaseResponse, len(p.Networks))
		for name, n := range p.Networks {
			resp.Networks[name] = h.networkPhaseEntityToResponse(n)
		}
	}
	if p.PlatformdConfig != nil {
		resp.PlatformdConfig = &PlatformdConfigResponse{
			ConfigType: p.PlatformdConfig.ConfigType,
			Reference:  p.PlatformdConfig.Reference,
			ConfigName: p.PlatformdConfig.ConfigName,
			ConfigPath: p.PlatformdConfig.ConfigPath,
			Version:    p.PlatformdConfig.Version,
		}
	}
	if p.MatchRules != nil {
		resp.MatchRules = &MatchRulesResponse{
			MACPrefix:         p.MatchRules.MACPrefix,
			SerialPrefix:      p.MatchRules.SerialPrefix,
			Model:             p.MatchRules.Model,
			ModelPattern:      p.MatchRules.ModelPattern,
			SerialPattern:     p.MatchRules.SerialPattern,
			ManufacturerMatch: p.MatchRules.ManufacturerMatch,
			TPMVendor:         p.MatchRules.TPMVendor,
			CustomAttributes:  p.MatchRules.CustomAttributes,
		}
	}

	return resp
}

func (h *CRUDHandler) networkPhaseEntityToResponse(c *entities.NetworkPhaseConfig) *NetworkPhaseResponse {
	if c == nil {
		return nil
	}

	resp := &NetworkPhaseResponse{
		VLAN:       c.VLAN,
		StaticIP:   c.StaticIP,
		Gateway:    c.Gateway,
		DNS:        c.DNS,
		AuthMethod: string(c.AuthMethod),
		Subnet:     c.Subnet,
		DNSServers: c.DNSServers,
		DHCP:       c.DHCP,
		Zone:       c.Zone,
	}

	if c.DHCPPool != nil {
		resp.DHCPPool = &DHCPPoolResponse{
			Network:    c.DHCPPool.Network,
			RangeStart: c.DHCPPool.RangeStart,
			RangeEnd:   c.DHCPPool.RangeEnd,
			LeaseTime:  c.DHCPPool.LeaseTime,
		}
	}

	for _, acl := range c.ACLs {
		resp.ACLs = append(resp.ACLs, ACLResponse{
			Priority: acl.Priority,
			Protocol: acl.Protocol,
			SrcIP:    acl.SrcIP,
			DstIP:    acl.DstIP,
			SrcPort:  acl.SrcPort,
			DstPort:  acl.DstPort,
			Action:   acl.Action,
		})
	}

	return resp
}

func (h *CRUDHandler) stringToAuthMethod(method string) entities.AuthMethod {
	switch strings.ToLower(method) {
	case "802.1x", "8021x":
		return entities.AuthMethod802_1X
	default:
		return entities.AuthMethodNone
	}
}
