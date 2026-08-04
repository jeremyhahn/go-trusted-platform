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
// Template REST Handler Errors
// =============================================================================

// ErrTemplateServiceNotAvailable is returned when the template service is not configured.
type ErrTemplateServiceNotAvailable struct{}

func (e ErrTemplateServiceNotAvailable) Error() string {
	return "template service not available"
}

// ErrTemplateInvalidID is returned when a template ID is invalid or empty.
type ErrTemplateInvalidID struct {
	ID string
}

func (e ErrTemplateInvalidID) Error() string {
	if e.ID == "" {
		return "template ID is required"
	}
	return fmt.Sprintf("invalid template ID: %s", e.ID)
}

// ErrTemplateNotFound is returned when a template is not found.
type ErrTemplateNotFound struct {
	ID uint64
}

func (e ErrTemplateNotFound) Error() string {
	return fmt.Sprintf("template not found with ID: %d", e.ID)
}

// ErrTemplateNameRequired is returned when template name is required but not provided.
type ErrTemplateNameRequired struct{}

func (e ErrTemplateNameRequired) Error() string {
	return "template name is required"
}

// ErrTemplateOperationFailed is returned when a template operation fails.
type ErrTemplateOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrTemplateOperationFailed) Error() string {
	return fmt.Sprintf("template operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrTemplateOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceIdentityRequired is returned when no device identifier is provided.
type ErrDeviceIdentityRequired struct{}

func (e ErrDeviceIdentityRequired) Error() string {
	return "at least one of ek_serial or mac_address is required"
}

// =============================================================================
// Request/Response Types
// =============================================================================

// DeviceTemplateCreateRequest represents a device template creation request.
type DeviceTemplateCreateRequest struct {
	Name        string                    `json:"name"`
	TenantID    string                    `json:"tenant_id,omitempty"`
	Description string                    `json:"description,omitempty"`
	Role        string                    `json:"role,omitempty"`
	Config      []byte                    `json:"config,omitempty"`
	MatchRules  *ProfileMatchRulesRequest `json:"match_rules,omitempty"`
}

// DeviceTemplateUpdateRequest represents a device template update request.
type DeviceTemplateUpdateRequest struct {
	Name        string                    `json:"name,omitempty"`
	TenantID    string                    `json:"tenant_id,omitempty"`
	Description string                    `json:"description,omitempty"`
	Role        string                    `json:"role,omitempty"`
	Config      []byte                    `json:"config,omitempty"`
	MatchRules  *ProfileMatchRulesRequest `json:"match_rules,omitempty"`
}

// DeviceTemplateResponse represents a device template in API responses.
type DeviceTemplateResponse struct {
	ID          uint64                     `json:"id"`
	TenantID    string                     `json:"tenant_id,omitempty"`
	Name        string                     `json:"name"`
	Description string                     `json:"description,omitempty"`
	Role        string                     `json:"role,omitempty"`
	Config      []byte                     `json:"config,omitempty"`
	MatchRules  *ProfileMatchRulesResponse `json:"match_rules,omitempty"`
	CreatedAt   time.Time                  `json:"created_at"`
	UpdatedAt   time.Time                  `json:"updated_at"`
}

// DeviceTemplateListResponse represents a list of device templates.
type DeviceTemplateListResponse struct {
	Templates  []DeviceTemplateResponse `json:"templates"`
	Pagination *PaginationResponse      `json:"pagination"`
	Timestamp  time.Time                `json:"timestamp"`
}

// CreateProfileFromTemplateRequest represents a request to create a profile from a template.
type CreateProfileFromTemplateRequest struct {
	Overrides *ProfileCreateRequest `json:"overrides,omitempty"`
}

// FindConfigForDeviceQuery holds the query parameters for config lookup.
type FindConfigForDeviceQuery struct {
	EKSerial string
	MAC      string
}

// AssignProfileRequest represents a request to assign a profile to a device.
// EKCert optionally prestages the device's PEM-encoded TPM Endorsement Key
// certificate on the profile during assignment; the certificate is
// source-agnostic (swtpm-backed vTPM or physical hardware TPM). An empty
// EKCert leaves any previously prestaged certificate untouched.
type AssignProfileRequest struct {
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	EKCert     string `json:"ek_cert,omitempty"`
}

// =============================================================================
// Service Interfaces
// =============================================================================

// TemplateServiceInterface defines the interface for template operations.
type TemplateServiceInterface interface {
	Save(ctx context.Context, template *entities.DeviceTemplate) error
	Get(ctx context.Context, id uint64) (*entities.DeviceTemplate, error)
	Delete(ctx context.Context, template *entities.DeviceTemplate) error
	Update(ctx context.Context, template *entities.DeviceTemplate) error
	Count(ctx context.Context) (int, error)
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceTemplate], error)
	FindByName(ctx context.Context, tenantID, name string) (*entities.DeviceTemplate, error)
	ToProfile(ctx context.Context, templateID uint64, overrides *entities.DeviceProfile) (*entities.DeviceProfile, error)
}

// ConfigForDeviceResolver defines the interface for finding config by device identity.
type ConfigForDeviceResolver interface {
	FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error)
}

// =============================================================================
// Template Handlers
// =============================================================================

// TemplateHandlers provides REST API handlers for device template operations.
type TemplateHandlers struct {
	templateService TemplateServiceInterface
	profileService  ProfileServiceInterface
	logger          *slog.Logger
}

// NewTemplateHandlers creates a new TemplateHandlers instance.
func NewTemplateHandlers(
	templateService TemplateServiceInterface,
	profileService ProfileServiceInterface,
	logger *slog.Logger,
) *TemplateHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &TemplateHandlers{
		templateService: templateService,
		profileService:  profileService,
		logger:          logger,
	}
}

// RegisterRoutes registers all template and config delivery routes on the provided router.
// IMPORTANT: Route order matters in gorilla/mux. Static routes must be registered
// BEFORE parameterized routes to avoid incorrect matching.
func (h *TemplateHandlers) RegisterRoutes(router *mux.Router) {
	// Template CRUD - static routes before parameterized
	router.HandleFunc("/api/v1/devices/templates", h.handleCreateTemplate).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/devices/templates", h.handleListTemplates).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/devices/templates/{id}", h.handleGetTemplate).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/devices/templates/{id}", h.handleUpdateTemplate).Methods(http.MethodPut)
	router.HandleFunc("/api/v1/devices/templates/{id}", h.handleDeleteTemplate).Methods(http.MethodDelete)

	// Template operations
	router.HandleFunc("/api/v1/devices/templates/{id}/create-profile", h.handleCreateProfileFromTemplate).Methods(http.MethodPost)

	// Config delivery - static route before parameterized profile routes
	router.HandleFunc("/api/v1/devices/profiles/find-config", h.handleFindConfigForDevice).Methods(http.MethodGet)

	// Profile assignment
	router.HandleFunc("/api/v1/devices/profiles/{id}/assign", h.handleAssignProfileToDevice).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/devices/profiles/{id}/unassign", h.handleUnassignProfileFromDevice).Methods(http.MethodPost)

	h.logger.Info("Template and config delivery REST routes registered")
}

// handleCreateTemplate handles POST /api/v1/devices/templates
func (h *TemplateHandlers) handleCreateTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTemplateServiceNotAvailable{})
		return
	}

	var req DeviceTemplateCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrTemplateNameRequired{})
		return
	}

	templateID := generateTemplateID(req.Name)
	now := time.Now()

	template := &entities.DeviceTemplate{
		ID:          templateID,
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Role:        entities.DeviceRole(req.Role),
		Config:      req.Config,
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	if req.MatchRules != nil {
		template.MatchRules = &entities.ProfileMatchRules{
			MACPrefix:    req.MatchRules.MACPrefix,
			SerialPrefix: req.MatchRules.SerialPrefix,
			Model:        req.MatchRules.Model,
		}
	}

	if err := h.templateService.Save(r.Context(), template); err != nil {
		h.logger.Error("Failed to create template", "name", req.Name, "error", err)
		h.writeTemplateError(w, "create", err)
		return
	}

	resp := h.templateToResponse(template)
	h.logger.Info("Template created", "id", template.ID, "name", template.Name)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListTemplates handles GET /api/v1/devices/templates
func (h *TemplateHandlers) handleListTemplates(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTemplateServiceNotAvailable{})
		return
	}

	query := h.parsePageQuery(r)

	result, err := h.templateService.Page(r.Context(), query)
	if err != nil {
		h.logger.Error("Failed to list templates", "error", err)
		h.writeTemplateError(w, "list", err)
		return
	}

	templates := make([]DeviceTemplateResponse, 0, len(result.Entities))
	for _, t := range result.Entities {
		templates = append(templates, h.templateToResponse(t))
	}

	resp := DeviceTemplateListResponse{
		Templates: templates,
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

// handleGetTemplate handles GET /api/v1/devices/templates/{id}
func (h *TemplateHandlers) handleGetTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTemplateServiceNotAvailable{})
		return
	}

	id, err := h.parseTemplateID(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	template, err := h.templateService.Get(r.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get template", "id", id, "error", err)
		h.writeTemplateError(w, "get", err)
		return
	}

	resp := h.templateToResponse(template)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleUpdateTemplate handles PUT /api/v1/devices/templates/{id}
func (h *TemplateHandlers) handleUpdateTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTemplateServiceNotAvailable{})
		return
	}

	id, err := h.parseTemplateID(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	var req DeviceTemplateUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	existing, err := h.templateService.Get(r.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get template for update", "id", id, "error", err)
		h.writeTemplateError(w, "get", err)
		return
	}

	if req.Name != "" {
		existing.Name = req.Name
	}
	if req.TenantID != "" {
		existing.TenantID = req.TenantID
	}
	if req.Description != "" {
		existing.Description = req.Description
	}
	if req.Role != "" {
		existing.Role = entities.DeviceRole(req.Role)
	}
	if req.Config != nil {
		existing.Config = req.Config
	}
	if req.MatchRules != nil {
		existing.MatchRules = &entities.ProfileMatchRules{
			MACPrefix:    req.MatchRules.MACPrefix,
			SerialPrefix: req.MatchRules.SerialPrefix,
			Model:        req.MatchRules.Model,
		}
	}
	existing.UpdatedAt = time.Now()

	if err := h.templateService.Update(r.Context(), existing); err != nil {
		h.logger.Error("Failed to update template", "id", id, "error", err)
		h.writeTemplateError(w, "update", err)
		return
	}

	resp := h.templateToResponse(existing)
	h.logger.Info("Template updated", "id", existing.ID, "name", existing.Name)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteTemplate handles DELETE /api/v1/devices/templates/{id}
func (h *TemplateHandlers) handleDeleteTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTemplateServiceNotAvailable{})
		return
	}

	id, err := h.parseTemplateID(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	existing, err := h.templateService.Get(r.Context(), id)
	if err != nil {
		h.logger.Error("Failed to get template for delete", "id", id, "error", err)
		h.writeTemplateError(w, "get", err)
		return
	}

	if err := h.templateService.Delete(r.Context(), existing); err != nil {
		h.logger.Error("Failed to delete template", "id", id, "error", err)
		h.writeTemplateError(w, "delete", err)
		return
	}

	h.logger.Info("Template deleted", "id", id)
	w.WriteHeader(http.StatusNoContent)
}

// handleCreateProfileFromTemplate handles POST /api/v1/devices/templates/{id}/create-profile
func (h *TemplateHandlers) handleCreateProfileFromTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrTemplateServiceNotAvailable{})
		return
	}
	if h.profileService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrProfileServiceNotAvailable{})
		return
	}

	templateID, err := h.parseTemplateID(r)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	var overrides *entities.DeviceProfile
	var req CreateProfileFromTemplateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Overrides != nil {
		overrides = &entities.DeviceProfile{
			Name:  req.Overrides.Name,
			Model: req.Overrides.Model,
			Role:  entities.DeviceRole(req.Overrides.Role),
		}
	}

	profile, err := h.templateService.ToProfile(r.Context(), templateID, overrides)
	if err != nil {
		h.logger.Error("Failed to create profile from template", "template_id", templateID, "error", err)
		h.writeTemplateError(w, "create-profile", err)
		return
	}

	// Generate profile ID if not set from overrides
	if profile.ID == 0 && profile.Name != "" {
		profile.ID = generateProfileID(profile.Name)
	}

	if err := h.profileService.Save(r.Context(), profile); err != nil {
		h.logger.Error("Failed to save profile from template", "error", err)
		h.writeProfileError(w, "create", err)
		return
	}

	h.logger.Info("Profile created from template", "template_id", templateID, "profile_id", profile.ID)
	h.writeJSON(w, http.StatusCreated, h.profileToResponse(profile))
}

// handleFindConfigForDevice handles GET /api/v1/devices/profiles/find-config
func (h *TemplateHandlers) handleFindConfigForDevice(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrProfileServiceNotAvailable{})
		return
	}

	ekSerial := r.URL.Query().Get("ek_serial")
	mac := r.URL.Query().Get("mac")

	if ekSerial == "" && mac == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceIdentityRequired{})
		return
	}

	resolver, ok := h.profileService.(ConfigForDeviceResolver)
	if !ok {
		h.writeError(w, http.StatusServiceUnavailable, ErrProfileServiceNotAvailable{})
		return
	}

	profile, err := resolver.FindConfigForDevice(r.Context(), ekSerial, mac)
	if err != nil {
		h.logger.Error("Failed to find config for device",
			"ek_serial", ekSerial, "mac", mac, "error", err)
		h.writeProfileError(w, "find-config", err)
		return
	}

	h.writeJSON(w, http.StatusOK, h.profileToResponse(profile))
}

// handleAssignProfileToDevice handles POST /api/v1/devices/profiles/{id}/assign
func (h *TemplateHandlers) handleAssignProfileToDevice(w http.ResponseWriter, r *http.Request) {
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

	var req AssignProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.EKSerial == "" && req.MACAddress == "" {
		h.writeError(w, http.StatusBadRequest, ErrDeviceIdentityRequired{})
		return
	}

	// A prestaged EK certificate binds config delivery and remote UKI
	// signing to the hardware EK; an unparseable value can never match a
	// presented certificate, so reject it at the boundary.
	if err := entities.ValidateEKCertPEM(req.EKCert); err != nil {
		h.writeError(w, http.StatusBadRequest, err)
		return
	}

	if err := h.profileService.AssignToDeviceWithEK(r.Context(), id, req.EKSerial, req.MACAddress, req.EKCert); err != nil {
		h.logger.Error("Failed to assign profile to device",
			"profile_id", id, "error", err)
		h.writeProfileError(w, "assign", err)
		return
	}

	// Retrieve updated profile
	profile, err := h.profileService.Get(r.Context(), id)
	if err != nil {
		h.writeProfileError(w, "get", err)
		return
	}

	h.logger.Info("Profile assigned to device",
		"profile_id", id, "ek_serial", req.EKSerial, "mac", req.MACAddress,
		"ek_cert_prestaged", req.EKCert != "")
	h.writeJSON(w, http.StatusOK, h.profileToResponse(profile))
}

// handleUnassignProfileFromDevice handles POST /api/v1/devices/profiles/{id}/unassign.
// It clears the profile's device binding: the EK serial, MAC address,
// prestaged EK certificate, and assignment state are all reset.
func (h *TemplateHandlers) handleUnassignProfileFromDevice(w http.ResponseWriter, r *http.Request) {
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

	if err := h.profileService.UnassignFromDevice(r.Context(), id); err != nil {
		h.logger.Error("Failed to unassign profile from device",
			"profile_id", id, "error", err)
		h.writeProfileError(w, "unassign", err)
		return
	}

	profile, err := h.profileService.Get(r.Context(), id)
	if err != nil {
		h.writeProfileError(w, "get", err)
		return
	}

	h.logger.Info("Profile unassigned from device", "profile_id", id)
	h.writeJSON(w, http.StatusOK, h.profileToResponse(profile))
}

// =============================================================================
// Helper Methods
// =============================================================================

func (h *TemplateHandlers) parseTemplateID(r *http.Request) (uint64, error) {
	vars := mux.Vars(r)
	idStr := vars["id"]
	if idStr == "" {
		return 0, ErrTemplateInvalidID{}
	}
	id, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		return 0, ErrTemplateInvalidID{ID: idStr}
	}
	return id, nil
}

func (h *TemplateHandlers) parsePageQuery(r *http.Request) datastore.PageQuery {
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

func (h *TemplateHandlers) templateToResponse(t *entities.DeviceTemplate) DeviceTemplateResponse {
	resp := DeviceTemplateResponse{
		ID:          t.ID,
		TenantID:    t.TenantID,
		Name:        t.Name,
		Description: t.Description,
		Role:        string(t.Role),
		Config:      t.Config,
		CreatedAt:   t.CreatedAt,
		UpdatedAt:   t.UpdatedAt,
	}

	if t.MatchRules != nil {
		resp.MatchRules = &ProfileMatchRulesResponse{
			MACPrefix:    t.MatchRules.MACPrefix,
			SerialPrefix: t.MatchRules.SerialPrefix,
			Model:        t.MatchRules.Model,
		}
	}

	return resp
}

func (h *TemplateHandlers) profileToResponse(p *entities.DeviceProfile) ProfileResponse {
	resp := ProfileResponse{
		ID:       p.ID,
		Name:     p.Name,
		Model:    p.Model,
		Role:     string(p.Role),
		EventLog: p.EventLog,
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

func (h *TemplateHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

func (h *TemplateHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

func (h *TemplateHandlers) writeTemplateError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch {
	case isNotFoundError(err):
		status = http.StatusNotFound
	case isAlreadyExistsError(err):
		status = http.StatusConflict
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrTemplateOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}

func (h *TemplateHandlers) writeProfileError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch {
	case isNotFoundError(err):
		status = http.StatusNotFound
	case isAlreadyExistsError(err):
		status = http.StatusConflict
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrProfileOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}

// generateTemplateID generates a deterministic template ID from name.
func generateTemplateID(name string) uint64 {
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
