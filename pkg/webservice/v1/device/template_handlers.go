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
	"context"
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// ConfigForDeviceFinder provides config resolution for devices by identity.
type ConfigForDeviceFinder interface {
	FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error)
}

// ProfileAssigner provides profile-to-device binding.
type ProfileAssigner interface {
	AssignToDevice(ctx context.Context, profileID uint64, ekSerial, mac string) error
}

// TemplateCRUDHandler provides REST handlers for device template and config delivery operations.
type TemplateCRUDHandler interface {
	// Template CRUD
	CreateTemplate(w http.ResponseWriter, r *http.Request)
	GetTemplate(w http.ResponseWriter, r *http.Request)
	UpdateTemplate(w http.ResponseWriter, r *http.Request)
	DeleteTemplate(w http.ResponseWriter, r *http.Request)
	ListTemplates(w http.ResponseWriter, r *http.Request)
	FindTemplateByName(w http.ResponseWriter, r *http.Request)

	// Template operations
	CreateProfileFromTemplate(w http.ResponseWriter, r *http.Request)

	// Config delivery
	FindConfigForDevice(w http.ResponseWriter, r *http.Request)
	AssignProfileToDevice(w http.ResponseWriter, r *http.Request)
}

// TemplateHandler implements TemplateCRUDHandler.
type TemplateHandler struct {
	logger          *logging.Logger
	responseWriter  response.HttpWriter
	templateService device.DeviceTemplateService
	profileService  device.DeviceProfileService
}

// NewTemplateHandler creates a new TemplateHandler.
func NewTemplateHandler(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	templateService device.DeviceTemplateService,
	profileService device.DeviceProfileService,
) TemplateCRUDHandler {
	return &TemplateHandler{
		logger:          logger,
		responseWriter:  responseWriter,
		templateService: templateService,
		profileService:  profileService,
	}
}

// CreateTemplate handles POST /api/v1/device/templates
func (h *TemplateHandler) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.responseWriter.Error500(w, r, ErrTemplateServiceNotInitialized{})
		return
	}

	var req TemplateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Promote nested envelope fields when present so the WebUI's
	// `{template: {name, role}}` payload reaches the entity mapper.
	if req.Template != nil {
		if req.Template.ID != 0 {
			req.ID = req.Template.ID
		}
		if req.Template.TenantID != "" {
			req.TenantID = req.Template.TenantID
		}
		if req.Template.Name != "" {
			req.Name = req.Template.Name
		}
		if req.Template.Description != "" {
			req.Description = req.Template.Description
		}
		if req.Template.Role != "" {
			req.Role = req.Template.Role
		}
		if len(req.Template.Config) > 0 {
			req.Config = req.Template.Config
		}
		if req.Template.MatchRules != nil {
			req.MatchRules = req.Template.MatchRules
		}
	}

	templateEntity := h.requestToTemplate(&req)
	if templateEntity.ID == 0 {
		// Server-side ID generation matches the device CRUD path so
		// callers don't need to mint identifiers client-side.
		templateEntity.ID = device.NewID()
	}

	if err := h.templateService.Save(r.Context(), templateEntity); err != nil {
		h.logger.Errorf("failed to create template: %v", err)
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	h.logger.Infof("template created: id=%d name=%s", templateEntity.ID, templateEntity.Name)
	h.responseWriter.Success201(w, r, h.templateToResponse(templateEntity))
}

// GetTemplate handles GET /api/v1/device/templates/{id}
func (h *TemplateHandler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.responseWriter.Error500(w, r, ErrTemplateServiceNotInitialized{})
		return
	}

	id, err := h.getTemplateID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidTemplateID{})
		return
	}

	templateEntity, err := h.templateService.Get(r.Context(), id)
	if err != nil {
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, h.templateToResponse(templateEntity))
}

// UpdateTemplate handles PUT /api/v1/device/templates/{id}
func (h *TemplateHandler) UpdateTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.responseWriter.Error500(w, r, ErrTemplateServiceNotInitialized{})
		return
	}

	id, err := h.getTemplateID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidTemplateID{})
		return
	}

	var req TemplateRequest
	if err := decodeJSONBody(r, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	req.ID = id
	templateEntity := h.requestToTemplate(&req)

	if err := h.templateService.Update(r.Context(), templateEntity); err != nil {
		h.logger.Errorf("failed to update template: id=%d error=%v", id, err)
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	h.logger.Infof("template updated: id=%d", id)
	h.responseWriter.Success200(w, r, h.templateToResponse(templateEntity))
}

// DeleteTemplate handles DELETE /api/v1/device/templates/{id}
func (h *TemplateHandler) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.responseWriter.Error500(w, r, ErrTemplateServiceNotInitialized{})
		return
	}

	id, err := h.getTemplateID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidTemplateID{})
		return
	}

	templateEntity, err := h.templateService.Get(r.Context(), id)
	if err != nil {
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	if err := h.templateService.Delete(r.Context(), templateEntity); err != nil {
		h.logger.Errorf("failed to delete template: id=%d error=%v", id, err)
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	h.logger.Infof("template deleted: id=%d", id)
	w.WriteHeader(http.StatusNoContent)
}

// ListTemplates handles GET /api/v1/device/templates
func (h *TemplateHandler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.responseWriter.Error500(w, r, ErrTemplateServiceNotInitialized{})
		return
	}

	query := parsePaginationQuery(r)

	result, err := h.templateService.Page(r.Context(), query)
	if err != nil {
		h.logger.Errorf("failed to list templates: %v", err)
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	templates := make([]TemplateResponse, 0, len(result.Entities))
	for _, t := range result.Entities {
		templates = append(templates, *h.templateToResponse(t))
	}

	resp := TemplateListResponse{
		Templates: templates,
		Pagination: PaginationResponse{
			Page:       result.Page,
			PageSize:   result.PageSize,
			Total:      result.Total,
			TotalPages: calculatePages(result.Total, result.PageSize),
			HasMore:    result.HasMore,
		},
	}

	h.responseWriter.Success200(w, r, resp)
}

// FindTemplateByName handles GET /api/v1/device/templates/name/{name}
func (h *TemplateHandler) FindTemplateByName(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.responseWriter.Error500(w, r, ErrTemplateServiceNotInitialized{})
		return
	}

	name := mux.Vars(r)["name"]
	if name == "" {
		h.responseWriter.Error400(w, r, ErrMissingTemplateName{})
		return
	}

	tenantID := r.URL.Query().Get("tenant_id")

	templateEntity, err := h.templateService.FindByName(r.Context(), tenantID, name)
	if err != nil {
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, h.templateToResponse(templateEntity))
}

// CreateProfileFromTemplate handles POST /api/v1/device/templates/{id}/create-profile
func (h *TemplateHandler) CreateProfileFromTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.responseWriter.Error500(w, r, ErrTemplateServiceNotInitialized{})
		return
	}
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	templateID, err := h.getTemplateID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidTemplateID{})
		return
	}

	var overrides *entities.DeviceProfile
	var req CreateProfileFromTemplateRequest
	if err := decodeJSONBody(r, &req); err == nil && req.Overrides != nil {
		overrides = h.profileRequestToEntity(req.Overrides)
	}

	profile, err := h.templateService.ToProfile(r.Context(), templateID, overrides)
	if err != nil {
		h.logger.Errorf("failed to create profile from template: template_id=%d error=%v", templateID, err)
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	if err := h.profileService.Save(r.Context(), profile); err != nil {
		h.logger.Errorf("failed to save profile from template: %v", err)
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	h.logger.Infof("profile created from template: template_id=%d profile_id=%d", templateID, profile.ID)
	h.responseWriter.Success201(w, r, h.profileToResponse(profile))
}

// FindConfigForDevice handles GET /api/v1/device/profiles/find-config
func (h *TemplateHandler) FindConfigForDevice(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	ekSerial := r.URL.Query().Get("ek_serial")
	mac := r.URL.Query().Get("mac")

	if ekSerial == "" && mac == "" {
		h.responseWriter.Error400(w, r, ErrMissingDeviceIdentity{})
		return
	}

	finder, ok := h.profileService.(ConfigForDeviceFinder)
	if !ok {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	profile, err := finder.FindConfigForDevice(r.Context(), ekSerial, mac)
	if err != nil {
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	h.responseWriter.Success200(w, r, h.profileToResponse(profile))
}

// AssignProfileToDevice handles POST /api/v1/device/profiles/{id}/assign
func (h *TemplateHandler) AssignProfileToDevice(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	profileID, err := h.getProfileID(r)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidProfileID{})
		return
	}

	var req AssignProfileToDeviceRequest
	if err := decodeJSONBody(r, &req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.EKSerial == "" && req.MACAddress == "" {
		h.responseWriter.Error400(w, r, ErrMissingDeviceIdentity{})
		return
	}

	assigner, ok := h.profileService.(ProfileAssigner)
	if !ok {
		h.responseWriter.Error500(w, r, ErrProfileServiceNotInitializedError{})
		return
	}

	if err := assigner.AssignToDevice(r.Context(), profileID, req.EKSerial, req.MACAddress); err != nil {
		h.logger.Errorf("failed to assign profile to device: profile_id=%d error=%v", profileID, err)
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	profile, err := h.profileService.Get(r.Context(), profileID)
	if err != nil {
		handleServiceErr(h.responseWriter, w, r, err)
		return
	}

	h.logger.Infof("profile assigned to device: profile_id=%d ek_serial=%s mac=%s",
		profileID, req.EKSerial, req.MACAddress)
	h.responseWriter.Success200(w, r, h.profileToResponse(profile))
}

// Helper methods

func (h *TemplateHandler) getTemplateID(r *http.Request) (uint64, error) {
	idStr := mux.Vars(r)["id"]
	return strconv.ParseUint(idStr, 10, 64)
}

func (h *TemplateHandler) getProfileID(r *http.Request) (uint64, error) {
	idStr := mux.Vars(r)["id"]
	return strconv.ParseUint(idStr, 10, 64)
}

func calculatePages(total, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	pages := total / pageSize
	if total%pageSize > 0 {
		pages++
	}
	return pages
}

func (h *TemplateHandler) requestToTemplate(req *TemplateRequest) *entities.DeviceTemplate {
	template := &entities.DeviceTemplate{
		ID:          req.ID,
		TenantID:    req.TenantID,
		Name:        req.Name,
		Description: req.Description,
		Role:        stringToRole(req.Role),
		Config:      req.Config,
	}

	if req.MatchRules != nil {
		template.MatchRules = matchRulesRequestToEntity(req.MatchRules)
	}

	return template
}

func (h *TemplateHandler) templateToResponse(t *entities.DeviceTemplate) *TemplateResponse {
	if t == nil {
		return nil
	}

	resp := &TemplateResponse{
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
		resp.MatchRules = matchRulesEntityToResponse(t.MatchRules)
	}

	return resp
}

func (h *TemplateHandler) profileRequestToEntity(req *ProfileRequest) *entities.DeviceProfile {
	if req == nil {
		return nil
	}
	return &entities.DeviceProfile{
		ID:    req.ID,
		Name:  req.Name,
		Model: req.Model,
		Role:  stringToRole(req.Role),
	}
}

func (h *TemplateHandler) profileToResponse(p *entities.DeviceProfile) *ProfileFullResponse {
	if p == nil {
		return nil
	}

	resp := &ProfileFullResponse{
		ID:    p.ID,
		Name:  p.Name,
		Model: p.Model,
		Role:  string(p.Role),
	}

	if p.MatchRules != nil {
		resp.MatchRules = matchRulesEntityToResponse(p.MatchRules)
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

	return resp
}

// Compile-time interface check.
var _ TemplateCRUDHandler = (*TemplateHandler)(nil)
