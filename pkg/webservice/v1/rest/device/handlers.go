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
	"net/http"
	"strconv"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// templateRequest is the JSON body the bootstrap seeder sends when uploading
// a device template. The Template field contains the raw platform configuration
// as a JSON object (originally YAML, converted by the seeder).
type templateRequest struct {
	Role     string          `json:"role"`
	Template json.RawMessage `json:"template"`
}

// templateResponse is the JSON response returned after creating a device template.
type templateResponse struct {
	ID string `json:"id"`
}

// profileRequest is the JSON body the bootstrap seeder sends when creating
// a device profile from a template.
type profileRequest struct {
	MAC       string                 `json:"mac"`
	Hostname  string                 `json:"hostname"`
	Role      string                 `json:"role"`
	Overrides map[string]interface{} `json:"overrides,omitempty"`
}

// DeviceTemplateHandlers provides REST handlers for the bootstrap seeder's
// template upload and profile creation endpoints.
type DeviceTemplateHandlers struct {
	logger          *logging.Logger
	responseWriter  response.HttpWriter
	templateService device.DeviceTemplateService
	profileService  device.DeviceProfileService
}

// NewDeviceTemplateHandlers creates a new DeviceTemplateHandlers.
func NewDeviceTemplateHandlers(
	logger *logging.Logger,
	responseWriter response.HttpWriter,
	templateService device.DeviceTemplateService,
	profileService device.DeviceProfileService,
) *DeviceTemplateHandlers {
	return &DeviceTemplateHandlers{
		logger:          logger,
		responseWriter:  responseWriter,
		templateService: templateService,
		profileService:  profileService,
	}
}

// HandleUploadTemplate handles POST /api/v1/devices/templates.
// It accepts the seeder's templateRequest format, generates a deterministic
// template ID from the role name, persists the template, and returns the ID.
func (h *DeviceTemplateHandlers) HandleUploadTemplate(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.responseWriter.Error500(w, r, ErrTemplateServiceNil{})
		return
	}

	var req templateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Role == "" {
		h.responseWriter.Error400(w, r, ErrMissingRole{})
		return
	}

	if len(req.Template) == 0 || string(req.Template) == "null" {
		h.responseWriter.Error400(w, r, ErrMissingTemplate{})
		return
	}

	// Generate a deterministic ID from the role name so repeated uploads
	// for the same role produce the same template record (idempotent).
	templateID := util.NewID([]byte(req.Role))

	template := &entities.DeviceTemplate{
		ID:     templateID,
		Name:   req.Role,
		Role:   entities.DeviceRole(req.Role),
		Config: req.Template,
	}

	if err := h.templateService.Save(r.Context(), template); err != nil {
		h.logger.Errorf("device: failed to save template: role=%s error=%v", req.Role, err)
		h.responseWriter.Error500(w, r, ErrTemplateSaveFailed{Cause: err})
		return
	}

	h.logger.Infof("device: template uploaded: role=%s id=%d", req.Role, templateID)
	h.responseWriter.Success201(w, r, templateResponse{
		ID: strconv.FormatUint(templateID, 10),
	})
}

// HandleCreateProfile handles POST /api/v1/devices/templates/{id}/create-profile.
// It accepts the seeder's profileRequest format, converts the template to a
// profile with optional overrides, saves the profile, and returns 201 Created.
func (h *DeviceTemplateHandlers) HandleCreateProfile(w http.ResponseWriter, r *http.Request) {
	if h.templateService == nil {
		h.responseWriter.Error500(w, r, ErrTemplateServiceNil{})
		return
	}
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNil{})
		return
	}

	idStr := mux.Vars(r)["id"]
	templateID, err := strconv.ParseUint(idStr, 10, 64)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidTemplateID{})
		return
	}

	var req profileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Hostname == "" {
		h.responseWriter.Error400(w, r, ErrMissingHostname{})
		return
	}

	// Build profile overrides from the seeder request.
	overrides := &entities.DeviceProfile{
		Name: req.Hostname,
	}
	if req.Role != "" {
		overrides.Role = entities.DeviceRole(req.Role)
	}

	// Generate a deterministic profile ID from the hostname so repeated
	// seeding for the same host is idempotent.
	overrides.ID = util.NewID([]byte(req.Hostname))

	profile, err := h.templateService.ToProfile(r.Context(), templateID, overrides)
	if err != nil {
		h.logger.Errorf("device: failed to create profile from template: template_id=%d hostname=%s error=%v",
			templateID, req.Hostname, err)
		h.responseWriter.Error500(w, r, ErrProfileCreateFailed{Cause: err})
		return
	}

	if err := h.profileService.Save(r.Context(), profile); err != nil {
		h.logger.Errorf("device: failed to save profile: hostname=%s error=%v", req.Hostname, err)
		h.responseWriter.Error500(w, r, ErrProfileSaveFailed{Cause: err})
		return
	}

	h.logger.Infof("device: profile created from template: template_id=%d profile_id=%d hostname=%s",
		templateID, profile.ID, req.Hostname)
	w.WriteHeader(http.StatusCreated)
}
