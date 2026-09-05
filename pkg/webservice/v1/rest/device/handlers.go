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
	"net/http"
	"strconv"

	"github.com/gorilla/mux"
	"gopkg.in/yaml.v3"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	devicewire "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// templateRequest is the JSON body the bootstrap seeder sends when uploading
// a device template. The Template field contains the raw platform configuration
// as a JSON object (originally YAML, converted by the seeder).
type templateRequest struct {
	Role     string          `json:"role"`
	Template json.RawMessage `json:"template"`
}

// templateResponse is the JSON response returned after creating a device
// template.
//
// The ID was a Go string filled by strconv.FormatUint, which produced the same
// wire shape devicewire.ID produces -- a third spelling of one concept on one
// surface, and the one a reader sweeping for `,string` would miss (#342).
type templateResponse struct {
	ID devicewire.ID `json:"id"`
}

// profileRequest is the JSON body the bootstrap seeder sends when creating
// a device profile from a template.
//
// Config, when present, is the node's fully merged platform configuration
// (template + global identity + per-node overrides, merged by the seeder)
// and is stored on the profile verbatim: it is authoritative, so it is not
// merged onto the template again. Overrides are key-level patches applied
// to the template config for callers that do not send a merged Config.
type profileRequest struct {
	MAC       string                 `json:"mac"`
	Hostname  string                 `json:"hostname"`
	Role      string                 `json:"role"`
	Config    json.RawMessage        `json:"config,omitempty"`
	EKCert    string                 `json:"ek_cert,omitempty"`
	Overrides map[string]interface{} `json:"overrides,omitempty"`
}

// profileResponse is the JSON payload returned after creating a device
// profile. Its fields and JSON tags are the subset of the profile shape
// listed by GET /api/v1/devices/profiles that the seeder consumes.
//
// A previous version of this comment said the full ProfileFullResponse could
// not be reused "because pkg/webservice/v1/device imports this package". That
// is not true and was not true when it was written -- `go list -deps` shows no
// import in either direction. The comment is what justified duplicating the
// shape, so it is corrected here rather than left to justify it again (#342).
// Whether to reuse ProfileFullResponse outright is a separate question; this
// type stays a deliberate subset of it.
//
// The ID is a devicewire.ID, which marshals as a JSON string because a uint64
// exceeds the precision of a double.
type profileResponse struct {
	ID         devicewire.ID       `json:"id"`
	Name       string              `json:"name"`
	Role       string              `json:"role,omitempty"`
	MACAddress string              `json:"mac_address,omitempty"`
	MatchRules *matchRulesResponse `json:"match_rules,omitempty"`
	Assigned   bool                `json:"assigned"`
}

// matchRulesResponse mirrors entities.ProfileMatchRules with the JSON tags
// used by the profile list endpoint.
type matchRulesResponse struct {
	MACPrefix         string            `json:"mac_prefix,omitempty"`
	SerialPrefix      string            `json:"serial_prefix,omitempty"`
	Model             string            `json:"model,omitempty"`
	ModelPattern      string            `json:"model_pattern,omitempty"`
	SerialPattern     string            `json:"serial_pattern,omitempty"`
	ManufacturerMatch string            `json:"manufacturer_match,omitempty"`
	TPMVendor         string            `json:"tpm_vendor,omitempty"`
	CustomAttributes  map[string]string `json:"custom_attributes,omitempty"`
}

// profileToResponse maps a saved profile entity onto the create-profile
// response payload.
func profileToResponse(p *entities.DeviceProfile) profileResponse {
	resp := profileResponse{
		ID:         devicewire.ID(p.ID),
		Name:       p.Name,
		Role:       string(p.Role),
		MACAddress: p.MACAddress,
		Assigned:   p.Assigned,
	}
	if p.MatchRules != nil {
		resp.MatchRules = &matchRulesResponse{
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

	template, err := device.NewRoleTemplate(req.Role, req.Template)
	if err != nil {
		h.responseWriter.Error400(w, r, err)
		return
	}
	templateID := template.ID

	if err := h.templateService.Save(r.Context(), template); err != nil {
		h.logger.Errorf("device: failed to save template: role=%s error=%v", req.Role, err)
		h.responseWriter.Error500(w, r, ErrTemplateSaveFailed{Cause: err})
		return
	}

	h.logger.Infof("device: template uploaded: role=%s id=%d", req.Role, templateID)
	h.responseWriter.Success201(w, r, templateResponse{
		ID: devicewire.ID(templateID),
	})
}

// HandleCreateProfile handles POST /api/v1/devices/templates/{id}/create-profile.
// It accepts the seeder's profileRequest format, converts the template to a
// profile with optional overrides, saves the profile, and returns 201 Created
// with the profile (id as a JSON string) in the standard response envelope.
//
// When the request contains an Overrides map, those key-value pairs are
// deep-merged onto the template's base platform config. This produces a full
// merged config stored in profile.Config for delivery via HandleGetConfig.
// When the request carries a merged Config (the seeder's shape), that config
// is stored as-is and wins over the template-derived one. An ek_cert is
// refused: this route is unauthenticated and must not prestage hardware
// identity.
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

	// Only an omitted config is absent; any supplied value, including an
	// explicit null, must decode to a JSON object or the request is refused
	// rather than silently falling back to the template-derived config.
	var mergedConfig map[string]interface{}
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &mergedConfig); err != nil {
			h.responseWriter.Error400(w, r, ErrInvalidProfileConfig{Cause: err})
			return
		}
		if mergedConfig == nil {
			h.responseWriter.Error400(w, r, ErrInvalidProfileConfig{Cause: ErrProfileConfigNull{}})
			return
		}
	}

	// This route carries no caller credential (docs/bootstrap/api.md §6,
	// "Authorization — an open question"), so it must not prestage
	// hardware identity: an attacker reaching it could bind the profile to
	// an EK it controls. EK prestaging stays on the authenticated
	// POST /api/v1/device/profiles/{id}/assign route.
	if req.EKCert != "" {
		h.responseWriter.Error400(w, r, ErrEKCertNotAccepted{})
		return
	}

	// Build profile overrides from the seeder request.
	overrides := &entities.DeviceProfile{
		Name: req.Hostname,
	}
	if req.Role != "" {
		role, err := entities.ParseDeviceRole(req.Role)
		if err != nil {
			h.responseWriter.Error400(w, r, err)
			return
		}
		overrides.Role = role
	}
	if req.MAC != "" {
		overrides.MatchRules = &entities.ProfileMatchRules{
			MACPrefix: req.MAC,
		}
	}

	// Generate a deterministic profile ID from the hostname so repeated
	// seeding for the same host is idempotent.
	overrides.ID = util.NewID([]byte(req.Hostname))

	// Apply config-level overrides (hostname, IP, etc.) via deep merge
	// onto the template's base platform config.
	profile, err := h.templateService.ToProfileWithConfigOverrides(
		r.Context(), templateID, overrides, req.Overrides)
	if err != nil {
		h.logger.Errorf("device: failed to create profile from template: template_id=%d hostname=%s error=%v",
			templateID, req.Hostname, err)
		h.responseWriter.Error500(w, r, ErrProfileCreateFailed{Cause: err})
		return
	}

	// The seeder's merged config is the complete per-node configuration;
	// it replaces the template-derived config so HandleGetConfig delivers
	// exactly what the seeder computed.
	if mergedConfig != nil {
		profile.Config = mergedConfig
		if profile.PlatformdConfig == nil {
			profile.PlatformdConfig = &entities.PlatformdConfigRef{ConfigType: "inline"}
		}
		profile.PlatformdConfig.Inline = mergedConfig
	}

	if err := h.profileService.Save(r.Context(), profile); err != nil {
		h.logger.Errorf("device: failed to save profile: hostname=%s error=%v", req.Hostname, err)
		// A profile the caller described invalidly is a 400, not a 500.
		var vlans device.ErrProfileVLANsNotDistinct
		if errors.As(err, &vlans) {
			h.responseWriter.Error400(w, r, ErrProfileSaveFailed{Cause: err})
			return
		}
		h.responseWriter.Error500(w, r, ErrProfileSaveFailed{Cause: err})
		return
	}

	h.logger.Infof("device: profile created from template: template_id=%d profile_id=%d hostname=%s",
		templateID, profile.ID, req.Hostname)
	h.responseWriter.Success201(w, r, profileToResponse(profile))
}

// HandleGetConfig handles GET /api/v1/devices/config.
// It looks up a device profile by MAC address or serial number and returns
// the profile's Config field as raw YAML. The response is NOT wrapped in the
// standard JSON envelope because the installer reads it as a plain YAML file.
//
// Query parameters:
//
//	mac    - MAC address of the device (e.g., "aa:bb:cc:dd:ee:ff")
//	serial - serial number of the device
//
// At least one of mac or serial is required. When both are provided, the
// handler attempts an exact MAC lookup first, then serial, then falls back
// to profile match rules using both values.
func (h *DeviceTemplateHandlers) HandleGetConfig(w http.ResponseWriter, r *http.Request) {
	if h.profileService == nil {
		h.responseWriter.Error500(w, r, ErrProfileServiceNil{})
		return
	}

	mac := r.URL.Query().Get("mac")
	serial := r.URL.Query().Get("serial")

	if mac == "" && serial == "" {
		h.responseWriter.Error400(w, r, ErrMissingDeviceIdentifier{})
		return
	}

	profile, err := h.resolveProfile(r, mac, serial)
	if err != nil {
		h.logger.Errorf("device: config lookup failed: mac=%s serial=%s error=%v", mac, serial, err)
		http.Error(w, ErrProfileNotFound{MAC: mac, Serial: serial}.Error(), http.StatusNotFound)
		return
	}

	// Resolve config from either the Config field (direct, contains merged
	// template+overrides) or PlatformdConfig.Inline (backward compatibility).
	configData := profile.Config
	if configData == nil && profile.PlatformdConfig != nil && profile.PlatformdConfig.Inline != nil {
		configData = profile.PlatformdConfig.Inline
	}

	if configData == nil {
		h.logger.Errorf("device: profile %d has no config: mac=%s serial=%s", profile.ID, mac, serial)
		http.Error(w, ErrProfileConfigEmpty{ProfileID: profile.ID}.Error(), http.StatusNotFound)
		return
	}

	yamlBytes, err := yaml.Marshal(configData)
	if err != nil {
		h.logger.Errorf("device: failed to marshal config to YAML: profile_id=%d error=%v", profile.ID, err)
		h.responseWriter.Error500(w, r, ErrConfigMarshalFailed{Cause: err})
		return
	}

	w.Header().Set("Content-Type", "application/x-yaml")
	w.WriteHeader(http.StatusOK)
	w.Write(yamlBytes)
}

// resolveProfile attempts to find a device profile using the following
// resolution order:
//  1. Exact MAC address lookup via FindByMACAddress
//  2. Exact serial number lookup via FindBySerial
//  3. Fuzzy match via FindMatchingProfile using match rules
func (h *DeviceTemplateHandlers) resolveProfile(r *http.Request, mac, serial string) (*entities.DeviceProfile, error) {
	ctx := r.Context()

	// Try exact MAC lookup first.
	if mac != "" {
		profile, err := h.profileService.FindByMACAddress(ctx, mac)
		if err == nil && profile != nil {
			return profile, nil
		}
	}

	// Try exact serial lookup.
	if serial != "" {
		profile, err := h.profileService.FindBySerial(ctx, serial)
		if err == nil && profile != nil {
			return profile, nil
		}
	}

	// Fall back to match rules (prefix matching, model matching).
	profile, err := h.profileService.FindMatchingProfile(ctx, mac, serial, "")
	if err == nil && profile != nil {
		return profile, nil
	}

	return nil, ErrProfileNotFound{MAC: mac, Serial: serial}
}
