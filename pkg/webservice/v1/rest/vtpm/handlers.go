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

package vtpm

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	defaultLimit  = 50
	maxLimit      = 1000
	defaultOffset = 0

	requestTimeout = 30 * time.Second
)

// VTPMHandlers provides REST handlers for vTPM operations.
type VTPMHandlers struct {
	logger     *logging.Logger
	service    vtpm.VTPMService
	respWriter response.HttpWriter
}

// NewVTPMHandlers creates a new VTPMHandlers instance.
func NewVTPMHandlers(
	logger *logging.Logger,
	service vtpm.VTPMService,
	respWriter response.HttpWriter,
) *VTPMHandlers {
	return &VTPMHandlers{
		logger:     logger,
		service:    service,
		respWriter: respWriter,
	}
}

// Helper methods

func (h *VTPMHandlers) getBundleID(r *http.Request) string {
	return mux.Vars(r)["id"]
}

func (h *VTPMHandlers) getTemplateID(r *http.Request) string {
	return mux.Vars(r)["id"]
}

func (h *VTPMHandlers) createContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), requestTimeout)
}

func (h *VTPMHandlers) decodeJSON(r *http.Request, v interface{}) error {
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	return decoder.Decode(v)
}

func (h *VTPMHandlers) getPaginationParams(r *http.Request) (int, int) {
	limit := defaultLimit
	offset := defaultOffset

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
			if limit > maxLimit {
				limit = maxLimit
			}
			if limit < 1 {
				limit = defaultLimit
			}
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil {
			offset = parsed
			if offset < 0 {
				offset = defaultOffset
			}
		}
	}

	return limit, offset
}

func (h *VTPMHandlers) handleServiceError(w http.ResponseWriter, r *http.Request, err error) {
	errMsg := err.Error()

	if containsAny(errMsg, "not found", "does not exist", "no such") {
		h.respWriter.Error404(w, r, err)
		return
	}

	if containsAny(errMsg, "invalid", "required", "must be", "cannot be") {
		h.respWriter.Error400(w, r, err)
		return
	}

	h.respWriter.Error500(w, r, err)
}

// Bundle Handlers

// CreateBundle handles POST /api/v1/vtpm/bundles
func (h *VTPMHandlers) CreateBundle(w http.ResponseWriter, r *http.Request) {
	var req CreateBundleRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	mode := h.parseBundleMode(req.Mode)
	if req.Mode != "" && !mode.IsValid() {
		h.respWriter.Error400(w, r, ErrInvalidBundleMode{Mode: req.Mode})
		return
	}

	ekAlg, err := vtpm.ParseEKAlgorithm(req.EKAlgorithm)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	// Validate hostname for pre-assigned mode
	if mode == vtpm.BundleModePreAssigned && req.Hostname == "" {
		h.respWriter.Error400(w, r, ErrMissingHostname{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	opts := &vtpm.CreateBundleOptions{
		Mode:              mode,
		Hostname:          req.Hostname,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: req.SecureBootEnabled,
		Labels:            req.Labels,
		TemplateID:        req.TemplateID,
		DeviceProfileID:   req.DeviceProfileID,
	}

	bundle, err := h.service.CreateBundle(ctx, opts)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.bundleToResponse(bundle))
}

// GetBundle handles GET /api/v1/vtpm/bundles/{id}
func (h *VTPMHandlers) GetBundle(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	bundle, err := h.service.GetBundle(ctx, id)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.bundleToResponse(bundle))
}

// DeleteBundle handles DELETE /api/v1/vtpm/bundles/{id}
func (h *VTPMHandlers) DeleteBundle(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.service.DeleteBundle(ctx, id)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "bundle deleted successfully",
	})
}

// ListBundles handles GET /api/v1/vtpm/bundles
func (h *VTPMHandlers) ListBundles(w http.ResponseWriter, r *http.Request) {
	limit, offset := h.getPaginationParams(r)
	modeStr := r.URL.Query().Get("mode")

	var mode vtpm.BundleMode
	if modeStr != "" {
		mode = h.parseBundleMode(modeStr)
	}

	labels, err := parseLabelsQuery(r)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	profileID, err := parseDeviceProfileIDQuery(r)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	opts := &vtpm.ListOptions{
		Mode:            mode,
		Labels:          labels,
		Limit:           limit,
		Offset:          offset,
		DeviceProfileID: profileID,
	}

	bundles, err := h.service.ListBundles(ctx, opts)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	bundleResponses := make([]BundleResponse, 0, len(bundles))
	for _, bundle := range bundles {
		bundleResponses = append(bundleResponses, h.bundleToResponse(bundle))
	}

	h.respWriter.Success200(w, r, ListBundlesResponse{
		Bundles: bundleResponses,
		Total:   len(bundles),
	})
}

// Template Handlers

// CreateTemplate handles POST /api/v1/vtpm/templates
func (h *VTPMHandlers) CreateTemplate(w http.ResponseWriter, r *http.Request) {
	var req CreateTemplateRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.ID == "" {
		h.respWriter.Error400(w, r, ErrMissingTemplateID{})
		return
	}

	ekAlg, err := vtpm.ParseEKAlgorithm(req.EKAlgorithm)
	if err != nil {
		h.respWriter.Error400(w, r, err)
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	opts := &vtpm.CreateTemplateOptions{
		ID:                req.ID,
		Description:       req.Description,
		EKAlgorithm:       ekAlg,
		SecureBootEnabled: req.SecureBootEnabled,
	}

	template, err := h.service.CreateTemplate(ctx, opts)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.templateToResponse(template))
}

// GetTemplate handles GET /api/v1/vtpm/templates/{id}
func (h *VTPMHandlers) GetTemplate(w http.ResponseWriter, r *http.Request) {
	id := h.getTemplateID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingTemplateID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	template, err := h.service.GetTemplate(ctx, id)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.templateToResponse(template))
}

// DeleteTemplate handles DELETE /api/v1/vtpm/templates/{id}
func (h *VTPMHandlers) DeleteTemplate(w http.ResponseWriter, r *http.Request) {
	id := h.getTemplateID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingTemplateID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.service.DeleteTemplate(ctx, id)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "template deleted successfully",
	})
}

// ListTemplates handles GET /api/v1/vtpm/templates
func (h *VTPMHandlers) ListTemplates(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.createContext()
	defer cancel()

	templates, err := h.service.ListTemplates(ctx)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	templateResponses := make([]TemplateResponse, 0, len(templates))
	for _, template := range templates {
		templateResponses = append(templateResponses, h.templateToResponse(template))
	}

	h.respWriter.Success200(w, r, ListTemplatesResponse{
		Templates: templateResponses,
	})
}

// CloneTemplate handles POST /api/v1/vtpm/templates/{id}/clone
func (h *VTPMHandlers) CloneTemplate(w http.ResponseWriter, r *http.Request) {
	templateID := h.getTemplateID(r)
	if templateID == "" {
		h.respWriter.Error400(w, r, ErrMissingTemplateID{})
		return
	}

	var req CloneTemplateRequest
	if err := h.decodeJSON(r, &req); err != nil {
		h.respWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Hostname == "" {
		h.respWriter.Error400(w, r, ErrMissingHostname{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	opts := &vtpm.CloneOptions{
		TemplateID: templateID,
		Hostname:   req.Hostname,
		Labels:     req.Labels,
	}

	bundle, err := h.service.CloneTemplate(ctx, opts)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.bundleToResponse(bundle))
}

// Export/Import Handlers

// ExportBundle handles GET /api/v1/vtpm/bundles/{id}/export
func (h *VTPMHandlers) ExportBundle(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	// Set headers for tar.gz download
	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+id+".tar.gz\"")

	err := h.service.ExportBundle(ctx, id, w)
	if err != nil {
		// If we haven't written anything yet, we can send an error response
		h.handleServiceError(w, r, err)
		return
	}
}

// ImportBundle handles POST /api/v1/vtpm/bundles/import
func (h *VTPMHandlers) ImportBundle(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := h.createContext()
	defer cancel()

	// Limit the size of the upload
	r.Body = http.MaxBytesReader(w, r.Body, 100*1024*1024) // 100MB max

	bundle, err := h.service.ImportBundle(ctx, r.Body)
	if err != nil {
		h.handleServiceError(w, r, err)
		return
	}

	h.respWriter.Success200(w, r, h.bundleToResponse(bundle))
}

// Validation Handler

// ValidateBundle handles POST /api/v1/vtpm/bundles/{id}/validate
func (h *VTPMHandlers) ValidateBundle(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	ctx, cancel := h.createContext()
	defer cancel()

	err := h.service.ValidateBundle(ctx, id)
	if err != nil {
		h.respWriter.Success200(w, r, ValidateBundleResponse{
			Valid:  false,
			Errors: []string{err.Error()},
		})
		return
	}

	h.respWriter.Success200(w, r, ValidateBundleResponse{
		Valid:  true,
		Errors: nil,
	})
}

// Path Getter Handlers

// GetBundlePath handles GET /api/v1/vtpm/bundles/{id}/path
func (h *VTPMHandlers) GetBundlePath(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	path := h.service.GetBundlePath(id)

	h.respWriter.Success200(w, r, PathResponse{Path: path})
}

// GetTPMSocketPath handles GET /api/v1/vtpm/bundles/{id}/tpm-socket
func (h *VTPMHandlers) GetTPMSocketPath(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	path := h.service.GetTPMSocketPath(id)

	h.respWriter.Success200(w, r, PathResponse{Path: path})
}

// GetNVRAMPath handles GET /api/v1/vtpm/bundles/{id}/nvram
func (h *VTPMHandlers) GetNVRAMPath(w http.ResponseWriter, r *http.Request) {
	id := h.getBundleID(r)
	if id == "" {
		h.respWriter.Error400(w, r, ErrMissingBundleID{})
		return
	}

	path := h.service.GetNVRAMPath(id)

	h.respWriter.Success200(w, r, PathResponse{Path: path})
}

// Conversion helpers

func (h *VTPMHandlers) parseBundleMode(mode string) vtpm.BundleMode {
	switch strings.ToLower(mode) {
	case "template", "bundle_mode_template":
		return vtpm.BundleModeTemplate
	case "pre-assigned", "preassigned", "pre_assigned", "bundle_mode_pre_assigned":
		return vtpm.BundleModePreAssigned
	default:
		return ""
	}
}

// parseLabelsQuery reads the repeated labels=key=value query parameter the
// ListBundles filter takes; nil when absent.
func parseLabelsQuery(r *http.Request) (map[string]string, error) {
	values := r.URL.Query()["labels"]
	if len(values) == 0 {
		return nil, nil
	}
	labels := make(map[string]string, len(values))
	for _, value := range values {
		key, val, ok := strings.Cut(value, "=")
		if !ok || key == "" {
			return nil, ErrInvalidLabelQuery{Value: value}
		}
		labels[key] = val
	}
	return labels, nil
}

// parseDeviceProfileIDQuery reads the device_profile_id query parameter, 0
// (no filter) when absent.
func parseDeviceProfileIDQuery(r *http.Request) (uint64, error) {
	raw := r.URL.Query().Get("device_profile_id")
	if raw == "" {
		return 0, nil
	}
	id, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, ErrInvalidDeviceProfileIDQuery{Value: raw}
	}
	return id, nil
}

func (h *VTPMHandlers) bundleToResponse(bundle *vtpm.Bundle) BundleResponse {
	if bundle == nil {
		return BundleResponse{}
	}

	resp := BundleResponse{
		ID:         bundle.ID,
		Mode:       string(bundle.Mode),
		ClonedFrom: bundle.ClonedFrom,
	}

	if !bundle.CreatedAt.IsZero() {
		resp.CreatedAt = &bundle.CreatedAt
	}

	if bundle.Manifest != nil {
		resp.Manifest = h.manifestToResponse(bundle.Manifest)
	}

	if bundle.TPMState != nil {
		resp.TPMState = &TPMStateResponse{
			StateDir:     bundle.TPMState.StateDir,
			PermallFile:  bundle.TPMState.PermallFile,
			VolatileFile: bundle.TPMState.VolatileFile,
		}
	}

	if bundle.OVMFState != nil {
		resp.OVMFState = &OVMFStateResponse{
			NVRAMFile: bundle.OVMFState.NVRAMFile,
		}
	}

	if bundle.SecureBootKeys != nil {
		resp.SecureBootKeys = &SecureBootKeyPathsResponse{
			Dir:     bundle.SecureBootKeys.Dir,
			PKKey:   bundle.SecureBootKeys.PKKey,
			PKCert:  bundle.SecureBootKeys.PKCert,
			KEKKey:  bundle.SecureBootKeys.KEKKey,
			KEKCert: bundle.SecureBootKeys.KEKCert,
			DBKey:   bundle.SecureBootKeys.DBKey,
			DBCert:  bundle.SecureBootKeys.DBCert,
		}
	}

	return resp
}

func (h *VTPMHandlers) manifestToResponse(manifest *vtpm.Manifest) *ManifestResponse {
	if manifest == nil {
		return nil
	}

	resp := &ManifestResponse{
		Version:           manifest.Version,
		ID:                manifest.ID,
		Mode:              string(manifest.Mode),
		Hostname:          manifest.Hostname,
		EKAlgorithm:       string(manifest.EKAlgorithm),
		EKHandle:          manifest.EKHandle,
		SecureBootEnabled: manifest.SecureBootEnabled,
		Checksums:         manifest.Checksums,
		Labels:            manifest.Labels,
		ClonedFrom:        manifest.ClonedFrom,
		DeviceProfileID:   manifest.DeviceProfileID,
	}

	if !manifest.CreatedAt.IsZero() {
		resp.CreatedAt = &manifest.CreatedAt
	}

	if manifest.EKCertificate != nil {
		resp.EKCertificate = &EKCertInfoResponse{
			Subject:      manifest.EKCertificate.Subject,
			Issuer:       manifest.EKCertificate.Issuer,
			SerialNumber: manifest.EKCertificate.SerialNumber,
			Fingerprint:  manifest.EKCertificate.Fingerprint,
		}
		if !manifest.EKCertificate.NotBefore.IsZero() {
			resp.EKCertificate.NotBefore = &manifest.EKCertificate.NotBefore
		}
		if !manifest.EKCertificate.NotAfter.IsZero() {
			resp.EKCertificate.NotAfter = &manifest.EKCertificate.NotAfter
		}
	}

	if manifest.SecureBootKeys != nil {
		resp.SecureBootKeys = &SecureBootKeyInfoResponse{
			PKFingerprint:  manifest.SecureBootKeys.PKFingerprint,
			KEKFingerprint: manifest.SecureBootKeys.KEKFingerprint,
			DBFingerprint:  manifest.SecureBootKeys.DBFingerprint,
			OwnerGUID:      manifest.SecureBootKeys.OwnerGUID,
		}
	}

	return resp
}

func (h *VTPMHandlers) templateToResponse(template *vtpm.Template) TemplateResponse {
	if template == nil {
		return TemplateResponse{}
	}

	resp := TemplateResponse{
		ID:                template.ID,
		Description:       template.Description,
		TPMStateDir:       template.TPMStateDir,
		NVRAMPath:         template.NVRAMPath,
		SecureBootKeysDir: template.SecureBootKeysDir,
		EKAlgorithm:       string(template.EKAlgorithm),
		SecureBootEnabled: template.SecureBootEnabled,
	}

	if !template.CreatedAt.IsZero() {
		resp.CreatedAt = &template.CreatedAt
	}

	return resp
}

// containsAny checks if the string contains any of the substrings.
func containsAny(s string, substrings ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrings {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// Ensure VTPMHandlers satisfies io.Writer for export
var _ io.Writer = (*exportWriter)(nil)

type exportWriter struct {
	w http.ResponseWriter
}

func (e *exportWriter) Write(p []byte) (n int, err error) {
	return e.w.Write(p)
}
