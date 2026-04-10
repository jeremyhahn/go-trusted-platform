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
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// HandlerParams contains the dependencies for creating a vTPM instance handler.
type HandlerParams struct {
	Logger           *logging.Logger
	GeneratorService GeneratorServicer
	ResponseWriter   response.HttpWriter
}

// handler implements the RestHandler interface.
type handler struct {
	logger           *logging.Logger
	generatorService GeneratorServicer
	responseWriter   response.HttpWriter
}

// NewHandler creates a new vTPM instance handler with the given parameters.
func NewHandler(params HandlerParams) (RestHandler, error) {
	if params.Logger == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingLogger{}}
	}
	if params.GeneratorService == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingGeneratorService{}}
	}
	if params.ResponseWriter == nil {
		return nil, ErrServiceError{Operation: "NewHandler", Cause: ErrMissingResponseWriter{}}
	}

	return &handler{
		logger:           params.Logger,
		generatorService: params.GeneratorService,
		responseWriter:   params.ResponseWriter,
	}, nil
}

// CreateInstance creates a new vTPM instance.
// POST /api/v1/vtpm/instances
func (h *handler) CreateInstance(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("vtpm: create instance request received")

	ctx := r.Context()

	var req CreateInstanceRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Empty body is allowed - use defaults
		if err.Error() != "EOF" {
			h.logger.Debug("vtpm: failed to decode request body", slog.String("error", err.Error()))
			h.responseWriter.Error400(w, r, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	// Build generate options from request
	opts := h.buildGenerateOptions(&req)

	// Validate EK algorithm if provided
	if req.Config != nil && req.Config.EKAlgorithm != "" {
		if !h.isValidEKAlgorithm(req.Config.EKAlgorithm) {
			h.responseWriter.Error400(w, r, ErrInvalidEKAlgorithm{Algorithm: req.Config.EKAlgorithm})
			return
		}
	}

	var instance *vtpm.VTPMInstance
	var err error

	// Generate instance (with or without profile association)
	instance, err = h.generatorService.Generate(ctx, opts)
	if err != nil {
		h.writeServiceError(w, r, "create", err)
		return
	}

	h.logger.Info("vtpm: instance created successfully",
		slog.String("instance_id", instance.ID),
		slog.String("ek_fingerprint", instance.EKFingerprint))

	resp := ToInstanceResponse(instance)
	h.responseWriter.Success201(w, r, resp)
}

// ListInstances lists all vTPM instances.
// GET /api/v1/vtpm/instances
func (h *handler) ListInstances(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("vtpm: list instances request received")

	ctx := r.Context()

	instances, err := h.generatorService.List(ctx)
	if err != nil {
		h.logger.Errorf("vtpm: failed to list instances: %v", err)
		h.responseWriter.Error500(w, r, ErrServiceError{Operation: "list", Cause: err})
		return
	}

	// Update running status for each instance
	for _, instance := range instances {
		instance.Running = h.generatorService.IsRunning(instance.ID)
	}

	h.logger.Debug("vtpm: listed instances", slog.Int("count", len(instances)))

	resp := ToInstanceListResponse(instances)
	h.responseWriter.Success200(w, r, resp)
}

// GetInstance retrieves a vTPM instance by ID.
// GET /api/v1/vtpm/instances/{id}
func (h *handler) GetInstance(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("vtpm: get instance request received")

	vars := mux.Vars(r)
	instanceID := vars["id"]
	if instanceID == "" {
		h.responseWriter.Error400(w, r, ErrMissingInstanceID{})
		return
	}

	ctx := r.Context()

	instance, err := h.generatorService.Get(ctx, instanceID)
	if err != nil {
		h.writeGetError(w, r, instanceID, err)
		return
	}

	// Update running status
	instance.Running = h.generatorService.IsRunning(instanceID)

	h.logger.Debug("vtpm: retrieved instance", slog.String("instance_id", instance.ID))

	resp := ToInstanceResponse(instance)
	h.responseWriter.Success200(w, r, resp)
}

// GetInstanceByProfile retrieves the vTPM instance for a profile.
// GET /api/v1/vtpm/instances/profile/{profile_id}
func (h *handler) GetInstanceByProfile(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("vtpm: get instance by profile request received")

	vars := mux.Vars(r)
	profileIDStr := vars["profile_id"]
	if profileIDStr == "" {
		h.responseWriter.Error400(w, r, ErrMissingProfileID{})
		return
	}

	profileID, err := strconv.ParseUint(profileIDStr, 10, 64)
	if err != nil {
		h.responseWriter.Error400(w, r, ErrInvalidProfileID{ID: profileIDStr})
		return
	}

	ctx := r.Context()

	instance, err := h.generatorService.GetByProfile(ctx, profileID)
	if err != nil {
		h.writeGetByProfileError(w, r, profileID, err)
		return
	}

	// Update running status
	instance.Running = h.generatorService.IsRunning(instance.ID)

	h.logger.Debug("vtpm: retrieved instance by profile",
		slog.Uint64("profile_id", profileID),
		slog.String("instance_id", instance.ID))

	resp := ToInstanceResponse(instance)
	h.responseWriter.Success200(w, r, resp)
}

// DeleteInstance deletes a vTPM instance.
// DELETE /api/v1/vtpm/instances/{id}
func (h *handler) DeleteInstance(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("vtpm: delete instance request received")

	vars := mux.Vars(r)
	instanceID := vars["id"]
	if instanceID == "" {
		h.responseWriter.Error400(w, r, ErrMissingInstanceID{})
		return
	}

	ctx := r.Context()

	// Stop the instance if running
	if h.generatorService.IsRunning(instanceID) {
		if err := h.generatorService.Stop(ctx, instanceID); err != nil {
			h.logger.Warnf("vtpm: failed to stop instance before delete: %v", err)
		}
	}

	if err := h.generatorService.Delete(ctx, instanceID); err != nil {
		h.writeDeleteError(w, r, instanceID, err)
		return
	}

	h.logger.Info("vtpm: instance deleted successfully", slog.String("instance_id", instanceID))

	h.responseWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "instance deleted successfully",
	})
}

// StartInstance starts a vTPM instance.
// POST /api/v1/vtpm/instances/{id}/start
func (h *handler) StartInstance(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("vtpm: start instance request received")

	vars := mux.Vars(r)
	instanceID := vars["id"]
	if instanceID == "" {
		h.responseWriter.Error400(w, r, ErrMissingInstanceID{})
		return
	}

	ctx := r.Context()

	// Check if already running
	if h.generatorService.IsRunning(instanceID) {
		h.responseWriter.Error400(w, r, ErrInstanceAlreadyRunning{ID: instanceID})
		return
	}

	if err := h.generatorService.Start(ctx, instanceID); err != nil {
		h.writeStartError(w, r, instanceID, err)
		return
	}

	h.logger.Info("vtpm: instance started successfully", slog.String("instance_id", instanceID))

	h.responseWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "instance started successfully",
	})
}

// StopInstance stops a vTPM instance.
// POST /api/v1/vtpm/instances/{id}/stop
func (h *handler) StopInstance(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("vtpm: stop instance request received")

	vars := mux.Vars(r)
	instanceID := vars["id"]
	if instanceID == "" {
		h.responseWriter.Error400(w, r, ErrMissingInstanceID{})
		return
	}

	ctx := r.Context()

	// Check if running
	if !h.generatorService.IsRunning(instanceID) {
		h.responseWriter.Error400(w, r, ErrInstanceNotRunning{ID: instanceID})
		return
	}

	if err := h.generatorService.Stop(ctx, instanceID); err != nil {
		h.writeStopError(w, r, instanceID, err)
		return
	}

	h.logger.Info("vtpm: instance stopped successfully", slog.String("instance_id", instanceID))

	h.responseWriter.Success200(w, r, SuccessResponse{
		Success: true,
		Message: "instance stopped successfully",
	})
}

// GetInstanceStatus returns the running status of a vTPM instance.
// GET /api/v1/vtpm/instances/{id}/status
func (h *handler) GetInstanceStatus(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("vtpm: get instance status request received")

	vars := mux.Vars(r)
	instanceID := vars["id"]
	if instanceID == "" {
		h.responseWriter.Error400(w, r, ErrMissingInstanceID{})
		return
	}

	ctx := r.Context()

	// Verify instance exists
	instance, err := h.generatorService.Get(ctx, instanceID)
	if err != nil {
		h.writeGetError(w, r, instanceID, err)
		return
	}

	running := h.generatorService.IsRunning(instanceID)

	resp := InstanceStatusResponse{
		ID:      instanceID,
		Running: running,
	}

	if running {
		resp.SocketPath = instance.SocketPath
	}

	h.logger.Debug("vtpm: retrieved instance status",
		slog.String("instance_id", instanceID),
		slog.Bool("running", running))

	h.responseWriter.Success200(w, r, resp)
}

// ExportEKCertificate exports the EK certificate in PEM format.
// GET /api/v1/vtpm/instances/{id}/ek
func (h *handler) ExportEKCertificate(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("vtpm: export EK certificate request received")

	vars := mux.Vars(r)
	instanceID := vars["id"]
	if instanceID == "" {
		h.responseWriter.Error400(w, r, ErrMissingInstanceID{})
		return
	}

	ctx := r.Context()

	cert, err := h.generatorService.ExportEKCertificate(ctx, instanceID)
	if err != nil {
		h.writeEKExportError(w, r, instanceID, err)
		return
	}

	// Encode certificate as PEM
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	pemData := pem.EncodeToMemory(pemBlock)

	h.logger.Debug("vtpm: exported EK certificate",
		slog.String("instance_id", instanceID),
		slog.String("subject", cert.Subject.String()))

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename=\"ek-"+instanceID+".pem\"")
	w.WriteHeader(http.StatusOK)
	w.Write(pemData)
}

// GetEKFingerprint returns the EK certificate fingerprint.
// GET /api/v1/vtpm/instances/{id}/ek/fingerprint
func (h *handler) GetEKFingerprint(w http.ResponseWriter, r *http.Request) {
	h.logger.Debug("vtpm: get EK fingerprint request received")

	vars := mux.Vars(r)
	instanceID := vars["id"]
	if instanceID == "" {
		h.responseWriter.Error400(w, r, ErrMissingInstanceID{})
		return
	}

	ctx := r.Context()

	fingerprint, err := h.generatorService.GetEKFingerprint(ctx, instanceID)
	if err != nil {
		h.writeEKFingerprintError(w, r, instanceID, err)
		return
	}

	h.logger.Debug("vtpm: retrieved EK fingerprint",
		slog.String("instance_id", instanceID),
		slog.String("fingerprint", fingerprint))

	resp := EKFingerprintResponse{
		ID:          instanceID,
		Fingerprint: fingerprint,
		Algorithm:   "SHA256",
	}

	h.responseWriter.Success200(w, r, resp)
}

// Helper methods

// buildGenerateOptions builds GenerateOptions from the request.
func (h *handler) buildGenerateOptions(req *CreateInstanceRequest) *vtpm.GenerateOptions {
	opts := &vtpm.GenerateOptions{}

	if req.Config != nil {
		opts.Hostname = req.Config.Hostname
		opts.Labels = req.Config.Labels
		opts.SecureBootEnabled = req.Config.SecureBootEnabled

		if req.Config.EKAlgorithm != "" {
			opts.EKAlgorithm = h.parseEKAlgorithm(req.Config.EKAlgorithm)
		}
	}

	return opts
}

// parseEKAlgorithm parses the EK algorithm string to vtpm.EKAlgorithm.
func (h *handler) parseEKAlgorithm(alg string) vtpm.EKAlgorithm {
	switch strings.ToUpper(alg) {
	case "RSA":
		return vtpm.EKAlgorithmRSA
	case "ECC":
		return vtpm.EKAlgorithmECC
	default:
		return vtpm.EKAlgorithmRSA
	}
}

// isValidEKAlgorithm checks if the EK algorithm is valid.
func (h *handler) isValidEKAlgorithm(alg string) bool {
	switch strings.ToUpper(alg) {
	case "RSA", "ECC":
		return true
	default:
		return false
	}
}

// Error handling helpers

func (h *handler) writeServiceError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	h.logger.Errorf("vtpm: %s operation failed: %v", operation, err)

	errMsg := err.Error()

	if h.containsAny(errMsg, "not found", "does not exist") {
		h.responseWriter.Error404(w, r, err)
		return
	}

	if h.containsAny(errMsg, "invalid", "required", "must be", "cannot be") {
		h.responseWriter.Error400(w, r, err)
		return
	}

	if h.containsAny(errMsg, "already exists", "already running") {
		h.responseWriter.Write(w, r, http.StatusConflict, response.WebServiceResponse{
			Code:    http.StatusConflict,
			Error:   err.Error(),
			Success: false,
		})
		return
	}

	h.responseWriter.Error500(w, r, ErrServiceError{Operation: operation, Cause: err})
}

func (h *handler) writeGetError(w http.ResponseWriter, r *http.Request, instanceID string, err error) {
	if h.containsAny(err.Error(), "not found") {
		h.responseWriter.Error404(w, r, ErrInstanceNotFound{ID: instanceID})
		return
	}
	h.logger.Errorf("vtpm: failed to get instance id=%s: %v", instanceID, err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: "get", Cause: err})
}

func (h *handler) writeGetByProfileError(w http.ResponseWriter, r *http.Request, profileID uint64, err error) {
	if h.containsAny(err.Error(), "not found", "not associated") {
		h.responseWriter.Error404(w, r, ErrProfileNotFound{ProfileID: profileID})
		return
	}
	h.logger.Errorf("vtpm: failed to get instance by profile_id=%d: %v", profileID, err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: "getByProfile", Cause: err})
}

func (h *handler) writeDeleteError(w http.ResponseWriter, r *http.Request, instanceID string, err error) {
	if h.containsAny(err.Error(), "not found") {
		h.responseWriter.Error404(w, r, ErrInstanceNotFound{ID: instanceID})
		return
	}
	h.logger.Errorf("vtpm: failed to delete instance id=%s: %v", instanceID, err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: "delete", Cause: err})
}

func (h *handler) writeStartError(w http.ResponseWriter, r *http.Request, instanceID string, err error) {
	if h.containsAny(err.Error(), "not found") {
		h.responseWriter.Error404(w, r, ErrInstanceNotFound{ID: instanceID})
		return
	}
	if h.containsAny(err.Error(), "already running") {
		h.responseWriter.Error400(w, r, ErrInstanceAlreadyRunning{ID: instanceID})
		return
	}
	h.logger.Errorf("vtpm: failed to start instance id=%s: %v", instanceID, err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: "start", Cause: err})
}

func (h *handler) writeStopError(w http.ResponseWriter, r *http.Request, instanceID string, err error) {
	if h.containsAny(err.Error(), "not found") {
		h.responseWriter.Error404(w, r, ErrInstanceNotFound{ID: instanceID})
		return
	}
	if h.containsAny(err.Error(), "not running") {
		h.responseWriter.Error400(w, r, ErrInstanceNotRunning{ID: instanceID})
		return
	}
	h.logger.Errorf("vtpm: failed to stop instance id=%s: %v", instanceID, err)
	h.responseWriter.Error500(w, r, ErrServiceError{Operation: "stop", Cause: err})
}

func (h *handler) writeEKExportError(w http.ResponseWriter, r *http.Request, instanceID string, err error) {
	if h.containsAny(err.Error(), "not found") {
		h.responseWriter.Error404(w, r, ErrInstanceNotFound{ID: instanceID})
		return
	}
	h.logger.Errorf("vtpm: failed to export EK certificate for instance id=%s: %v", instanceID, err)
	h.responseWriter.Error500(w, r, ErrEKCertNotAvailable{ID: instanceID})
}

func (h *handler) writeEKFingerprintError(w http.ResponseWriter, r *http.Request, instanceID string, err error) {
	if h.containsAny(err.Error(), "not found") {
		h.responseWriter.Error404(w, r, ErrInstanceNotFound{ID: instanceID})
		return
	}
	h.logger.Errorf("vtpm: failed to get EK fingerprint for instance id=%s: %v", instanceID, err)
	h.responseWriter.Error500(w, r, ErrEKCertNotAvailable{ID: instanceID})
}

func (h *handler) containsAny(s string, substrings ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrings {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}
