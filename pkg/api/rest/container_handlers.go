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

// Package rest provides REST API handlers for the trusted platform services.
package rest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// =============================================================================
// Container REST Handler Errors
// =============================================================================

// ErrContainerOrchestratorNotAvailable is returned when the container orchestrator
// is not configured or unavailable.
type ErrContainerOrchestratorNotAvailable struct{}

func (e ErrContainerOrchestratorNotAvailable) Error() string {
	return "container orchestrator not available"
}

// Note: ErrInvalidContainerID, ErrInvalidRequestBody, ErrMissingRequiredField
// are defined in errors.go

// ErrContainerOperationFailed is returned when a container operation fails.
type ErrContainerOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrContainerOperationFailed) Error() string {
	return fmt.Sprintf("container operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrContainerOperationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Request/Response Types
// =============================================================================

// CreateContainerRequest represents a container creation request.
type CreateContainerRequest struct {
	Name        string            `json:"name"`
	Image       string            `json:"image,omitempty"`
	ProfileID   uint64            `json:"profile_id,omitempty"`
	ProfileName string            `json:"profile_name,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Memory      int               `json:"memory,omitempty"`
	CPUs        int               `json:"cpus,omitempty"`
	NetworkMode string            `json:"network_mode,omitempty"`
}

// ContainerResponse represents a container in API responses.
type ContainerResponse struct {
	ID                 string                      `json:"id"`
	Name               string                      `json:"name"`
	State              string                      `json:"state"`
	Type               string                      `json:"type"`
	Image              string                      `json:"image,omitempty"`
	PID                int                         `json:"pid,omitempty"`
	CreatedAt          time.Time                   `json:"created_at"`
	UpdatedAt          time.Time                   `json:"updated_at"`
	Metadata           map[string]string           `json:"metadata,omitempty"`
	NetworkAttachments []NetworkAttachmentResponse `json:"network_attachments,omitempty"`
}

// NetworkAttachmentResponse represents a network attachment in API responses.
type NetworkAttachmentResponse struct {
	PortName   string    `json:"port_name"`
	BridgeName string    `json:"bridge_name"`
	VLAN       uint16    `json:"vlan,omitempty"`
	MACAddress string    `json:"mac_address,omitempty"`
	IPAddress  string    `json:"ip_address,omitempty"`
	AttachedAt time.Time `json:"attached_at"`
}

// ContainerListResponse represents a list of containers.
type ContainerListResponse struct {
	Containers []ContainerResponse `json:"containers"`
	Count      int                 `json:"count"`
	Timestamp  time.Time           `json:"timestamp"`
}

// ContainerActionResponse represents a container action result.
type ContainerActionResponse struct {
	ContainerID string `json:"container_id"`
	Action      string `json:"action"`
	Success     bool   `json:"success"`
	Message     string `json:"message,omitempty"`
}

// ContainerLogsResponse represents container logs.
type ContainerLogsResponse struct {
	ContainerID string    `json:"container_id"`
	Logs        string    `json:"logs"`
	Timestamp   time.Time `json:"timestamp"`
}

// AttestContainerRequest represents a container attestation request.
type AttestContainerRequest struct {
	Nonce           string `json:"nonce,omitempty"`
	IncludePCRs     []int  `json:"include_pcrs,omitempty"`
	IncludeEventLog bool   `json:"include_event_log,omitempty"`
}

// AttestContainerResponse represents a container attestation response.
type AttestContainerResponse struct {
	ContainerID   string         `json:"container_id"`
	ContainerName string         `json:"container_name"`
	Verified      bool           `json:"verified"`
	Timestamp     time.Time      `json:"timestamp"`
	ImageDigest   string         `json:"image_digest,omitempty"`
	ConfigDigest  string         `json:"config_digest,omitempty"`
	PCRValues     map[int]string `json:"pcr_values,omitempty"`
	Quote         string         `json:"quote,omitempty"`
	Signature     string         `json:"signature,omitempty"`
}

// Note: ErrorResponse is defined in errors.go

// =============================================================================
// Container Handlers
// =============================================================================

// ContainerHandlers provides REST API handlers for container operations.
type ContainerHandlers struct {
	orchestrator ContainerOrchestratorInterface
	logger       *slog.Logger
}

// ContainerOrchestratorInterface defines the interface for container orchestration.
// This allows for both the compute.Orchestrator and container.ContainerOrchestrator
// implementations to be used.
type ContainerOrchestratorInterface interface {
	// Create creates a new container instance
	Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error)

	// Start starts a stopped container
	Start(ctx context.Context, instanceID string) error

	// Stop stops a running container
	Stop(ctx context.Context, instanceID string) error

	// Delete deletes a container
	Delete(ctx context.Context, instanceID string) error

	// List returns all containers
	List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error)

	// Get retrieves a specific container by ID
	Get(ctx context.Context, instanceID string) (*compute.Instance, error)

	// GetState returns the current state of a container
	GetState(ctx context.Context, instanceID string) (compute.InstanceState, error)
}

// ExtendedContainerOrchestrator extends the basic interface with logs and attestation.
type ExtendedContainerOrchestrator interface {
	ContainerOrchestratorInterface

	// Logs returns container logs
	Logs(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error)

	// Attest performs TPM attestation for a container
	Attest(ctx context.Context, id string) (*container.AttestationReport, error)
}

// NewContainerHandlers creates a new ContainerHandlers instance.
// Kept with no caller: it carries the container logs route that #452 owns.
func NewContainerHandlers(orchestrator ContainerOrchestratorInterface, logger *slog.Logger) *ContainerHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &ContainerHandlers{
		orchestrator: orchestrator,
		logger:       logger,
	}
}

// RegisterRoutes registers all container routes on the provided router.
func (h *ContainerHandlers) RegisterRoutes(router *mux.Router) {
	// Container CRUD operations
	router.HandleFunc("/api/v1/containers", h.handleCreateContainer).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/containers", h.handleListContainers).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/containers/{id}", h.handleGetContainer).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/containers/{id}", h.handleRemoveContainer).Methods(http.MethodDelete)

	// Container lifecycle operations
	router.HandleFunc("/api/v1/containers/{id}/start", h.handleStartContainer).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/containers/{id}/stop", h.handleStopContainer).Methods(http.MethodPost)

	// Container logs
	router.HandleFunc("/api/v1/containers/{id}/logs", h.handleGetContainerLogs).Methods(http.MethodGet)

	// Container attestation
	router.HandleFunc("/api/v1/containers/{id}/attest", h.handleAttestContainer).Methods(http.MethodPost)

	// Container operational routes (exec, metrics, attach)
	h.RegisterOpsRoutes(router)

	h.logger.Info("Container REST routes registered")
}

// handleCreateContainer handles POST /api/v1/containers
func (h *ContainerHandlers) handleCreateContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	var req CreateContainerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	// Validate required fields
	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	// Build device profile from request
	profile := h.buildProfileFromRequest(&req)

	instance, err := h.orchestrator.Create(ctx, profile)
	if err != nil {
		h.logger.Error("Failed to create container", "error", err, "name", req.Name)
		h.writeContainerError(w, "create", err)
		return
	}

	resp := h.instanceToResponse(instance)
	h.logger.Info("Container created", "id", instance.ID, "name", instance.Name)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListContainers handles GET /api/v1/containers
func (h *ContainerHandlers) handleListContainers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	// Parse query parameters for filtering
	filter := h.parseListFilter(r)

	instances, err := h.orchestrator.List(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to list containers", "error", err)
		h.writeContainerError(w, "list", err)
		return
	}

	containers := make([]ContainerResponse, 0, len(instances))
	for _, inst := range instances {
		containers = append(containers, h.instanceToResponse(inst))
	}

	resp := ContainerListResponse{
		Containers: containers,
		Count:      len(containers),
		Timestamp:  time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetContainer handles GET /api/v1/containers/{id}
func (h *ContainerHandlers) handleGetContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	instance, err := h.orchestrator.Get(ctx, containerID)
	if err != nil {
		h.logger.Error("Failed to get container", "error", err, "id", containerID)
		h.writeContainerError(w, "get", err)
		return
	}

	resp := h.instanceToResponse(instance)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleStartContainer handles POST /api/v1/containers/{id}/start
func (h *ContainerHandlers) handleStartContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	if err := h.orchestrator.Start(ctx, containerID); err != nil {
		h.logger.Error("Failed to start container", "error", err, "id", containerID)
		h.writeContainerError(w, "start", err)
		return
	}

	resp := ContainerActionResponse{
		ContainerID: containerID,
		Action:      "start",
		Success:     true,
		Message:     "container started successfully",
	}

	h.logger.Info("Container started", "id", containerID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleStopContainer handles POST /api/v1/containers/{id}/stop
func (h *ContainerHandlers) handleStopContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	if err := h.orchestrator.Stop(ctx, containerID); err != nil {
		h.logger.Error("Failed to stop container", "error", err, "id", containerID)
		h.writeContainerError(w, "stop", err)
		return
	}

	resp := ContainerActionResponse{
		ContainerID: containerID,
		Action:      "stop",
		Success:     true,
		Message:     "container stopped successfully",
	}

	h.logger.Info("Container stopped", "id", containerID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleRemoveContainer handles DELETE /api/v1/containers/{id}
func (h *ContainerHandlers) handleRemoveContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	if err := h.orchestrator.Delete(ctx, containerID); err != nil {
		h.logger.Error("Failed to remove container", "error", err, "id", containerID)
		h.writeContainerError(w, "remove", err)
		return
	}

	resp := ContainerActionResponse{
		ContainerID: containerID,
		Action:      "remove",
		Success:     true,
		Message:     "container removed successfully",
	}

	h.logger.Info("Container removed", "id", containerID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetContainerLogs handles GET /api/v1/containers/{id}/logs
func (h *ContainerHandlers) handleGetContainerLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	// Check if orchestrator supports logs
	extOrch, ok := h.orchestrator.(ExtendedContainerOrchestrator)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrContainerOperationFailed{
			Operation: "logs",
			Cause:     errors.New("logs not supported by this orchestrator"),
		})
		return
	}

	// Parse log options from query parameters
	opts := h.parseLogOptions(r)

	// Check for streaming
	follow := r.URL.Query().Get("follow") == "true"
	if follow {
		h.streamContainerLogs(ctx, w, extOrch, containerID, opts)
		return
	}

	// Non-streaming: read all logs and return
	reader, err := extOrch.Logs(ctx, containerID, opts)
	if err != nil {
		h.logger.Error("Failed to get container logs", "error", err, "id", containerID)
		h.writeContainerError(w, "logs", err)
		return
	}
	defer reader.Close()

	logs, err := io.ReadAll(reader)
	if err != nil {
		h.logger.Error("Failed to read container logs", "error", err, "id", containerID)
		h.writeContainerError(w, "logs", err)
		return
	}

	resp := ContainerLogsResponse{
		ContainerID: containerID,
		Logs:        string(logs),
		Timestamp:   time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// streamContainerLogs streams logs using Server-Sent Events.
func (h *ContainerHandlers) streamContainerLogs(ctx context.Context, w http.ResponseWriter, orch ExtendedContainerOrchestrator, containerID string, opts container.LogOptions) {
	opts.Follow = true

	reader, err := orch.Logs(ctx, containerID, opts)
	if err != nil {
		h.logger.Error("Failed to get container logs stream", "error", err, "id", containerID)
		h.writeContainerError(w, "logs", err)
		return
	}
	defer reader.Close()

	// The writer is checked before the SSE headers go out: once a 200 is
	// sent, the refusal below could no longer reach the client as an error.
	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, ErrContainerOperationFailed{
			Operation: "logs",
			Cause:     errors.New("streaming not supported"),
		})
		return
	}

	// Set up SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
			n, err := reader.Read(buf)
			if n > 0 {
				fmt.Fprintf(w, "data: %s\n\n", string(buf[:n]))
				flusher.Flush()
			}
			if err != nil {
				if err == io.EOF {
					fmt.Fprintf(w, "event: end\ndata: stream ended\n\n")
					flusher.Flush()
				}
				return
			}
		}
	}
}

// handleAttestContainer handles POST /api/v1/containers/{id}/attest
func (h *ContainerHandlers) handleAttestContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.orchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	// Check if orchestrator supports attestation
	extOrch, ok := h.orchestrator.(ExtendedContainerOrchestrator)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrContainerOperationFailed{
			Operation: "attest",
			Cause:     errors.New("attestation not supported by this orchestrator"),
		})
		return
	}

	// Parse optional request body
	var req AttestContainerRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	report, err := extOrch.Attest(ctx, containerID)
	if err != nil {
		h.logger.Error("Failed to attest container", "error", err, "id", containerID)
		h.writeContainerError(w, "attest", err)
		return
	}

	resp := h.attestationReportToResponse(report)
	h.logger.Info("Container attested", "id", containerID, "verified", report.Verified)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// buildProfileFromRequest creates a DeviceProfile from a CreateContainerRequest.
func (h *ContainerHandlers) buildProfileFromRequest(req *CreateContainerRequest) *entities.DeviceProfile {
	profile := &entities.DeviceProfile{
		Name: req.Name,
	}

	if req.ProfileID != 0 {
		profile.ID = req.ProfileID
	}

	return profile
}

// parseListFilter parses query parameters into an InstanceFilter.
func (h *ContainerHandlers) parseListFilter(r *http.Request) *compute.InstanceFilter {
	query := r.URL.Query()

	filter := &compute.InstanceFilter{}

	// Filter by state
	if stateStr := query.Get("state"); stateStr != "" {
		state := compute.InstanceState(stateStr)
		if state.IsValid() {
			filter.State = &state
		}
	}

	// Filter by name
	if name := query.Get("name"); name != "" {
		filter.Name = name
	}

	// Filter by type (container only for this handler)
	containerType := compute.ComputeTypeContainer
	filter.Type = &containerType

	return filter
}

// parseLogOptions parses query parameters into LogOptions.
func (h *ContainerHandlers) parseLogOptions(r *http.Request) container.LogOptions {
	query := r.URL.Query()

	opts := container.LogOptions{
		Stdout: true,
		Stderr: true,
	}

	if query.Get("stdout") == "false" {
		opts.Stdout = false
	}
	if query.Get("stderr") == "false" {
		opts.Stderr = false
	}
	if tail := query.Get("tail"); tail != "" {
		opts.Tail = tail
	}
	if query.Get("timestamps") == "true" {
		opts.Timestamps = true
	}
	if since := query.Get("since"); since != "" {
		if t, err := time.Parse(time.RFC3339, since); err == nil {
			opts.Since = t
		}
	}
	if until := query.Get("until"); until != "" {
		if t, err := time.Parse(time.RFC3339, until); err == nil {
			opts.Until = t
		}
	}

	return opts
}

// instanceToResponse converts a compute.Instance to ContainerResponse.
func (h *ContainerHandlers) instanceToResponse(inst *compute.Instance) ContainerResponse {
	resp := ContainerResponse{
		ID:        inst.ID,
		Name:      inst.Name,
		State:     string(inst.State),
		Type:      string(inst.Type),
		PID:       inst.PID,
		CreatedAt: inst.CreatedAt,
		UpdatedAt: inst.UpdatedAt,
		Metadata:  inst.Metadata,
	}

	// Extract image from metadata if available
	if inst.Metadata != nil {
		if image, ok := inst.Metadata["image"]; ok {
			resp.Image = image
		}
	}

	// Convert network attachments
	if len(inst.NetworkAttachments) > 0 {
		resp.NetworkAttachments = make([]NetworkAttachmentResponse, 0, len(inst.NetworkAttachments))
		for _, att := range inst.NetworkAttachments {
			resp.NetworkAttachments = append(resp.NetworkAttachments, NetworkAttachmentResponse{
				PortName:   att.PortName,
				BridgeName: att.BridgeName,
				VLAN:       att.VLAN,
				MACAddress: att.MACAddress,
				IPAddress:  att.IPAddress,
				AttachedAt: att.AttachedAt,
			})
		}
	}

	return resp
}

// attestationReportToResponse converts an AttestationReport to AttestContainerResponse.
func (h *ContainerHandlers) attestationReportToResponse(report *container.AttestationReport) AttestContainerResponse {
	resp := AttestContainerResponse{
		ContainerID:   report.ContainerID,
		ContainerName: report.ContainerName,
		Verified:      report.Verified,
		Timestamp:     report.Timestamp,
	}

	// Already canonical OCI digest strings ("sha256:<64 hex>"); hex
	// encoding them again would emit the hex of their ASCII bytes.
	resp.ImageDigest = report.ImageDigest
	resp.ConfigDigest = report.ConfigDigest
	if len(report.Quote) > 0 {
		resp.Quote = fmt.Sprintf("%x", report.Quote)
	}
	if len(report.Signature) > 0 {
		resp.Signature = fmt.Sprintf("%x", report.Signature)
	}
	if len(report.PCRValues) > 0 {
		resp.PCRValues = make(map[int]string)
		for pcr, value := range report.PCRValues {
			resp.PCRValues[pcr] = fmt.Sprintf("%x", value)
		}
	}

	return resp
}

// writeJSON writes a JSON response.
func (h *ContainerHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *ContainerHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writeContainerError maps container errors to appropriate HTTP status codes.
func (h *ContainerHandlers) writeContainerError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch {
	case errors.Is(err, compute.ErrInstanceNotFound):
		status = http.StatusNotFound
	case errors.Is(err, compute.ErrInstanceAlreadyExists):
		status = http.StatusConflict
	case errors.Is(err, compute.ErrInstanceAlreadyRunning):
		status = http.StatusConflict
	case errors.Is(err, compute.ErrInstanceNotRunning):
		status = http.StatusConflict
	case errors.Is(err, compute.ErrInvalidInstanceID):
		status = http.StatusBadRequest
	case errors.Is(err, compute.ErrInvalidProfile):
		status = http.StatusBadRequest
	case errors.Is(err, compute.ErrInvalidState):
		status = http.StatusConflict
	case errors.Is(err, compute.ErrResourceExhausted):
		status = http.StatusServiceUnavailable
	case errors.Is(err, compute.ErrOrchestratorNotInitialized):
		status = http.StatusServiceUnavailable
	case errors.Is(err, container.ErrContainerNotFound):
		status = http.StatusNotFound
	case errors.Is(err, container.ErrContainerExists):
		status = http.StatusConflict
	case errors.Is(err, container.ErrContainerRunning):
		status = http.StatusConflict
	case errors.Is(err, container.ErrContainerStopped):
		status = http.StatusConflict
	case errors.Is(err, container.ErrAttestationFailed):
		status = http.StatusInternalServerError
	case errors.Is(err, container.ErrPolicyDenied):
		status = http.StatusForbidden
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrContainerOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}

// Note: ParseBoolParam and ParseIntParam are defined in errors.go
