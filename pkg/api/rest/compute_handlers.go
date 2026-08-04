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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// =============================================================================
// Compute REST Handler Errors
// =============================================================================

// ErrVMOrchestratorNotAvailable is returned when the VM orchestrator
// is not configured or unavailable.
type ErrVMOrchestratorNotAvailable struct{}

func (e ErrVMOrchestratorNotAvailable) Error() string {
	return "VM orchestrator not available"
}

// ErrInvalidComputeVMID is returned when a VM ID is invalid or empty.
type ErrInvalidComputeVMID struct {
	ID string
}

func (e ErrInvalidComputeVMID) Error() string {
	if e.ID == "" {
		return "VM ID is required"
	}
	return fmt.Sprintf("invalid VM ID: %s", e.ID)
}

// ErrVMOperationFailed is returned when a VM operation fails.
type ErrVMOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrVMOperationFailed) Error() string {
	return fmt.Sprintf("VM operation %s failed: %v", e.Operation, e.Cause)
}

func (e ErrVMOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrComputeOperationNotSupported is returned when a compute operation is not
// supported by the orchestrator.
type ErrComputeOperationNotSupported struct {
	Operation string
}

func (e ErrComputeOperationNotSupported) Error() string {
	return fmt.Sprintf("compute operation %s not supported", e.Operation)
}

// =============================================================================
// VM Request/Response Types
// =============================================================================

// CreateVMRequest represents a VM creation request.
type CreateVMRequest struct {
	Name        string            `json:"name"`
	ProfileID   uint64            `json:"profile_id,omitempty"`
	ProfileName string            `json:"profile_name,omitempty"`
	Memory      int               `json:"memory,omitempty"`
	CPUs        int               `json:"cpus,omitempty"`
	DiskSize    string            `json:"disk_size,omitempty"`
	ISOPath     string            `json:"iso_path,omitempty"`
	BootMode    string            `json:"boot_mode,omitempty"`
	EnableKVM   bool              `json:"enable_kvm,omitempty"`
	SecureBoot  bool              `json:"secure_boot,omitempty"`
	TPMEnabled  bool              `json:"tpm_enabled,omitempty"`
	Environment map[string]string `json:"environment,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	NetworkMode string            `json:"network_mode,omitempty"`
}

// VMResponse represents a VM in API responses.
type VMResponse struct {
	ID                 string                      `json:"id"`
	Name               string                      `json:"name"`
	State              string                      `json:"state"`
	Type               string                      `json:"type"`
	PID                int                         `json:"pid,omitempty"`
	Memory             int                         `json:"memory,omitempty"`
	CPUs               int                         `json:"cpus,omitempty"`
	DiskPath           string                      `json:"disk_path,omitempty"`
	DiskSize           string                      `json:"disk_size,omitempty"`
	BootMode           string                      `json:"boot_mode,omitempty"`
	SecureBoot         bool                        `json:"secure_boot,omitempty"`
	TPMEnabled         bool                        `json:"tpm_enabled,omitempty"`
	CreatedAt          time.Time                   `json:"created_at"`
	UpdatedAt          time.Time                   `json:"updated_at"`
	Metadata           map[string]string           `json:"metadata,omitempty"`
	NetworkAttachments []NetworkAttachmentResponse `json:"network_attachments,omitempty"`
}

// VMListResponse represents a list of VMs.
type VMListResponse struct {
	VMs       []VMResponse `json:"vms"`
	Count     int          `json:"count"`
	Timestamp time.Time    `json:"timestamp"`
}

// VMActionResponse represents a VM action result.
type VMActionResponse struct {
	VMID    string `json:"vm_id"`
	Action  string `json:"action"`
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// VMConsoleResponse represents VM console information.
type VMConsoleResponse struct {
	VMID     string `json:"vm_id"`
	Type     string `json:"type"`
	Address  string `json:"address,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// AttestVMRequest represents a VM attestation request.
type AttestVMRequest struct {
	Nonce           string `json:"nonce,omitempty"`
	IncludePCRs     []int  `json:"include_pcrs,omitempty"`
	IncludeEventLog bool   `json:"include_event_log,omitempty"`
}

// AttestVMResponse represents a VM attestation response. Binary fields are
// hex encoded.
type AttestVMResponse struct {
	VMID      string         `json:"vm_id"`
	VMName    string         `json:"vm_name"`
	Verified  bool           `json:"verified"`
	Timestamp time.Time      `json:"timestamp"`
	Nonce     string         `json:"nonce,omitempty"`
	PCRValues map[int]string `json:"pcr_values,omitempty"`
	Quote     string         `json:"quote,omitempty"`
	Signature string         `json:"signature,omitempty"`
	EventLog  string         `json:"event_log,omitempty"`
	AKPublic  string         `json:"ak_public,omitempty"`
}

// VerifyVMAttestationRequest carries VM attestation evidence for
// verification. Binary fields are base64 (standard) encoded.
type VerifyVMAttestationRequest struct {
	Quote        string         `json:"quote"`
	Signature    string         `json:"signature"`
	Nonce        string         `json:"nonce"`
	ExpectedPCRs map[int]string `json:"expected_pcrs,omitempty"`
}

// VerifyVMAttestationResponse reports the attestation verification outcome.
// PCR values are hex encoded.
type VerifyVMAttestationResponse struct {
	VMID           string         `json:"vm_id"`
	Verified       bool           `json:"verified"`
	SignatureValid bool           `json:"signature_valid"`
	NonceValid     bool           `json:"nonce_valid"`
	PCRsValid      bool           `json:"pcrs_valid"`
	Message        string         `json:"message,omitempty"`
	ActualPCRs     map[int]string `json:"actual_pcrs,omitempty"`
	Timestamp      time.Time      `json:"timestamp"`
}

// =============================================================================
// Compute Container Request/Response Types (extending existing)
// =============================================================================

// ComputeContainerResponse extends ContainerResponse for compute endpoints.
type ComputeContainerResponse struct {
	ID                 string                      `json:"id"`
	Name               string                      `json:"name"`
	State              string                      `json:"state"`
	Type               string                      `json:"type"`
	Image              string                      `json:"image,omitempty"`
	ImageID            string                      `json:"image_id,omitempty"`
	PID                int                         `json:"pid,omitempty"`
	ExitCode           int                         `json:"exit_code,omitempty"`
	CreatedAt          time.Time                   `json:"created_at"`
	StartedAt          time.Time                   `json:"started_at,omitempty"`
	FinishedAt         time.Time                   `json:"finished_at,omitempty"`
	Labels             map[string]string           `json:"labels,omitempty"`
	NetworkAttachments []NetworkAttachmentResponse `json:"network_attachments,omitempty"`
	Platform           string                      `json:"platform,omitempty"`
}

// ComputeContainerListResponse represents a list of containers.
type ComputeContainerListResponse struct {
	Containers []ComputeContainerResponse `json:"containers"`
	Count      int                        `json:"count"`
	Timestamp  time.Time                  `json:"timestamp"`
}

// CreateComputeContainerRequest represents a container creation request via compute API.
type CreateComputeContainerRequest struct {
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	Command       []string          `json:"command,omitempty"`
	Args          []string          `json:"args,omitempty"`
	Environment   map[string]string `json:"environment,omitempty"`
	Labels        map[string]string `json:"labels,omitempty"`
	WorkingDir    string            `json:"working_dir,omitempty"`
	User          string            `json:"user,omitempty"`
	Privileged    bool              `json:"privileged,omitempty"`
	NetworkMode   string            `json:"network_mode,omitempty"`
	Mounts        []MountRequest    `json:"mounts,omitempty"`
	Ports         []PortRequest     `json:"ports,omitempty"`
	RestartPolicy string            `json:"restart_policy,omitempty"`
	CPULimit      string            `json:"cpu_limit,omitempty"`
	MemoryLimit   string            `json:"memory_limit,omitempty"`
	CapAdd        []string          `json:"cap_add,omitempty"`
	CapDrop       []string          `json:"cap_drop,omitempty"`
	Start         bool              `json:"start,omitempty"`
}

// MountRequest represents a mount configuration in requests.
type MountRequest struct {
	Source   string `json:"source"`
	Target   string `json:"target"`
	Type     string `json:"type,omitempty"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// PortRequest represents a port mapping in requests.
type PortRequest struct {
	HostIP        string `json:"host_ip,omitempty"`
	HostPort      uint16 `json:"host_port"`
	ContainerPort uint16 `json:"container_port"`
	Protocol      string `json:"protocol,omitempty"`
}

// StopContainerRequest represents a container stop request.
type StopContainerRequest struct {
	Timeout int `json:"timeout,omitempty"`
}

// ContainerExecRequest represents a container exec request.
type ContainerExecRequest struct {
	Command     []string `json:"command"`
	Environment []string `json:"environment,omitempty"`
	WorkingDir  string   `json:"working_dir,omitempty"`
	User        string   `json:"user,omitempty"`
	Tty         bool     `json:"tty,omitempty"`
	Stdin       bool     `json:"stdin,omitempty"`
}

// ContainerExecResponse represents a container exec response.
type ContainerExecResponse struct {
	ContainerID string `json:"container_id"`
	ExecID      string `json:"exec_id,omitempty"`
	ExitCode    int    `json:"exit_code,omitempty"`
	Output      string `json:"output,omitempty"`
}

// =============================================================================
// Orchestrator Interfaces
// =============================================================================

// VMOrchestrator defines the interface for VM orchestration.
type VMOrchestrator interface {
	// Create creates a new VM instance from a device profile
	Create(ctx context.Context, profile *entities.DeviceProfile) (*compute.Instance, error)

	// Start starts a stopped VM
	Start(ctx context.Context, instanceID string) error

	// Stop stops a running VM
	Stop(ctx context.Context, instanceID string) error

	// Delete deletes a VM
	Delete(ctx context.Context, instanceID string) error

	// List returns all VMs
	List(ctx context.Context, filter *compute.InstanceFilter) ([]*compute.Instance, error)

	// Get retrieves a specific VM by ID
	Get(ctx context.Context, instanceID string) (*compute.Instance, error)

	// GetState returns the current state of a VM
	GetState(ctx context.Context, instanceID string) (compute.InstanceState, error)
}

// VMExtendedLifecycle groups the extended lifecycle operations (suspend /
// resume / restart / console) that are not yet provided by any production
// orchestrator. Handlers type-assert this interface so the operations fail
// gracefully with 501 until an orchestrator implements them.
type VMExtendedLifecycle interface {
	// Suspend suspends a running VM
	Suspend(ctx context.Context, instanceID string) error

	// Resume resumes a suspended VM
	Resume(ctx context.Context, instanceID string) error

	// Restart restarts a VM
	Restart(ctx context.Context, instanceID string) error

	// GetConsole returns console access information for a VM
	GetConsole(ctx context.Context, instanceID string) (*VMConsoleInfo, error)
}

// ExtendedVMOrchestrator composes the full extended VM capability set. The
// snapshot and attestation capabilities are the canonical pkg/compute
// interfaces (compute.VMSnapshotter / compute.VMAttester); handlers assert
// each capability individually so partially-capable orchestrators (such as
// compute.QEMUOrchestrator) expose exactly what they support.
type ExtendedVMOrchestrator interface {
	VMOrchestrator
	VMExtendedLifecycle
	compute.VMSnapshotter
	compute.VMAttester
}

// VMConsoleInfo contains console access information.
type VMConsoleInfo struct {
	Type     string `json:"type"`
	Address  string `json:"address,omitempty"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// VMAttestationReport is the canonical compute attestation report.
type VMAttestationReport = compute.VMAttestationReport

// ComputeContainerOrchestrator defines the interface for container orchestration
// via the compute API.
type ComputeContainerOrchestrator interface {
	// Create creates a new container
	Create(ctx context.Context, spec *container.OrchestratorContainerSpec) (*container.Container, error)

	// Start starts a stopped container
	Start(ctx context.Context, id string) error

	// Stop stops a running container
	Stop(ctx context.Context, id string, timeout time.Duration) error

	// Remove removes a container
	Remove(ctx context.Context, id string, force bool) error

	// Get retrieves a container by ID
	Get(ctx context.Context, id string) (*container.Container, error)

	// List returns containers matching the filter options
	List(ctx context.Context, opts container.ListOptions) ([]*container.Container, error)

	// Logs returns container logs
	Logs(ctx context.Context, id string, opts container.LogOptions) (io.ReadCloser, error)

	// Attest performs TPM attestation for a container
	Attest(ctx context.Context, id string) (*container.AttestationReport, error)

	// Exec executes a command in a running container
	Exec(ctx context.Context, id string, cmd []string, opts ExecOptions) (*ExecResult, error)
}

// ExecOptions contains options for container exec.
type ExecOptions struct {
	Env        []string
	WorkingDir string
	User       string
	Tty        bool
	Stdin      bool
}

// ExecResult contains the result of a container exec.
type ExecResult struct {
	ExitCode int
	Output   []byte
}

// =============================================================================
// Compute Handlers
// =============================================================================

// ComputeHandlers provides REST API handlers for compute operations (VMs and Containers).
type ComputeHandlers struct {
	vmOrchestrator        VMOrchestrator
	containerOrchestrator ComputeContainerOrchestrator
	logger                *slog.Logger
}

// NewComputeHandlers creates a new ComputeHandlers instance.
func NewComputeHandlers(
	vmOrch VMOrchestrator,
	containerOrch ComputeContainerOrchestrator,
	logger *slog.Logger,
) *ComputeHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	return &ComputeHandlers{
		vmOrchestrator:        vmOrch,
		containerOrchestrator: containerOrch,
		logger:                logger,
	}
}

// RegisterRoutes registers all compute routes on the provided router.
func (h *ComputeHandlers) RegisterRoutes(router *mux.Router) {
	// VM endpoints
	router.HandleFunc("/api/v1/compute/vms", h.handleCreateVM).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/vms", h.handleListVMs).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/compute/vms/{id}", h.handleGetVM).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/compute/vms/{id}", h.handleDeleteVM).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/compute/vms/{id}/start", h.handleStartVM).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/vms/{id}/stop", h.handleStopVM).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/vms/{id}/restart", h.handleRestartVM).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/vms/{id}/suspend", h.handleSuspendVM).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/vms/{id}/resume", h.handleResumeVM).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/vms/{id}/attest", h.handleAttestVM).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/vms/{id}/attest/verify", h.handleVerifyVMAttestation).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/vms/{id}/console", h.handleGetVMConsole).Methods(http.MethodGet)

	// Container endpoints
	router.HandleFunc("/api/v1/compute/containers", h.handleCreateComputeContainer).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/containers", h.handleListComputeContainers).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/compute/containers/{id}", h.handleGetComputeContainer).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/compute/containers/{id}", h.handleDeleteComputeContainer).Methods(http.MethodDelete)
	router.HandleFunc("/api/v1/compute/containers/{id}/start", h.handleStartComputeContainer).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/containers/{id}/stop", h.handleStopComputeContainer).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/containers/{id}/logs", h.handleGetComputeContainerLogs).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/compute/containers/{id}/exec", h.handleExecComputeContainer).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/compute/containers/{id}/attest", h.handleAttestComputeContainer).Methods(http.MethodPost)

	h.logger.Info("Compute REST routes registered",
		"vm_endpoints", 12,
		"container_endpoints", 9,
	)
}

// =============================================================================
// VM Handlers
// =============================================================================

// handleCreateVM handles POST /api/v1/compute/vms
func (h *ComputeHandlers) handleCreateVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	var req CreateVMRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	profile := h.buildVMProfileFromRequest(&req)

	instance, err := h.vmOrchestrator.Create(ctx, profile)
	if err != nil {
		h.logger.Error("Failed to create VM", "error", err, "name", req.Name)
		h.writeVMError(w, "create", err)
		return
	}

	resp := h.instanceToVMResponse(instance)
	h.logger.Info("VM created", "id", instance.ID, "name", instance.Name)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListVMs handles GET /api/v1/compute/vms
func (h *ComputeHandlers) handleListVMs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	filter := h.parseVMListFilter(r)

	instances, err := h.vmOrchestrator.List(ctx, filter)
	if err != nil {
		h.logger.Error("Failed to list VMs", "error", err)
		h.writeVMError(w, "list", err)
		return
	}

	vms := make([]VMResponse, 0, len(instances))
	for _, inst := range instances {
		vms = append(vms, h.instanceToVMResponse(inst))
	}

	resp := VMListResponse{
		VMs:       vms,
		Count:     len(vms),
		Timestamp: time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetVM handles GET /api/v1/compute/vms/{id}
func (h *ComputeHandlers) handleGetVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidComputeVMID{})
		return
	}

	instance, err := h.vmOrchestrator.Get(ctx, vmID)
	if err != nil {
		h.logger.Error("Failed to get VM", "error", err, "id", vmID)
		h.writeVMError(w, "get", err)
		return
	}

	resp := h.instanceToVMResponse(instance)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteVM handles DELETE /api/v1/compute/vms/{id}
func (h *ComputeHandlers) handleDeleteVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidComputeVMID{})
		return
	}

	if err := h.vmOrchestrator.Delete(ctx, vmID); err != nil {
		h.logger.Error("Failed to delete VM", "error", err, "id", vmID)
		h.writeVMError(w, "delete", err)
		return
	}

	resp := VMActionResponse{
		VMID:    vmID,
		Action:  "delete",
		Success: true,
		Message: "VM deleted successfully",
	}

	h.logger.Info("VM deleted", "id", vmID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleStartVM handles POST /api/v1/compute/vms/{id}/start
func (h *ComputeHandlers) handleStartVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidComputeVMID{})
		return
	}

	if err := h.vmOrchestrator.Start(ctx, vmID); err != nil {
		h.logger.Error("Failed to start VM", "error", err, "id", vmID)
		h.writeVMError(w, "start", err)
		return
	}

	resp := VMActionResponse{
		VMID:    vmID,
		Action:  "start",
		Success: true,
		Message: "VM started successfully",
	}

	h.logger.Info("VM started", "id", vmID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleStopVM handles POST /api/v1/compute/vms/{id}/stop
func (h *ComputeHandlers) handleStopVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidComputeVMID{})
		return
	}

	if err := h.vmOrchestrator.Stop(ctx, vmID); err != nil {
		h.logger.Error("Failed to stop VM", "error", err, "id", vmID)
		h.writeVMError(w, "stop", err)
		return
	}

	resp := VMActionResponse{
		VMID:    vmID,
		Action:  "stop",
		Success: true,
		Message: "VM stopped successfully",
	}

	h.logger.Info("VM stopped", "id", vmID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleRestartVM handles POST /api/v1/compute/vms/{id}/restart
func (h *ComputeHandlers) handleRestartVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidComputeVMID{})
		return
	}

	extOrch, ok := h.vmOrchestrator.(VMExtendedLifecycle)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrComputeOperationNotSupported{Operation: "restart"})
		return
	}

	if err := extOrch.Restart(ctx, vmID); err != nil {
		h.logger.Error("Failed to restart VM", "error", err, "id", vmID)
		h.writeVMError(w, "restart", err)
		return
	}

	resp := VMActionResponse{
		VMID:    vmID,
		Action:  "restart",
		Success: true,
		Message: "VM restarted successfully",
	}

	h.logger.Info("VM restarted", "id", vmID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleSuspendVM handles POST /api/v1/compute/vms/{id}/suspend
func (h *ComputeHandlers) handleSuspendVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidComputeVMID{})
		return
	}

	extOrch, ok := h.vmOrchestrator.(VMExtendedLifecycle)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrComputeOperationNotSupported{Operation: "suspend"})
		return
	}

	if err := extOrch.Suspend(ctx, vmID); err != nil {
		h.logger.Error("Failed to suspend VM", "error", err, "id", vmID)
		h.writeVMError(w, "suspend", err)
		return
	}

	resp := VMActionResponse{
		VMID:    vmID,
		Action:  "suspend",
		Success: true,
		Message: "VM suspended successfully",
	}

	h.logger.Info("VM suspended", "id", vmID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleResumeVM handles POST /api/v1/compute/vms/{id}/resume
func (h *ComputeHandlers) handleResumeVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidComputeVMID{})
		return
	}

	extOrch, ok := h.vmOrchestrator.(VMExtendedLifecycle)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrComputeOperationNotSupported{Operation: "resume"})
		return
	}

	if err := extOrch.Resume(ctx, vmID); err != nil {
		h.logger.Error("Failed to resume VM", "error", err, "id", vmID)
		h.writeVMError(w, "resume", err)
		return
	}

	resp := VMActionResponse{
		VMID:    vmID,
		Action:  "resume",
		Success: true,
		Message: "VM resumed successfully",
	}

	h.logger.Info("VM resumed", "id", vmID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleAttestVM handles POST /api/v1/compute/vms/{id}/attest
func (h *ComputeHandlers) handleAttestVM(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidComputeVMID{})
		return
	}

	attester, ok := h.vmOrchestrator.(compute.VMAttester)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrComputeOperationNotSupported{Operation: "attest"})
		return
	}

	// Parse optional request body
	var req AttestVMRequest
	if r.Body != nil && r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
			return
		}
	}

	var nonce []byte
	if req.Nonce != "" {
		decoded, err := base64.StdEncoding.DecodeString(req.Nonce)
		if err != nil {
			h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: "nonce must be base64 encoded: " + err.Error()})
			return
		}
		nonce = decoded
	}

	report, err := attester.AttestVM(ctx, vmID, nonce, req.IncludePCRs)
	if err != nil {
		h.logger.Error("Failed to attest VM", "error", err, "id", vmID)
		h.writeVMError(w, "attest", err)
		return
	}

	resp := h.attestationReportToVMResponse(report)
	h.logger.Info("VM attested", "id", vmID, "verified", report.Verified)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetVMConsole handles GET /api/v1/compute/vms/{id}/console
func (h *ComputeHandlers) handleGetVMConsole(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidComputeVMID{})
		return
	}

	extOrch, ok := h.vmOrchestrator.(VMExtendedLifecycle)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrComputeOperationNotSupported{Operation: "console"})
		return
	}

	consoleInfo, err := extOrch.GetConsole(ctx, vmID)
	if err != nil {
		h.logger.Error("Failed to get VM console", "error", err, "id", vmID)
		h.writeVMError(w, "console", err)
		return
	}

	resp := VMConsoleResponse{
		VMID:     vmID,
		Type:     consoleInfo.Type,
		Address:  consoleInfo.Address,
		Port:     consoleInfo.Port,
		Protocol: consoleInfo.Protocol,
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleVerifyVMAttestation handles POST /api/v1/compute/vms/{id}/attest/verify
func (h *ComputeHandlers) handleVerifyVMAttestation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.vmOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrVMOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	vmID := vars["id"]
	if vmID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidComputeVMID{})
		return
	}

	attester, ok := h.vmOrchestrator.(compute.VMAttester)
	if !ok {
		h.writeError(w, http.StatusNotImplemented, ErrComputeOperationNotSupported{Operation: "attest-verify"})
		return
	}

	var req VerifyVMAttestationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	evidence, err := h.verifyRequestToEvidence(&req)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	result, err := attester.VerifyVMAttestation(ctx, vmID, evidence)
	if err != nil {
		h.logger.Error("Failed to verify VM attestation", "error", err, "id", vmID)
		h.writeVMError(w, "attest-verify", err)
		return
	}

	resp := VerifyVMAttestationResponse{
		VMID:           vmID,
		Verified:       result.Verified,
		SignatureValid: result.SignatureValid,
		NonceValid:     result.NonceValid,
		PCRsValid:      result.PCRsValid,
		Message:        result.Message,
		Timestamp:      time.Now().UTC(),
	}
	if len(result.ActualPCRs) > 0 {
		resp.ActualPCRs = make(map[int]string, len(result.ActualPCRs))
		for pcr, value := range result.ActualPCRs {
			resp.ActualPCRs[pcr] = fmt.Sprintf("%x", value)
		}
	}

	h.logger.Info("VM attestation verified", "id", vmID, "verified", result.Verified)
	h.writeJSON(w, http.StatusOK, resp)
}

// verifyRequestToEvidence decodes the base64 evidence fields of a
// VerifyVMAttestationRequest into canonical compute evidence.
func (h *ComputeHandlers) verifyRequestToEvidence(req *VerifyVMAttestationRequest) (*compute.VMAttestationEvidence, error) {
	quote, err := base64.StdEncoding.DecodeString(req.Quote)
	if err != nil {
		return nil, fmt.Errorf("quote must be base64 encoded: %w", err)
	}
	signature, err := base64.StdEncoding.DecodeString(req.Signature)
	if err != nil {
		return nil, fmt.Errorf("signature must be base64 encoded: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(req.Nonce)
	if err != nil {
		return nil, fmt.Errorf("nonce must be base64 encoded: %w", err)
	}

	evidence := &compute.VMAttestationEvidence{
		Quote:     quote,
		Signature: signature,
		Nonce:     nonce,
	}
	if len(req.ExpectedPCRs) > 0 {
		evidence.ExpectedPCRs = make(map[int][]byte, len(req.ExpectedPCRs))
		for pcr, encoded := range req.ExpectedPCRs {
			value, err := base64.StdEncoding.DecodeString(encoded)
			if err != nil {
				return nil, fmt.Errorf("expected PCR %d must be base64 encoded: %w", pcr, err)
			}
			evidence.ExpectedPCRs[pcr] = value
		}
	}

	return evidence, nil
}

// =============================================================================
// Container Handlers
// =============================================================================

// handleCreateComputeContainer handles POST /api/v1/compute/containers
func (h *ComputeHandlers) handleCreateComputeContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.containerOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	var req CreateComputeContainerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if req.Name == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "name"})
		return
	}

	if req.Image == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "image"})
		return
	}

	spec := h.buildContainerSpecFromRequest(&req)

	containerObj, err := h.containerOrchestrator.Create(ctx, spec)
	if err != nil {
		h.logger.Error("Failed to create container", "error", err, "name", req.Name)
		h.writeContainerComputeError(w, "create", err)
		return
	}

	// Start container if requested
	if req.Start {
		if err := h.containerOrchestrator.Start(ctx, containerObj.ID); err != nil {
			h.logger.Warn("Failed to start container after creation",
				"error", err, "id", containerObj.ID)
		} else {
			containerObj, _ = h.containerOrchestrator.Get(ctx, containerObj.ID)
		}
	}

	resp := h.containerToComputeResponse(containerObj)
	h.logger.Info("Container created", "id", containerObj.ID, "name", containerObj.Name)
	h.writeJSON(w, http.StatusCreated, resp)
}

// handleListComputeContainers handles GET /api/v1/compute/containers
func (h *ComputeHandlers) handleListComputeContainers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.containerOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	opts := h.parseContainerListOptions(r)

	containers, err := h.containerOrchestrator.List(ctx, opts)
	if err != nil {
		h.logger.Error("Failed to list containers", "error", err)
		h.writeContainerComputeError(w, "list", err)
		return
	}

	containerResponses := make([]ComputeContainerResponse, 0, len(containers))
	for _, c := range containers {
		containerResponses = append(containerResponses, h.containerToComputeResponse(c))
	}

	resp := ComputeContainerListResponse{
		Containers: containerResponses,
		Count:      len(containerResponses),
		Timestamp:  time.Now().UTC(),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleGetComputeContainer handles GET /api/v1/compute/containers/{id}
func (h *ComputeHandlers) handleGetComputeContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.containerOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	containerObj, err := h.containerOrchestrator.Get(ctx, containerID)
	if err != nil {
		h.logger.Error("Failed to get container", "error", err, "id", containerID)
		h.writeContainerComputeError(w, "get", err)
		return
	}

	resp := h.containerToComputeResponse(containerObj)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleDeleteComputeContainer handles DELETE /api/v1/compute/containers/{id}
func (h *ComputeHandlers) handleDeleteComputeContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.containerOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	// Check for force flag
	force := r.URL.Query().Get("force") == "true"

	if err := h.containerOrchestrator.Remove(ctx, containerID, force); err != nil {
		h.logger.Error("Failed to delete container", "error", err, "id", containerID)
		h.writeContainerComputeError(w, "delete", err)
		return
	}

	resp := ContainerActionResponse{
		ContainerID: containerID,
		Action:      "delete",
		Success:     true,
		Message:     "container deleted successfully",
	}

	h.logger.Info("Container deleted", "id", containerID)
	h.writeJSON(w, http.StatusOK, resp)
}

// handleStartComputeContainer handles POST /api/v1/compute/containers/{id}/start
func (h *ComputeHandlers) handleStartComputeContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.containerOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	if err := h.containerOrchestrator.Start(ctx, containerID); err != nil {
		h.logger.Error("Failed to start container", "error", err, "id", containerID)
		h.writeContainerComputeError(w, "start", err)
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

// handleStopComputeContainer handles POST /api/v1/compute/containers/{id}/stop
func (h *ComputeHandlers) handleStopComputeContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.containerOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	// Parse optional stop request
	timeout := 30 * time.Second
	if r.Body != nil && r.ContentLength > 0 {
		var req StopContainerRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err == nil && req.Timeout > 0 {
			timeout = time.Duration(req.Timeout) * time.Second
		}
	}

	if err := h.containerOrchestrator.Stop(ctx, containerID, timeout); err != nil {
		h.logger.Error("Failed to stop container", "error", err, "id", containerID)
		h.writeContainerComputeError(w, "stop", err)
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

// handleGetComputeContainerLogs handles GET /api/v1/compute/containers/{id}/logs
func (h *ComputeHandlers) handleGetComputeContainerLogs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.containerOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	opts := h.parseLogOptions(r)
	follow := r.URL.Query().Get("follow") == "true"

	if follow {
		h.streamContainerLogs(ctx, w, containerID, opts)
		return
	}

	reader, err := h.containerOrchestrator.Logs(ctx, containerID, opts)
	if err != nil {
		h.logger.Error("Failed to get container logs", "error", err, "id", containerID)
		h.writeContainerComputeError(w, "logs", err)
		return
	}
	defer reader.Close()

	logs, err := io.ReadAll(reader)
	if err != nil {
		h.logger.Error("Failed to read container logs", "error", err, "id", containerID)
		h.writeContainerComputeError(w, "logs", err)
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
func (h *ComputeHandlers) streamContainerLogs(ctx context.Context, w http.ResponseWriter, containerID string, opts container.LogOptions) {
	opts.Follow = true

	reader, err := h.containerOrchestrator.Logs(ctx, containerID, opts)
	if err != nil {
		h.logger.Error("Failed to get container logs stream", "error", err, "id", containerID)
		h.writeContainerComputeError(w, "logs", err)
		return
	}
	defer reader.Close()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	flusher, ok := w.(http.Flusher)
	if !ok {
		h.writeError(w, http.StatusInternalServerError, ErrContainerOperationFailed{
			Operation: "logs",
			Cause:     errors.New("streaming not supported"),
		})
		return
	}

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

// handleExecComputeContainer handles POST /api/v1/compute/containers/{id}/exec
func (h *ComputeHandlers) handleExecComputeContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.containerOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
		return
	}

	var req ContainerExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}

	if len(req.Command) == 0 {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "command"})
		return
	}

	opts := ExecOptions{
		Env:        req.Environment,
		WorkingDir: req.WorkingDir,
		User:       req.User,
		Tty:        req.Tty,
		Stdin:      req.Stdin,
	}

	result, err := h.containerOrchestrator.Exec(ctx, containerID, req.Command, opts)
	if err != nil {
		h.logger.Error("Failed to exec in container", "error", err, "id", containerID)
		h.writeContainerComputeError(w, "exec", err)
		return
	}

	resp := ContainerExecResponse{
		ContainerID: containerID,
		ExitCode:    result.ExitCode,
		Output:      string(result.Output),
	}

	h.writeJSON(w, http.StatusOK, resp)
}

// handleAttestComputeContainer handles POST /api/v1/compute/containers/{id}/attest
func (h *ComputeHandlers) handleAttestComputeContainer(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if h.containerOrchestrator == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrContainerOrchestratorNotAvailable{})
		return
	}

	vars := mux.Vars(r)
	containerID := vars["id"]
	if containerID == "" {
		h.writeError(w, http.StatusBadRequest, ErrInvalidContainerID{})
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

	report, err := h.containerOrchestrator.Attest(ctx, containerID)
	if err != nil {
		h.logger.Error("Failed to attest container", "error", err, "id", containerID)
		h.writeContainerComputeError(w, "attest", err)
		return
	}

	resp := h.attestationReportToContainerResponse(report)
	h.logger.Info("Container attested", "id", containerID, "verified", report.Verified)
	h.writeJSON(w, http.StatusOK, resp)
}

// =============================================================================
// Helper Methods
// =============================================================================

// buildVMProfileFromRequest creates a DeviceProfile from a CreateVMRequest.
func (h *ComputeHandlers) buildVMProfileFromRequest(req *CreateVMRequest) *entities.DeviceProfile {
	profile := &entities.DeviceProfile{
		Name: req.Name,
	}

	if req.ProfileID != 0 {
		profile.ID = req.ProfileID
	}

	return profile
}

// parseVMListFilter parses query parameters into an InstanceFilter.
func (h *ComputeHandlers) parseVMListFilter(r *http.Request) *compute.InstanceFilter {
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

	// Filter by type (VM only for this handler)
	vmType := compute.ComputeTypeVM
	filter.Type = &vmType

	return filter
}

// instanceToVMResponse converts a compute.Instance to VMResponse.
func (h *ComputeHandlers) instanceToVMResponse(inst *compute.Instance) VMResponse {
	resp := VMResponse{
		ID:        inst.ID,
		Name:      inst.Name,
		State:     string(inst.State),
		Type:      string(inst.Type),
		PID:       inst.PID,
		CreatedAt: inst.CreatedAt,
		UpdatedAt: inst.UpdatedAt,
		Metadata:  inst.Metadata,
	}

	// Extract config fields if available
	if inst.Config != nil {
		resp.Memory = inst.Config.Memory
		resp.CPUs = inst.Config.CPUs
		resp.DiskPath = inst.Config.DiskPath
		resp.DiskSize = inst.Config.DiskSize
		resp.BootMode = inst.Config.BootMode
		resp.SecureBoot = inst.Config.SecureBoot
		resp.TPMEnabled = inst.Config.TPMEnabled
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

// attestationReportToVMResponse converts a VMAttestationReport to AttestVMResponse.
func (h *ComputeHandlers) attestationReportToVMResponse(report *VMAttestationReport) AttestVMResponse {
	resp := AttestVMResponse{
		VMID:      report.VMID,
		VMName:    report.VMName,
		Verified:  report.Verified,
		Timestamp: report.Timestamp,
	}

	if len(report.Nonce) > 0 {
		resp.Nonce = fmt.Sprintf("%x", report.Nonce)
	}
	if len(report.Quote) > 0 {
		resp.Quote = fmt.Sprintf("%x", report.Quote)
	}
	if len(report.Signature) > 0 {
		resp.Signature = fmt.Sprintf("%x", report.Signature)
	}
	if len(report.EventLog) > 0 {
		resp.EventLog = fmt.Sprintf("%x", report.EventLog)
	}
	if len(report.AKPublicKey) > 0 {
		resp.AKPublic = fmt.Sprintf("%x", report.AKPublicKey)
	}
	if len(report.PCRValues) > 0 {
		resp.PCRValues = make(map[int]string)
		for pcr, value := range report.PCRValues {
			resp.PCRValues[pcr] = fmt.Sprintf("%x", value)
		}
	}

	return resp
}

// buildContainerSpecFromRequest creates an OrchestratorContainerSpec from a CreateComputeContainerRequest.
func (h *ComputeHandlers) buildContainerSpecFromRequest(req *CreateComputeContainerRequest) *container.OrchestratorContainerSpec {
	spec := &container.OrchestratorContainerSpec{
		Name:       req.Name,
		Image:      req.Image,
		Command:    req.Command,
		Args:       req.Args,
		Env:        req.Environment,
		Labels:     req.Labels,
		User:       req.User,
		WorkingDir: req.WorkingDir,
		Privileged: req.Privileged,
	}

	// Set network mode
	if req.NetworkMode != "" {
		spec.Network = container.ContainerNetworkConfig{
			Mode: container.NetworkMode(req.NetworkMode),
		}
	}

	// Convert mounts
	if len(req.Mounts) > 0 {
		spec.Mounts = make([]container.MountConfig, len(req.Mounts))
		for i, m := range req.Mounts {
			spec.Mounts[i] = container.MountConfig{
				Source:   m.Source,
				Target:   m.Target,
				Type:     container.MountType(m.Type),
				ReadOnly: m.ReadOnly,
			}
		}
	}

	// Convert ports
	if len(req.Ports) > 0 {
		spec.Ports = make([]container.PortMapping, len(req.Ports))
		for i, p := range req.Ports {
			spec.Ports[i] = container.PortMapping{
				HostIP:        p.HostIP,
				HostPort:      p.HostPort,
				ContainerPort: p.ContainerPort,
				Protocol:      p.Protocol,
			}
		}
	}

	// Set capabilities
	if len(req.CapAdd) > 0 || len(req.CapDrop) > 0 {
		spec.Capabilities = container.CapabilityConfig{
			Add:  req.CapAdd,
			Drop: req.CapDrop,
		}
	}

	// Set resources
	if req.CPULimit != "" || req.MemoryLimit != "" {
		spec.Resources = container.ResourceConfig{
			CPULimit:    req.CPULimit,
			MemoryLimit: req.MemoryLimit,
		}
	}

	// Set restart policy
	if req.RestartPolicy != "" {
		spec.RestartPolicy = container.RestartPolicy(req.RestartPolicy)
	}

	return spec
}

// parseContainerListOptions parses query parameters into ListOptions.
func (h *ComputeHandlers) parseContainerListOptions(r *http.Request) container.ListOptions {
	query := r.URL.Query()

	opts := container.ListOptions{
		All: query.Get("all") == "true",
	}

	if limitStr := query.Get("limit"); limitStr != "" {
		if limit, err := strconv.Atoi(limitStr); err == nil && limit > 0 {
			opts.Limit = limit
		}
	}

	// Parse filters
	filters := make(map[string][]string)
	if state := query.Get("state"); state != "" {
		filters["status"] = []string{state}
	}
	if name := query.Get("name"); name != "" {
		filters["name"] = []string{name}
	}
	if image := query.Get("image"); image != "" {
		filters["ancestor"] = []string{image}
	}
	if len(filters) > 0 {
		opts.Filters = filters
	}

	return opts
}

// parseLogOptions parses query parameters into LogOptions.
func (h *ComputeHandlers) parseLogOptions(r *http.Request) container.LogOptions {
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

// containerToComputeResponse converts a container.Container to ComputeContainerResponse.
func (h *ComputeHandlers) containerToComputeResponse(c *container.Container) ComputeContainerResponse {
	resp := ComputeContainerResponse{
		ID:         c.ID,
		Name:       c.Name,
		State:      string(c.State),
		Type:       "container",
		Image:      c.Image,
		ImageID:    c.ImageID,
		PID:        c.Pid,
		ExitCode:   c.ExitCode,
		CreatedAt:  c.CreatedAt,
		StartedAt:  c.StartedAt,
		FinishedAt: c.FinishedAt,
		Labels:     c.Labels,
		Platform:   c.Platform,
	}

	return resp
}

// attestationReportToContainerResponse converts an AttestationReport to AttestContainerResponse.
func (h *ComputeHandlers) attestationReportToContainerResponse(report *container.AttestationReport) AttestContainerResponse {
	resp := AttestContainerResponse{
		ContainerID:   report.ContainerID,
		ContainerName: report.ContainerName,
		Verified:      report.Verified,
		Timestamp:     report.Timestamp,
	}

	if len(report.ImageDigest) > 0 {
		resp.ImageDigest = fmt.Sprintf("%x", report.ImageDigest)
	}
	if len(report.ConfigDigest) > 0 {
		resp.ConfigDigest = fmt.Sprintf("%x", report.ConfigDigest)
	}
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
func (h *ComputeHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("Failed to encode JSON response", "error", err)
	}
}

// writeError writes an error response.
func (h *ComputeHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}

// writeVMError maps VM errors to appropriate HTTP status codes.
func (h *ComputeHandlers) writeVMError(w http.ResponseWriter, operation string, err error) {
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
	case errors.Is(err, compute.ErrTimeout):
		status = http.StatusGatewayTimeout
	case errors.Is(err, compute.ErrUnsupportedOperation):
		status = http.StatusNotImplemented
	case errors.Is(err, compute.ErrInvalidSnapshotName),
		errors.Is(err, compute.ErrInvalidAttestationEvidence):
		status = http.StatusBadRequest
	case errors.Is(err, compute.ErrSnapshotNotFound):
		status = http.StatusNotFound
	case errors.Is(err, compute.ErrUnsupportedDiskFormat),
		errors.Is(err, compute.ErrVTPMNotAvailable):
		status = http.StatusConflict
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrVMOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}

// writeContainerComputeError maps container errors to appropriate HTTP status codes.
func (h *ComputeHandlers) writeContainerComputeError(w http.ResponseWriter, operation string, err error) {
	var status int

	switch {
	case errors.Is(err, container.ErrContainerNotFound):
		status = http.StatusNotFound
	case errors.Is(err, container.ErrContainerExists):
		status = http.StatusConflict
	case errors.Is(err, container.ErrContainerRunning):
		status = http.StatusConflict
	case errors.Is(err, container.ErrContainerStopped):
		status = http.StatusConflict
	case errors.Is(err, container.ErrInvalidSpec):
		status = http.StatusBadRequest
	case errors.Is(err, container.ErrInvalidName):
		status = http.StatusBadRequest
	case errors.Is(err, container.ErrInvalidImage):
		status = http.StatusBadRequest
	case errors.Is(err, container.ErrAttestationFailed):
		status = http.StatusInternalServerError
	case errors.Is(err, container.ErrPolicyDenied):
		status = http.StatusForbidden
	case errors.Is(err, container.ErrOperationTimeout):
		status = http.StatusGatewayTimeout
	case errors.Is(err, container.ErrImageNotFound):
		status = http.StatusNotFound
	case errors.Is(err, container.ErrImageVerificationFailed):
		status = http.StatusForbidden
	case errors.Is(err, container.ErrOrchestratorNotInitialized):
		status = http.StatusServiceUnavailable
	default:
		status = http.StatusInternalServerError
	}

	h.writeError(w, status, ErrContainerOperationFailed{
		Operation: operation,
		Cause:     err,
	})
}
