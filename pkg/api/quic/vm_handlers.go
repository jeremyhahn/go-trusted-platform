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

package quic

import (
	"context"
	"errors"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// VM operation codes use the existing opcodes from protocol.go (0x60-0x6A range)
// Additional VM-specific operations
const (
	// OpVMRestart restarts a VM
	OpVMRestart byte = 0xB6

	// OpVMSuspend suspends a running VM
	OpVMSuspend byte = 0xB7

	// OpVMResume resumes a suspended VM
	OpVMResume byte = 0xB8

	// OpVMAttest performs TPM attestation for a VM
	OpVMAttest byte = 0xB9

	// OpVMConsole retrieves console information for a VM
	OpVMConsole byte = 0xBA

	// OpVMSnapshot creates a snapshot of a VM
	OpVMSnapshot byte = 0xBB

	// OpVMSnapshotRestore restores a VM from a snapshot
	OpVMSnapshotRestore byte = 0xBC

	// OpVMSnapshotDelete deletes a snapshot
	OpVMSnapshotDelete byte = 0xBD

	// OpVMSnapshotList lists snapshots for a VM
	OpVMSnapshotList byte = 0xBE
)

// VM-specific sentinel errors
var (
	// ErrVMOrchestratorNotAvailable is returned when the VM orchestrator
	// is not configured or unavailable.
	ErrVMOrchestratorNotAvailable = errors.New("VM orchestrator not available")

	// ErrVMMissingID is returned when a VM ID is required but not provided.
	ErrVMMissingID = errors.New("VM ID is required")

	// ErrVMMissingName is returned when a VM name is required but not provided.
	ErrVMMissingName = errors.New("VM name is required")

	// ErrVMMissingSnapshotName is returned when a snapshot name is required but not provided.
	ErrVMMissingSnapshotName = errors.New("snapshot name is required")

	// ErrVMOperationNotSupported is returned when an operation is not supported.
	ErrVMOperationNotSupported = errors.New("operation not supported by orchestrator")
)

// VMOrchestrator defines the interface for VM orchestration over QUIC.
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

	// AttachNetwork attaches a VM to a network port
	AttachNetwork(ctx context.Context, instanceID, portName string) error

	// DetachNetwork detaches a VM from a network port
	DetachNetwork(ctx context.Context, instanceID, portName string) error
}

// ExtendedVMOrchestrator extends VMOrchestrator with additional operations.
type ExtendedVMOrchestrator interface {
	VMOrchestrator

	// Suspend suspends a running VM
	Suspend(ctx context.Context, instanceID string) error

	// Resume resumes a suspended VM
	Resume(ctx context.Context, instanceID string) error

	// Restart restarts a VM
	Restart(ctx context.Context, instanceID string) error

	// GetConsole returns console access information for a VM
	GetConsole(ctx context.Context, instanceID string) (*VMConsoleInfo, error)

	// Attest performs TPM attestation for a VM
	Attest(ctx context.Context, instanceID string) (*VMAttestationReport, error)

	// CreateSnapshot creates a snapshot of a VM
	CreateSnapshot(ctx context.Context, instanceID, snapshotName string) (*VMSnapshot, error)

	// RestoreSnapshot restores a VM from a snapshot
	RestoreSnapshot(ctx context.Context, instanceID, snapshotName string) error

	// DeleteSnapshot deletes a snapshot
	DeleteSnapshot(ctx context.Context, instanceID, snapshotName string) error

	// ListSnapshots lists all snapshots for a VM
	ListSnapshots(ctx context.Context, instanceID string) ([]*VMSnapshot, error)
}

// VMConsoleInfo contains console access information.
type VMConsoleInfo struct {
	Type     string `json:"type" codec:"type"`
	Address  string `json:"address,omitempty" codec:"address"`
	Port     int    `json:"port,omitempty" codec:"port"`
	Protocol string `json:"protocol,omitempty" codec:"protocol"`
}

// VMAttestationReport contains VM attestation results.
type VMAttestationReport struct {
	VMID      string         `json:"vm_id" codec:"vm_id"`
	VMName    string         `json:"vm_name" codec:"vm_name"`
	Timestamp time.Time      `json:"timestamp" codec:"timestamp"`
	Verified  bool           `json:"verified" codec:"verified"`
	PCRValues map[int][]byte `json:"pcr_values,omitempty" codec:"pcr_values"`
	Quote     []byte         `json:"quote,omitempty" codec:"quote"`
	Signature []byte         `json:"signature,omitempty" codec:"signature"`
	EventLog  []byte         `json:"event_log,omitempty" codec:"event_log"`
}

// VMSnapshot represents a VM snapshot.
type VMSnapshot struct {
	Name        string    `json:"name" codec:"name"`
	VMID        string    `json:"vm_id" codec:"vm_id"`
	CreatedAt   time.Time `json:"created_at" codec:"created_at"`
	SizeBytes   int64     `json:"size_bytes" codec:"size_bytes"`
	Description string    `json:"description,omitempty" codec:"description"`
}

// VMHandler handles VM operations over QUIC
type VMHandler struct {
	orchestrator VMOrchestrator
	logger       *logging.Logger
}

// NewVMHandler creates a new VM handler
func NewVMHandler(logger *logging.Logger, orchestrator VMOrchestrator) *VMHandler {
	return &VMHandler{
		orchestrator: orchestrator,
		logger:       logger,
	}
}

// HandleRequest processes a VM request and returns a response
func (h *VMHandler) HandleRequest(ctx context.Context, req *Request) *Response {
	if req == nil {
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte(ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	case OpVMCreate:
		return h.handleCreate(ctx, req)
	case OpVMDelete:
		return h.handleDelete(ctx, req)
	case OpVMStart:
		return h.handleStart(ctx, req)
	case OpVMStop:
		return h.handleStop(ctx, req)
	case OpVMGet:
		return h.handleGet(ctx, req)
	case OpVMList:
		return h.handleList(ctx, req)
	case OpVMAttachNet:
		return h.handleAttachNetwork(ctx, req)
	case OpVMDetachNet:
		return h.handleDetachNetwork(ctx, req)
	case OpVMGetState:
		return h.handleGetState(ctx, req)
	case OpVMRestart:
		return h.handleRestart(ctx, req)
	case OpVMSuspend:
		return h.handleSuspend(ctx, req)
	case OpVMResume:
		return h.handleResume(ctx, req)
	case OpVMAttest:
		return h.handleAttest(ctx, req)
	case OpVMConsole:
		return h.handleGetConsole(ctx, req)
	case OpVMSnapshot:
		return h.handleCreateSnapshot(ctx, req)
	case OpVMSnapshotRestore:
		return h.handleRestoreSnapshot(ctx, req)
	case OpVMSnapshotDelete:
		return h.handleDeleteSnapshot(ctx, req)
	case OpVMSnapshotList:
		return h.handleListSnapshots(ctx, req)
	default:
		return &Response{
			Status:  StatusInvalidRequest,
			Payload: []byte("unknown VM operation"),
		}
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// VMCreateRequest represents a VM creation request
type VMCreateRequest struct {
	Name        string            `codec:"name"`
	ProfileID   uint64            `codec:"profile_id"`
	ProfileName string            `codec:"profile_name"`
	Memory      int               `codec:"memory"`
	CPUs        int               `codec:"cpus"`
	DiskSize    string            `codec:"disk_size"`
	ISOPath     string            `codec:"iso_path"`
	BootMode    string            `codec:"boot_mode"`
	EnableKVM   bool              `codec:"enable_kvm"`
	SecureBoot  bool              `codec:"secure_boot"`
	TPMEnabled  bool              `codec:"tpm_enabled"`
	NetworkMode string            `codec:"network_mode"`
	Environment map[string]string `codec:"environment"`
	Labels      map[string]string `codec:"labels"`
}

// VMCreateResponse represents a VM creation response
type VMCreateResponse struct {
	VM        *VMInfo `codec:"vm"`
	Timestamp int64   `codec:"timestamp"`
}

// VMInfo contains VM information
type VMInfo struct {
	ID                 string             `codec:"id"`
	Name               string             `codec:"name"`
	State              string             `codec:"state"`
	Type               string             `codec:"type"`
	PID                int                `codec:"pid"`
	Memory             int                `codec:"memory"`
	CPUs               int                `codec:"cpus"`
	DiskPath           string             `codec:"disk_path"`
	DiskSize           string             `codec:"disk_size"`
	BootMode           string             `codec:"boot_mode"`
	SecureBoot         bool               `codec:"secure_boot"`
	TPMEnabled         bool               `codec:"tpm_enabled"`
	CreatedAt          int64              `codec:"created_at"`
	UpdatedAt          int64              `codec:"updated_at"`
	Metadata           map[string]string  `codec:"metadata"`
	NetworkAttachments []*VMNetworkAttach `codec:"network_attachments"`
}

// VMNetworkAttach represents a network attachment
type VMNetworkAttach struct {
	PortName   string `codec:"port_name"`
	BridgeName string `codec:"bridge_name"`
	VLAN       uint16 `codec:"vlan"`
	MACAddress string `codec:"mac_address"`
	IPAddress  string `codec:"ip_address"`
	AttachedAt int64  `codec:"attached_at"`
}

// VMDeleteRequest represents a VM deletion request
type VMDeleteRequest struct {
	ID string `codec:"id"`
}

// VMDeleteResponse represents a VM deletion response
type VMDeleteResponse struct {
	ID        string `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VMStartRequest represents a VM start request
type VMStartRequest struct {
	ID string `codec:"id"`
}

// VMStartResponse represents a VM start response
type VMStartResponse struct {
	ID        string `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VMStopRequest represents a VM stop request
type VMStopRequest struct {
	ID string `codec:"id"`
}

// VMStopResponse represents a VM stop response
type VMStopResponse struct {
	ID        string `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VMGetRequest represents a VM get request
type VMGetRequest struct {
	ID string `codec:"id"`
}

// VMGetResponse represents a VM get response
type VMGetResponse struct {
	VM        *VMInfo `codec:"vm"`
	Timestamp int64   `codec:"timestamp"`
}

// VMListRequest represents a VM list request
type VMListRequest struct {
	Limit        int32  `codec:"limit"`
	State        string `codec:"state"`
	Name         string `codec:"name"`
	ProfileID    uint64 `codec:"profile_id"`
	CreatedAfter int64  `codec:"created_after"`
}

// VMListResponse represents a VM list response
type VMListResponse struct {
	VMs       []*VMInfo `codec:"vms"`
	Count     int32     `codec:"count"`
	Timestamp int64     `codec:"timestamp"`
}

// VMAttachNetworkRequest represents a network attach request
type VMAttachNetworkRequest struct {
	ID       string `codec:"id"`
	PortName string `codec:"port_name"`
}

// VMAttachNetworkResponse represents a network attach response
type VMAttachNetworkResponse struct {
	ID        string `codec:"id"`
	PortName  string `codec:"port_name"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VMDetachNetworkRequest represents a network detach request
type VMDetachNetworkRequest struct {
	ID       string `codec:"id"`
	PortName string `codec:"port_name"`
}

// VMDetachNetworkResponse represents a network detach response
type VMDetachNetworkResponse struct {
	ID        string `codec:"id"`
	PortName  string `codec:"port_name"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VMGetStateRequest represents a get state request
type VMGetStateRequest struct {
	ID string `codec:"id"`
}

// VMGetStateResponse represents a get state response
type VMGetStateResponse struct {
	ID        string `codec:"id"`
	State     string `codec:"state"`
	Timestamp int64  `codec:"timestamp"`
}

// VMRestartRequest represents a VM restart request
type VMRestartRequest struct {
	ID string `codec:"id"`
}

// VMRestartResponse represents a VM restart response
type VMRestartResponse struct {
	ID        string `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VMSuspendRequest represents a VM suspend request
type VMSuspendRequest struct {
	ID string `codec:"id"`
}

// VMSuspendResponse represents a VM suspend response
type VMSuspendResponse struct {
	ID        string `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VMResumeRequest represents a VM resume request
type VMResumeRequest struct {
	ID string `codec:"id"`
}

// VMResumeResponse represents a VM resume response
type VMResumeResponse struct {
	ID        string `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VMAttestRequest represents a VM attestation request
type VMAttestRequest struct {
	ID string `codec:"id"`
}

// VMAttestResponse represents a VM attestation response
type VMAttestResponse struct {
	VMID      string         `codec:"vm_id"`
	VMName    string         `codec:"vm_name"`
	Verified  bool           `codec:"verified"`
	Timestamp int64          `codec:"timestamp"`
	PCRValues map[int][]byte `codec:"pcr_values"`
	Quote     []byte         `codec:"quote"`
	Signature []byte         `codec:"signature"`
	EventLog  []byte         `codec:"event_log"`
}

// VMConsoleRequest represents a VM console request
type VMConsoleRequest struct {
	ID string `codec:"id"`
}

// VMConsoleResponse represents a VM console response
type VMConsoleResponse struct {
	VMID      string `codec:"vm_id"`
	Type      string `codec:"type"`
	Address   string `codec:"address"`
	Port      int    `codec:"port"`
	Protocol  string `codec:"protocol"`
	Timestamp int64  `codec:"timestamp"`
}

// VMSnapshotCreateRequest represents a snapshot creation request
type VMSnapshotCreateRequest struct {
	ID          string `codec:"id"`
	Name        string `codec:"name"`
	Description string `codec:"description"`
}

// VMSnapshotCreateResponse represents a snapshot creation response
type VMSnapshotCreateResponse struct {
	Snapshot  *VMSnapshotInfo `codec:"snapshot"`
	Timestamp int64           `codec:"timestamp"`
}

// VMSnapshotInfo contains snapshot information
type VMSnapshotInfo struct {
	Name        string `codec:"name"`
	VMID        string `codec:"vm_id"`
	CreatedAt   int64  `codec:"created_at"`
	SizeBytes   int64  `codec:"size_bytes"`
	Description string `codec:"description"`
}

// VMSnapshotRestoreRequest represents a snapshot restore request
type VMSnapshotRestoreRequest struct {
	ID   string `codec:"id"`
	Name string `codec:"name"`
}

// VMSnapshotRestoreResponse represents a snapshot restore response
type VMSnapshotRestoreResponse struct {
	ID        string `codec:"id"`
	Name      string `codec:"name"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VMSnapshotDeleteRequest represents a snapshot deletion request
type VMSnapshotDeleteRequest struct {
	ID   string `codec:"id"`
	Name string `codec:"name"`
}

// VMSnapshotDeleteResponse represents a snapshot deletion response
type VMSnapshotDeleteResponse struct {
	ID        string `codec:"id"`
	Name      string `codec:"name"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// VMSnapshotListRequest represents a snapshot list request
type VMSnapshotListRequest struct {
	ID string `codec:"id"`
}

// VMSnapshotListResponse represents a snapshot list response
type VMSnapshotListResponse struct {
	VMID      string            `codec:"vm_id"`
	Snapshots []*VMSnapshotInfo `codec:"snapshots"`
	Count     int32             `codec:"count"`
	Timestamp int64             `codec:"timestamp"`
}

// =============================================================================
// Handler Methods
// =============================================================================

// handleCreate creates a new VM
func (h *VMHandler) handleCreate(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var createReq VMCreateRequest
	if err := DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingName)
	}

	// Build device profile from request
	profile := h.buildProfileFromRequest(&createReq)

	// Create VM
	instance, err := h.orchestrator.Create(ctx, profile)
	if err != nil {
		h.logger.Error(err, "failed to create VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMCreateResponse{
		VM:        h.instanceToVMInfo(instance),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleDelete deletes a VM
func (h *VMHandler) handleDelete(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var deleteReq VMDeleteRequest
	if err := DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if deleteReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if err := h.orchestrator.Delete(ctx, deleteReq.ID); err != nil {
		h.logger.Error(err, "failed to delete VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMDeleteResponse{
		ID:        deleteReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleStart starts a stopped VM
func (h *VMHandler) handleStart(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var startReq VMStartRequest
	if err := DecodePayload(req.Payload, &startReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if startReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if err := h.orchestrator.Start(ctx, startReq.ID); err != nil {
		h.logger.Error(err, "failed to start VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMStartResponse{
		ID:        startReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleStop stops a running VM
func (h *VMHandler) handleStop(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var stopReq VMStopRequest
	if err := DecodePayload(req.Payload, &stopReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if stopReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if err := h.orchestrator.Stop(ctx, stopReq.ID); err != nil {
		h.logger.Error(err, "failed to stop VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMStopResponse{
		ID:        stopReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGet retrieves a VM by ID
func (h *VMHandler) handleGet(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var getReq VMGetRequest
	if err := DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if getReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	instance, err := h.orchestrator.Get(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMGetResponse{
		VM:        h.instanceToVMInfo(instance),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleList lists VMs
func (h *VMHandler) handleList(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var listReq VMListRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	// Build filter from request
	filter := h.buildFilterFromRequest(&listReq)

	instances, err := h.orchestrator.List(ctx, filter)
	if err != nil {
		h.logger.Error(err, "failed to list VMs")
		return h.vmErrorResponse(err)
	}

	vmInfos := make([]*VMInfo, 0, len(instances))
	for _, inst := range instances {
		vmInfos = append(vmInfos, h.instanceToVMInfo(inst))
	}

	resp := &VMListResponse{
		VMs:       vmInfos,
		Count:     int32(len(vmInfos)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleAttachNetwork attaches a VM to a network port
func (h *VMHandler) handleAttachNetwork(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var attachReq VMAttachNetworkRequest
	if err := DecodePayload(req.Payload, &attachReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if attachReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if attachReq.PortName == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingPortName)
	}

	if err := h.orchestrator.AttachNetwork(ctx, attachReq.ID, attachReq.PortName); err != nil {
		h.logger.Error(err, "failed to attach network")
		return h.vmErrorResponse(err)
	}

	resp := &VMAttachNetworkResponse{
		ID:        attachReq.ID,
		PortName:  attachReq.PortName,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleDetachNetwork detaches a VM from a network port
func (h *VMHandler) handleDetachNetwork(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var detachReq VMDetachNetworkRequest
	if err := DecodePayload(req.Payload, &detachReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if detachReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if detachReq.PortName == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingPortName)
	}

	if err := h.orchestrator.DetachNetwork(ctx, detachReq.ID, detachReq.PortName); err != nil {
		h.logger.Error(err, "failed to detach network")
		return h.vmErrorResponse(err)
	}

	resp := &VMDetachNetworkResponse{
		ID:        detachReq.ID,
		PortName:  detachReq.PortName,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGetState gets the state of a VM
func (h *VMHandler) handleGetState(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var stateReq VMGetStateRequest
	if err := DecodePayload(req.Payload, &stateReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if stateReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	state, err := h.orchestrator.GetState(ctx, stateReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get VM state")
		return h.vmErrorResponse(err)
	}

	resp := &VMGetStateResponse{
		ID:        stateReq.ID,
		State:     string(state),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleRestart restarts a VM (extended operation)
func (h *VMHandler) handleRestart(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	extOrch, ok := h.orchestrator.(ExtendedVMOrchestrator)
	if !ok {
		return h.errorResponse(StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var restartReq VMRestartRequest
	if err := DecodePayload(req.Payload, &restartReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if restartReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if err := extOrch.Restart(ctx, restartReq.ID); err != nil {
		h.logger.Error(err, "failed to restart VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMRestartResponse{
		ID:        restartReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleSuspend suspends a running VM (extended operation)
func (h *VMHandler) handleSuspend(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	extOrch, ok := h.orchestrator.(ExtendedVMOrchestrator)
	if !ok {
		return h.errorResponse(StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var suspendReq VMSuspendRequest
	if err := DecodePayload(req.Payload, &suspendReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if suspendReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if err := extOrch.Suspend(ctx, suspendReq.ID); err != nil {
		h.logger.Error(err, "failed to suspend VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMSuspendResponse{
		ID:        suspendReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleResume resumes a suspended VM (extended operation)
func (h *VMHandler) handleResume(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	extOrch, ok := h.orchestrator.(ExtendedVMOrchestrator)
	if !ok {
		return h.errorResponse(StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var resumeReq VMResumeRequest
	if err := DecodePayload(req.Payload, &resumeReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if resumeReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if err := extOrch.Resume(ctx, resumeReq.ID); err != nil {
		h.logger.Error(err, "failed to resume VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMResumeResponse{
		ID:        resumeReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleAttest performs TPM attestation for a VM (extended operation)
func (h *VMHandler) handleAttest(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	extOrch, ok := h.orchestrator.(ExtendedVMOrchestrator)
	if !ok {
		return h.errorResponse(StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var attestReq VMAttestRequest
	if err := DecodePayload(req.Payload, &attestReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if attestReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	report, err := extOrch.Attest(ctx, attestReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to attest VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMAttestResponse{
		VMID:      report.VMID,
		VMName:    report.VMName,
		Verified:  report.Verified,
		Timestamp: report.Timestamp.Unix(),
		PCRValues: report.PCRValues,
		Quote:     report.Quote,
		Signature: report.Signature,
		EventLog:  report.EventLog,
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleGetConsole retrieves console information for a VM (extended operation)
func (h *VMHandler) handleGetConsole(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	extOrch, ok := h.orchestrator.(ExtendedVMOrchestrator)
	if !ok {
		return h.errorResponse(StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var consoleReq VMConsoleRequest
	if err := DecodePayload(req.Payload, &consoleReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if consoleReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	consoleInfo, err := extOrch.GetConsole(ctx, consoleReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get VM console")
		return h.vmErrorResponse(err)
	}

	resp := &VMConsoleResponse{
		VMID:      consoleReq.ID,
		Type:      consoleInfo.Type,
		Address:   consoleInfo.Address,
		Port:      consoleInfo.Port,
		Protocol:  consoleInfo.Protocol,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleCreateSnapshot creates a VM snapshot (extended operation)
func (h *VMHandler) handleCreateSnapshot(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	extOrch, ok := h.orchestrator.(ExtendedVMOrchestrator)
	if !ok {
		return h.errorResponse(StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var snapshotReq VMSnapshotCreateRequest
	if err := DecodePayload(req.Payload, &snapshotReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if snapshotReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if snapshotReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingSnapshotName)
	}

	snapshot, err := extOrch.CreateSnapshot(ctx, snapshotReq.ID, snapshotReq.Name)
	if err != nil {
		h.logger.Error(err, "failed to create snapshot")
		return h.vmErrorResponse(err)
	}

	resp := &VMSnapshotCreateResponse{
		Snapshot:  h.snapshotToInfo(snapshot),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleRestoreSnapshot restores a VM from a snapshot (extended operation)
func (h *VMHandler) handleRestoreSnapshot(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	extOrch, ok := h.orchestrator.(ExtendedVMOrchestrator)
	if !ok {
		return h.errorResponse(StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var restoreReq VMSnapshotRestoreRequest
	if err := DecodePayload(req.Payload, &restoreReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if restoreReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if restoreReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingSnapshotName)
	}

	if err := extOrch.RestoreSnapshot(ctx, restoreReq.ID, restoreReq.Name); err != nil {
		h.logger.Error(err, "failed to restore snapshot")
		return h.vmErrorResponse(err)
	}

	resp := &VMSnapshotRestoreResponse{
		ID:        restoreReq.ID,
		Name:      restoreReq.Name,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleDeleteSnapshot deletes a VM snapshot (extended operation)
func (h *VMHandler) handleDeleteSnapshot(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	extOrch, ok := h.orchestrator.(ExtendedVMOrchestrator)
	if !ok {
		return h.errorResponse(StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var deleteReq VMSnapshotDeleteRequest
	if err := DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if deleteReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	if deleteReq.Name == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingSnapshotName)
	}

	if err := extOrch.DeleteSnapshot(ctx, deleteReq.ID, deleteReq.Name); err != nil {
		h.logger.Error(err, "failed to delete snapshot")
		return h.vmErrorResponse(err)
	}

	resp := &VMSnapshotDeleteResponse{
		ID:        deleteReq.ID,
		Name:      deleteReq.Name,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// handleListSnapshots lists all snapshots for a VM (extended operation)
func (h *VMHandler) handleListSnapshots(ctx context.Context, req *Request) *Response {
	if h.orchestrator == nil {
		return h.errorResponse(StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	extOrch, ok := h.orchestrator.(ExtendedVMOrchestrator)
	if !ok {
		return h.errorResponse(StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var listReq VMSnapshotListRequest
	if err := DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if listReq.ID == "" {
		return h.errorResponse(StatusInvalidArgument, ErrVMMissingID)
	}

	snapshots, err := extOrch.ListSnapshots(ctx, listReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to list snapshots")
		return h.vmErrorResponse(err)
	}

	snapshotInfos := make([]*VMSnapshotInfo, 0, len(snapshots))
	for _, s := range snapshots {
		snapshotInfos = append(snapshotInfos, h.snapshotToInfo(s))
	}

	resp := &VMSnapshotListResponse{
		VMID:      listReq.ID,
		Snapshots: snapshotInfos,
		Count:     int32(len(snapshotInfos)),
		Timestamp: time.Now().Unix(),
	}

	payload, err := EncodePayload(resp)
	if err != nil {
		return h.errorResponse(StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &Response{
		Status:  StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// buildProfileFromRequest creates a DeviceProfile from a VMCreateRequest
func (h *VMHandler) buildProfileFromRequest(req *VMCreateRequest) *entities.DeviceProfile {
	profile := &entities.DeviceProfile{
		Name: req.Name,
	}

	if req.ProfileID != 0 {
		profile.ID = req.ProfileID
	}

	return profile
}

// buildFilterFromRequest creates an InstanceFilter from a VMListRequest
func (h *VMHandler) buildFilterFromRequest(req *VMListRequest) *compute.InstanceFilter {
	filter := &compute.InstanceFilter{}

	// Set type to VM
	vmType := compute.ComputeTypeVM
	filter.Type = &vmType

	// Apply state filter
	if req.State != "" {
		state := compute.InstanceState(req.State)
		if state.IsValid() {
			filter.State = &state
		}
	}

	// Apply name filter
	if req.Name != "" {
		filter.Name = req.Name
	}

	// Apply profile filter
	if req.ProfileID != 0 {
		filter.ProfileID = &req.ProfileID
	}

	// Apply created after filter
	if req.CreatedAfter > 0 {
		t := time.Unix(req.CreatedAfter, 0)
		filter.CreatedAfter = &t
	}

	return filter
}

// instanceToVMInfo converts a compute.Instance to VMInfo
func (h *VMHandler) instanceToVMInfo(inst *compute.Instance) *VMInfo {
	if inst == nil {
		return nil
	}

	info := &VMInfo{
		ID:        inst.ID,
		Name:      inst.Name,
		State:     string(inst.State),
		Type:      string(inst.Type),
		PID:       inst.PID,
		CreatedAt: inst.CreatedAt.Unix(),
		UpdatedAt: inst.UpdatedAt.Unix(),
		Metadata:  inst.Metadata,
	}

	// Extract config fields if available
	if inst.Config != nil {
		info.Memory = inst.Config.Memory
		info.CPUs = inst.Config.CPUs
		info.DiskPath = inst.Config.DiskPath
		info.DiskSize = inst.Config.DiskSize
		info.BootMode = inst.Config.BootMode
		info.SecureBoot = inst.Config.SecureBoot
		info.TPMEnabled = inst.Config.TPMEnabled
	}

	// Convert network attachments
	if len(inst.NetworkAttachments) > 0 {
		info.NetworkAttachments = make([]*VMNetworkAttach, 0, len(inst.NetworkAttachments))
		for _, att := range inst.NetworkAttachments {
			info.NetworkAttachments = append(info.NetworkAttachments, &VMNetworkAttach{
				PortName:   att.PortName,
				BridgeName: att.BridgeName,
				VLAN:       att.VLAN,
				MACAddress: att.MACAddress,
				IPAddress:  att.IPAddress,
				AttachedAt: att.AttachedAt.Unix(),
			})
		}
	}

	return info
}

// snapshotToInfo converts a VMSnapshot to VMSnapshotInfo
func (h *VMHandler) snapshotToInfo(s *VMSnapshot) *VMSnapshotInfo {
	if s == nil {
		return nil
	}

	return &VMSnapshotInfo{
		Name:        s.Name,
		VMID:        s.VMID,
		CreatedAt:   s.CreatedAt.Unix(),
		SizeBytes:   s.SizeBytes,
		Description: s.Description,
	}
}

// errorResponse creates an error response with the given status and error
func (h *VMHandler) errorResponse(status byte, err error) *Response {
	return &Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// vmErrorResponse maps VM errors to appropriate status codes
func (h *VMHandler) vmErrorResponse(err error) *Response {
	var status byte

	switch {
	case errors.Is(err, compute.ErrInstanceNotFound):
		status = StatusNotFound
	case errors.Is(err, compute.ErrInstanceAlreadyExists):
		status = StatusAlreadyExists
	case errors.Is(err, compute.ErrInstanceAlreadyRunning):
		status = StatusInvalidRequest
	case errors.Is(err, compute.ErrInstanceNotRunning):
		status = StatusInvalidRequest
	case errors.Is(err, compute.ErrInvalidInstanceID):
		status = StatusInvalidArgument
	case errors.Is(err, compute.ErrInvalidProfile):
		status = StatusInvalidArgument
	case errors.Is(err, compute.ErrInvalidConfiguration):
		status = StatusInvalidArgument
	case errors.Is(err, compute.ErrInvalidState):
		status = StatusInvalidRequest
	case errors.Is(err, compute.ErrResourceExhausted):
		status = StatusResourceExhausted
	case errors.Is(err, compute.ErrOrchestratorNotInitialized):
		status = StatusUnavailable
	case errors.Is(err, compute.ErrTimeout):
		status = StatusTimeout
	case errors.Is(err, compute.ErrUnsupportedOperation):
		status = StatusNotImplemented
	case errors.Is(err, compute.ErrNetworkAttachmentFailed):
		status = StatusInternalError
	case errors.Is(err, compute.ErrNetworkDetachmentFailed):
		status = StatusInternalError
	default:
		status = StatusInternalError
	}

	return h.errorResponse(status, err)
}

// =============================================================================
// VM Error Types
// =============================================================================

// ErrVMEncodingFailed represents an encoding failure error
type ErrVMEncodingFailed struct {
	Cause error
}

func (e ErrVMEncodingFailed) Error() string {
	return "failed to encode VM payload: " + e.Cause.Error()
}

func (e ErrVMEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrVMDecodingFailed represents a decoding failure error
type ErrVMDecodingFailed struct {
	Cause error
}

func (e ErrVMDecodingFailed) Error() string {
	return "failed to decode VM payload: " + e.Cause.Error()
}

func (e ErrVMDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrVMOperationFailed represents a VM operation failure
type ErrVMOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrVMOperationFailed) Error() string {
	return "VM operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrVMOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrVMMissingPortName is returned when a port name is required but not provided.
var ErrVMMissingPortName = errors.New("port name is required")
