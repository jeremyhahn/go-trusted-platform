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
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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

// VMConsoleProvider returns console access information for a VM. No
// production orchestrator provides it yet, so OpVMConsole answers with a
// typed not-supported error until one does.
type VMConsoleProvider interface {
	// GetConsole returns console access information for a VM
	GetConsole(ctx context.Context, instanceID string) (*VMConsoleInfo, error)
}

// ExtendedVMOrchestrator composes the full extended VM capability set. The
// suspend, snapshot and attestation capabilities are the canonical
// pkg/compute interfaces (compute.VMSuspender / compute.VMSnapshotter /
// compute.VMAttester); handlers assert each capability individually so
// partially-capable orchestrators (such as compute.QEMUOrchestrator, which
// implements suspend, snapshots and attestation but not console) expose
// exactly what they support. Restart needs only Start and Stop, so every
// VMOrchestrator restarts through compute.Reboot, as gRPC RebootVM does.
type ExtendedVMOrchestrator interface {
	VMOrchestrator
	compute.VMSuspender
	VMConsoleProvider
	compute.VMSnapshotter
	compute.VMAttester
}

// VMConsoleInfo contains console access information.
type VMConsoleInfo struct {
	Type     string `json:"type" codec:"type"`
	Address  string `json:"address,omitempty" codec:"address"`
	Port     int    `json:"port,omitempty" codec:"port"`
	Protocol string `json:"protocol,omitempty" codec:"protocol"`
}

// VMAttestationReport is the canonical compute attestation report.
type VMAttestationReport = compute.VMAttestationReport

// VMSnapshot is the canonical compute VM snapshot descriptor.
type VMSnapshot = compute.VMSnapshot

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
func (h *VMHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte(quicwire.ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	case quicwire.OpVMCreate:
		return h.handleCreate(ctx, req)
	case quicwire.OpVMDelete:
		return h.handleDelete(ctx, req)
	case quicwire.OpVMStart:
		return h.handleStart(ctx, req)
	case quicwire.OpVMStop:
		return h.handleStop(ctx, req)
	case quicwire.OpVMGet:
		return h.handleGet(ctx, req)
	case quicwire.OpVMList:
		return h.handleList(ctx, req)
	case quicwire.OpVMAttachNet:
		return h.handleAttachNetwork(ctx, req)
	case quicwire.OpVMDetachNet:
		return h.handleDetachNetwork(ctx, req)
	case quicwire.OpVMGetState:
		return h.handleGetState(ctx, req)
	case quicwire.OpVMRestart:
		return h.handleRestart(ctx, req)
	case quicwire.OpVMSuspend:
		return h.handleSuspend(ctx, req)
	case quicwire.OpVMResume:
		return h.handleResume(ctx, req)
	case quicwire.OpVMAttest:
		return h.handleAttest(ctx, req)
	case quicwire.OpVMConsole:
		return h.handleGetConsole(ctx, req)
	case quicwire.OpVMSnapshot:
		return h.handleCreateSnapshot(ctx, req)
	case quicwire.OpVMSnapshotRestore:
		return h.handleRestoreSnapshot(ctx, req)
	case quicwire.OpVMSnapshotDelete:
		return h.handleDeleteSnapshot(ctx, req)
	case quicwire.OpVMSnapshotList:
		return h.handleListSnapshots(ctx, req)
	case quicwire.OpVMVerifyAttest:
		return h.handleVerifyAttestation(ctx, req)
	case quicwire.OpVMExtendedCategory:
		return h.handleExtendedCategory(ctx, req)
	default:
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte("unknown VM operation"),
		}
	}
}

// handleExtendedCategory unwraps the category framing: payload[0] carries
// the extended VM sub-opcode (one of the 0xB6-0xBF constants) and the rest
// of the payload is the inner request payload.
func (h *VMHandler) handleExtendedCategory(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if len(req.Payload) < 1 {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte("VM extended category requires a sub-opcode in payload[0]"),
		}
	}

	sub := req.Payload[0]
	if sub < quicwire.OpVMRestart || sub > quicwire.OpVMVerifyAttest {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte("unknown VM extended sub-opcode"),
		}
	}

	return h.HandleRequest(ctx, &quicwire.Request{
		Opcode:  sub,
		Token:   req.Token,
		Payload: req.Payload[1:],
	})
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

// VMAttestRequest represents a VM attestation request. Nonce and PCRs are
// optional: an empty nonce is replaced with a platform-generated random
// nonce and an empty PCR selection defaults to PCRs 0-7.
type VMAttestRequest struct {
	ID    string `codec:"id"`
	Nonce []byte `codec:"nonce"`
	PCRs  []int  `codec:"pcrs"`
}

// VMAttestResponse represents a VM attestation response
type VMAttestResponse struct {
	VMID      string         `codec:"vm_id"`
	VMName    string         `codec:"vm_name"`
	Verified  bool           `codec:"verified"`
	Timestamp int64          `codec:"timestamp"`
	Nonce     []byte         `codec:"nonce"`
	PCRValues map[int][]byte `codec:"pcr_values"`
	Quote     []byte         `codec:"quote"`
	Signature []byte         `codec:"signature"`
	EventLog  []byte         `codec:"event_log"`
	AKPublic  []byte         `codec:"ak_public"`
	// SignatureAlgorithm names the scheme the AK signed the quote with
	// ("SHA256-RSAPSS", ...); verification checks the quote under it alone.
	SignatureAlgorithm string `codec:"signature_algorithm"`
}

// VMVerifyAttestRequest carries VM attestation evidence for verification.
type VMVerifyAttestRequest struct {
	ID           string         `codec:"id"`
	Quote        []byte         `codec:"quote"`
	Signature    []byte         `codec:"signature"`
	Nonce        []byte         `codec:"nonce"`
	ExpectedPCRs map[int][]byte `codec:"expected_pcrs"`
	// SignatureAlgorithm is the scheme the quote declares; an absent or
	// unknown scheme fails verification.
	SignatureAlgorithm string `codec:"signature_algorithm"`
}

// VMVerifyAttestResponse reports the attestation verification outcome.
type VMVerifyAttestResponse struct {
	VMID           string         `codec:"vm_id"`
	Verified       bool           `codec:"verified"`
	SignatureValid bool           `codec:"signature_valid"`
	NonceValid     bool           `codec:"nonce_valid"`
	PCRsValid      bool           `codec:"pcrs_valid"`
	Message        string         `codec:"message"`
	ActualPCRs     map[int][]byte `codec:"actual_pcrs"`
	Timestamp      int64          `codec:"timestamp"`
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
func (h *VMHandler) handleCreate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var createReq VMCreateRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingName)
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDelete deletes a VM
func (h *VMHandler) handleDelete(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var deleteReq VMDeleteRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if deleteReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleStart starts a stopped VM
func (h *VMHandler) handleStart(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var startReq VMStartRequest
	if err := quicwire.DecodePayload(req.Payload, &startReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if startReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleStop stops a running VM
func (h *VMHandler) handleStop(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var stopReq VMStopRequest
	if err := quicwire.DecodePayload(req.Payload, &stopReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if stopReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGet retrieves a VM by ID
func (h *VMHandler) handleGet(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var getReq VMGetRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if getReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleList lists VMs
func (h *VMHandler) handleList(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var listReq VMListRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleAttachNetwork attaches a VM to a network port
func (h *VMHandler) handleAttachNetwork(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var attachReq VMAttachNetworkRequest
	if err := quicwire.DecodePayload(req.Payload, &attachReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if attachReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	if attachReq.PortName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingPortName)
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDetachNetwork detaches a VM from a network port
func (h *VMHandler) handleDetachNetwork(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var detachReq VMDetachNetworkRequest
	if err := quicwire.DecodePayload(req.Payload, &detachReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if detachReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	if detachReq.PortName == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingPortName)
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetState gets the state of a VM
func (h *VMHandler) handleGetState(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var stateReq VMGetStateRequest
	if err := quicwire.DecodePayload(req.Payload, &stateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if stateReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleRestart restarts a VM through compute.Reboot, the implementation
// gRPC RebootVM uses (extended operation)
func (h *VMHandler) handleRestart(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	var restartReq VMRestartRequest
	if err := quicwire.DecodePayload(req.Payload, &restartReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if restartReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	if err := compute.Reboot(ctx, h.orchestrator, restartReq.ID); err != nil {
		h.logger.Error(err, "failed to restart VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMRestartResponse{
		ID:        restartReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleSuspend suspends a running VM (extended operation)
func (h *VMHandler) handleSuspend(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	suspender, ok := h.orchestrator.(compute.VMSuspender)
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var suspendReq VMSuspendRequest
	if err := quicwire.DecodePayload(req.Payload, &suspendReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if suspendReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	if err := suspender.Suspend(ctx, suspendReq.ID); err != nil {
		h.logger.Error(err, "failed to suspend VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMSuspendResponse{
		ID:        suspendReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleResume resumes a suspended VM (extended operation)
func (h *VMHandler) handleResume(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	suspender, ok := h.orchestrator.(compute.VMSuspender)
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var resumeReq VMResumeRequest
	if err := quicwire.DecodePayload(req.Payload, &resumeReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if resumeReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	if err := suspender.Resume(ctx, resumeReq.ID); err != nil {
		h.logger.Error(err, "failed to resume VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMResumeResponse{
		ID:        resumeReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleAttest performs TPM attestation for a VM (extended operation)
func (h *VMHandler) handleAttest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	attester, ok := h.orchestrator.(compute.VMAttester)
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var attestReq VMAttestRequest
	if err := quicwire.DecodePayload(req.Payload, &attestReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if attestReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	report, err := attester.AttestVM(ctx, attestReq.ID, attestReq.Nonce, attestReq.PCRs)
	if err != nil {
		h.logger.Error(err, "failed to attest VM")
		return h.vmErrorResponse(err)
	}

	resp := &VMAttestResponse{
		VMID:      report.VMID,
		VMName:    report.VMName,
		Verified:  report.Verified,
		Timestamp: report.Timestamp.Unix(),
		Nonce:     report.Nonce,
		PCRValues: report.PCRValues,
		Quote:     report.Quote,
		Signature: report.Signature,
		EventLog:  report.EventLog,
		AKPublic:  report.AKPublicKey,
		// The scheme the AK signed under; OpVMVerifyAttest needs it back.
		SignatureAlgorithm: report.SignatureAlgorithm,
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleVerifyAttestation verifies VM attestation evidence (extended operation)
func (h *VMHandler) handleVerifyAttestation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	attester, ok := h.orchestrator.(compute.VMAttester)
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var verifyReq VMVerifyAttestRequest
	if err := quicwire.DecodePayload(req.Payload, &verifyReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if verifyReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	result, err := attester.VerifyVMAttestation(ctx, verifyReq.ID, &compute.VMAttestationEvidence{
		Quote:              verifyReq.Quote,
		Signature:          verifyReq.Signature,
		SignatureAlgorithm: verifyReq.SignatureAlgorithm,
		Nonce:              verifyReq.Nonce,
		ExpectedPCRs:       verifyReq.ExpectedPCRs,
	})
	if err != nil {
		h.logger.Error(err, "failed to verify VM attestation")
		return h.vmErrorResponse(err)
	}

	resp := &VMVerifyAttestResponse{
		VMID:           verifyReq.ID,
		Verified:       result.Verified,
		SignatureValid: result.SignatureValid,
		NonceValid:     result.NonceValid,
		PCRsValid:      result.PCRsValid,
		Message:        result.Message,
		ActualPCRs:     result.ActualPCRs,
		Timestamp:      time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGetConsole retrieves console information for a VM (extended operation)
func (h *VMHandler) handleGetConsole(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	consoleProvider, ok := h.orchestrator.(VMConsoleProvider)
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var consoleReq VMConsoleRequest
	if err := quicwire.DecodePayload(req.Payload, &consoleReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if consoleReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	consoleInfo, err := consoleProvider.GetConsole(ctx, consoleReq.ID)
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleCreateSnapshot creates a VM snapshot (extended operation)
func (h *VMHandler) handleCreateSnapshot(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	snapshotter, ok := h.orchestrator.(compute.VMSnapshotter)
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var snapshotReq VMSnapshotCreateRequest
	if err := quicwire.DecodePayload(req.Payload, &snapshotReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if snapshotReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	if snapshotReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingSnapshotName)
	}

	snapshot, err := snapshotter.CreateSnapshot(ctx, snapshotReq.ID, snapshotReq.Name)
	if err != nil {
		h.logger.Error(err, "failed to create snapshot")
		return h.vmErrorResponse(err)
	}

	resp := &VMSnapshotCreateResponse{
		Snapshot:  h.snapshotToInfo(snapshot),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleRestoreSnapshot restores a VM from a snapshot (extended operation)
func (h *VMHandler) handleRestoreSnapshot(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	snapshotter, ok := h.orchestrator.(compute.VMSnapshotter)
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var restoreReq VMSnapshotRestoreRequest
	if err := quicwire.DecodePayload(req.Payload, &restoreReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if restoreReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	if restoreReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingSnapshotName)
	}

	if err := snapshotter.RestoreSnapshot(ctx, restoreReq.ID, restoreReq.Name); err != nil {
		h.logger.Error(err, "failed to restore snapshot")
		return h.vmErrorResponse(err)
	}

	resp := &VMSnapshotRestoreResponse{
		ID:        restoreReq.ID,
		Name:      restoreReq.Name,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleDeleteSnapshot deletes a VM snapshot (extended operation)
func (h *VMHandler) handleDeleteSnapshot(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	snapshotter, ok := h.orchestrator.(compute.VMSnapshotter)
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var deleteReq VMSnapshotDeleteRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if deleteReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	if deleteReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingSnapshotName)
	}

	if err := snapshotter.DeleteSnapshot(ctx, deleteReq.ID, deleteReq.Name); err != nil {
		h.logger.Error(err, "failed to delete snapshot")
		return h.vmErrorResponse(err)
	}

	resp := &VMSnapshotDeleteResponse{
		ID:        deleteReq.ID,
		Name:      deleteReq.Name,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleListSnapshots lists all snapshots for a VM (extended operation)
func (h *VMHandler) handleListSnapshots(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrVMOrchestratorNotAvailable)
	}

	snapshotter, ok := h.orchestrator.(compute.VMSnapshotter)
	if !ok {
		return h.errorResponse(quicwire.StatusNotImplemented, ErrVMOperationNotSupported)
	}

	var listReq VMSnapshotListRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrVMDecodingFailed{Cause: err})
	}

	if listReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrVMMissingID)
	}

	snapshots, err := snapshotter.ListSnapshots(ctx, listReq.ID)
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

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrVMEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
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
func (h *VMHandler) errorResponse(status byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// vmErrorResponse maps VM errors to appropriate status codes
func (h *VMHandler) vmErrorResponse(err error) *quicwire.Response {
	var status byte

	switch {
	case errors.Is(err, compute.ErrInstanceNotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, compute.ErrInstanceAlreadyExists):
		status = quicwire.StatusAlreadyExists
	case errors.Is(err, compute.ErrInstanceAlreadyRunning):
		status = quicwire.StatusFailedPrecondition
	case errors.Is(err, compute.ErrInstanceNotRunning):
		status = quicwire.StatusFailedPrecondition
	case errors.Is(err, compute.ErrInstanceNotSuspended):
		status = quicwire.StatusFailedPrecondition
	case errors.Is(err, compute.ErrInvalidInstanceID):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, compute.ErrInvalidProfile):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, compute.ErrInvalidConfiguration):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, compute.ErrInvalidState):
		status = quicwire.StatusFailedPrecondition
	case errors.Is(err, compute.ErrResourceExhausted):
		status = quicwire.StatusResourceExhausted
	case errors.Is(err, compute.ErrOrchestratorNotInitialized):
		status = quicwire.StatusUnavailable
	case errors.Is(err, compute.ErrTimeout):
		status = quicwire.StatusTimeout
	case errors.Is(err, compute.ErrUnsupportedOperation):
		status = quicwire.StatusNotImplemented
	case errors.Is(err, compute.ErrNetworkAttachmentFailed):
		status = quicwire.StatusInternalError
	case errors.Is(err, compute.ErrNetworkDetachmentFailed):
		status = quicwire.StatusInternalError
	case errors.Is(err, compute.ErrInvalidSnapshotName):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, compute.ErrSnapshotNotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, compute.ErrUnsupportedDiskFormat):
		status = quicwire.StatusInvalidRequest
	case errors.Is(err, compute.ErrVTPMNotAvailable):
		status = quicwire.StatusInvalidRequest
	case errors.Is(err, compute.ErrInvalidAttestationEvidence):
		status = quicwire.StatusInvalidArgument
	default:
		status = quicwire.StatusInternalError
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
