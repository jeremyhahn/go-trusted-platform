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

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// containerSubOpcodes is the set of container opcodes accepted as compute
// extended category sub-opcodes.
var containerSubOpcodes = map[byte]bool{
	quicwire.OpContainerCreate: true,
	quicwire.OpContainerStart:  true,
	quicwire.OpContainerStop:   true,
	quicwire.OpContainerRemove: true,
	quicwire.OpContainerGet:    true,
	quicwire.OpContainerList:   true,
	quicwire.OpContainerAttest: true,

	quicwire.OpContainerExec:    true,
	quicwire.OpContainerMetrics: true,
}

// IsContainerSubOpcode reports whether op is a container operation that may
// be carried as a compute extended category sub-opcode in payload[0].
func IsContainerSubOpcode(op byte) bool {
	return containerSubOpcodes[op]
}

// Container pagination defaults
const (
	containerDefaultLimit int32 = 50
	containerMaxLimit     int32 = 1000
)

// Container-specific sentinel errors
var (
	// ErrContainerOrchestratorNotAvailable is returned when the container
	// orchestrator is not configured or unavailable.
	ErrContainerOrchestratorNotAvailable = errors.New("container orchestrator not available")

	// ErrContainerMissingID is returned when a container ID is required but not provided.
	ErrContainerMissingID = errors.New("container ID is required")

	// ErrContainerMissingName is returned when a container name is required but not provided.
	ErrContainerMissingName = errors.New("container name is required")

	// ErrContainerMissingImage is returned when a container image is required but not provided.
	ErrContainerMissingImage = errors.New("container image is required")
)

// ContainerHandler handles container operations over QUIC
type ContainerHandler struct {
	orchestrator container.ContainerOrchestrator
	logger       *logging.Logger
}

// NewContainerHandler creates a new container handler
func NewContainerHandler(logger *logging.Logger, orchestrator container.ContainerOrchestrator) *ContainerHandler {
	return &ContainerHandler{
		orchestrator: orchestrator,
		logger:       logger,
	}
}

// HandleRequest processes a container request and returns a response
func (h *ContainerHandler) HandleRequest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if req == nil {
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte(quicwire.ErrNilRequest.Error()),
		}
	}

	switch req.Opcode {
	case quicwire.OpContainerCreate:
		return h.handleCreate(ctx, req)
	case quicwire.OpContainerStart:
		return h.handleStart(ctx, req)
	case quicwire.OpContainerStop:
		return h.handleStop(ctx, req)
	case quicwire.OpContainerRemove:
		return h.handleRemove(ctx, req)
	case quicwire.OpContainerGet:
		return h.handleGet(ctx, req)
	case quicwire.OpContainerList:
		return h.handleList(ctx, req)
	case quicwire.OpContainerAttest:
		return h.handleAttest(ctx, req)
	default:
		return &quicwire.Response{
			Status:  quicwire.StatusInvalidRequest,
			Payload: []byte("unknown container operation"),
		}
	}
}

// =============================================================================
// Request/Response Types
// =============================================================================

// ContainerCreateRequest represents a container creation request
type ContainerCreateRequest struct {
	Name          string            `codec:"name"`
	Image         string            `codec:"image"`
	Command       []string          `codec:"command"`
	Args          []string          `codec:"args"`
	Env           map[string]string `codec:"env"`
	Labels        map[string]string `codec:"labels"`
	User          string            `codec:"user"`
	WorkingDir    string            `codec:"working_dir"`
	Privileged    bool              `codec:"privileged"`
	NetworkMode   string            `codec:"network_mode"`
	Mounts        []ContainerMount  `codec:"mounts"`
	Ports         []ContainerPort   `codec:"ports"`
	CapAdd        []string          `codec:"cap_add"`
	CapDrop       []string          `codec:"cap_drop"`
	CPULimit      string            `codec:"cpu_limit"`
	MemoryLimit   string            `codec:"memory_limit"`
	RestartPolicy string            `codec:"restart_policy"`
}

// ContainerMount represents a mount configuration
type ContainerMount struct {
	Source   string `codec:"source"`
	Target   string `codec:"target"`
	Type     string `codec:"type"`
	ReadOnly bool   `codec:"read_only"`
}

// ContainerPort represents a port mapping
type ContainerPort struct {
	HostIP        string `codec:"host_ip"`
	HostPort      uint16 `codec:"host_port"`
	ContainerPort uint16 `codec:"container_port"`
	Protocol      string `codec:"protocol"`
}

// ContainerCreateResponse represents a container creation response
type ContainerCreateResponse struct {
	Container *ContainerInfo `codec:"container"`
	Timestamp int64          `codec:"timestamp"`
}

// ContainerInfo contains container information
type ContainerInfo struct {
	ID              string            `codec:"id"`
	Name            string            `codec:"name"`
	Image           string            `codec:"image"`
	ImageID         string            `codec:"image_id"`
	State           string            `codec:"state"`
	CreatedAt       int64             `codec:"created_at"`
	StartedAt       int64             `codec:"started_at"`
	FinishedAt      int64             `codec:"finished_at"`
	ExitCode        int               `codec:"exit_code"`
	Pid             int               `codec:"pid"`
	Labels          map[string]string `codec:"labels"`
	NetworkSettings *NetworkSettings  `codec:"network_settings"`
	Platform        string            `codec:"platform"`
}

// NetworkSettings contains container network information
type NetworkSettings struct {
	IPAddress  string                   `codec:"ip_address"`
	Gateway    string                   `codec:"gateway"`
	MACAddress string                   `codec:"mac_address"`
	Ports      map[string][]PortBinding `codec:"ports"`
	Networks   map[string]*NetworkInfo  `codec:"networks"`
}

// PortBinding represents a port binding
type PortBinding struct {
	HostIP   string `codec:"host_ip"`
	HostPort string `codec:"host_port"`
}

// NetworkInfo contains network information
type NetworkInfo struct {
	NetworkID  string `codec:"network_id"`
	IPAddress  string `codec:"ip_address"`
	Gateway    string `codec:"gateway"`
	MACAddress string `codec:"mac_address"`
}

// ContainerStartRequest represents a container start request
type ContainerStartRequest struct {
	ID string `codec:"id"`
}

// ContainerStartResponse represents a container start response
type ContainerStartResponse struct {
	ID        string `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// ContainerStopRequest represents a container stop request
type ContainerStopRequest struct {
	ID      string `codec:"id"`
	Timeout int32  `codec:"timeout"`
}

// ContainerStopResponse represents a container stop response
type ContainerStopResponse struct {
	ID        string `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// ContainerRemoveRequest represents a container removal request
type ContainerRemoveRequest struct {
	ID    string `codec:"id"`
	Force bool   `codec:"force"`
}

// ContainerRemoveResponse represents a container removal response
type ContainerRemoveResponse struct {
	ID        string `codec:"id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// ContainerGetRequest represents a container get request
type ContainerGetRequest struct {
	ID string `codec:"id"`
}

// ContainerGetResponse represents a container get response
type ContainerGetResponse struct {
	Container *ContainerInfo `codec:"container"`
	Timestamp int64          `codec:"timestamp"`
}

// ContainerListRequest represents a container list request
type ContainerListRequest struct {
	All     bool              `codec:"all"`
	Limit   int32             `codec:"limit"`
	Filters map[string]string `codec:"filters"`
}

// ContainerListResponse represents a container list response
type ContainerListResponse struct {
	Containers []*ContainerInfo `codec:"containers"`
	Count      int32            `codec:"count"`
	Timestamp  int64            `codec:"timestamp"`
}

// ContainerAttestRequest represents a container attestation request
type ContainerAttestRequest struct {
	ID string `codec:"id"`
}

// ContainerAttestResponse represents a container attestation response
type ContainerAttestResponse struct {
	ContainerID   string         `codec:"container_id"`
	ContainerName string         `codec:"container_name"`
	Verified      bool           `codec:"verified"`
	Timestamp     int64          `codec:"timestamp"`
	Quote         []byte         `codec:"quote"`
	Signature     []byte         `codec:"signature"`
	ImageDigest   []byte         `codec:"image_digest"`
	ConfigDigest  []byte         `codec:"config_digest"`
	PCRValues     map[int][]byte `codec:"pcr_values"`
}

// =============================================================================
// Handler Methods
// =============================================================================

// handleCreate creates a new container
func (h *ContainerHandler) handleCreate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrContainerOrchestratorNotAvailable)
	}

	var createReq ContainerCreateRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrContainerDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrContainerMissingName)
	}

	if createReq.Image == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrContainerMissingImage)
	}

	// Build container spec from request
	spec := h.buildSpecFromRequest(&createReq)

	// Create container
	containerObj, err := h.orchestrator.Create(ctx, spec)
	if err != nil {
		h.logger.Error(err, "failed to create container")
		return h.containerErrorResponse(err)
	}

	resp := &ContainerCreateResponse{
		Container: h.containerToInfo(containerObj),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrContainerEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleStart starts a stopped container
func (h *ContainerHandler) handleStart(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrContainerOrchestratorNotAvailable)
	}

	var startReq ContainerStartRequest
	if err := quicwire.DecodePayload(req.Payload, &startReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrContainerDecodingFailed{Cause: err})
	}

	if startReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrContainerMissingID)
	}

	if err := h.orchestrator.Start(ctx, startReq.ID); err != nil {
		h.logger.Error(err, "failed to start container")
		return h.containerErrorResponse(err)
	}

	resp := &ContainerStartResponse{
		ID:        startReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrContainerEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleStop stops a running container
func (h *ContainerHandler) handleStop(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrContainerOrchestratorNotAvailable)
	}

	var stopReq ContainerStopRequest
	if err := quicwire.DecodePayload(req.Payload, &stopReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrContainerDecodingFailed{Cause: err})
	}

	if stopReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrContainerMissingID)
	}

	// Convert timeout from seconds to duration
	timeout := time.Duration(stopReq.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second // default timeout
	}

	if err := h.orchestrator.Stop(ctx, stopReq.ID, timeout); err != nil {
		h.logger.Error(err, "failed to stop container")
		return h.containerErrorResponse(err)
	}

	resp := &ContainerStopResponse{
		ID:        stopReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrContainerEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleRemove removes a container
func (h *ContainerHandler) handleRemove(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrContainerOrchestratorNotAvailable)
	}

	var removeReq ContainerRemoveRequest
	if err := quicwire.DecodePayload(req.Payload, &removeReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrContainerDecodingFailed{Cause: err})
	}

	if removeReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrContainerMissingID)
	}

	if err := h.orchestrator.Remove(ctx, removeReq.ID, removeReq.Force); err != nil {
		h.logger.Error(err, "failed to remove container")
		return h.containerErrorResponse(err)
	}

	resp := &ContainerRemoveResponse{
		ID:        removeReq.ID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrContainerEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleGet retrieves a container by ID
func (h *ContainerHandler) handleGet(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrContainerOrchestratorNotAvailable)
	}

	var getReq ContainerGetRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrContainerDecodingFailed{Cause: err})
	}

	if getReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrContainerMissingID)
	}

	containerObj, err := h.orchestrator.Get(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get container")
		return h.containerErrorResponse(err)
	}

	resp := &ContainerGetResponse{
		Container: h.containerToInfo(containerObj),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrContainerEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleList lists containers
func (h *ContainerHandler) handleList(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrContainerOrchestratorNotAvailable)
	}

	var listReq ContainerListRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrContainerDecodingFailed{Cause: err})
	}

	// Build list options
	opts := container.ListOptions{
		All: listReq.All,
	}

	if listReq.Limit > 0 {
		limit := listReq.Limit
		if limit > containerMaxLimit {
			limit = containerMaxLimit
		}
		opts.Limit = int(limit)
	} else {
		opts.Limit = int(containerDefaultLimit)
	}

	// Convert filters
	if len(listReq.Filters) > 0 {
		opts.Filters = make(map[string][]string)
		for k, v := range listReq.Filters {
			opts.Filters[k] = []string{v}
		}
	}

	containers, err := h.orchestrator.List(ctx, opts)
	if err != nil {
		h.logger.Error(err, "failed to list containers")
		return h.containerErrorResponse(err)
	}

	containerInfos := make([]*ContainerInfo, 0, len(containers))
	for _, c := range containers {
		containerInfos = append(containerInfos, h.containerToInfo(c))
	}

	resp := &ContainerListResponse{
		Containers: containerInfos,
		Count:      int32(len(containerInfos)),
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrContainerEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// handleAttest performs TPM attestation for a container
func (h *ContainerHandler) handleAttest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.orchestrator == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrContainerOrchestratorNotAvailable)
	}

	var attestReq ContainerAttestRequest
	if err := quicwire.DecodePayload(req.Payload, &attestReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrContainerDecodingFailed{Cause: err})
	}

	if attestReq.ID == "" {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrContainerMissingID)
	}

	report, err := h.orchestrator.Attest(ctx, attestReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to attest container")
		return h.containerErrorResponse(err)
	}

	resp := &ContainerAttestResponse{
		ContainerID:   report.ContainerID,
		ContainerName: report.ContainerName,
		Verified:      report.Verified,
		Timestamp:     report.Timestamp.Unix(),
		Quote:         report.Quote,
		Signature:     report.Signature,
		// The report carries canonical OCI digest strings
		// ("sha256:<64 hex>"); the wire field is bytes, so the ASCII of
		// that canonical form is what crosses the wire.
		ImageDigest:  []byte(report.ImageDigest),
		ConfigDigest: []byte(report.ConfigDigest),
		PCRValues:    report.PCRValues,
	}

	payload, err := quicwire.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrContainerEncodingFailed{Cause: err})
	}

	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Helper Methods
// =============================================================================

// buildSpecFromRequest creates an OrchestratorContainerSpec from a create request
func (h *ContainerHandler) buildSpecFromRequest(req *ContainerCreateRequest) *container.OrchestratorContainerSpec {
	spec := &container.OrchestratorContainerSpec{
		Name:       req.Name,
		Image:      req.Image,
		Command:    req.Command,
		Args:       req.Args,
		Env:        req.Env,
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

// containerToInfo converts a container.Container to ContainerInfo
func (h *ContainerHandler) containerToInfo(c *container.Container) *ContainerInfo {
	if c == nil {
		return nil
	}

	info := &ContainerInfo{
		ID:        c.ID,
		Name:      c.Name,
		Image:     c.Image,
		ImageID:   c.ImageID,
		State:     string(c.State),
		CreatedAt: c.CreatedAt.Unix(),
		ExitCode:  c.ExitCode,
		Pid:       c.Pid,
		Labels:    c.Labels,
		Platform:  c.Platform,
	}

	if !c.StartedAt.IsZero() {
		info.StartedAt = c.StartedAt.Unix()
	}
	if !c.FinishedAt.IsZero() {
		info.FinishedAt = c.FinishedAt.Unix()
	}

	// Convert network settings
	if c.NetworkSettings != nil {
		info.NetworkSettings = &NetworkSettings{
			IPAddress:  c.NetworkSettings.IPAddress,
			Gateway:    c.NetworkSettings.Gateway,
			MACAddress: c.NetworkSettings.MACAddress,
		}

		if len(c.NetworkSettings.Ports) > 0 {
			info.NetworkSettings.Ports = make(map[string][]PortBinding)
			for k, bindings := range c.NetworkSettings.Ports {
				quicBindings := make([]PortBinding, len(bindings))
				for i, b := range bindings {
					quicBindings[i] = PortBinding{
						HostIP:   b.HostIP,
						HostPort: b.HostPort,
					}
				}
				info.NetworkSettings.Ports[k] = quicBindings
			}
		}

		if len(c.NetworkSettings.Networks) > 0 {
			info.NetworkSettings.Networks = make(map[string]*NetworkInfo)
			for k, net := range c.NetworkSettings.Networks {
				info.NetworkSettings.Networks[k] = &NetworkInfo{
					NetworkID:  net.NetworkID,
					IPAddress:  net.IPAddress,
					Gateway:    net.Gateway,
					MACAddress: net.MACAddress,
				}
			}
		}
	}

	return info
}

// errorResponse creates an error response with the given status and error
func (h *ContainerHandler) errorResponse(status byte, err error) *quicwire.Response {
	return &quicwire.Response{
		Status:  status,
		Payload: []byte(err.Error()),
	}
}

// containerErrorResponse maps container errors to appropriate status codes
func (h *ContainerHandler) containerErrorResponse(err error) *quicwire.Response {
	var status byte

	switch {
	case errors.Is(err, container.ErrContainerNotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, container.ErrContainerExists):
		status = quicwire.StatusAlreadyExists
	case errors.Is(err, container.ErrContainerRunning):
		status = quicwire.StatusInvalidRequest
	case errors.Is(err, container.ErrContainerStopped):
		status = quicwire.StatusInvalidRequest
	case errors.Is(err, container.ErrInvalidSpec):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, container.ErrInvalidName):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, container.ErrInvalidImage):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, container.ErrInvalidContainerID):
		status = quicwire.StatusInvalidArgument
	case errors.Is(err, container.ErrAttestationFailed):
		status = quicwire.StatusInternalError
	case errors.Is(err, container.ErrPolicyDenied):
		status = quicwire.StatusPermissionDenied
	case errors.Is(err, container.ErrOrchestratorNotInitialized):
		status = quicwire.StatusUnavailable
	case errors.Is(err, container.ErrOrchestratorClosed):
		status = quicwire.StatusUnavailable
	case errors.Is(err, container.ErrOperationTimeout):
		status = quicwire.StatusTimeout
	case errors.Is(err, container.ErrImageNotFound):
		status = quicwire.StatusNotFound
	case errors.Is(err, container.ErrImageVerificationFailed):
		status = quicwire.StatusPermissionDenied
	case errors.Is(err, container.ErrImagePullFailed):
		status = quicwire.StatusInternalError
	default:
		status = quicwire.StatusInternalError
	}

	return h.errorResponse(status, err)
}

// =============================================================================
// Container Error Types
// =============================================================================

// ErrContainerEncodingFailed represents an encoding failure error
type ErrContainerEncodingFailed struct {
	Cause error
}

func (e ErrContainerEncodingFailed) Error() string {
	return "failed to encode container payload: " + e.Cause.Error()
}

func (e ErrContainerEncodingFailed) Unwrap() error {
	return e.Cause
}

// ErrContainerDecodingFailed represents a decoding failure error
type ErrContainerDecodingFailed struct {
	Cause error
}

func (e ErrContainerDecodingFailed) Error() string {
	return "failed to decode container payload: " + e.Cause.Error()
}

func (e ErrContainerDecodingFailed) Unwrap() error {
	return e.Cause
}

// ErrContainerOperationFailed represents a container operation failure
type ErrContainerOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrContainerOperationFailed) Error() string {
	return "container operation " + e.Operation + " failed: " + e.Cause.Error()
}

func (e ErrContainerOperationFailed) Unwrap() error {
	return e.Cause
}
