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

package grpc

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ContainerService error types.

// ErrNilOrchestrator is returned when the orchestrator is nil.
type ErrNilOrchestrator struct{}

func (e ErrNilOrchestrator) Error() string {
	return "container orchestrator is nil"
}

// ErrMissingContainerID is returned when a container ID is required but not provided.
type ErrMissingContainerID struct{}

func (e ErrMissingContainerID) Error() string {
	return "container ID is required"
}

// ErrMissingContainerConfig is returned when container configuration is required but not provided.
type ErrMissingContainerConfig struct{}

func (e ErrMissingContainerConfig) Error() string {
	return "container configuration is required"
}

// ErrMissingContainerName is returned when container name is required but not provided.
type ErrMissingContainerName struct{}

func (e ErrMissingContainerName) Error() string {
	return "container name is required"
}

// ErrMissingContainerImage is returned when container image is required but not provided.
type ErrMissingContainerImage struct{}

func (e ErrMissingContainerImage) Error() string {
	return "container image is required"
}

// ErrStreamSend is returned when sending to a gRPC stream fails.
type ErrStreamSend struct {
	Cause error
}

func (e ErrStreamSend) Error() string {
	return "failed to send stream message: " + e.Cause.Error()
}

func (e ErrStreamSend) Unwrap() error {
	return e.Cause
}

// ContainerGRPCService implements gRPC service methods for container operations.
// It wraps the container.ContainerOrchestrator interface to provide gRPC access
// to container lifecycle management, logs streaming, and TPM attestation.
type ContainerGRPCService struct {
	logger       *logging.Logger
	orchestrator container.ContainerOrchestrator
}

// NewContainerGRPCService creates a new ContainerGRPCService instance.
func NewContainerGRPCService(
	logger *logging.Logger,
	orchestrator container.ContainerOrchestrator,
) *ContainerGRPCService {
	return &ContainerGRPCService{
		logger:       logger,
		orchestrator: orchestrator,
	}
}

// CreateContainer creates a new container from the provided configuration.
func (s *ContainerGRPCService) CreateContainer(
	ctx context.Context,
	req *platformv1.CreateContainerRequest,
) (*platformv1.CreateContainerResponse, error) {

	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilOrchestrator{}.Error())
	}

	config := req.GetConfig()
	if config == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingContainerConfig{}.Error())
	}

	if config.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingContainerName{}.Error())
	}

	if config.GetImage() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingContainerImage{}.Error())
	}

	spec := s.protoConfigToSpec(config)

	created, err := s.orchestrator.Create(ctx, spec)
	if err != nil {
		return nil, s.mapError("CreateContainer", err)
	}

	// Optionally start the container if requested
	if req.GetStart() {
		if startErr := s.orchestrator.Start(ctx, created.ID); startErr != nil {
			s.logger.Error(startErr, "container created but failed to start",
				"container_id", created.ID)
			// Still return the container, but with the start error in the status
			return &platformv1.CreateContainerResponse{
				Status: &platformv1.Status{
					Success: false,
					Message: "container created but failed to start: " + startErr.Error(),
				},
				Container: s.containerToProto(created),
			}, nil
		}
		// Refresh container state after start
		created, err = s.orchestrator.Get(ctx, created.ID)
		if err != nil {
			return nil, s.mapError("CreateContainer", err)
		}
	}

	return &platformv1.CreateContainerResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "container created successfully",
		},
		Container: s.containerToProto(created),
	}, nil
}

// StartContainer starts a stopped container.
func (s *ContainerGRPCService) StartContainer(
	ctx context.Context,
	req *platformv1.StartContainerRequest,
) (*platformv1.StartContainerResponse, error) {

	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilOrchestrator{}.Error())
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingContainerID{}.Error())
	}

	if err := s.orchestrator.Start(ctx, containerID); err != nil {
		return nil, s.mapError("StartContainer", err)
	}

	return &platformv1.StartContainerResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "container started successfully",
		},
	}, nil
}

// StopContainer stops a running container.
func (s *ContainerGRPCService) StopContainer(
	ctx context.Context,
	req *platformv1.StopContainerRequest,
) (*platformv1.StopContainerResponse, error) {

	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilOrchestrator{}.Error())
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingContainerID{}.Error())
	}

	timeout := time.Duration(req.GetTimeoutSeconds()) * time.Second
	if timeout == 0 {
		timeout = 30 * time.Second // Default timeout
	}

	if err := s.orchestrator.Stop(ctx, containerID, timeout); err != nil {
		return nil, s.mapError("StopContainer", err)
	}

	return &platformv1.StopContainerResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "container stopped successfully",
		},
	}, nil
}

// DeleteContainer removes a container.
func (s *ContainerGRPCService) DeleteContainer(
	ctx context.Context,
	req *platformv1.DeleteContainerRequest,
) (*platformv1.DeleteContainerResponse, error) {

	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilOrchestrator{}.Error())
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingContainerID{}.Error())
	}

	force := req.GetForce()

	if err := s.orchestrator.Remove(ctx, containerID, force); err != nil {
		return nil, s.mapError("DeleteContainer", err)
	}

	return &platformv1.DeleteContainerResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "container deleted successfully",
		},
	}, nil
}

// GetContainer retrieves a container by ID.
func (s *ContainerGRPCService) GetContainer(
	ctx context.Context,
	req *platformv1.GetContainerRequest,
) (*platformv1.GetContainerResponse, error) {

	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilOrchestrator{}.Error())
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingContainerID{}.Error())
	}

	c, err := s.orchestrator.Get(ctx, containerID)
	if err != nil {
		return nil, s.mapError("GetContainer", err)
	}

	return &platformv1.GetContainerResponse{
		Container: s.containerToProto(c),
	}, nil
}

// ListContainers returns containers matching the filter options.
func (s *ContainerGRPCService) ListContainers(
	ctx context.Context,
	req *platformv1.ListContainersRequest,
) (*platformv1.ListContainersResponse, error) {

	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilOrchestrator{}.Error())
	}

	opts := s.protoToListOptions(req)

	containers, err := s.orchestrator.List(ctx, opts)
	if err != nil {
		return nil, s.mapError("ListContainers", err)
	}

	protoContainers := make([]*platformv1.Container, 0, len(containers))
	for _, c := range containers {
		protoContainers = append(protoContainers, s.containerToProto(c))
	}

	// Build pagination response
	pagination := req.GetPagination()
	var paginationResp *platformv1.PaginationResponse
	if pagination != nil {
		pageSize := pagination.GetPageSize()
		if pageSize == 0 {
			pageSize = 50
		}
		totalItems := uint64(len(protoContainers))
		totalPages := uint32((totalItems + uint64(pageSize) - 1) / uint64(pageSize))

		paginationResp = &platformv1.PaginationResponse{
			Page:       pagination.GetPage(),
			PageSize:   pageSize,
			TotalPages: totalPages,
			TotalItems: totalItems,
		}
	}

	return &platformv1.ListContainersResponse{
		Containers: protoContainers,
		Pagination: paginationResp,
	}, nil
}

// GetContainerLogs streams container logs.
func (s *ContainerGRPCService) GetContainerLogs(
	req *platformv1.GetContainerLogsRequest,
	stream platformv1.ComputeService_GetContainerLogsServer,
) error {

	if s.orchestrator == nil {
		return status.Error(codes.FailedPrecondition, ErrNilOrchestrator{}.Error())
	}

	containerID := req.GetId()
	if containerID == "" {
		return status.Error(codes.InvalidArgument, ErrMissingContainerID{}.Error())
	}

	opts := container.LogOptions{
		Follow:     req.GetFollow(),
		Stdout:     req.GetStdout(),
		Stderr:     req.GetStderr(),
		Timestamps: true,
	}

	if !opts.Stdout && !opts.Stderr {
		// Default to both streams
		opts.Stdout = true
		opts.Stderr = true
	}

	if req.GetTailLines() > 0 {
		opts.Tail = string(rune(req.GetTailLines()))
	}

	if req.GetSince() != nil {
		opts.Since = req.GetSince().AsTime()
	}

	reader, err := s.orchestrator.Logs(stream.Context(), containerID, opts)
	if err != nil {
		return s.mapError("GetContainerLogs", err)
	}
	defer reader.Close()

	buf := make([]byte, 4096)
	for {
		select {
		case <-stream.Context().Done():
			return stream.Context().Err()
		default:
			n, readErr := reader.Read(buf)
			if n > 0 {
				logEntry := &platformv1.LogEntry{
					Timestamp: timestamppb.Now(),
					Level:     "INFO",
					Message:   string(buf[:n]),
					Source:    containerID,
				}
				if sendErr := stream.Send(logEntry); sendErr != nil {
					return status.Error(codes.Internal, ErrStreamSend{Cause: sendErr}.Error())
				}
			}
			if readErr != nil {
				if readErr == io.EOF {
					return nil
				}
				return s.mapError("GetContainerLogs", readErr)
			}
		}
	}
}

// AttestContainer performs TPM attestation for a container.
func (s *ContainerGRPCService) AttestContainer(
	ctx context.Context,
	containerID string,
) (*platformv1.AttestVMResponse, error) {

	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilOrchestrator{}.Error())
	}

	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingContainerID{}.Error())
	}

	report, err := s.orchestrator.Attest(ctx, containerID)
	if err != nil {
		return nil, s.mapError("AttestContainer", err)
	}

	// Convert PCR values to proto format
	pcrValues := make([]*platformv1.PCRValue, 0, len(report.PCRValues))
	for idx, value := range report.PCRValues {
		pcrValues = append(pcrValues, &platformv1.PCRValue{
			Index: uint32(idx),
			Value: value,
		})
	}

	return &platformv1.AttestVMResponse{
		Status: &platformv1.Status{
			Success: report.Verified,
			Message: "attestation completed",
		},
		Quote:     report.Quote,
		Signature: report.Signature,
		PcrValues: pcrValues,
		AkPublic:  report.AIKCertificate,
	}, nil
}

// protoConfigToSpec converts a protobuf ContainerConfig to an OrchestratorContainerSpec.
func (s *ContainerGRPCService) protoConfigToSpec(config *platformv1.ContainerConfig) *container.OrchestratorContainerSpec {
	spec := &container.OrchestratorContainerSpec{
		Name:       config.GetName(),
		Image:      config.GetImage(),
		Command:    config.GetCommand(),
		Args:       config.GetArgs(),
		WorkingDir: config.GetWorkingDir(),
		Privileged: config.GetPrivileged(),
		Labels:     config.GetLabels(),
	}

	// Convert environment variables
	env := config.GetEnv()
	if len(env) > 0 {
		spec.Env = make(map[string]string)
		for _, e := range env {
			spec.Env[e.GetName()] = e.GetValue()
		}
	}

	// Convert volume mounts
	volumes := config.GetVolumes()
	if len(volumes) > 0 {
		spec.Mounts = make([]container.MountConfig, 0, len(volumes))
		for _, v := range volumes {
			spec.Mounts = append(spec.Mounts, container.MountConfig{
				Source:   v.GetSource(),
				Target:   v.GetDestination(),
				ReadOnly: v.GetReadonly(),
				Type:     container.MountType(v.GetType()),
			})
		}
	}

	// Convert port mappings
	ports := config.GetPorts()
	if len(ports) > 0 {
		spec.Ports = make([]container.PortMapping, 0, len(ports))
		for _, p := range ports {
			spec.Ports = append(spec.Ports, container.PortMapping{
				ContainerPort: uint16(p.GetContainerPort()),
				HostPort:      uint16(p.GetHostPort()),
				HostIP:        p.GetHostIp(),
				Protocol:      p.GetProtocol(),
			})
		}
	}

	// Convert capabilities
	caps := config.GetCapabilities()
	if len(caps) > 0 {
		spec.Capabilities = container.CapabilityConfig{
			Add: caps,
		}
	}

	// Convert resource limits
	resources := config.GetResources()
	if resources != nil {
		spec.Resources = container.ResourceConfig{
			CPUShares:   int64(resources.GetMaxCpus()),
			PidsLimit:   int64(resources.GetMaxInstances()),
			MemoryLimit: s.formatMemory(resources.GetMaxMemoryMb()),
		}
	}

	// Convert restart policy
	restartPolicy := config.GetRestartPolicy()
	switch restartPolicy {
	case platformv1.RestartPolicy_RESTART_POLICY_ALWAYS:
		spec.RestartPolicy = container.RestartAlways
	case platformv1.RestartPolicy_RESTART_POLICY_ON_FAILURE:
		spec.RestartPolicy = container.RestartOnFailure
	case platformv1.RestartPolicy_RESTART_POLICY_UNLESS_STOPPED:
		spec.RestartPolicy = container.RestartUnlessStopped
	default:
		spec.RestartPolicy = container.RestartNever
	}

	// Set network mode - default to bridge if not specified
	network := config.GetNetwork()
	switch network {
	case "host":
		spec.Network.Mode = container.NetworkModeHost
	case "none":
		spec.Network.Mode = container.NetworkModeNone
	case "sdn":
		spec.Network.Mode = container.NetworkModeSDN
	default:
		// Default to bridge for empty string or any other unrecognized value
		spec.Network.Mode = container.NetworkModeBridge
	}

	return spec
}

// containerToProto converts a container.Container to a protobuf Container.
func (s *ContainerGRPCService) containerToProto(c *container.Container) *platformv1.Container {
	if c == nil {
		return nil
	}

	proto := &platformv1.Container{
		Id:         c.ID,
		State:      s.stateToProto(c.State),
		CreatedAt:  timestamppb.New(c.CreatedAt),
		StartedAt:  timestamppb.New(c.StartedAt),
		FinishedAt: timestamppb.New(c.FinishedAt),
		ExitCode:   int32(c.ExitCode),
	}

	// Convert spec to config
	if c.Spec != nil {
		proto.Config = s.specToProtoConfig(c.Spec)
	} else {
		proto.Config = &platformv1.ContainerConfig{
			Name:  c.Name,
			Image: c.Image,
		}
	}

	return proto
}

// specToProtoConfig converts an OrchestratorContainerSpec to a protobuf ContainerConfig.
func (s *ContainerGRPCService) specToProtoConfig(spec *container.OrchestratorContainerSpec) *platformv1.ContainerConfig {
	if spec == nil {
		return nil
	}

	config := &platformv1.ContainerConfig{
		Name:       spec.Name,
		Image:      spec.Image,
		Command:    spec.Command,
		Args:       spec.Args,
		WorkingDir: spec.WorkingDir,
		Privileged: spec.Privileged,
		Labels:     spec.Labels,
	}

	// Convert environment variables
	if len(spec.Env) > 0 {
		config.Env = make([]*platformv1.EnvVar, 0, len(spec.Env))
		for name, value := range spec.Env {
			config.Env = append(config.Env, &platformv1.EnvVar{
				Name:  name,
				Value: value,
			})
		}
	}

	// Convert mounts
	if len(spec.Mounts) > 0 {
		config.Volumes = make([]*platformv1.VolumeMount, 0, len(spec.Mounts))
		for _, m := range spec.Mounts {
			config.Volumes = append(config.Volumes, &platformv1.VolumeMount{
				Source:      m.Source,
				Destination: m.Target,
				Readonly:    m.ReadOnly,
				Type:        string(m.Type),
			})
		}
	}

	// Convert ports
	if len(spec.Ports) > 0 {
		config.Ports = make([]*platformv1.PortMapping, 0, len(spec.Ports))
		for _, p := range spec.Ports {
			config.Ports = append(config.Ports, &platformv1.PortMapping{
				ContainerPort: uint32(p.ContainerPort),
				HostPort:      uint32(p.HostPort),
				HostIp:        p.HostIP,
				Protocol:      p.Protocol,
			})
		}
	}

	// Convert capabilities
	if len(spec.Capabilities.Add) > 0 {
		config.Capabilities = spec.Capabilities.Add
	}

	// Convert restart policy
	switch spec.RestartPolicy {
	case container.RestartAlways:
		config.RestartPolicy = platformv1.RestartPolicy_RESTART_POLICY_ALWAYS
	case container.RestartOnFailure:
		config.RestartPolicy = platformv1.RestartPolicy_RESTART_POLICY_ON_FAILURE
	case container.RestartUnlessStopped:
		config.RestartPolicy = platformv1.RestartPolicy_RESTART_POLICY_UNLESS_STOPPED
	default:
		config.RestartPolicy = platformv1.RestartPolicy_RESTART_POLICY_NO
	}

	// Set network mode
	switch spec.Network.Mode {
	case container.NetworkModeHost:
		config.Network = "host"
	case container.NetworkModeNone:
		config.Network = "none"
	case container.NetworkModeSDN:
		config.Network = "sdn"
	default:
		config.Network = "bridge"
	}

	return config
}

// stateToProto converts a container.ContainerState to a protobuf ContainerState.
func (s *ContainerGRPCService) stateToProto(state container.ContainerState) platformv1.ContainerState {
	switch state {
	case container.StateCreated:
		return platformv1.ContainerState_CONTAINER_STATE_CREATED
	case container.StateRunning:
		return platformv1.ContainerState_CONTAINER_STATE_RUNNING
	case container.StatePaused:
		return platformv1.ContainerState_CONTAINER_STATE_PAUSED
	case container.StateStopped:
		return platformv1.ContainerState_CONTAINER_STATE_STOPPED
	case container.StateRestarting:
		return platformv1.ContainerState_CONTAINER_STATE_STARTING
	case container.StateRemoving:
		return platformv1.ContainerState_CONTAINER_STATE_STOPPING
	case container.StateExited:
		return platformv1.ContainerState_CONTAINER_STATE_EXITED
	case container.StateDead:
		return platformv1.ContainerState_CONTAINER_STATE_ERROR
	default:
		return platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED
	}
}

// protoToListOptions converts a protobuf ListContainersRequest to container.ListOptions.
func (s *ContainerGRPCService) protoToListOptions(req *platformv1.ListContainersRequest) container.ListOptions {
	opts := container.ListOptions{
		All: true, // Default to showing all containers
	}

	// Apply state filters
	states := req.GetStates()
	if len(states) > 0 {
		opts.All = false
		opts.Filters = make(map[string][]string)
		stateStrings := make([]string, 0, len(states))
		for _, state := range states {
			stateStrings = append(stateStrings, s.protoStateToString(state))
		}
		opts.Filters["status"] = stateStrings
	}

	// Apply label selector
	selector := req.GetSelector()
	if selector != nil {
		if opts.Filters == nil {
			opts.Filters = make(map[string][]string)
		}
		for key, value := range selector.GetMatchLabels() {
			opts.Filters["label"] = append(opts.Filters["label"], key+"="+value)
		}
	}

	// Apply pagination limit
	pagination := req.GetPagination()
	if pagination != nil && pagination.GetPageSize() > 0 {
		opts.Limit = int(pagination.GetPageSize())
	}

	return opts
}

// protoStateToString converts a protobuf ContainerState to a string.
func (s *ContainerGRPCService) protoStateToString(state platformv1.ContainerState) string {
	switch state {
	case platformv1.ContainerState_CONTAINER_STATE_CREATED:
		return "created"
	case platformv1.ContainerState_CONTAINER_STATE_RUNNING:
		return "running"
	case platformv1.ContainerState_CONTAINER_STATE_PAUSED:
		return "paused"
	case platformv1.ContainerState_CONTAINER_STATE_STOPPED:
		return "stopped"
	case platformv1.ContainerState_CONTAINER_STATE_EXITED:
		return "exited"
	case platformv1.ContainerState_CONTAINER_STATE_STARTING:
		return "starting"
	case platformv1.ContainerState_CONTAINER_STATE_STOPPING:
		return "stopping"
	case platformv1.ContainerState_CONTAINER_STATE_ERROR:
		return "error"
	default:
		return ""
	}
}

// formatMemory converts MB to a memory string format.
func (s *ContainerGRPCService) formatMemory(mb uint64) string {
	if mb == 0 {
		return ""
	}
	if mb >= 1024 {
		return string(rune(mb/1024)) + "G"
	}
	return string(rune(mb)) + "M"
}

// mapError maps container errors to appropriate gRPC status codes.
func (s *ContainerGRPCService) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "container operation failed", "operation", operation)

	var code codes.Code
	switch {
	case errors.Is(err, container.ErrContainerNotFound):
		code = codes.NotFound
	case errors.Is(err, container.ErrContainerExists):
		code = codes.AlreadyExists
	case errors.Is(err, container.ErrContainerRunning):
		code = codes.FailedPrecondition
	case errors.Is(err, container.ErrContainerStopped):
		code = codes.FailedPrecondition
	case errors.Is(err, container.ErrInvalidSpec):
		code = codes.InvalidArgument
	case errors.Is(err, container.ErrInvalidName):
		code = codes.InvalidArgument
	case errors.Is(err, container.ErrInvalidImage):
		code = codes.InvalidArgument
	case errors.Is(err, container.ErrInvalidContainerID):
		code = codes.InvalidArgument
	case errors.Is(err, container.ErrPolicyDenied):
		code = codes.PermissionDenied
	case errors.Is(err, container.ErrAttestationFailed):
		code = codes.FailedPrecondition
	case errors.Is(err, container.ErrAttestationRequired):
		code = codes.FailedPrecondition
	case errors.Is(err, container.ErrOrchestratorNotInitialized):
		code = codes.FailedPrecondition
	case errors.Is(err, container.ErrOrchestratorClosed):
		code = codes.Unavailable
	case errors.Is(err, container.ErrOperationTimeout):
		code = codes.DeadlineExceeded
	case errors.Is(err, container.ErrImageNotFound):
		code = codes.NotFound
	case errors.Is(err, container.ErrImagePullFailed):
		code = codes.Unavailable
	case errors.Is(err, container.ErrRegistryUnreachable):
		code = codes.Unavailable
	case errors.Is(err, container.ErrRegistryAuthFailed):
		code = codes.Unauthenticated
	default:
		code = codes.Internal
	}

	return status.Error(code, err.Error())
}

// AttestationReportToProto converts a container.AttestationReport to a protobuf format.
func (s *ContainerGRPCService) AttestationReportToProto(report *container.AttestationReport) map[string]string {
	if report == nil {
		return nil
	}

	result := map[string]string{
		"container_id":   report.ContainerID,
		"container_name": report.ContainerName,
		"verified":       "false",
		"timestamp":      report.Timestamp.Format(time.RFC3339),
	}

	if report.Verified {
		result["verified"] = "true"
	}

	if len(report.ImageDigest) > 0 {
		result["image_digest"] = hex.EncodeToString(report.ImageDigest)
	}

	if len(report.ConfigDigest) > 0 {
		result["config_digest"] = hex.EncodeToString(report.ConfigDigest)
	}

	if len(report.Quote) > 0 {
		result["quote"] = hex.EncodeToString(report.Quote)
	}

	if len(report.Signature) > 0 {
		result["signature"] = hex.EncodeToString(report.Signature)
	}

	return result
}
