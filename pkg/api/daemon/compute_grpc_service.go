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

package daemon

import (
	"context"
	"fmt"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ComputeGRPCService implements the Compute gRPC service for VM and container operations.
type ComputeGRPCService struct {
	platformv1.UnimplementedComputeServiceServer

	logger       *logging.Logger
	orchestrator compute.Orchestrator
}

// NewComputeGRPCService creates a new Compute gRPC service instance.
func NewComputeGRPCService(logger *logging.Logger, orchestrator compute.Orchestrator) *ComputeGRPCService {
	return &ComputeGRPCService{
		logger:       logger,
		orchestrator: orchestrator,
	}
}

// SetOrchestrator sets the compute orchestrator for the service.
func (s *ComputeGRPCService) SetOrchestrator(orchestrator compute.Orchestrator) {
	s.orchestrator = orchestrator
}

// =============================================================================
// VM Operations
// =============================================================================

// CreateVM creates a new virtual machine.
func (s *ComputeGRPCService) CreateVM(ctx context.Context, req *platformv1.CreateVMRequest) (*platformv1.CreateVMResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	config := req.GetConfig()
	if config == nil {
		return nil, status.Error(codes.InvalidArgument, "VM configuration is required")
	}

	if config.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "VM name is required")
	}

	// Extract memory and CPU from nested config
	memory := 1024 // Default
	cpus := 1      // Default
	if config.GetMemory() != nil {
		memory = int(config.GetMemory().GetSizeMb())
	}
	if config.GetCpu() != nil {
		cpus = int(config.GetCpu().GetCores())
	}

	// Build device profile from request config
	profile := &entities.DeviceProfile{
		Name: config.GetName(),
	}

	// Add metadata for compute settings (we pass these via metadata since DeviceProfile
	// doesn't have direct compute fields)
	profile.Model = fmt.Sprintf("vm:memory=%d,cpus=%d,tpm=%v,secureboot=%v",
		memory, cpus, config.GetTpm() != nil, config.GetSecureBoot())

	// Create the instance using orchestrator
	instance, err := s.orchestrator.Create(ctx, profile)
	if err != nil {
		s.logger.Error(err, "Failed to create VM", "name", config.GetName())
		return nil, status.Error(codes.Internal, "failed to create VM: "+err.Error())
	}

	return &platformv1.CreateVMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VM created successfully",
		},
		Vm: s.instanceToVMProto(instance),
	}, nil
}

// StartVM starts a stopped virtual machine.
func (s *ComputeGRPCService) StartVM(ctx context.Context, req *platformv1.StartVMRequest) (*platformv1.StartVMResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	vmID := req.GetId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}

	if err := s.orchestrator.Start(ctx, vmID); err != nil {
		s.logger.Error(err, "Failed to start VM", "vm_id", vmID)
		return nil, status.Error(codes.Internal, "failed to start VM: "+err.Error())
	}

	return &platformv1.StartVMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VM started successfully",
		},
	}, nil
}

// StopVM stops a running virtual machine.
func (s *ComputeGRPCService) StopVM(ctx context.Context, req *platformv1.StopVMRequest) (*platformv1.StopVMResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	vmID := req.GetId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}

	if err := s.orchestrator.Stop(ctx, vmID); err != nil {
		s.logger.Error(err, "Failed to stop VM", "vm_id", vmID)
		return nil, status.Error(codes.Internal, "failed to stop VM: "+err.Error())
	}

	return &platformv1.StopVMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VM stopped successfully",
		},
	}, nil
}

// RebootVM reboots a virtual machine.
func (s *ComputeGRPCService) RebootVM(ctx context.Context, req *platformv1.RebootVMRequest) (*platformv1.RebootVMResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	vmID := req.GetId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}

	// Reboot by stopping then starting
	if err := s.orchestrator.Stop(ctx, vmID); err != nil {
		s.logger.Error(err, "Failed to stop VM for reboot", "vm_id", vmID)
		return nil, status.Error(codes.Internal, "failed to reboot VM: "+err.Error())
	}

	if err := s.orchestrator.Start(ctx, vmID); err != nil {
		s.logger.Error(err, "Failed to start VM after reboot stop", "vm_id", vmID)
		return nil, status.Error(codes.Internal, "failed to reboot VM: "+err.Error())
	}

	return &platformv1.RebootVMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VM rebooted successfully",
		},
	}, nil
}

// DeleteVM deletes a virtual machine.
func (s *ComputeGRPCService) DeleteVM(ctx context.Context, req *platformv1.DeleteVMRequest) (*platformv1.DeleteVMResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	vmID := req.GetId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}

	if err := s.orchestrator.Delete(ctx, vmID); err != nil {
		s.logger.Error(err, "Failed to delete VM", "vm_id", vmID)
		return nil, status.Error(codes.Internal, "failed to delete VM: "+err.Error())
	}

	return &platformv1.DeleteVMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VM deleted successfully",
		},
	}, nil
}

// GetVM retrieves information about a virtual machine.
func (s *ComputeGRPCService) GetVM(ctx context.Context, req *platformv1.GetVMRequest) (*platformv1.GetVMResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	vmID := req.GetId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}

	instance, err := s.orchestrator.Get(ctx, vmID)
	if err != nil {
		s.logger.Error(err, "Failed to get VM", "vm_id", vmID)
		return nil, status.Error(codes.NotFound, "VM not found: "+vmID)
	}

	return &platformv1.GetVMResponse{
		Vm: s.instanceToVMProto(instance),
	}, nil
}

// ListVMs lists virtual machines.
func (s *ComputeGRPCService) ListVMs(ctx context.Context, req *platformv1.ListVMsRequest) (*platformv1.ListVMsResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	vmType := compute.ComputeTypeVM
	filter := &compute.InstanceFilter{
		Type: &vmType,
	}

	instances, err := s.orchestrator.List(ctx, filter)
	if err != nil {
		s.logger.Error(err, "Failed to list VMs")
		return nil, status.Error(codes.Internal, "failed to list VMs: "+err.Error())
	}

	protoVMs := make([]*platformv1.VM, len(instances))
	for i, instance := range instances {
		protoVMs[i] = s.instanceToVMProto(instance)
	}

	return &platformv1.ListVMsResponse{
		Vms: protoVMs,
	}, nil
}

// =============================================================================
// VM Console and Monitoring (Streaming)
// =============================================================================

// AttachVMConsole attaches to a VM console (server streaming).
func (s *ComputeGRPCService) AttachVMConsole(req *platformv1.AttachVMConsoleRequest, stream grpc.ServerStreamingServer[platformv1.ConsoleOutput]) error {
	// Console attachment not yet implemented in orchestrator
	return status.Error(codes.Unimplemented, "VM console attachment not yet implemented")
}

// SendVMConsoleInput sends input to a VM console (client streaming).
func (s *ComputeGRPCService) SendVMConsoleInput(stream grpc.ClientStreamingServer[platformv1.ConsoleInput, platformv1.ConsoleInputResponse]) error {
	// Console input not yet implemented in orchestrator
	return status.Error(codes.Unimplemented, "VM console input not yet implemented")
}

// GetVMLogs streams VM logs (server streaming).
func (s *ComputeGRPCService) GetVMLogs(req *platformv1.GetVMLogsRequest, stream grpc.ServerStreamingServer[platformv1.LogEntry]) error {
	// Log streaming not yet implemented in orchestrator
	return status.Error(codes.Unimplemented, "VM log streaming not yet implemented")
}

// GetVMMetrics retrieves VM metrics.
func (s *ComputeGRPCService) GetVMMetrics(ctx context.Context, req *platformv1.GetVMMetricsRequest) (*platformv1.VMMetricsResponse, error) {
	// Metrics collection not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "VM metrics not yet implemented")
}

// =============================================================================
// VM Disk Operations
// =============================================================================

// AttachDisk attaches a disk to a VM.
func (s *ComputeGRPCService) AttachDisk(ctx context.Context, req *platformv1.AttachDiskRequest) (*platformv1.AttachDiskResponse, error) {
	// Disk attachment not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "disk attachment not yet implemented")
}

// DetachDisk detaches a disk from a VM.
func (s *ComputeGRPCService) DetachDisk(ctx context.Context, req *platformv1.DetachDiskRequest) (*platformv1.DetachDiskResponse, error) {
	// Disk detachment not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "disk detachment not yet implemented")
}

// ResizeDisk resizes a VM disk.
func (s *ComputeGRPCService) ResizeDisk(ctx context.Context, req *platformv1.ResizeDiskRequest) (*platformv1.ResizeDiskResponse, error) {
	// Disk resize not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "disk resize not yet implemented")
}

// =============================================================================
// VM Snapshot Operations
// =============================================================================

// CreateSnapshot creates a VM snapshot.
func (s *ComputeGRPCService) CreateSnapshot(ctx context.Context, req *platformv1.CreateSnapshotRequest) (*platformv1.CreateSnapshotResponse, error) {
	// Snapshots not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "snapshots not yet implemented")
}

// RestoreSnapshot restores a VM from a snapshot.
func (s *ComputeGRPCService) RestoreSnapshot(ctx context.Context, req *platformv1.RestoreSnapshotRequest) (*platformv1.RestoreSnapshotResponse, error) {
	// Snapshots not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "snapshots not yet implemented")
}

// DeleteSnapshot deletes a VM snapshot.
func (s *ComputeGRPCService) DeleteSnapshot(ctx context.Context, req *platformv1.DeleteSnapshotRequest) (*platformv1.DeleteSnapshotResponse, error) {
	// Snapshots not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "snapshots not yet implemented")
}

// ListSnapshots lists VM snapshots.
func (s *ComputeGRPCService) ListSnapshots(ctx context.Context, req *platformv1.ListSnapshotsRequest) (*platformv1.ListSnapshotsResponse, error) {
	// Snapshots not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "snapshots not yet implemented")
}

// MigrateVM migrates a VM to another host.
func (s *ComputeGRPCService) MigrateVM(ctx context.Context, req *platformv1.MigrateVMRequest) (*platformv1.MigrateVMResponse, error) {
	// Migration not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "VM migration not yet implemented")
}

// =============================================================================
// Container Operations
// =============================================================================

// CreateContainer creates a new container.
func (s *ComputeGRPCService) CreateContainer(ctx context.Context, req *platformv1.CreateContainerRequest) (*platformv1.CreateContainerResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	config := req.GetConfig()
	if config == nil {
		return nil, status.Error(codes.InvalidArgument, "container configuration is required")
	}

	if config.GetImage() == "" {
		return nil, status.Error(codes.InvalidArgument, "container image is required")
	}

	// Build device profile from request config
	profile := &entities.DeviceProfile{
		Name:  config.GetName(),
		Model: fmt.Sprintf("container:image=%s", config.GetImage()),
	}

	// Create the instance using orchestrator
	instance, err := s.orchestrator.Create(ctx, profile)
	if err != nil {
		s.logger.Error(err, "Failed to create container")
		return nil, status.Error(codes.Internal, "failed to create container: "+err.Error())
	}

	return &platformv1.CreateContainerResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "Container created successfully",
		},
		Container: s.instanceToContainerProto(instance),
	}, nil
}

// StartContainer starts a stopped container.
func (s *ComputeGRPCService) StartContainer(ctx context.Context, req *platformv1.StartContainerRequest) (*platformv1.StartContainerResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, "container ID is required")
	}

	if err := s.orchestrator.Start(ctx, containerID); err != nil {
		s.logger.Error(err, "Failed to start container", "container_id", containerID)
		return nil, status.Error(codes.Internal, "failed to start container: "+err.Error())
	}

	return &platformv1.StartContainerResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "Container started successfully",
		},
	}, nil
}

// StopContainer stops a running container.
func (s *ComputeGRPCService) StopContainer(ctx context.Context, req *platformv1.StopContainerRequest) (*platformv1.StopContainerResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, "container ID is required")
	}

	if err := s.orchestrator.Stop(ctx, containerID); err != nil {
		s.logger.Error(err, "Failed to stop container", "container_id", containerID)
		return nil, status.Error(codes.Internal, "failed to stop container: "+err.Error())
	}

	return &platformv1.StopContainerResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "Container stopped successfully",
		},
	}, nil
}

// DeleteContainer deletes a container.
func (s *ComputeGRPCService) DeleteContainer(ctx context.Context, req *platformv1.DeleteContainerRequest) (*platformv1.DeleteContainerResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, "container ID is required")
	}

	if err := s.orchestrator.Delete(ctx, containerID); err != nil {
		s.logger.Error(err, "Failed to delete container", "container_id", containerID)
		return nil, status.Error(codes.Internal, "failed to delete container: "+err.Error())
	}

	return &platformv1.DeleteContainerResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "Container deleted successfully",
		},
	}, nil
}

// GetContainer retrieves information about a container.
func (s *ComputeGRPCService) GetContainer(ctx context.Context, req *platformv1.GetContainerRequest) (*platformv1.GetContainerResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, "container ID is required")
	}

	instance, err := s.orchestrator.Get(ctx, containerID)
	if err != nil {
		s.logger.Error(err, "Failed to get container", "container_id", containerID)
		return nil, status.Error(codes.NotFound, "container not found: "+containerID)
	}

	return &platformv1.GetContainerResponse{
		Container: s.instanceToContainerProto(instance),
	}, nil
}

// ListContainers lists containers.
func (s *ComputeGRPCService) ListContainers(ctx context.Context, req *platformv1.ListContainersRequest) (*platformv1.ListContainersResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	containerType := compute.ComputeTypeContainer
	filter := &compute.InstanceFilter{
		Type: &containerType,
	}

	instances, err := s.orchestrator.List(ctx, filter)
	if err != nil {
		s.logger.Error(err, "Failed to list containers")
		return nil, status.Error(codes.Internal, "failed to list containers: "+err.Error())
	}

	protoContainers := make([]*platformv1.Container, len(instances))
	for i, instance := range instances {
		protoContainers[i] = s.instanceToContainerProto(instance)
	}

	return &platformv1.ListContainersResponse{
		Containers: protoContainers,
	}, nil
}

// AttachContainer attaches to a container (server streaming).
func (s *ComputeGRPCService) AttachContainer(req *platformv1.AttachContainerRequest, stream grpc.ServerStreamingServer[platformv1.ConsoleOutput]) error {
	// Container attachment not yet implemented in orchestrator
	return status.Error(codes.Unimplemented, "container attachment not yet implemented")
}

// ExecContainer executes a command in a container.
func (s *ComputeGRPCService) ExecContainer(ctx context.Context, req *platformv1.ExecContainerRequest) (*platformv1.ExecContainerResponse, error) {
	// Container exec not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "container exec not yet implemented")
}

// GetContainerLogs streams container logs (server streaming).
func (s *ComputeGRPCService) GetContainerLogs(req *platformv1.GetContainerLogsRequest, stream grpc.ServerStreamingServer[platformv1.LogEntry]) error {
	// Container logs not yet implemented in orchestrator
	return status.Error(codes.Unimplemented, "container logs not yet implemented")
}

// GetContainerMetrics retrieves container metrics.
func (s *ComputeGRPCService) GetContainerMetrics(ctx context.Context, req *platformv1.GetContainerMetricsRequest) (*platformv1.ContainerMetricsResponse, error) {
	// Container metrics not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "container metrics not yet implemented")
}

// =============================================================================
// VM Attestation
// =============================================================================

// AttestVM performs attestation for a VM.
func (s *ComputeGRPCService) AttestVM(ctx context.Context, req *platformv1.AttestVMRequest) (*platformv1.AttestVMResponse, error) {
	// VM attestation not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "VM attestation not yet implemented")
}

// VerifyVMAttestation verifies VM attestation.
func (s *ComputeGRPCService) VerifyVMAttestation(ctx context.Context, req *platformv1.VerifyVMAttestationRequest) (*platformv1.VerifyVMAttestationResponse, error) {
	// VM attestation verification not yet implemented in orchestrator
	return nil, status.Error(codes.Unimplemented, "VM attestation verification not yet implemented")
}

// =============================================================================
// Helper Functions
// =============================================================================

// instanceToVMProto converts a compute.Instance to a platformv1.VM.
func (s *ComputeGRPCService) instanceToVMProto(instance *compute.Instance) *platformv1.VM {
	if instance == nil {
		return nil
	}

	vm := &platformv1.VM{
		Id:        instance.ID,
		State:     s.instanceStateToVMState(instance.State),
		CreatedAt: timestamppb.New(instance.CreatedAt),
		UpdatedAt: timestamppb.New(instance.UpdatedAt),
	}

	// Populate config from instance config if available
	if instance.Config != nil {
		vm.Config = &platformv1.VMConfig{
			Name: instance.Name,
			Memory: &platformv1.MemoryConfig{
				SizeMb: uint64(instance.Config.Memory),
			},
			Cpu: &platformv1.CPUConfig{
				Cores: uint32(instance.Config.CPUs),
			},
			SecureBoot: instance.Config.SecureBoot,
		}
		if instance.Config.TPMEnabled {
			vm.Config.Tpm = &platformv1.TPMConfig{
				Enabled: true,
				Version: platformv1.TPMVersion_TPM_VERSION_2_0,
			}
		}
	} else if instance.Name != "" {
		// If no config but we have a name, still populate config with name
		vm.Config = &platformv1.VMConfig{
			Name: instance.Name,
		}
	}

	return vm
}

// instanceStateToVMState converts compute.InstanceState to platformv1.VMState.
func (s *ComputeGRPCService) instanceStateToVMState(state compute.InstanceState) platformv1.VMState {
	switch state {
	case compute.StateStopped:
		return platformv1.VMState_VM_STATE_STOPPED
	case compute.StateStarting:
		return platformv1.VMState_VM_STATE_STARTING
	case compute.StateRunning:
		return platformv1.VMState_VM_STATE_RUNNING
	case compute.StateStopping:
		return platformv1.VMState_VM_STATE_STOPPING
	case compute.StateError:
		return platformv1.VMState_VM_STATE_ERROR
	default:
		return platformv1.VMState_VM_STATE_UNSPECIFIED
	}
}

// instanceToContainerProto converts a compute.Instance to a platformv1.Container.
func (s *ComputeGRPCService) instanceToContainerProto(instance *compute.Instance) *platformv1.Container {
	if instance == nil {
		return nil
	}

	container := &platformv1.Container{
		Id:        instance.ID,
		State:     s.instanceStateToContainerState(instance.State),
		CreatedAt: timestamppb.New(instance.CreatedAt),
	}

	// Container doesn't have a Name field directly, it's in Config
	if instance.Name != "" {
		container.Config = &platformv1.ContainerConfig{
			Name: instance.Name,
		}
	}

	return container
}

// instanceStateToContainerState converts compute.InstanceState to platformv1.ContainerState.
func (s *ComputeGRPCService) instanceStateToContainerState(state compute.InstanceState) platformv1.ContainerState {
	switch state {
	case compute.StateCreating:
		return platformv1.ContainerState_CONTAINER_STATE_CREATED
	case compute.StateRunning:
		return platformv1.ContainerState_CONTAINER_STATE_RUNNING
	case compute.StateStopped:
		return platformv1.ContainerState_CONTAINER_STATE_EXITED
	default:
		return platformv1.ContainerState_CONTAINER_STATE_UNSPECIFIED
	}
}
