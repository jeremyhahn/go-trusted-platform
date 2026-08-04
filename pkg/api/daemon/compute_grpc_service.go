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
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
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

// vmMetricsReader returns the orchestrator as a VMMetricsReader or a typed error.
func (s *ComputeGRPCService) vmMetricsReader() (compute.VMMetricsReader, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}
	r, ok := s.orchestrator.(compute.VMMetricsReader)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "VM metrics not supported by this compute orchestrator")
	}
	return r, nil
}

func (s *ComputeGRPCService) vmLogStreamer() (compute.VMLogStreamer, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}
	r, ok := s.orchestrator.(compute.VMLogStreamer)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "VM logs not supported by this compute orchestrator")
	}
	return r, nil
}

func (s *ComputeGRPCService) vmConsole() (compute.VMConsole, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}
	c, ok := s.orchestrator.(compute.VMConsole)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "VM console not supported by this compute orchestrator")
	}
	return c, nil
}

func (s *ComputeGRPCService) vmDiskManager() (compute.VMDiskManager, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}
	m, ok := s.orchestrator.(compute.VMDiskManager)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "VM disk management not supported by this compute orchestrator")
	}
	return m, nil
}

func vmOpsErrToStatus(err error) error {
	switch {
	case errors.Is(err, compute.ErrInstanceNotFound), errors.Is(err, compute.ErrDiskNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, compute.ErrInvalidInstanceID), errors.Is(err, compute.ErrInvalidDiskRequest):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, compute.ErrDiskAlreadyAttached):
		return status.Error(codes.AlreadyExists, err.Error())
	case errors.Is(err, compute.ErrInstanceNotRunning),
		errors.Is(err, compute.ErrConsoleUnavailable),
		errors.Is(err, compute.ErrVMMetricsUnavailable),
		errors.Is(err, compute.ErrVMLogsUnavailable):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

func vmMetricsToProto(m *compute.VMMetrics) *platformv1.VMMetrics {
	if m == nil {
		return nil
	}
	return &platformv1.VMMetrics{
		CpuUsagePercent:   m.CPUUsagePercent,
		MemoryUsedMb:      m.MemoryUsedMB,
		MemoryAvailableMb: m.MemoryAvailableMB,
		DiskReadBytes:     m.DiskReadBytes,
		DiskWriteBytes:    m.DiskWriteBytes,
		NetworkRxBytes:    m.NetworkRxBytes,
		NetworkTxBytes:    m.NetworkTxBytes,
		UptimeSeconds:     m.UptimeSeconds,
	}
}

func diskBusToString(bus platformv1.DiskBus) string {
	switch bus {
	case platformv1.DiskBus_DISK_BUS_SATA:
		return "sata"
	case platformv1.DiskBus_DISK_BUS_SCSI:
		return "scsi"
	case platformv1.DiskBus_DISK_BUS_IDE:
		return "ide"
	case platformv1.DiskBus_DISK_BUS_NVME:
		return "nvme"
	default: // UNSPECIFIED or VIRTIO — only virtio supports hotplug.
		return "virtio"
	}
}

// vmIDFromMetadata extracts the target VM id from the "vm_id" gRPC request
// metadata. SendVMConsoleInput is a client stream whose ConsoleInput messages
// carry no id, so the VM is identified via request metadata (documented).
func vmIDFromMetadata(ctx context.Context) string {
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		if v := md.Get("vm_id"); len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

// AttachVMConsole attaches to a VM console (server streaming, multi-viewer).
func (s *ComputeGRPCService) AttachVMConsole(req *platformv1.AttachVMConsoleRequest, stream grpc.ServerStreamingServer[platformv1.ConsoleOutput]) error {
	console, err := s.vmConsole()
	if err != nil {
		return err
	}
	vmID := req.GetId()
	if vmID == "" {
		return status.Error(codes.InvalidArgument, "VM ID is required")
	}
	session, err := console.AttachConsole(stream.Context(), vmID)
	if err != nil {
		return vmOpsErrToStatus(err)
	}
	defer session.Close()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case chunk, ok := <-session.Output():
			if !ok {
				return nil
			}
			if err := stream.Send(&platformv1.ConsoleOutput{
				Data:      chunk,
				Timestamp: timestamppb.Now(),
				Stream:    "console",
			}); err != nil {
				return status.Error(codes.Internal, "failed to send console output: "+err.Error())
			}
		}
	}
}

// SendVMConsoleInput sends input to a VM console (client streaming).
func (s *ComputeGRPCService) SendVMConsoleInput(stream grpc.ClientStreamingServer[platformv1.ConsoleInput, platformv1.ConsoleInputResponse]) error {
	console, err := s.vmConsole()
	if err != nil {
		return err
	}
	vmID := vmIDFromMetadata(stream.Context())
	if vmID == "" {
		return status.Error(codes.InvalidArgument, "VM ID is required in 'vm_id' request metadata")
	}
	for {
		in, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return stream.SendAndClose(&platformv1.ConsoleInputResponse{
					Status: &platformv1.Status{Success: true, Message: "console input stream closed"},
				})
			}
			return status.Error(codes.Internal, "failed to receive console input: "+err.Error())
		}
		if err := console.SendConsoleInput(stream.Context(), vmID, in.GetData()); err != nil {
			return vmOpsErrToStatus(err)
		}
	}
}

// GetVMLogs streams VM logs (server streaming).
func (s *ComputeGRPCService) GetVMLogs(req *platformv1.GetVMLogsRequest, stream grpc.ServerStreamingServer[platformv1.LogEntry]) error {
	streamer, err := s.vmLogStreamer()
	if err != nil {
		return err
	}
	vmID := req.GetId()
	if vmID == "" {
		return status.Error(codes.InvalidArgument, "VM ID is required")
	}
	opts := compute.VMLogOptions{Follow: req.GetFollow(), TailLines: int(req.GetTailLines())}
	if req.GetSince() != nil {
		opts.Since = req.GetSince().AsTime()
	}
	err = streamer.StreamVMLogs(stream.Context(), vmID, opts, func(e compute.LogEntry) error {
		return stream.Send(&platformv1.LogEntry{
			Timestamp: timestamppb.New(e.Timestamp),
			Level:     e.Level,
			Message:   e.Message,
			Source:    e.Source,
		})
	})
	if err != nil {
		if errors.Is(err, context.Canceled) {
			return nil
		}
		return vmOpsErrToStatus(err)
	}
	return nil
}

// GetVMMetrics retrieves VM metrics.
func (s *ComputeGRPCService) GetVMMetrics(ctx context.Context, req *platformv1.GetVMMetricsRequest) (*platformv1.VMMetricsResponse, error) {
	reader, err := s.vmMetricsReader()
	if err != nil {
		return nil, err
	}
	vmID := req.GetId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}
	m, err := reader.GetVMMetrics(ctx, vmID)
	if err != nil {
		s.logger.Error(err, "Failed to get VM metrics", "vm_id", vmID)
		return nil, vmOpsErrToStatus(err)
	}
	return &platformv1.VMMetricsResponse{Metrics: vmMetricsToProto(m)}, nil
}

// =============================================================================
// VM Disk Operations
// =============================================================================

// AttachDisk attaches a disk to a VM.
func (s *ComputeGRPCService) AttachDisk(ctx context.Context, req *platformv1.AttachDiskRequest) (*platformv1.AttachDiskResponse, error) {
	mgr, err := s.vmDiskManager()
	if err != nil {
		return nil, err
	}
	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}
	disk := req.GetDisk()
	if disk == nil || disk.GetPath() == "" {
		return nil, status.Error(codes.InvalidArgument, "disk path is required")
	}
	if _, err := mgr.AttachDisk(ctx, vmID, compute.DiskAttachRequest{
		ID:       disk.GetId(),
		Path:     disk.GetPath(),
		Bus:      diskBusToString(disk.GetBus()),
		SizeGB:   disk.GetSizeGb(),
		Readonly: disk.GetReadonly(),
	}); err != nil {
		s.logger.Error(err, "Failed to attach disk", "vm_id", vmID)
		return nil, vmOpsErrToStatus(err)
	}
	return &platformv1.AttachDiskResponse{Status: &platformv1.Status{Success: true, Message: "disk attached"}}, nil
}

// DetachDisk detaches a disk from a VM.
func (s *ComputeGRPCService) DetachDisk(ctx context.Context, req *platformv1.DetachDiskRequest) (*platformv1.DetachDiskResponse, error) {
	mgr, err := s.vmDiskManager()
	if err != nil {
		return nil, err
	}
	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}
	diskID := req.GetDiskId()
	if diskID == "" {
		return nil, status.Error(codes.InvalidArgument, "disk ID is required")
	}
	if err := mgr.DetachDisk(ctx, vmID, diskID); err != nil {
		s.logger.Error(err, "Failed to detach disk", "vm_id", vmID, "disk_id", diskID)
		return nil, vmOpsErrToStatus(err)
	}
	return &platformv1.DetachDiskResponse{Status: &platformv1.Status{Success: true, Message: "disk detached"}}, nil
}

// ResizeDisk resizes a VM disk.
func (s *ComputeGRPCService) ResizeDisk(ctx context.Context, req *platformv1.ResizeDiskRequest) (*platformv1.ResizeDiskResponse, error) {
	mgr, err := s.vmDiskManager()
	if err != nil {
		return nil, err
	}
	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}
	if err := mgr.ResizeDisk(ctx, vmID, req.GetDiskId(), req.GetNewSizeGb()); err != nil {
		s.logger.Error(err, "Failed to resize disk", "vm_id", vmID, "disk_id", req.GetDiskId())
		return nil, vmOpsErrToStatus(err)
	}
	return &platformv1.ResizeDiskResponse{Status: &platformv1.Status{Success: true, Message: "disk resized"}}, nil
}

// =============================================================================
// VM Snapshot Operations
// =============================================================================

// vmSnapshotErrToStatus maps compute snapshot errors onto gRPC status codes.
func vmSnapshotErrToStatus(err error) error {
	switch {
	case errors.Is(err, compute.ErrInstanceNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, compute.ErrInvalidInstanceID),
		errors.Is(err, compute.ErrInvalidSnapshotName),
		errors.Is(err, compute.ErrInvalidAttestationEvidence):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, compute.ErrSnapshotNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, compute.ErrInstanceNotRunning),
		errors.Is(err, compute.ErrUnsupportedDiskFormat),
		errors.Is(err, compute.ErrVTPMNotAvailable):
		return status.Error(codes.FailedPrecondition, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// vmSnapshotToProto converts a compute.VMSnapshot to the proto Snapshot
// message. Internal QEMU snapshots always capture both memory and disk.
func vmSnapshotToProto(snapshot *compute.VMSnapshot) *platformv1.Snapshot {
	if snapshot == nil {
		return nil
	}
	return &platformv1.Snapshot{
		Id:   snapshot.Name,
		VmId: snapshot.VMID,
		Config: &platformv1.SnapshotConfig{
			Name:           snapshot.Name,
			Description:    snapshot.Description,
			MemorySnapshot: true,
			DiskSnapshot:   true,
		},
		CreatedAt: timestamppb.New(snapshot.CreatedAt),
		SizeBytes: uint64(snapshot.SizeBytes),
		VmState:   platformv1.VMState_VM_STATE_RUNNING,
	}
}

// vmSnapshotter returns the orchestrator's VM snapshot capability or a gRPC
// error when the orchestrator is missing or does not manage VMs.
func (s *ComputeGRPCService) vmSnapshotter() (compute.VMSnapshotter, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}
	snapshotter, ok := s.orchestrator.(compute.VMSnapshotter)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "VM snapshots not supported by this compute orchestrator")
	}
	return snapshotter, nil
}

// CreateSnapshot creates an internal QEMU snapshot (memory + disk) of a
// running VM.
func (s *ComputeGRPCService) CreateSnapshot(ctx context.Context, req *platformv1.CreateSnapshotRequest) (*platformv1.CreateSnapshotResponse, error) {
	snapshotter, err := s.vmSnapshotter()
	if err != nil {
		return nil, err
	}

	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}

	config := req.GetConfig()
	if config == nil || config.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "snapshot name is required")
	}

	// Internal QEMU snapshots always capture both memory and disk. A
	// request for exactly one of the two asks for semantics this
	// implementation cannot provide, so reject it explicitly instead of
	// silently taking a full snapshot.
	if config.GetMemorySnapshot() != config.GetDiskSnapshot() {
		return nil, status.Error(codes.InvalidArgument,
			"internal QEMU snapshots capture both memory and disk; disk-only and memory-only snapshots are not supported")
	}

	snapshot, err := snapshotter.CreateSnapshot(ctx, vmID, config.GetName())
	if err != nil {
		s.logger.Error(err, "Failed to create VM snapshot", "vm_id", vmID, "snapshot", config.GetName())
		return nil, vmSnapshotErrToStatus(err)
	}
	snapshot.Description = config.GetDescription()

	return &platformv1.CreateSnapshotResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "Snapshot created successfully",
		},
		Snapshot: vmSnapshotToProto(snapshot),
	}, nil
}

// RestoreSnapshot restores a running VM from an internal snapshot.
func (s *ComputeGRPCService) RestoreSnapshot(ctx context.Context, req *platformv1.RestoreSnapshotRequest) (*platformv1.RestoreSnapshotResponse, error) {
	snapshotter, err := s.vmSnapshotter()
	if err != nil {
		return nil, err
	}

	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}
	snapshotID := req.GetSnapshotId()
	if snapshotID == "" {
		return nil, status.Error(codes.InvalidArgument, "snapshot ID is required")
	}

	if err := snapshotter.RestoreSnapshot(ctx, vmID, snapshotID); err != nil {
		s.logger.Error(err, "Failed to restore VM snapshot", "vm_id", vmID, "snapshot", snapshotID)
		return nil, vmSnapshotErrToStatus(err)
	}

	return &platformv1.RestoreSnapshotResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "Snapshot restored successfully",
		},
	}, nil
}

// DeleteSnapshot deletes an internal VM snapshot.
func (s *ComputeGRPCService) DeleteSnapshot(ctx context.Context, req *platformv1.DeleteSnapshotRequest) (*platformv1.DeleteSnapshotResponse, error) {
	snapshotter, err := s.vmSnapshotter()
	if err != nil {
		return nil, err
	}

	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}
	snapshotID := req.GetSnapshotId()
	if snapshotID == "" {
		return nil, status.Error(codes.InvalidArgument, "snapshot ID is required")
	}

	if err := snapshotter.DeleteSnapshot(ctx, vmID, snapshotID); err != nil {
		s.logger.Error(err, "Failed to delete VM snapshot", "vm_id", vmID, "snapshot", snapshotID)
		return nil, vmSnapshotErrToStatus(err)
	}

	return &platformv1.DeleteSnapshotResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "Snapshot deleted successfully",
		},
	}, nil
}

// ListSnapshots lists internal VM snapshots.
func (s *ComputeGRPCService) ListSnapshots(ctx context.Context, req *platformv1.ListSnapshotsRequest) (*platformv1.ListSnapshotsResponse, error) {
	snapshotter, err := s.vmSnapshotter()
	if err != nil {
		return nil, err
	}

	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}

	snapshots, err := snapshotter.ListSnapshots(ctx, vmID)
	if err != nil {
		s.logger.Error(err, "Failed to list VM snapshots", "vm_id", vmID)
		return nil, vmSnapshotErrToStatus(err)
	}

	protoSnapshots := make([]*platformv1.Snapshot, len(snapshots))
	for i, snapshot := range snapshots {
		protoSnapshots[i] = vmSnapshotToProto(snapshot)
	}

	return &platformv1.ListSnapshotsResponse{
		Snapshots: protoSnapshots,
	}, nil
}

// vmMigrator returns the orchestrator's VM migration capability or a gRPC error
// when the orchestrator is missing or does not manage VMs.
func (s *ComputeGRPCService) vmMigrator() (compute.VMMigrator, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}
	m, ok := s.orchestrator.(compute.VMMigrator)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "VM migration not supported by this compute orchestrator")
	}
	return m, nil
}

// migrateVMErrToStatus maps compute migration errors onto gRPC status codes.
func migrateVMErrToStatus(err error) error {
	switch {
	case errors.Is(err, compute.ErrLiveMigrationRequiresSharedStorage),
		errors.Is(err, compute.ErrMigrationNotConfigured),
		errors.Is(err, compute.ErrMigrationTLSNotConfigured):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, compute.ErrMigrationDestinationRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return vmOpsErrToStatus(err)
	}
}

// MigrateVM migrates a VM to another host (cold or live).
func (s *ComputeGRPCService) MigrateVM(ctx context.Context, req *platformv1.MigrateVMRequest) (*platformv1.MigrateVMResponse, error) {
	migrator, err := s.vmMigrator()
	if err != nil {
		return nil, err
	}
	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}
	dest := req.GetDestinationHost()
	if dest == "" {
		return nil, status.Error(codes.InvalidArgument, "destination host is required")
	}
	result, err := migrator.MigrateVM(ctx, vmID, dest, compute.MigrateOptions{
		Live:               req.GetLiveMigration(),
		BandwidthLimitMbps: req.GetBandwidthLimitMbps(),
	})
	if err != nil {
		s.logger.Error(err, "Failed to migrate VM", "vm_id", vmID, "destination", dest)
		return nil, migrateVMErrToStatus(err)
	}
	return &platformv1.MigrateVMResponse{Status: &platformv1.Status{Success: result.Success, Message: result.Message}}, nil
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

	// Optionally attest the container if requested
	if req.GetAttestOnCreate() {
		attester, ok := s.orchestrator.(containerAttester)
		if !ok {
			return nil, status.Error(codes.Unimplemented, "attest-on-create not supported by this orchestrator")
		}
		if _, attestErr := attester.Attest(ctx, instance.ID); attestErr != nil {
			s.logger.Error(attestErr, "Container created but attestation failed", "container_id", instance.ID)
			return &platformv1.CreateContainerResponse{
				Status: &platformv1.Status{
					Success: false,
					Message: "Container created but attestation failed: " + attestErr.Error(),
				},
				Container: s.instanceToContainerProto(instance),
			}, nil
		}
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
		Name: req.GetNameFilter(),
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

// AttachContainer attaches to a running container's console and streams the
// output to the client (server streaming). It delegates to the orchestrator's
// Attach capability, fanning the pseudo-terminal console chunks onto the gRPC
// stream. This RPC is output-only: interactive stdin injection would require a
// bidirectional RPC (mirroring the VM SendVMConsoleInput surface); the pb
// AttachContainerRequest.stdin flag is accepted but not consumed here.
func (s *ComputeGRPCService) AttachContainer(req *platformv1.AttachContainerRequest, stream grpc.ServerStreamingServer[platformv1.ConsoleOutput]) error {
	if s.orchestrator == nil {
		return status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	containerID := req.GetId()
	if containerID == "" {
		return status.Error(codes.InvalidArgument, "container ID is required")
	}

	attacher, ok := s.orchestrator.(containerAttacher)
	if !ok {
		return status.Error(codes.Unimplemented, "container attachment not supported by this orchestrator")
	}

	ctx := stream.Context()
	session, err := attacher.Attach(ctx, containerID, container.ExecOptions{TTY: req.GetTty()})
	if err != nil {
		s.logger.Error(err, "Failed to attach to container", "container_id", containerID)
		return containerOpsErrToStatus(err)
	}
	defer session.Close()

	output := session.Output()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case chunk, ok := <-output:
			if !ok {
				return nil
			}
			if sendErr := stream.Send(attachChunkToProto(chunk)); sendErr != nil {
				return status.Error(codes.Internal, "failed to send console output: "+sendErr.Error())
			}
		}
	}
}

// ExecContainer executes a command inside a running container and returns the
// buffered stdout/stderr and exit code. It delegates to the orchestrator's Exec
// capability (the same service path the REST exec route and MCP container_exec
// tool use).
func (s *ComputeGRPCService) ExecContainer(ctx context.Context, req *platformv1.ExecContainerRequest) (*platformv1.ExecContainerResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, "container ID is required")
	}
	if len(req.GetCommand()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "exec command is required")
	}

	executor, ok := s.orchestrator.(containerExecutor)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "container exec not supported by this orchestrator")
	}

	result, err := executor.Exec(ctx, containerID, execOptionsFromProto(req))
	if err != nil {
		s.logger.Error(err, "Failed to exec in container", "container_id", containerID)
		return nil, containerOpsErrToStatus(err)
	}

	return execResultToProto(result), nil
}

// GetContainerLogs streams container logs (server streaming). It delegates
// to the orchestrator's Logs verb — the same service logic the REST
// GET /api/v1/containers/{id}/logs route uses — and streams the log data as
// LogEntry messages.
func (s *ComputeGRPCService) GetContainerLogs(req *platformv1.GetContainerLogsRequest, stream grpc.ServerStreamingServer[platformv1.LogEntry]) error {
	if s.orchestrator == nil {
		return status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	containerID := req.GetId()
	if containerID == "" {
		return status.Error(codes.InvalidArgument, "container ID is required")
	}

	streamer, ok := s.orchestrator.(containerLogStreamer)
	if !ok {
		return status.Error(codes.Unimplemented, "container logs not supported by this orchestrator")
	}

	opts := container.LogOptions{
		Follow:     req.GetFollow(),
		Stdout:     req.GetStdout(),
		Stderr:     req.GetStderr(),
		Timestamps: req.GetTimestamps(),
	}
	if !opts.Stdout && !opts.Stderr {
		// Default to both streams.
		opts.Stdout = true
		opts.Stderr = true
	}
	if req.GetTailLines() > 0 {
		opts.Tail = strconv.FormatUint(uint64(req.GetTailLines()), 10)
	}
	if req.GetSince() != nil {
		opts.Since = req.GetSince().AsTime()
	}
	if req.GetUntil() != nil {
		opts.Until = req.GetUntil().AsTime()
	}

	reader, err := streamer.Logs(stream.Context(), containerID, opts)
	if err != nil {
		s.logger.Error(err, "Failed to open container logs", "container_id", containerID)
		return containerLogsErrToStatus(err)
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
				entry := &platformv1.LogEntry{
					Timestamp: timestamppb.Now(),
					Level:     "INFO",
					Message:   string(buf[:n]),
					Source:    containerID,
				}
				if sendErr := stream.Send(entry); sendErr != nil {
					return status.Error(codes.Internal, "failed to send log entry: "+sendErr.Error())
				}
			}
			if readErr != nil {
				if errors.Is(readErr, io.EOF) {
					return nil
				}
				return containerLogsErrToStatus(readErr)
			}
		}
	}
}

// containerLogsErrToStatus maps container log errors onto gRPC status codes.
func containerLogsErrToStatus(err error) error {
	switch {
	case errors.Is(err, container.ErrContainerNotFound),
		errors.Is(err, compute.ErrInstanceNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, container.ErrInvalidContainerID),
		errors.Is(err, compute.ErrInvalidInstanceID):
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// GetContainerMetrics retrieves a container's resource-usage metrics. It
// delegates to the orchestrator's Metrics capability (the same service path the
// REST metrics route and MCP container_metrics tool use).
func (s *ComputeGRPCService) GetContainerMetrics(ctx context.Context, req *platformv1.GetContainerMetricsRequest) (*platformv1.ContainerMetricsResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, "container ID is required")
	}

	reader, ok := s.orchestrator.(containerMetricsReader)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "container metrics not supported by this orchestrator")
	}

	stats, err := reader.Metrics(ctx, containerID)
	if err != nil {
		s.logger.Error(err, "Failed to read container metrics", "container_id", containerID)
		return nil, containerOpsErrToStatus(err)
	}

	return &platformv1.ContainerMetricsResponse{Metrics: containerStatsToProto(stats)}, nil
}

// =============================================================================
// VM Attestation
// =============================================================================

// vmAttester returns the orchestrator's VM attestation capability or a gRPC
// error when the orchestrator is missing or does not manage VMs.
func (s *ComputeGRPCService) vmAttester() (compute.VMAttester, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}
	attester, ok := s.orchestrator.(compute.VMAttester)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "VM attestation not supported by this compute orchestrator")
	}
	return attester, nil
}

// validateVMPCRBank rejects PCR banks the vTPM quote path does not support.
// Only SHA-256 (or unspecified, which defaults to SHA-256) is accepted.
func validateVMPCRBank(bank platformv1.PCRBank) error {
	switch bank {
	case platformv1.PCRBank_PCR_BANK_UNSPECIFIED, platformv1.PCRBank_PCR_BANK_SHA256:
		return nil
	default:
		return status.Error(codes.InvalidArgument,
			"unsupported PCR bank "+bank.String()+": VM attestation supports only the SHA-256 bank")
	}
}

// AttestVM generates a vTPM quote for a running VM.
func (s *ComputeGRPCService) AttestVM(ctx context.Context, req *platformv1.AttestVMRequest) (*platformv1.AttestVMResponse, error) {
	attester, err := s.vmAttester()
	if err != nil {
		return nil, err
	}

	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}

	if err := validateVMPCRBank(req.GetPcrBank()); err != nil {
		return nil, err
	}

	pcrIndices := make([]int, 0, len(req.GetPcrIndices()))
	for _, idx := range req.GetPcrIndices() {
		if idx > 23 {
			return nil, status.Error(codes.InvalidArgument, "PCR index must be between 0 and 23")
		}
		pcrIndices = append(pcrIndices, int(idx))
	}

	report, err := attester.AttestVM(ctx, vmID, req.GetNonce(), pcrIndices)
	if err != nil {
		s.logger.Error(err, "Failed to attest VM", "vm_id", vmID)
		return nil, vmSnapshotErrToStatus(err)
	}

	return &platformv1.AttestVMResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VM quote generated successfully",
		},
		Quote:     report.Quote,
		Signature: report.Signature,
		PcrValues: vmPCRValuesToProto(report.PCRValues),
		EventLog:  report.EventLog,
		AkPublic:  report.AKPublicKey,
	}, nil
}

// VerifyVMAttestation verifies VM quote evidence against the instance's
// live vTPM attestation key.
func (s *ComputeGRPCService) VerifyVMAttestation(ctx context.Context, req *platformv1.VerifyVMAttestationRequest) (*platformv1.VerifyVMAttestationResponse, error) {
	attester, err := s.vmAttester()
	if err != nil {
		return nil, err
	}

	vmID := req.GetVmId()
	if vmID == "" {
		return nil, status.Error(codes.InvalidArgument, "VM ID is required")
	}

	expectedPCRs := make(map[int][]byte, len(req.GetExpectedPcrs()))
	for _, pcr := range req.GetExpectedPcrs() {
		if err := validateVMPCRBank(pcr.GetBank()); err != nil {
			return nil, err
		}
		expectedPCRs[int(pcr.GetIndex())] = pcr.GetValue()
	}

	result, err := attester.VerifyVMAttestation(ctx, vmID, &compute.VMAttestationEvidence{
		Quote:        req.GetQuote(),
		Signature:    req.GetSignature(),
		Nonce:        req.GetNonce(),
		ExpectedPCRs: expectedPCRs,
	})
	if err != nil {
		s.logger.Error(err, "Failed to verify VM attestation", "vm_id", vmID)
		return nil, vmSnapshotErrToStatus(err)
	}

	return &platformv1.VerifyVMAttestationResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "verification completed",
		},
		Verified:   result.Verified,
		Message:    result.Message,
		ActualPcrs: vmPCRValuesToProto(result.ActualPCRs),
	}, nil
}

// vmPCRValuesToProto converts a PCR index -> value map to sorted proto
// PCRValue messages (SHA-256 bank).
func vmPCRValuesToProto(pcrValues map[int][]byte) []*platformv1.PCRValue {
	if len(pcrValues) == 0 {
		return nil
	}
	indices := make([]int, 0, len(pcrValues))
	for idx := range pcrValues {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	protoValues := make([]*platformv1.PCRValue, 0, len(indices))
	for _, idx := range indices {
		protoValues = append(protoValues, &platformv1.PCRValue{
			Index: uint32(idx),
			Bank:  platformv1.PCRBank_PCR_BANK_SHA256,
			Value: pcrValues[idx],
		})
	}
	return protoValues
}

// =============================================================================
// Container Attestation
// =============================================================================

// containerAttester is the orchestrator capability required for container
// quote attestation. It matches the Attest verb the REST
// POST /api/v1/containers/{id}/attest route type-asserts on the orchestrator.
type containerAttester interface {
	Attest(ctx context.Context, id string) (*container.AttestationReport, error)
}

// AttestContainer performs quote-based TPM attestation for a container. It
// delegates to the orchestrator's Attest verb — the same service logic the
// REST container attest route uses.
func (s *ComputeGRPCService) AttestContainer(ctx context.Context, req *platformv1.AttestContainerRequest) (*platformv1.AttestContainerResponse, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}

	containerID := req.GetId()
	if containerID == "" {
		return nil, status.Error(codes.InvalidArgument, "container ID is required")
	}

	attester, ok := s.orchestrator.(containerAttester)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "container attestation not supported by this orchestrator")
	}

	report, err := attester.Attest(ctx, containerID)
	if err != nil {
		s.logger.Error(err, "Failed to attest container", "container_id", containerID)
		return nil, status.Error(codes.Internal, "failed to attest container: "+err.Error())
	}

	return grpcapi.AttestationReportToProto(report, req.GetPcrBank()), nil
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
