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

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// Inter-daemon migration handshake (destination side)
// =============================================================================
//
// PrepareMigration and FinalizeMigration are the destination half of a VM
// migration. The migrating source daemon (see ComputeGRPCService.MigrateVM and
// the grpcMigrationCoordinator client) calls these RPCs over mutual TLS:
//
//   - PrepareMigration asks this daemon to launch a receiving QEMU for the VM
//     described by the request and returns the TCP port it listens on plus the
//     TLS hostname the source must pin.
//   - FinalizeMigration commits (resume the received guest) or aborts (tear the
//     receiver down) once the source reports the transfer outcome.
//
// Both handlers are registered as part of the ComputeService, so they are served
// on the same gRPC TCP and Unix-socket listeners as every other compute RPC (no
// extra registration in daemon.go is required).

// migrationReceiver returns the orchestrator's destination-side migration
// capability or a gRPC error when the orchestrator is missing or does not manage
// VMs.
func (s *ComputeGRPCService) migrationReceiver() (compute.MigrationReceiver, error) {
	if s.orchestrator == nil {
		return nil, status.Error(codes.FailedPrecondition, "compute orchestrator not initialized")
	}
	r, ok := s.orchestrator.(compute.MigrationReceiver)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "VM migration not supported by this compute orchestrator")
	}
	return r, nil
}

// PrepareMigration launches a receiving QEMU for an inbound VM migration and
// returns the endpoint the source streams to.
func (s *ComputeGRPCService) PrepareMigration(ctx context.Context, req *platformv1.PrepareMigrationRequest) (*platformv1.PrepareMigrationResponse, error) {
	receiver, err := s.migrationReceiver()
	if err != nil {
		return nil, err
	}
	protoSpec := req.GetSpec()
	if protoSpec == nil {
		return nil, status.Error(codes.InvalidArgument, "migration spec is required")
	}

	spec := compute.MigrationSpec{
		InstanceID: req.GetVmId(),
		VMName:     req.GetVmName(),
		Mode:       compute.MigrateMode(req.GetMode()),
		Config:     fromProtoMigrationSpec(protoSpec),
	}

	handle, err := receiver.ReceiveIncoming(ctx, spec)
	if err != nil {
		s.logger.Error(err, "Failed to prepare migration receiver", "vm_name", spec.VMName)
		return nil, prepareMigrationErrToStatus(err)
	}

	return &platformv1.PrepareMigrationResponse{
		Status:      &platformv1.Status{Success: true, Message: "migration receiver ready"},
		ReceiverId:  handle.ReceiverID,
		Port:        int32(handle.Port),
		TlsHostname: handle.TLSHostname,
	}, nil
}

// FinalizeMigration commits or aborts a prepared receiver.
func (s *ComputeGRPCService) FinalizeMigration(ctx context.Context, req *platformv1.FinalizeMigrationRequest) (*platformv1.FinalizeMigrationResponse, error) {
	receiver, err := s.migrationReceiver()
	if err != nil {
		return nil, err
	}
	if req.GetReceiverId() == "" {
		return nil, status.Error(codes.InvalidArgument, "receiver id is required")
	}

	if err := receiver.FinalizeIncoming(ctx, req.GetReceiverId(), req.GetCommit()); err != nil {
		s.logger.Error(err, "Failed to finalize migration receiver", "receiver_id", req.GetReceiverId(), "commit", req.GetCommit())
		return nil, finalizeMigrationErrToStatus(err)
	}

	return &platformv1.FinalizeMigrationResponse{
		Status: &platformv1.Status{Success: true, Message: "migration finalized"},
	}, nil
}

// fromProtoMigrationSpec projects the wire migration spec onto a compute
// InstanceConfig used to launch the receiver. Runtime-only fields (work
// directory, disk path) are filled by the orchestrator's receiver launcher.
func fromProtoMigrationSpec(spec *platformv1.VMMigrationSpec) *compute.InstanceConfig {
	if spec == nil {
		return nil
	}
	return &compute.InstanceConfig{
		Memory:      int(spec.GetMemoryMb()),
		CPUs:        int(spec.GetCpus()),
		DiskSize:    spec.GetDiskSize(),
		BootMode:    spec.GetBootMode(),
		SecureBoot:  spec.GetSecureBoot(),
		EnableKVM:   spec.GetEnableKvm(),
		TPMEnabled:  spec.GetTpmEnabled(),
		NetworkMode: spec.GetNetworkMode(),
		MACAddress:  spec.GetMacAddress(),
	}
}

// prepareMigrationErrToStatus maps ReceiveIncoming errors onto gRPC status codes.
func prepareMigrationErrToStatus(err error) error {
	switch {
	case errors.Is(err, compute.ErrMigrationSpecRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, compute.ErrMigrationServerTLSNotConfigured):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, compute.ErrMigrationReceiveFailed):
		return status.Error(codes.Internal, err.Error())
	default:
		return vmOpsErrToStatus(err)
	}
}

// finalizeMigrationErrToStatus maps FinalizeIncoming errors onto gRPC status codes.
func finalizeMigrationErrToStatus(err error) error {
	switch {
	case errors.Is(err, compute.ErrReceiverNotFound):
		return status.Error(codes.NotFound, err.Error())
	case errors.Is(err, compute.ErrMigrationReceiveFailed):
		return status.Error(codes.Internal, err.Error())
	default:
		return vmOpsErrToStatus(err)
	}
}
