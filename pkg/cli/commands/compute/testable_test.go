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

package compute

import (
	"context"
	"errors"

	"google.golang.org/grpc"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// MockComputeClient implements platformv1.ComputeServiceClient for unit testing
type MockComputeClient struct {
	CreateVMFunc     func(ctx context.Context, in *platformv1.CreateVMRequest, opts ...grpc.CallOption) (*platformv1.CreateVMResponse, error)
	StartVMFunc      func(ctx context.Context, in *platformv1.StartVMRequest, opts ...grpc.CallOption) (*platformv1.StartVMResponse, error)
	StopVMFunc       func(ctx context.Context, in *platformv1.StopVMRequest, opts ...grpc.CallOption) (*platformv1.StopVMResponse, error)
	DeleteVMFunc     func(ctx context.Context, in *platformv1.DeleteVMRequest, opts ...grpc.CallOption) (*platformv1.DeleteVMResponse, error)
	GetVMFunc        func(ctx context.Context, in *platformv1.GetVMRequest, opts ...grpc.CallOption) (*platformv1.GetVMResponse, error)
	ListVMsFunc      func(ctx context.Context, in *platformv1.ListVMsRequest, opts ...grpc.CallOption) (*platformv1.ListVMsResponse, error)
	RebootVMFunc     func(ctx context.Context, in *platformv1.RebootVMRequest, opts ...grpc.CallOption) (*platformv1.RebootVMResponse, error)
	SuspendVMFunc    func(ctx context.Context, in *platformv1.SuspendVMRequest, opts ...grpc.CallOption) (*platformv1.SuspendVMResponse, error)
	ResumeVMFunc     func(ctx context.Context, in *platformv1.ResumeVMRequest, opts ...grpc.CallOption) (*platformv1.ResumeVMResponse, error)
	GetVMMetricsFunc func(ctx context.Context, in *platformv1.GetVMMetricsRequest, opts ...grpc.CallOption) (*platformv1.VMMetricsResponse, error)
}

var errNotImplemented = errors.New("not implemented")

func (m *MockComputeClient) CreateVM(ctx context.Context, in *platformv1.CreateVMRequest, opts ...grpc.CallOption) (*platformv1.CreateVMResponse, error) {
	if m.CreateVMFunc != nil {
		return m.CreateVMFunc(ctx, in, opts...)
	}
	return nil, errNotImplemented
}

func (m *MockComputeClient) StartVM(ctx context.Context, in *platformv1.StartVMRequest, opts ...grpc.CallOption) (*platformv1.StartVMResponse, error) {
	if m.StartVMFunc != nil {
		return m.StartVMFunc(ctx, in, opts...)
	}
	return nil, errNotImplemented
}

func (m *MockComputeClient) StopVM(ctx context.Context, in *platformv1.StopVMRequest, opts ...grpc.CallOption) (*platformv1.StopVMResponse, error) {
	if m.StopVMFunc != nil {
		return m.StopVMFunc(ctx, in, opts...)
	}
	return nil, errNotImplemented
}

func (m *MockComputeClient) RebootVM(ctx context.Context, in *platformv1.RebootVMRequest, opts ...grpc.CallOption) (*platformv1.RebootVMResponse, error) {
	if m.RebootVMFunc != nil {
		return m.RebootVMFunc(ctx, in, opts...)
	}
	return nil, errNotImplemented
}

func (m *MockComputeClient) SuspendVM(ctx context.Context, in *platformv1.SuspendVMRequest, opts ...grpc.CallOption) (*platformv1.SuspendVMResponse, error) {
	if m.SuspendVMFunc != nil {
		return m.SuspendVMFunc(ctx, in, opts...)
	}
	return nil, errNotImplemented
}

func (m *MockComputeClient) ResumeVM(ctx context.Context, in *platformv1.ResumeVMRequest, opts ...grpc.CallOption) (*platformv1.ResumeVMResponse, error) {
	if m.ResumeVMFunc != nil {
		return m.ResumeVMFunc(ctx, in, opts...)
	}
	return nil, errNotImplemented
}

func (m *MockComputeClient) DeleteVM(ctx context.Context, in *platformv1.DeleteVMRequest, opts ...grpc.CallOption) (*platformv1.DeleteVMResponse, error) {
	if m.DeleteVMFunc != nil {
		return m.DeleteVMFunc(ctx, in, opts...)
	}
	return nil, errNotImplemented
}

func (m *MockComputeClient) GetVM(ctx context.Context, in *platformv1.GetVMRequest, opts ...grpc.CallOption) (*platformv1.GetVMResponse, error) {
	if m.GetVMFunc != nil {
		return m.GetVMFunc(ctx, in, opts...)
	}
	return nil, errNotImplemented
}

func (m *MockComputeClient) ListVMs(ctx context.Context, in *platformv1.ListVMsRequest, opts ...grpc.CallOption) (*platformv1.ListVMsResponse, error) {
	if m.ListVMsFunc != nil {
		return m.ListVMsFunc(ctx, in, opts...)
	}
	return nil, errNotImplemented
}

func (m *MockComputeClient) AttachVMConsole(ctx context.Context, in *platformv1.AttachVMConsoleRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[platformv1.ConsoleOutput], error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) SendVMConsoleInput(ctx context.Context, opts ...grpc.CallOption) (grpc.ClientStreamingClient[platformv1.ConsoleInput, platformv1.ConsoleInputResponse], error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) GetVMLogs(ctx context.Context, in *platformv1.GetVMLogsRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[platformv1.LogEntry], error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) GetVMMetrics(ctx context.Context, in *platformv1.GetVMMetricsRequest, opts ...grpc.CallOption) (*platformv1.VMMetricsResponse, error) {
	if m.GetVMMetricsFunc != nil {
		return m.GetVMMetricsFunc(ctx, in, opts...)
	}
	return nil, errNotImplemented
}

func (m *MockComputeClient) AttachDisk(ctx context.Context, in *platformv1.AttachDiskRequest, opts ...grpc.CallOption) (*platformv1.AttachDiskResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) DetachDisk(ctx context.Context, in *platformv1.DetachDiskRequest, opts ...grpc.CallOption) (*platformv1.DetachDiskResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) ResizeDisk(ctx context.Context, in *platformv1.ResizeDiskRequest, opts ...grpc.CallOption) (*platformv1.ResizeDiskResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) CreateSnapshot(ctx context.Context, in *platformv1.CreateSnapshotRequest, opts ...grpc.CallOption) (*platformv1.CreateSnapshotResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) RestoreSnapshot(ctx context.Context, in *platformv1.RestoreSnapshotRequest, opts ...grpc.CallOption) (*platformv1.RestoreSnapshotResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) DeleteSnapshot(ctx context.Context, in *platformv1.DeleteSnapshotRequest, opts ...grpc.CallOption) (*platformv1.DeleteSnapshotResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) ListSnapshots(ctx context.Context, in *platformv1.ListSnapshotsRequest, opts ...grpc.CallOption) (*platformv1.ListSnapshotsResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) GetSnapshot(ctx context.Context, in *platformv1.GetSnapshotRequest, opts ...grpc.CallOption) (*platformv1.GetSnapshotResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) MigrateVM(ctx context.Context, in *platformv1.MigrateVMRequest, opts ...grpc.CallOption) (*platformv1.MigrateVMResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) PrepareMigration(ctx context.Context, in *platformv1.PrepareMigrationRequest, opts ...grpc.CallOption) (*platformv1.PrepareMigrationResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) FinalizeMigration(ctx context.Context, in *platformv1.FinalizeMigrationRequest, opts ...grpc.CallOption) (*platformv1.FinalizeMigrationResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) CreateContainer(ctx context.Context, in *platformv1.CreateContainerRequest, opts ...grpc.CallOption) (*platformv1.CreateContainerResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) StartContainer(ctx context.Context, in *platformv1.StartContainerRequest, opts ...grpc.CallOption) (*platformv1.StartContainerResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) StopContainer(ctx context.Context, in *platformv1.StopContainerRequest, opts ...grpc.CallOption) (*platformv1.StopContainerResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) DeleteContainer(ctx context.Context, in *platformv1.DeleteContainerRequest, opts ...grpc.CallOption) (*platformv1.DeleteContainerResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) GetContainer(ctx context.Context, in *platformv1.GetContainerRequest, opts ...grpc.CallOption) (*platformv1.GetContainerResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) ListContainers(ctx context.Context, in *platformv1.ListContainersRequest, opts ...grpc.CallOption) (*platformv1.ListContainersResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) AttachContainer(ctx context.Context, in *platformv1.AttachContainerRequest, opts ...grpc.CallOption) (grpc.ServerStreamingClient[platformv1.ConsoleOutput], error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) ExecContainer(ctx context.Context, in *platformv1.ExecContainerRequest, opts ...grpc.CallOption) (*platformv1.ExecContainerResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) GetContainerMetrics(ctx context.Context, in *platformv1.GetContainerMetricsRequest, opts ...grpc.CallOption) (*platformv1.ContainerMetricsResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) AttestVM(ctx context.Context, in *platformv1.AttestVMRequest, opts ...grpc.CallOption) (*platformv1.AttestVMResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) AttestContainer(ctx context.Context, in *platformv1.AttestContainerRequest, opts ...grpc.CallOption) (*platformv1.AttestContainerResponse, error) {
	return nil, errNotImplemented
}

func (m *MockComputeClient) VerifyVMAttestation(ctx context.Context, in *platformv1.VerifyVMAttestationRequest, opts ...grpc.CallOption) (*platformv1.VerifyVMAttestationResponse, error) {
	return nil, errNotImplemented
}

// Compile-time interface check
var _ platformv1.ComputeServiceClient = (*MockComputeClient)(nil)
