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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package daemon

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// migrationReceiverOrchestrator augments the shared gRPC mock orchestrator with
// the destination-side migration capability so PrepareMigration /
// FinalizeMigration can be exercised without a real QEMU launch.
type migrationReceiverOrchestrator struct {
	*grpcMockOrchestrator

	handle      *compute.ReceiverHandle
	receiveErr  error
	finalizeErr error

	gotSpec        compute.MigrationSpec
	lastReceiverID string
	lastCommit     bool
}

func (m *migrationReceiverOrchestrator) ReceiveIncoming(_ context.Context, spec compute.MigrationSpec) (*compute.ReceiverHandle, error) {
	m.gotSpec = spec
	if m.receiveErr != nil {
		return nil, m.receiveErr
	}
	return m.handle, nil
}

func (m *migrationReceiverOrchestrator) FinalizeIncoming(_ context.Context, receiverID string, commit bool) error {
	m.lastReceiverID = receiverID
	m.lastCommit = commit
	return m.finalizeErr
}

func newMigrationReceiverService(recv *migrationReceiverOrchestrator) *ComputeGRPCService {
	return NewComputeGRPCService(logging.DefaultLogger(), recv)
}

func TestPrepareMigration_HappyPath(t *testing.T) {
	recv := &migrationReceiverOrchestrator{
		grpcMockOrchestrator: newGRPCMockOrchestrator(),
		handle:               &compute.ReceiverHandle{ReceiverID: "recv-1", Port: 49200, TLSHostname: "dest.example"},
	}
	svc := newMigrationReceiverService(recv)

	resp, err := svc.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{
		VmId:   "vm-1",
		VmName: "guest",
		Mode:   "cold",
		Spec: &platformv1.VMMigrationSpec{
			MemoryMb:    2048,
			Cpus:        2,
			DiskSize:    "20G",
			BootMode:    "boot",
			EnableKvm:   true,
			TpmEnabled:  true,
			NetworkMode: "bridge",
			MacAddress:  "52:54:00:12:34:56",
		},
	})
	require.NoError(t, err)
	require.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, "recv-1", resp.GetReceiverId())
	assert.Equal(t, int32(49200), resp.GetPort())
	assert.Equal(t, "dest.example", resp.GetTlsHostname())

	// The wire spec is projected onto the compute migration spec.
	assert.Equal(t, "guest", recv.gotSpec.VMName)
	assert.Equal(t, compute.MigrateModeCold, recv.gotSpec.Mode)
	require.NotNil(t, recv.gotSpec.Config)
	assert.Equal(t, 2048, recv.gotSpec.Config.Memory)
	assert.Equal(t, 2, recv.gotSpec.Config.CPUs)
	assert.True(t, recv.gotSpec.Config.TPMEnabled)
	assert.Equal(t, "52:54:00:12:34:56", recv.gotSpec.Config.MACAddress)
}

func TestPrepareMigration_MissingSpec(t *testing.T) {
	recv := &migrationReceiverOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()}
	svc := newMigrationReceiverService(recv)

	_, err := svc.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{VmName: "guest"})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestPrepareMigration_ReceiveFailure(t *testing.T) {
	recv := &migrationReceiverOrchestrator{
		grpcMockOrchestrator: newGRPCMockOrchestrator(),
		receiveErr:           compute.ErrMigrationServerTLSNotConfigured,
	}
	svc := newMigrationReceiverService(recv)

	_, err := svc.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{
		VmName: "guest",
		Spec:   &platformv1.VMMigrationSpec{MemoryMb: 1024},
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestPrepareMigration_NotSupported(t *testing.T) {
	// A plain orchestrator that does not implement MigrationReceiver.
	svc := NewComputeGRPCService(logging.DefaultLogger(), newGRPCMockOrchestrator())
	_, err := svc.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{
		VmName: "guest",
		Spec:   &platformv1.VMMigrationSpec{MemoryMb: 1024},
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestPrepareMigration_NilOrchestrator(t *testing.T) {
	svc := NewComputeGRPCService(logging.DefaultLogger(), nil)
	_, err := svc.PrepareMigration(context.Background(), &platformv1.PrepareMigrationRequest{
		Spec: &platformv1.VMMigrationSpec{MemoryMb: 1024},
	})
	require.Error(t, err)
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestFinalizeMigration_Commit(t *testing.T) {
	recv := &migrationReceiverOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()}
	svc := newMigrationReceiverService(recv)

	resp, err := svc.FinalizeMigration(context.Background(), &platformv1.FinalizeMigrationRequest{
		ReceiverId: "recv-1",
		Commit:     true,
	})
	require.NoError(t, err)
	require.True(t, resp.GetStatus().GetSuccess())
	assert.Equal(t, "recv-1", recv.lastReceiverID)
	assert.True(t, recv.lastCommit)
}

func TestFinalizeMigration_MissingReceiverID(t *testing.T) {
	recv := &migrationReceiverOrchestrator{grpcMockOrchestrator: newGRPCMockOrchestrator()}
	svc := newMigrationReceiverService(recv)

	_, err := svc.FinalizeMigration(context.Background(), &platformv1.FinalizeMigrationRequest{Commit: true})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestFinalizeMigration_ReceiverNotFound(t *testing.T) {
	recv := &migrationReceiverOrchestrator{
		grpcMockOrchestrator: newGRPCMockOrchestrator(),
		finalizeErr:          compute.ErrReceiverNotFound,
	}
	svc := newMigrationReceiverService(recv)

	_, err := svc.FinalizeMigration(context.Background(), &platformv1.FinalizeMigrationRequest{ReceiverId: "nope", Commit: false})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestFinalizeMigration_InternalError(t *testing.T) {
	recv := &migrationReceiverOrchestrator{
		grpcMockOrchestrator: newGRPCMockOrchestrator(),
		finalizeErr:          &compute.SentinelCauseError{Sentinel: compute.ErrMigrationReceiveFailed, Cause: &compute.MessageError{Msg: "resume failed"}},
	}
	svc := newMigrationReceiverService(recv)

	_, err := svc.FinalizeMigration(context.Background(), &platformv1.FinalizeMigrationRequest{ReceiverId: "recv-1", Commit: true})
	require.Error(t, err)
	assert.Equal(t, codes.Internal, status.Code(err))
}
