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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// diskRecordingComputeServer captures the disk and migration requests
// that reach the service, so a test can assert what crossed the wire.
type diskRecordingComputeServer struct {
	platformv1.UnimplementedComputeServiceServer
	attached *platformv1.AttachDiskRequest
	detached *platformv1.DetachDiskRequest
	resized  *platformv1.ResizeDiskRequest
	migrated *platformv1.MigrateVMRequest
}

func (s *diskRecordingComputeServer) AttachDisk(_ context.Context, req *platformv1.AttachDiskRequest) (*platformv1.AttachDiskResponse, error) {
	s.attached = req
	return &platformv1.AttachDiskResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (s *diskRecordingComputeServer) DetachDisk(_ context.Context, req *platformv1.DetachDiskRequest) (*platformv1.DetachDiskResponse, error) {
	s.detached = req
	return &platformv1.DetachDiskResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (s *diskRecordingComputeServer) ResizeDisk(_ context.Context, req *platformv1.ResizeDiskRequest) (*platformv1.ResizeDiskResponse, error) {
	s.resized = req
	return &platformv1.ResizeDiskResponse{Status: &platformv1.Status{Success: true}}, nil
}

func (s *diskRecordingComputeServer) MigrateVM(_ context.Context, req *platformv1.MigrateVMRequest) (*platformv1.MigrateVMResponse, error) {
	s.migrated = req
	return &platformv1.MigrateVMResponse{Status: &platformv1.Status{Success: true}}, nil
}

func TestSDKREST_AttachDisk(t *testing.T) {
	server := &diskRecordingComputeServer{}
	client, _ := connectComputeSDK(t, server)

	_, err := client.AttachDisk(context.Background(), &platformv1.AttachDiskRequest{
		VmId: "vm-1",
		Disk: &platformv1.DiskConfig{Id: "d2", Path: "/var/lib/vm/d2.qcow2", Type: platformv1.DiskType_DISK_TYPE_QCOW2, SizeGb: 10},
	})

	require.NoError(t, err, "the server's 201 is success")
	require.NotNil(t, server.attached)
	assert.Equal(t, "vm-1", server.attached.GetVmId())
	assert.Equal(t, "d2", server.attached.GetDisk().GetId())
	assert.Equal(t, "/var/lib/vm/d2.qcow2", server.attached.GetDisk().GetPath())
	assert.Equal(t, platformv1.DiskType_DISK_TYPE_QCOW2, server.attached.GetDisk().GetType())
	assert.Equal(t, uint64(10), server.attached.GetDisk().GetSizeGb())
}

func TestSDKREST_DetachDisk(t *testing.T) {
	server := &diskRecordingComputeServer{}
	client, _ := connectComputeSDK(t, server)

	_, err := client.DetachDisk(context.Background(),
		&platformv1.DetachDiskRequest{VmId: "vm-1", DiskId: "d2"})

	require.NoError(t, err)
	require.NotNil(t, server.detached)
	assert.Equal(t, "vm-1", server.detached.GetVmId())
	assert.Equal(t, "d2", server.detached.GetDiskId())
}

func TestSDKREST_ResizeDisk(t *testing.T) {
	server := &diskRecordingComputeServer{}
	client, _ := connectComputeSDK(t, server)

	_, err := client.ResizeDisk(context.Background(),
		&platformv1.ResizeDiskRequest{VmId: "vm-1", DiskId: "d2", NewSizeGb: 40})

	require.NoError(t, err)
	require.NotNil(t, server.resized)
	assert.Equal(t, "vm-1", server.resized.GetVmId())
	assert.Equal(t, "d2", server.resized.GetDiskId())
	assert.Equal(t, uint64(40), server.resized.GetNewSizeGb())
}

func TestSDKREST_MigrateVM(t *testing.T) {
	server := &diskRecordingComputeServer{}
	client, _ := connectComputeSDK(t, server)

	_, err := client.MigrateVM(context.Background(), &platformv1.MigrateVMRequest{
		VmId: "vm-1", DestinationHost: "dst", LiveMigration: true, BandwidthLimitMbps: 100,
	})

	require.NoError(t, err)
	require.NotNil(t, server.migrated)
	assert.Equal(t, "vm-1", server.migrated.GetVmId())
	assert.Equal(t, "dst", server.migrated.GetDestinationHost())
	assert.True(t, server.migrated.GetLiveMigration())
	assert.Equal(t, uint64(100), server.migrated.GetBandwidthLimitMbps())
}

func TestSDKREST_VMDiskClaims_EmptyIDRefusedBeforeSending(t *testing.T) {
	server := &diskRecordingComputeServer{}
	client, apiRequests := connectComputeSDK(t, server)
	ctx := context.Background()

	calls := map[string]func() error{
		"AttachDisk without vm_id": func() error {
			_, err := client.AttachDisk(ctx, &platformv1.AttachDiskRequest{Disk: &platformv1.DiskConfig{SizeGb: 10}})
			return err
		},
		"DetachDisk without vm_id": func() error {
			_, err := client.DetachDisk(ctx, &platformv1.DetachDiskRequest{DiskId: "d2"})
			return err
		},
		"DetachDisk without disk_id": func() error {
			_, err := client.DetachDisk(ctx, &platformv1.DetachDiskRequest{VmId: "vm-1"})
			return err
		},
		"ResizeDisk without vm_id": func() error {
			_, err := client.ResizeDisk(ctx, &platformv1.ResizeDiskRequest{DiskId: "d2", NewSizeGb: 40})
			return err
		},
		"ResizeDisk without disk_id": func() error {
			_, err := client.ResizeDisk(ctx, &platformv1.ResizeDiskRequest{VmId: "vm-1", NewSizeGb: 40})
			return err
		},
		"MigrateVM without vm_id": func() error {
			_, err := client.MigrateVM(ctx, &platformv1.MigrateVMRequest{DestinationHost: "dst"})
			return err
		},
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			err := call()
			require.Error(t, err)
			assert.Equal(t, codes.InvalidArgument, status.Code(err))
		})
	}
	assert.Zero(t, apiRequests.Load(), "an empty id must be refused before any request is sent")
	assert.Nil(t, server.attached)
	assert.Nil(t, server.detached)
	assert.Nil(t, server.resized)
	assert.Nil(t, server.migrated)
}
