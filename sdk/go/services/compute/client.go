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

// Package compute provides a client for compute service operations.
package compute

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to compute service operations.
type Client struct {
	grpc platformv1.ComputeServiceClient
}

// NewClient creates a new compute service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewComputeServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new compute service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.ComputeServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// VM Operations

// CreateVM creates a new virtual machine.
func (c *Client) CreateVM(ctx context.Context, config *platformv1.VMConfig, start bool) (*platformv1.VM, error) {
	resp, err := c.grpc.CreateVM(ctx, &platformv1.CreateVMRequest{Config: config, Start: start})
	if err != nil {
		return nil, &ErrCreateVMFailed{Cause: err}
	}
	return resp.Vm, nil
}

// StartVM starts a virtual machine.
func (c *Client) StartVM(ctx context.Context, id string) error {
	_, err := c.grpc.StartVM(ctx, &platformv1.StartVMRequest{Id: id})
	if err != nil {
		return &ErrStartVMFailed{ID: id, Cause: err}
	}
	return nil
}

// StopVM stops a virtual machine.
func (c *Client) StopVM(ctx context.Context, id string, force bool, timeoutSeconds uint32) error {
	_, err := c.grpc.StopVM(ctx, &platformv1.StopVMRequest{
		Id:             id,
		Force:          force,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		return &ErrStopVMFailed{ID: id, Cause: err}
	}
	return nil
}

// RebootVM reboots a virtual machine.
func (c *Client) RebootVM(ctx context.Context, id string, force bool) error {
	_, err := c.grpc.RebootVM(ctx, &platformv1.RebootVMRequest{Id: id, Force: force})
	if err != nil {
		return &ErrRebootVMFailed{ID: id, Cause: err}
	}
	return nil
}

// DeleteVM deletes a virtual machine.
func (c *Client) DeleteVM(ctx context.Context, id string, deleteDisks bool) error {
	_, err := c.grpc.DeleteVM(ctx, &platformv1.DeleteVMRequest{Id: id, DeleteDisks: deleteDisks})
	if err != nil {
		return &ErrDeleteVMFailed{ID: id, Cause: err}
	}
	return nil
}

// GetVM retrieves a virtual machine by ID.
func (c *Client) GetVM(ctx context.Context, id string) (*platformv1.VM, error) {
	resp, err := c.grpc.GetVM(ctx, &platformv1.GetVMRequest{Id: id})
	if err != nil {
		return nil, &ErrGetVMFailed{ID: id, Cause: err}
	}
	return resp.Vm, nil
}

// ListVMs lists virtual machines with optional filtering.
func (c *Client) ListVMs(ctx context.Context, req *platformv1.ListVMsRequest) ([]*platformv1.VM, *common.PageResult, error) {
	resp, err := c.grpc.ListVMs(ctx, req)
	if err != nil {
		return nil, nil, &ErrListVMsFailed{Cause: err}
	}
	var pageResult *common.PageResult
	if resp.Pagination != nil {
		pageResult = &common.PageResult{
			Page:       resp.Pagination.Page,
			PageSize:   resp.Pagination.PageSize,
			TotalPages: resp.Pagination.TotalPages,
			TotalItems: resp.Pagination.TotalItems,
		}
	}
	return resp.Vms, pageResult, nil
}

// GetVMMetrics retrieves metrics for a virtual machine.
func (c *Client) GetVMMetrics(ctx context.Context, id string) (*platformv1.VMMetrics, error) {
	resp, err := c.grpc.GetVMMetrics(ctx, &platformv1.GetVMMetricsRequest{Id: id})
	if err != nil {
		return nil, &ErrGetVMMetricsFailed{ID: id, Cause: err}
	}
	return resp.Metrics, nil
}

// AttachDisk attaches a disk to a virtual machine.
func (c *Client) AttachDisk(ctx context.Context, vmID string, disk *platformv1.DiskConfig) error {
	_, err := c.grpc.AttachDisk(ctx, &platformv1.AttachDiskRequest{VmId: vmID, Disk: disk})
	if err != nil {
		return &ErrAttachDiskFailed{VMID: vmID, Cause: err}
	}
	return nil
}

// DetachDisk detaches a disk from a virtual machine.
func (c *Client) DetachDisk(ctx context.Context, vmID, diskID string) error {
	_, err := c.grpc.DetachDisk(ctx, &platformv1.DetachDiskRequest{VmId: vmID, DiskId: diskID})
	if err != nil {
		return &ErrDetachDiskFailed{VMID: vmID, DiskID: diskID, Cause: err}
	}
	return nil
}

// ResizeDisk resizes a disk attached to a virtual machine.
func (c *Client) ResizeDisk(ctx context.Context, vmID, diskID string, newSizeGB uint64) error {
	_, err := c.grpc.ResizeDisk(ctx, &platformv1.ResizeDiskRequest{
		VmId:      vmID,
		DiskId:    diskID,
		NewSizeGb: newSizeGB,
	})
	if err != nil {
		return &ErrResizeDiskFailed{VMID: vmID, DiskID: diskID, Cause: err}
	}
	return nil
}

// Snapshot Operations

// CreateSnapshot creates a snapshot of a virtual machine.
func (c *Client) CreateSnapshot(ctx context.Context, vmID string, config *platformv1.SnapshotConfig) (*platformv1.Snapshot, error) {
	resp, err := c.grpc.CreateSnapshot(ctx, &platformv1.CreateSnapshotRequest{VmId: vmID, Config: config})
	if err != nil {
		return nil, &ErrCreateSnapshotFailed{VMID: vmID, Cause: err}
	}
	return resp.Snapshot, nil
}

// RestoreSnapshot restores a virtual machine from a snapshot.
func (c *Client) RestoreSnapshot(ctx context.Context, vmID, snapshotID string) error {
	_, err := c.grpc.RestoreSnapshot(ctx, &platformv1.RestoreSnapshotRequest{VmId: vmID, SnapshotId: snapshotID})
	if err != nil {
		return &ErrRestoreSnapshotFailed{VMID: vmID, SnapshotID: snapshotID, Cause: err}
	}
	return nil
}

// DeleteSnapshot deletes a snapshot.
func (c *Client) DeleteSnapshot(ctx context.Context, vmID, snapshotID string) error {
	_, err := c.grpc.DeleteSnapshot(ctx, &platformv1.DeleteSnapshotRequest{VmId: vmID, SnapshotId: snapshotID})
	if err != nil {
		return &ErrDeleteSnapshotFailed{VMID: vmID, SnapshotID: snapshotID, Cause: err}
	}
	return nil
}

// ListSnapshots lists snapshots for a virtual machine.
func (c *Client) ListSnapshots(ctx context.Context, vmID string) ([]*platformv1.Snapshot, error) {
	resp, err := c.grpc.ListSnapshots(ctx, &platformv1.ListSnapshotsRequest{VmId: vmID})
	if err != nil {
		return nil, &ErrListSnapshotsFailed{VMID: vmID, Cause: err}
	}
	return resp.Snapshots, nil
}

// MigrateVM migrates a virtual machine to another host.
func (c *Client) MigrateVM(ctx context.Context, vmID, destinationHost string, live bool, bandwidthLimit uint64) error {
	_, err := c.grpc.MigrateVM(ctx, &platformv1.MigrateVMRequest{
		VmId:               vmID,
		DestinationHost:    destinationHost,
		LiveMigration:      live,
		BandwidthLimitMbps: bandwidthLimit,
	})
	if err != nil {
		return &ErrMigrateVMFailed{VMID: vmID, Cause: err}
	}
	return nil
}

// Container Operations

// CreateContainer creates a new container.
func (c *Client) CreateContainer(ctx context.Context, config *platformv1.ContainerConfig, start bool) (*platformv1.Container, error) {
	resp, err := c.grpc.CreateContainer(ctx, &platformv1.CreateContainerRequest{Config: config, Start: start})
	if err != nil {
		return nil, &ErrCreateContainerFailed{Cause: err}
	}
	return resp.Container, nil
}

// StartContainer starts a container.
func (c *Client) StartContainer(ctx context.Context, id string) error {
	_, err := c.grpc.StartContainer(ctx, &platformv1.StartContainerRequest{Id: id})
	if err != nil {
		return &ErrStartContainerFailed{ID: id, Cause: err}
	}
	return nil
}

// StopContainer stops a container.
func (c *Client) StopContainer(ctx context.Context, id string, timeoutSeconds uint32) error {
	_, err := c.grpc.StopContainer(ctx, &platformv1.StopContainerRequest{Id: id, TimeoutSeconds: timeoutSeconds})
	if err != nil {
		return &ErrStopContainerFailed{ID: id, Cause: err}
	}
	return nil
}

// DeleteContainer deletes a container.
func (c *Client) DeleteContainer(ctx context.Context, id string, force, deleteVolumes bool) error {
	_, err := c.grpc.DeleteContainer(ctx, &platformv1.DeleteContainerRequest{
		Id:            id,
		Force:         force,
		DeleteVolumes: deleteVolumes,
	})
	if err != nil {
		return &ErrDeleteContainerFailed{ID: id, Cause: err}
	}
	return nil
}

// GetContainer retrieves a container by ID.
func (c *Client) GetContainer(ctx context.Context, id string) (*platformv1.Container, error) {
	resp, err := c.grpc.GetContainer(ctx, &platformv1.GetContainerRequest{Id: id})
	if err != nil {
		return nil, &ErrGetContainerFailed{ID: id, Cause: err}
	}
	return resp.Container, nil
}

// ListContainers lists containers with optional filtering.
func (c *Client) ListContainers(ctx context.Context, req *platformv1.ListContainersRequest) ([]*platformv1.Container, *common.PageResult, error) {
	resp, err := c.grpc.ListContainers(ctx, req)
	if err != nil {
		return nil, nil, &ErrListContainersFailed{Cause: err}
	}
	var pageResult *common.PageResult
	if resp.Pagination != nil {
		pageResult = &common.PageResult{
			Page:       resp.Pagination.Page,
			PageSize:   resp.Pagination.PageSize,
			TotalPages: resp.Pagination.TotalPages,
			TotalItems: resp.Pagination.TotalItems,
		}
	}
	return resp.Containers, pageResult, nil
}

// ExecContainer executes a command in a container.
func (c *Client) ExecContainer(ctx context.Context, req *platformv1.ExecContainerRequest) (*platformv1.ExecContainerResponse, error) {
	resp, err := c.grpc.ExecContainer(ctx, req)
	if err != nil {
		return nil, &ErrExecContainerFailed{ID: req.Id, Cause: err}
	}
	return resp, nil
}

// GetContainerMetrics retrieves metrics for a container.
func (c *Client) GetContainerMetrics(ctx context.Context, id string) (*platformv1.ContainerMetrics, error) {
	resp, err := c.grpc.GetContainerMetrics(ctx, &platformv1.GetContainerMetricsRequest{Id: id})
	if err != nil {
		return nil, &ErrGetContainerMetricsFailed{ID: id, Cause: err}
	}
	return resp.Metrics, nil
}

// VM Attestation

// AttestVM generates an attestation quote from a VM's vTPM.
func (c *Client) AttestVM(ctx context.Context, vmID string, nonce []byte, pcrIndices []uint32, pcrBank platformv1.PCRBank) (*platformv1.AttestVMResponse, error) {
	resp, err := c.grpc.AttestVM(ctx, &platformv1.AttestVMRequest{
		VmId:       vmID,
		Nonce:      nonce,
		PcrIndices: pcrIndices,
		PcrBank:    pcrBank,
	})
	if err != nil {
		return nil, &ErrAttestVMFailed{VMID: vmID, Cause: err}
	}
	return resp, nil
}

// VerifyVMAttestation verifies a VM attestation quote.
func (c *Client) VerifyVMAttestation(ctx context.Context, req *platformv1.VerifyVMAttestationRequest) (*platformv1.VerifyVMAttestationResponse, error) {
	resp, err := c.grpc.VerifyVMAttestation(ctx, req)
	if err != nil {
		return nil, &ErrVerifyVMAttestationFailed{VMID: req.VmId, Cause: err}
	}
	return resp, nil
}
