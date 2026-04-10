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

package main

import (
	"log/slog"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

// ComputeBinding exposes compute service methods to the Wails frontend.
type ComputeBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewComputeBinding creates a new ComputeBinding.
func NewComputeBinding(logger *slog.Logger, conn *ConnectionBinding) *ComputeBinding {
	return &ComputeBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *ComputeBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// CreateVM creates a new virtual machine.
func (b *ComputeBinding) CreateVM(name, description string, start bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().CreateVM(b.conn.ctx, &platformv1.CreateVMRequest{
		Config: &platformv1.VMConfig{
			Name:        name,
			Description: description,
		},
		Start: start,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// StartVM starts a virtual machine by ID.
func (b *ComputeBinding) StartVM(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().StartVM(b.conn.ctx, &platformv1.StartVMRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// StopVM stops a virtual machine by ID.
func (b *ComputeBinding) StopVM(id string, force bool, timeoutSeconds uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().StopVM(b.conn.ctx, &platformv1.StopVMRequest{
		Id:             id,
		Force:          force,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteVM deletes a virtual machine by ID.
func (b *ComputeBinding) DeleteVM(id string, deleteDisks bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().DeleteVM(b.conn.ctx, &platformv1.DeleteVMRequest{
		Id:          id,
		DeleteDisks: deleteDisks,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetVM returns a virtual machine by ID.
func (b *ComputeBinding) GetVM(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().GetVM(b.conn.ctx, &platformv1.GetVMRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListVMs returns all virtual machines.
func (b *ComputeBinding) ListVMs() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().ListVMs(b.conn.ctx, &platformv1.ListVMsRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetVMMetrics returns metrics for a virtual machine.
func (b *ComputeBinding) GetVMMetrics(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().GetVMMetrics(b.conn.ctx, &platformv1.GetVMMetricsRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CreateContainer creates a new container.
func (b *ComputeBinding) CreateContainer(name, image string, start bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().CreateContainer(b.conn.ctx, &platformv1.CreateContainerRequest{
		Config: &platformv1.ContainerConfig{
			Name:  name,
			Image: image,
		},
		Start: start,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// StartContainer starts a container by ID.
func (b *ComputeBinding) StartContainer(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().StartContainer(b.conn.ctx, &platformv1.StartContainerRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// StopContainer stops a container by ID.
func (b *ComputeBinding) StopContainer(id string, timeoutSeconds uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().StopContainer(b.conn.ctx, &platformv1.StopContainerRequest{
		Id:             id,
		TimeoutSeconds: timeoutSeconds,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteContainer deletes a container by ID.
func (b *ComputeBinding) DeleteContainer(id string, force, deleteVolumes bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().DeleteContainer(b.conn.ctx, &platformv1.DeleteContainerRequest{
		Id:            id,
		Force:         force,
		DeleteVolumes: deleteVolumes,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetContainer returns a container by ID.
func (b *ComputeBinding) GetContainer(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().GetContainer(b.conn.ctx, &platformv1.GetContainerRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListContainers returns all containers.
func (b *ComputeBinding) ListContainers() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().ListContainers(b.conn.ctx, &platformv1.ListContainersRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetContainerMetrics returns metrics for a container.
func (b *ComputeBinding) GetContainerMetrics(id string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().GetContainerMetrics(b.conn.ctx, &platformv1.GetContainerMetricsRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ExecContainer executes a command in a running container.
func (b *ComputeBinding) ExecContainer(id string, command []string, workingDir string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().ExecContainer(b.conn.ctx, &platformv1.ExecContainerRequest{
		Id:         id,
		Command:    command,
		WorkingDir: workingDir,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CreateSnapshot creates a snapshot of a virtual machine.
func (b *ComputeBinding) CreateSnapshot(vmID, name, description string, memorySnapshot, diskSnapshot bool) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().CreateSnapshot(b.conn.ctx, &platformv1.CreateSnapshotRequest{
		VmId: vmID,
		Config: &platformv1.SnapshotConfig{
			Name:           name,
			Description:    description,
			MemorySnapshot: memorySnapshot,
			DiskSnapshot:   diskSnapshot,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListSnapshots returns all snapshots for a virtual machine.
func (b *ComputeBinding) ListSnapshots(vmID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().ListSnapshots(b.conn.ctx, &platformv1.ListSnapshotsRequest{
		VmId: vmID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteSnapshot deletes a snapshot.
func (b *ComputeBinding) DeleteSnapshot(vmID, snapshotID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().DeleteSnapshot(b.conn.ctx, &platformv1.DeleteSnapshotRequest{
		VmId:       vmID,
		SnapshotId: snapshotID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// RestoreSnapshot restores a virtual machine from a snapshot.
func (b *ComputeBinding) RestoreSnapshot(vmID, snapshotID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().RestoreSnapshot(b.conn.ctx, &platformv1.RestoreSnapshotRequest{
		VmId:       vmID,
		SnapshotId: snapshotID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// AttestVM performs TPM-based attestation on a virtual machine.
func (b *ComputeBinding) AttestVM(vmID string, nonce []byte, pcrIndices []uint32) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Compute().AttestVM(b.conn.ctx, &platformv1.AttestVMRequest{
		VmId:       vmID,
		Nonce:      nonce,
		PcrIndices: pcrIndices,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}
