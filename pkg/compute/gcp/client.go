//go:build gcpcompute

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

package gcp

import (
	"context"

	gce "cloud.google.com/go/compute/apiv1"
	computepb "cloud.google.com/go/compute/apiv1/computepb"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// gceAPI is the narrow slice of Google Compute Engine used by the
// orchestrator. Every long-running Operation is waited on inside the concrete
// implementation so the seam exposes only settled values; unit tests provide a
// fake that never touches the network or the Operation machinery.
type gceAPI interface {
	// InsertInstance creates an instance, waits for the operation to settle,
	// and returns the freshly-read instance.
	InsertInstance(ctx context.Context, inst *computepb.Instance) (*computepb.Instance, error)
	StartInstance(ctx context.Context, name string) error
	StopInstance(ctx context.Context, name string) error
	DeleteInstance(ctx context.Context, name string) error
	GetInstance(ctx context.Context, name string) (*computepb.Instance, error)
	ListInstances(ctx context.Context, filter string) ([]*computepb.Instance, error)
	ShieldedIdentity(ctx context.Context, name string) (*computepb.ShieldedInstanceIdentity, error)

	// CreateDiskSnapshot snapshots a zonal disk and returns the settled global
	// snapshot resource.
	CreateDiskSnapshot(ctx context.Context, diskName string, snap *computepb.Snapshot) (*computepb.Snapshot, error)
	DeleteSnapshot(ctx context.Context, snapshotName string) error
	ListSnapshots(ctx context.Context, filter string) ([]*computepb.Snapshot, error)

	// InsertDisk creates a zonal disk (used to restore from a snapshot).
	InsertDisk(ctx context.Context, disk *computepb.Disk) error
	AttachDisk(ctx context.Context, instanceName string, disk *computepb.AttachedDisk) error
	DetachDisk(ctx context.Context, instanceName, deviceName string) error

	Close() error
}

// gceClients is the production gceAPI backed by the three GCE REST clients.
// It owns the project/zone scope so orchestrator call sites stay terse.
type gceClients struct {
	project   string
	zone      string
	instances *gce.InstancesClient
	disks     *gce.DisksClient
	snapshots *gce.SnapshotsClient
}

// newGCEClients builds the composite client from the provider configuration,
// applying an optional service-account credentials file (empty falls back to
// application default credentials).
func newGCEClients(ctx context.Context, project, zone, credentialsFile string) (*gceClients, error) {
	var opts []option.ClientOption
	if credentialsFile != "" {
		opts = append(opts, option.WithCredentialsFile(credentialsFile))
	}

	instances, err := gce.NewInstancesRESTClient(ctx, opts...)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrShieldedVMUnsupported, Cause: err}
	}
	disks, err := gce.NewDisksRESTClient(ctx, opts...)
	if err != nil {
		_ = instances.Close()
		return nil, &SentinelCauseError{Sentinel: ErrShieldedVMUnsupported, Cause: err}
	}
	snapshots, err := gce.NewSnapshotsRESTClient(ctx, opts...)
	if err != nil {
		_ = instances.Close()
		_ = disks.Close()
		return nil, &SentinelCauseError{Sentinel: ErrShieldedVMUnsupported, Cause: err}
	}
	return &gceClients{
		project:   project,
		zone:      zone,
		instances: instances,
		disks:     disks,
		snapshots: snapshots,
	}, nil
}

// InsertInstance implements gceAPI.
func (c *gceClients) InsertInstance(ctx context.Context, inst *computepb.Instance) (*computepb.Instance, error) {
	op, err := c.instances.Insert(ctx, &computepb.InsertInstanceRequest{
		Project:          c.project,
		Zone:             c.zone,
		InstanceResource: inst,
	})
	if err != nil {
		return nil, err
	}
	if err := op.Wait(ctx); err != nil {
		return nil, err
	}
	return c.GetInstance(ctx, inst.GetName())
}

// StartInstance implements gceAPI.
func (c *gceClients) StartInstance(ctx context.Context, name string) error {
	op, err := c.instances.Start(ctx, &computepb.StartInstanceRequest{
		Project:  c.project,
		Zone:     c.zone,
		Instance: name,
	})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

// StopInstance implements gceAPI.
func (c *gceClients) StopInstance(ctx context.Context, name string) error {
	op, err := c.instances.Stop(ctx, &computepb.StopInstanceRequest{
		Project:  c.project,
		Zone:     c.zone,
		Instance: name,
	})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

// DeleteInstance implements gceAPI.
func (c *gceClients) DeleteInstance(ctx context.Context, name string) error {
	op, err := c.instances.Delete(ctx, &computepb.DeleteInstanceRequest{
		Project:  c.project,
		Zone:     c.zone,
		Instance: name,
	})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

// GetInstance implements gceAPI.
func (c *gceClients) GetInstance(ctx context.Context, name string) (*computepb.Instance, error) {
	return c.instances.Get(ctx, &computepb.GetInstanceRequest{
		Project:  c.project,
		Zone:     c.zone,
		Instance: name,
	})
}

// ListInstances implements gceAPI.
func (c *gceClients) ListInstances(ctx context.Context, filter string) ([]*computepb.Instance, error) {
	req := &computepb.ListInstancesRequest{Project: c.project, Zone: c.zone}
	if filter != "" {
		req.Filter = &filter
	}
	it := c.instances.List(ctx, req)
	var out []*computepb.Instance
	for {
		inst, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, inst)
	}
	return out, nil
}

// ShieldedIdentity implements gceAPI.
func (c *gceClients) ShieldedIdentity(ctx context.Context, name string) (*computepb.ShieldedInstanceIdentity, error) {
	return c.instances.GetShieldedInstanceIdentity(ctx, &computepb.GetShieldedInstanceIdentityInstanceRequest{
		Project:  c.project,
		Zone:     c.zone,
		Instance: name,
	})
}

// CreateDiskSnapshot implements gceAPI.
func (c *gceClients) CreateDiskSnapshot(ctx context.Context, diskName string, snap *computepb.Snapshot) (*computepb.Snapshot, error) {
	op, err := c.disks.CreateSnapshot(ctx, &computepb.CreateSnapshotDiskRequest{
		Project:          c.project,
		Zone:             c.zone,
		Disk:             diskName,
		SnapshotResource: snap,
	})
	if err != nil {
		return nil, err
	}
	if err := op.Wait(ctx); err != nil {
		return nil, err
	}
	return c.snapshots.Get(ctx, &computepb.GetSnapshotRequest{
		Project:  c.project,
		Snapshot: snap.GetName(),
	})
}

// DeleteSnapshot implements gceAPI.
func (c *gceClients) DeleteSnapshot(ctx context.Context, snapshotName string) error {
	op, err := c.snapshots.Delete(ctx, &computepb.DeleteSnapshotRequest{
		Project:  c.project,
		Snapshot: snapshotName,
	})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

// ListSnapshots implements gceAPI.
func (c *gceClients) ListSnapshots(ctx context.Context, filter string) ([]*computepb.Snapshot, error) {
	req := &computepb.ListSnapshotsRequest{Project: c.project}
	if filter != "" {
		req.Filter = &filter
	}
	it := c.snapshots.List(ctx, req)
	var out []*computepb.Snapshot
	for {
		snap, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, snap)
	}
	return out, nil
}

// InsertDisk implements gceAPI.
func (c *gceClients) InsertDisk(ctx context.Context, disk *computepb.Disk) error {
	op, err := c.disks.Insert(ctx, &computepb.InsertDiskRequest{
		Project:      c.project,
		Zone:         c.zone,
		DiskResource: disk,
	})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

// AttachDisk implements gceAPI.
func (c *gceClients) AttachDisk(ctx context.Context, instanceName string, disk *computepb.AttachedDisk) error {
	op, err := c.instances.AttachDisk(ctx, &computepb.AttachDiskInstanceRequest{
		Project:              c.project,
		Zone:                 c.zone,
		Instance:             instanceName,
		AttachedDiskResource: disk,
	})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

// DetachDisk implements gceAPI.
func (c *gceClients) DetachDisk(ctx context.Context, instanceName, deviceName string) error {
	op, err := c.instances.DetachDisk(ctx, &computepb.DetachDiskInstanceRequest{
		Project:    c.project,
		Zone:       c.zone,
		Instance:   instanceName,
		DeviceName: deviceName,
	})
	if err != nil {
		return err
	}
	return op.Wait(ctx)
}

// Close releases the three underlying REST clients.
func (c *gceClients) Close() error {
	var firstErr error
	for _, closer := range []func() error{c.instances.Close, c.disks.Close, c.snapshots.Close} {
		if err := closer(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
