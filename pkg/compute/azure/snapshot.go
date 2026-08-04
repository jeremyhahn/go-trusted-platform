//go:build azurecompute

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

package azure

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// gibiBytes is the number of bytes in one GiB (Azure reports disk/snapshot size
// in GiB).
const gibiBytes int64 = 1024 * 1024 * 1024

// CreateSnapshot captures a managed-disk snapshot of the VM's OS disk. Azure
// snapshots are crash-consistent disk snapshots; unlike QEMU internal snapshots
// they do not capture live guest memory. See docs/compute/cloud-providers.md
// for the parity notes.
func (o *AzureOrchestrator) CreateSnapshot(ctx context.Context, instanceID, snapshotName string) (*compute.VMSnapshot, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}
	if snapshotName == "" {
		return nil, compute.ErrInvalidSnapshotName
	}

	azVM, err := o.describeVM(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	diskID, err := osDiskID(azVM)
	if err != nil {
		return nil, err
	}

	azSnapName := azureSnapshotName(instanceID, snapshotName)
	params := armcompute.Snapshot{
		Location: to.Ptr(o.azure.Location),
		Tags:     o.snapshotTags(snapshotName, instanceID),
		Properties: &armcompute.SnapshotProperties{
			CreationData: &armcompute.CreationData{
				CreateOption:     to.Ptr(armcompute.DiskCreateOptionCopy),
				SourceResourceID: to.Ptr(diskID),
			},
		},
	}
	created, err := o.client.CreateSnapshot(ctx, azSnapName, params)
	if err != nil {
		return nil, &APIError{Op: "CreateSnapshot", Err: err}
	}

	snap := &compute.VMSnapshot{
		Name:        snapshotName,
		VMID:        instanceID,
		CreatedAt:   snapshotTime(created),
		SizeBytes:   snapshotSizeBytes(created),
		Description: "azure snapshot " + derefStr(created.Name),
	}
	o.logger.Infof("Created Azure snapshot %s (%s) of VM %s", derefStr(created.Name), snapshotName, instanceID)
	return snap, nil
}

// DeleteSnapshot removes the snapshot correlated with the given name.
func (o *AzureOrchestrator) DeleteSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if snapshotName == "" {
		return compute.ErrInvalidSnapshotName
	}

	azSnapName, err := o.resolveSnapshotName(ctx, instanceID, snapshotName)
	if err != nil {
		return err
	}
	if err := o.client.DeleteSnapshot(ctx, azSnapName); err != nil {
		return &APIError{Op: "DeleteSnapshot", Err: err}
	}
	o.logger.Infof("Deleted Azure snapshot %s (%s)", azSnapName, snapshotName)
	return nil
}

// ListSnapshots lists all snapshots taken of the VM's disks.
func (o *AzureOrchestrator) ListSnapshots(ctx context.Context, instanceID string) ([]*compute.VMSnapshot, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}
	azSnaps, err := o.client.ListSnapshots(ctx)
	if err != nil {
		return nil, &APIError{Op: "ListSnapshots", Err: err}
	}
	snapshots := make([]*compute.VMSnapshot, 0)
	for _, s := range azSnaps {
		if tagValue(s.Tags, vmIDTagKey) != instanceID {
			continue
		}
		name := tagValue(s.Tags, snapNameTagKey)
		if name == "" {
			name = derefStr(s.Name)
		}
		snapshots = append(snapshots, &compute.VMSnapshot{
			Name:        name,
			VMID:        instanceID,
			CreatedAt:   snapshotTime(s),
			SizeBytes:   snapshotSizeBytes(s),
			Description: "azure snapshot " + derefStr(s.Name),
		})
	}
	return snapshots, nil
}

// RestoreSnapshot restores the VM's OS disk from a snapshot. Azure restore is
// not a live operation, so the honest full-parity sequence is: deallocate the
// VM, create a fresh managed disk from the snapshot, swap the VM's OS disk to
// the new disk via an update, and start the VM again. Guest memory is not
// restored (disk snapshots are disk-only).
func (o *AzureOrchestrator) RestoreSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if snapshotName == "" {
		return compute.ErrInvalidSnapshotName
	}

	azSnapName, err := o.resolveSnapshotName(ctx, instanceID, snapshotName)
	if err != nil {
		return err
	}
	snap, err := o.snapshotByName(ctx, instanceID, snapshotName)
	if err != nil {
		return err
	}
	snapshotID := derefStr(snap.ID)

	// 1. Deallocate the VM and wait for it to reach the deallocated state.
	if err := o.client.DeallocateVM(ctx, instanceID); err != nil {
		return &APIError{Op: "DeallocateVM", Err: err}
	}
	if err := o.pollPowerUntil(ctx, instanceID, func(state string) bool {
		return state == powerStateDeallocated || state == powerStateStopped
	}); err != nil {
		return err
	}

	// 2. Create a fresh managed disk from the snapshot in the VM's location.
	newDiskName := azSnapName + "-restore"
	diskParams := armcompute.Disk{
		Location: to.Ptr(o.azure.Location),
		Tags:     o.resourceTags(newDiskName, instanceID),
		Properties: &armcompute.DiskProperties{
			CreationData: &armcompute.CreationData{
				CreateOption:     to.Ptr(armcompute.DiskCreateOptionCopy),
				SourceResourceID: to.Ptr(snapshotID),
			},
		},
	}
	newDisk, err := o.client.CreateDisk(ctx, newDiskName, diskParams)
	if err != nil {
		return &APIError{Op: "CreateDisk", Err: err}
	}

	// 3. Swap the VM's OS disk to the restored disk and start it.
	update := armcompute.VirtualMachineUpdate{
		Properties: &armcompute.VirtualMachineProperties{
			StorageProfile: &armcompute.StorageProfile{
				OSDisk: &armcompute.OSDisk{
					CreateOption: to.Ptr(armcompute.DiskCreateOptionTypesAttach),
					ManagedDisk:  &armcompute.ManagedDiskParameters{ID: newDisk.ID},
				},
			},
		},
	}
	if _, err := o.client.UpdateVM(ctx, instanceID, update); err != nil {
		return &APIError{Op: "UpdateVM", Err: err}
	}
	if err := o.client.StartVM(ctx, instanceID); err != nil {
		return &APIError{Op: "StartVM", Err: err}
	}

	o.logger.Infof("Restored VM %s OS disk from snapshot %s (new disk %s)", instanceID, azSnapName, derefStr(newDisk.Name))
	return nil
}

// resolveSnapshotName resolves a platform snapshot name to its Azure snapshot
// name via the correlation tags.
func (o *AzureOrchestrator) resolveSnapshotName(ctx context.Context, instanceID, snapshotName string) (string, error) {
	snap, err := o.snapshotByName(ctx, instanceID, snapshotName)
	if err != nil {
		return "", err
	}
	return derefStr(snap.Name), nil
}

// snapshotByName returns the Azure snapshot resource whose correlation tags
// match the instance and platform snapshot name.
func (o *AzureOrchestrator) snapshotByName(ctx context.Context, instanceID, snapshotName string) (*armcompute.Snapshot, error) {
	azSnaps, err := o.client.ListSnapshots(ctx)
	if err != nil {
		return nil, &APIError{Op: "ListSnapshots", Err: err}
	}
	for _, s := range azSnaps {
		if tagValue(s.Tags, vmIDTagKey) == instanceID && tagValue(s.Tags, snapNameTagKey) == snapshotName {
			return s, nil
		}
	}
	return nil, compute.ErrSnapshotNotFound
}

// snapshotTags returns the tag set applied to a snapshot for correlation.
func (o *AzureOrchestrator) snapshotTags(snapshotName, instanceID string) map[string]*string {
	tags := o.resourceTags(snapshotName, instanceID)
	tags[snapNameTagKey] = to.Ptr(snapshotName)
	return tags
}

// osDiskID returns the resource ID of the VM's OS managed disk.
func osDiskID(azVM *armcompute.VirtualMachine) (string, error) {
	if azVM.Properties != nil &&
		azVM.Properties.StorageProfile != nil &&
		azVM.Properties.StorageProfile.OSDisk != nil &&
		azVM.Properties.StorageProfile.OSDisk.ManagedDisk != nil {
		if id := derefStr(azVM.Properties.StorageProfile.OSDisk.ManagedDisk.ID); id != "" {
			return id, nil
		}
	}
	return "", &SentinelCauseError{Sentinel: ErrCapabilityNotSupported, Cause: &compute.MessageError{Msg: "VM has no managed OS disk to snapshot"}}
}

// azureSnapshotName derives a deterministic, Azure-valid snapshot resource name
// from the instance ID and platform snapshot name.
func azureSnapshotName(instanceID, snapshotName string) string {
	return instanceID + "-" + snapshotName
}

// snapshotTime returns the snapshot creation time, defaulting to now.
func snapshotTime(s *armcompute.Snapshot) time.Time {
	if s != nil && s.Properties != nil && s.Properties.TimeCreated != nil {
		return s.Properties.TimeCreated.UTC()
	}
	return time.Now().UTC()
}

// snapshotSizeBytes returns the snapshot disk size in bytes, or 0 when unknown.
func snapshotSizeBytes(s *armcompute.Snapshot) int64 {
	if s != nil && s.Properties != nil && s.Properties.DiskSizeGB != nil {
		return int64(*s.Properties.DiskSizeGB) * gibiBytes
	}
	return 0
}
