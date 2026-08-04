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
	"strings"
	"time"

	"context"

	computepb "cloud.google.com/go/compute/apiv1/computepb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// gibiBytes is the number of bytes in one GiB (GCE reports disk/snapshot size
// in GiB).
const gibiBytes int64 = 1024 * 1024 * 1024

// CreateSnapshot captures a persistent-disk snapshot of the instance's boot
// disk. GCE snapshots are crash-consistent disk snapshots; unlike QEMU
// internal snapshots they do not capture live guest memory. See
// docs/compute/cloud-providers.md for the parity notes.
func (o *GCPOrchestrator) CreateSnapshot(ctx context.Context, instanceID, snapshotName string) (*compute.VMSnapshot, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}
	if snapshotName == "" {
		return nil, compute.ErrInvalidSnapshotName
	}

	gi, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	diskName, _, err := bootDisk(gi)
	if err != nil {
		return nil, err
	}

	snapResource := &computepb.Snapshot{
		Name:   ptr(sanitizeInstanceName(snapshotName)),
		Labels: o.snapshotLabels(snapshotName, instanceID),
	}
	created, err := o.client.CreateDiskSnapshot(ctx, diskName, snapResource)
	if err != nil {
		return nil, &APIError{Op: "CreateDiskSnapshot", Err: err}
	}

	snap := &compute.VMSnapshot{
		Name:        snapshotName,
		VMID:        instanceID,
		CreatedAt:   parseGCETime(created.GetCreationTimestamp()),
		SizeBytes:   created.GetDiskSizeGb() * gibiBytes,
		Description: "gce snapshot " + created.GetName(),
	}
	o.logger.Infof("Created GCE snapshot %s (%s) of instance %s", created.GetName(), snapshotName, instanceID)
	return snap, nil
}

// DeleteSnapshot removes the snapshot correlated with the given name.
func (o *GCPOrchestrator) DeleteSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if snapshotName == "" {
		return compute.ErrInvalidSnapshotName
	}

	snapshotID, err := o.resolveSnapshotName(ctx, instanceID, snapshotName)
	if err != nil {
		return err
	}
	if err := o.client.DeleteSnapshot(ctx, snapshotID); err != nil {
		return &APIError{Op: "DeleteSnapshot", Err: err}
	}
	o.logger.Infof("Deleted GCE snapshot %s (%s)", snapshotID, snapshotName)
	return nil
}

// ListSnapshots lists all snapshots taken of the instance's disks.
func (o *GCPOrchestrator) ListSnapshots(ctx context.Context, instanceID string) ([]*compute.VMSnapshot, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}
	gceSnaps, err := o.client.ListSnapshots(ctx, "labels."+vmIDLabelKey+"="+instanceID)
	if err != nil {
		return nil, &APIError{Op: "ListSnapshots", Err: err}
	}
	snapshots := make([]*compute.VMSnapshot, 0, len(gceSnaps))
	for _, s := range gceSnaps {
		name := labelValue(s.GetLabels(), snapNameLabelKey)
		if name == "" {
			name = s.GetName()
		}
		snapshots = append(snapshots, &compute.VMSnapshot{
			Name:        name,
			VMID:        instanceID,
			CreatedAt:   parseGCETime(s.GetCreationTimestamp()),
			SizeBytes:   s.GetDiskSizeGb() * gibiBytes,
			Description: "gce snapshot " + s.GetName(),
		})
	}
	return snapshots, nil
}

// RestoreSnapshot restores the instance's boot disk from a snapshot. GCE
// restore is not a live operation, so the honest full-parity sequence is: stop
// the instance, detach the current boot disk, create a fresh disk from the
// snapshot in the instance's zone, attach it as the boot disk, and start the
// instance again. Guest memory is not restored (disk snapshots are disk-only).
func (o *GCPOrchestrator) RestoreSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if snapshotName == "" {
		return compute.ErrInvalidSnapshotName
	}

	snapshotID, err := o.resolveSnapshotName(ctx, instanceID, snapshotName)
	if err != nil {
		return err
	}

	gi, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	oldDiskName, deviceName, err := bootDisk(gi)
	if err != nil {
		return err
	}

	// 1. Stop the instance and wait for it to be powered off.
	if err := o.client.StopInstance(ctx, instanceID); err != nil {
		return &APIError{Op: "StopInstance", Err: err}
	}
	if err := o.pollInstanceUntil(ctx, instanceID, func(status string) bool {
		return status == statusStopped || status == statusTerminated
	}); err != nil {
		return err
	}

	// 2. Detach the current boot disk.
	if err := o.client.DetachDisk(ctx, instanceID, deviceName); err != nil {
		return &APIError{Op: "DetachDisk", Err: err}
	}

	// 3. Create a fresh disk from the snapshot in the instance's zone.
	newDiskName := oldDiskName + "-restore"
	newDisk := &computepb.Disk{
		Name:           ptr(newDiskName),
		SourceSnapshot: ptr("global/snapshots/" + snapshotID),
	}
	if err := o.client.InsertDisk(ctx, newDisk); err != nil {
		return &APIError{Op: "InsertDisk", Err: err}
	}

	// 4. Attach the restored disk as the boot disk and restart.
	boot := true
	attached := &computepb.AttachedDisk{
		Boot:       &boot,
		DeviceName: ptr(deviceName),
		Source:     ptr("zones/" + o.gcp.Zone + "/disks/" + newDiskName),
	}
	if err := o.client.AttachDisk(ctx, instanceID, attached); err != nil {
		return &APIError{Op: "AttachDisk", Err: err}
	}
	if err := o.client.StartInstance(ctx, instanceID); err != nil {
		return &APIError{Op: "StartInstance", Err: err}
	}

	o.logger.Infof("Restored instance %s boot disk from snapshot %s (new disk %s)", instanceID, snapshotID, newDiskName)
	return nil
}

// resolveSnapshotName resolves a platform snapshot name to its GCE snapshot
// name via the correlation labels.
func (o *GCPOrchestrator) resolveSnapshotName(ctx context.Context, instanceID, snapshotName string) (string, error) {
	filter := "labels." + vmIDLabelKey + "=" + instanceID +
		" AND labels." + snapNameLabelKey + "=" + sanitizeInstanceName(snapshotName)
	snaps, err := o.client.ListSnapshots(ctx, filter)
	if err != nil {
		return "", &APIError{Op: "ListSnapshots", Err: err}
	}
	if len(snaps) == 0 {
		return "", compute.ErrSnapshotNotFound
	}
	return snaps[0].GetName(), nil
}

// snapshotLabels returns the label set applied to a snapshot for correlation.
func (o *GCPOrchestrator) snapshotLabels(snapshotName, instanceID string) map[string]string {
	labels := o.resourceLabels(snapshotName, instanceID)
	labels[snapNameLabelKey] = sanitizeInstanceName(snapshotName)
	return labels
}

// bootDisk returns the disk name and device name of the instance's boot disk.
func bootDisk(gi *computepb.Instance) (diskName, deviceName string, err error) {
	for _, d := range gi.GetDisks() {
		if d.GetBoot() {
			return resourceName(d.GetSource()), d.GetDeviceName(), nil
		}
	}
	return "", "", &SentinelCauseError{Sentinel: ErrCapabilityNotSupported, Cause: &compute.MessageError{Msg: "instance has no boot disk to snapshot"}}
}

// parseGCETime parses a GCE RFC3339 timestamp string, falling back to the
// current time when the field is empty or malformed.
func parseGCETime(ts string) time.Time {
	ts = strings.TrimSpace(ts)
	if ts != "" {
		if t, err := time.Parse(time.RFC3339, ts); err == nil {
			return t.UTC()
		}
	}
	return time.Now().UTC()
}
