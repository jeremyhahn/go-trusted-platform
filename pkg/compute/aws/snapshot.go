//go:build awscompute

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

package aws

import (
	"context"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

// snapshotNameTagKey correlates an EBS snapshot with its platform snapshot
// name for delete/restore lookup.
const snapshotNameTagKey = "trusted-platform:snapshot-name"

// gibiBytes is the number of bytes in one GiB (EBS reports volume/snapshot
// size in GiB).
const gibiBytes int64 = 1024 * 1024 * 1024

// CreateSnapshot captures an EBS snapshot of the instance's root volume. AWS
// EBS snapshots are crash-consistent disk snapshots; unlike QEMU internal
// snapshots they do not capture live guest memory. See
// docs/compute/cloud-providers.md for the parity notes.
func (o *AWSOrchestrator) CreateSnapshot(ctx context.Context, instanceID, snapshotName string) (*compute.VMSnapshot, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}
	if snapshotName == "" {
		return nil, compute.ErrInvalidSnapshotName
	}

	ec2Inst, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return nil, err
	}
	volumeID, _, err := rootVolume(ec2Inst)
	if err != nil {
		return nil, err
	}

	out, err := o.client.CreateSnapshot(ctx, &ec2.CreateSnapshotInput{
		VolumeId:    awssdk.String(volumeID),
		Description: awssdk.String("trusted-platform snapshot " + snapshotName + " of " + instanceID),
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeSnapshot,
			Tags: append(o.resourceTags(snapshotName, instanceID),
				ec2types.Tag{Key: awssdk.String(snapshotNameTagKey), Value: awssdk.String(snapshotName)}),
		}},
	})
	if err != nil {
		return nil, &APIError{Op: "CreateSnapshot", Err: err}
	}

	snap := &compute.VMSnapshot{
		Name:        snapshotName,
		VMID:        instanceID,
		CreatedAt:   awssdk.ToTime(out.StartTime),
		SizeBytes:   int64(awssdk.ToInt32(out.VolumeSize)) * gibiBytes,
		Description: "ebs snapshot " + awssdk.ToString(out.SnapshotId),
	}
	if snap.CreatedAt.IsZero() {
		snap.CreatedAt = time.Now().UTC()
	}
	o.logger.Infof("Created EBS snapshot %s (%s) of instance %s", awssdk.ToString(out.SnapshotId), snapshotName, instanceID)
	return snap, nil
}

// DeleteSnapshot removes the EBS snapshot correlated with the given name.
func (o *AWSOrchestrator) DeleteSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if snapshotName == "" {
		return compute.ErrInvalidSnapshotName
	}

	snapshotID, err := o.resolveSnapshotID(ctx, instanceID, snapshotName)
	if err != nil {
		return err
	}
	_, err = o.client.DeleteSnapshot(ctx, &ec2.DeleteSnapshotInput{
		SnapshotId: awssdk.String(snapshotID),
	})
	if err != nil {
		return &APIError{Op: "DeleteSnapshot", Err: err}
	}
	o.logger.Infof("Deleted EBS snapshot %s (%s)", snapshotID, snapshotName)
	return nil
}

// ListSnapshots lists all EBS snapshots taken of the instance's volumes.
func (o *AWSOrchestrator) ListSnapshots(ctx context.Context, instanceID string) ([]*compute.VMSnapshot, error) {
	if instanceID == "" {
		return nil, compute.ErrInvalidInstanceID
	}
	out, err := o.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		Filters: []ec2types.Filter{{
			Name:   awssdk.String("tag:" + vmIDTagKey),
			Values: []string{instanceID},
		}},
	})
	if err != nil {
		return nil, &APIError{Op: "DescribeSnapshots", Err: err}
	}

	snapshots := make([]*compute.VMSnapshot, 0, len(out.Snapshots))
	for i := range out.Snapshots {
		s := out.Snapshots[i]
		snapshots = append(snapshots, &compute.VMSnapshot{
			Name:        tagValue(s.Tags, snapshotNameTagKey),
			VMID:        instanceID,
			CreatedAt:   awssdk.ToTime(s.StartTime),
			SizeBytes:   int64(awssdk.ToInt32(s.VolumeSize)) * gibiBytes,
			Description: "ebs snapshot " + awssdk.ToString(s.SnapshotId),
		})
	}
	return snapshots, nil
}

// RestoreSnapshot restores the instance's root volume from an EBS snapshot.
// EBS restore is not a live operation, so the honest full-parity sequence is:
// stop the instance, detach the current root volume, create a fresh volume
// from the snapshot in the instance's availability zone, attach it at the
// original root device, and start the instance again. Guest memory is not
// restored (EBS snapshots are disk-only).
func (o *AWSOrchestrator) RestoreSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	if instanceID == "" {
		return compute.ErrInvalidInstanceID
	}
	if snapshotName == "" {
		return compute.ErrInvalidSnapshotName
	}

	snapshotID, err := o.resolveSnapshotID(ctx, instanceID, snapshotName)
	if err != nil {
		return err
	}

	ec2Inst, err := o.describeInstance(ctx, instanceID)
	if err != nil {
		return err
	}
	oldVolumeID, deviceName, err := rootVolume(ec2Inst)
	if err != nil {
		return err
	}
	az := ""
	if ec2Inst.Placement != nil {
		az = awssdk.ToString(ec2Inst.Placement.AvailabilityZone)
	}
	if az == "" {
		return &SentinelCauseError{Sentinel: ErrCapabilityNotSupported, Cause: &compute.MessageError{Msg: "instance has no availability zone; cannot create restore volume"}}
	}

	// 1. Stop the instance and wait for it to be fully stopped.
	if _, err := o.client.StopInstances(ctx, &ec2.StopInstancesInput{InstanceIds: []string{instanceID}}); err != nil {
		return &APIError{Op: "StopInstances", Err: err}
	}
	if err := o.pollInstanceUntil(ctx, instanceID, func(n ec2types.InstanceStateName) bool {
		return n == ec2types.InstanceStateNameStopped
	}); err != nil {
		return err
	}

	// 2. Detach the current root volume and wait until it is available.
	if _, err := o.client.DetachVolume(ctx, &ec2.DetachVolumeInput{VolumeId: awssdk.String(oldVolumeID)}); err != nil {
		return &APIError{Op: "DetachVolume", Err: err}
	}
	if err := o.pollVolumeUntil(ctx, oldVolumeID, ec2types.VolumeStateAvailable); err != nil {
		return err
	}

	// 3. Create a fresh volume from the snapshot in the instance's AZ and
	//    wait until it is available.
	created, err := o.client.CreateVolume(ctx, &ec2.CreateVolumeInput{
		SnapshotId:       awssdk.String(snapshotID),
		AvailabilityZone: awssdk.String(az),
		TagSpecifications: []ec2types.TagSpecification{{
			ResourceType: ec2types.ResourceTypeVolume,
			Tags:         o.resourceTags(snapshotName+"-restore", instanceID),
		}},
	})
	if err != nil {
		return &APIError{Op: "CreateVolume", Err: err}
	}
	newVolumeID := awssdk.ToString(created.VolumeId)
	if err := o.pollVolumeUntil(ctx, newVolumeID, ec2types.VolumeStateAvailable); err != nil {
		return err
	}

	// 4. Attach the restored volume at the original root device and restart.
	if _, err := o.client.AttachVolume(ctx, &ec2.AttachVolumeInput{
		VolumeId:   awssdk.String(newVolumeID),
		InstanceId: awssdk.String(instanceID),
		Device:     awssdk.String(deviceName),
	}); err != nil {
		return &APIError{Op: "AttachVolume", Err: err}
	}
	if _, err := o.client.StartInstances(ctx, &ec2.StartInstancesInput{InstanceIds: []string{instanceID}}); err != nil {
		return &APIError{Op: "StartInstances", Err: err}
	}

	o.logger.Infof("Restored instance %s root from snapshot %s (new volume %s)", instanceID, snapshotID, newVolumeID)
	return nil
}

// resolveSnapshotID resolves a platform snapshot name to its EBS snapshot ID
// via the correlation tags.
func (o *AWSOrchestrator) resolveSnapshotID(ctx context.Context, instanceID, snapshotName string) (string, error) {
	out, err := o.client.DescribeSnapshots(ctx, &ec2.DescribeSnapshotsInput{
		Filters: []ec2types.Filter{
			{Name: awssdk.String("tag:" + vmIDTagKey), Values: []string{instanceID}},
			{Name: awssdk.String("tag:" + snapshotNameTagKey), Values: []string{snapshotName}},
		},
	})
	if err != nil {
		return "", &APIError{Op: "DescribeSnapshots", Err: err}
	}
	if len(out.Snapshots) == 0 {
		return "", compute.ErrSnapshotNotFound
	}
	return awssdk.ToString(out.Snapshots[0].SnapshotId), nil
}

// pollVolumeUntil polls a volume's state on a ticker until it matches want,
// ctx is cancelled, or the poll timeout elapses.
func (o *AWSOrchestrator) pollVolumeUntil(ctx context.Context, volumeID string, want ec2types.VolumeState) error {
	deadline := time.NewTimer(o.pollTimeout)
	defer deadline.Stop()
	ticker := time.NewTicker(o.pollInterval)
	defer ticker.Stop()

	check := func() (bool, error) {
		out, err := o.client.DescribeVolumes(ctx, &ec2.DescribeVolumesInput{VolumeIds: []string{volumeID}})
		if err != nil {
			return false, &APIError{Op: "DescribeVolumes", Err: err}
		}
		if len(out.Volumes) > 0 && out.Volumes[0].State == want {
			return true, nil
		}
		return false, nil
	}

	if done, err := check(); err != nil || done {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return ErrWaitTimeout
		case <-ticker.C:
			if done, err := check(); err != nil || done {
				return err
			}
		}
	}
}

// rootVolume returns the volume ID and device name of the instance's root
// EBS volume.
func rootVolume(ec2Inst *ec2types.Instance) (volumeID, deviceName string, err error) {
	root := awssdk.ToString(ec2Inst.RootDeviceName)
	for _, m := range ec2Inst.BlockDeviceMappings {
		if awssdk.ToString(m.DeviceName) == root && m.Ebs != nil {
			return awssdk.ToString(m.Ebs.VolumeId), root, nil
		}
	}
	return "", "", &SentinelCauseError{Sentinel: ErrCapabilityNotSupported, Cause: &compute.MessageError{Msg: "instance has no EBS root volume to snapshot"}}
}
