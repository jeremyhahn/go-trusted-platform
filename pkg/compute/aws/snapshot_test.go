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
	"errors"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

func TestCreateSnapshot_Happy(t *testing.T) {
	inst := runningInstance("i-1")
	var snappedVolume string
	client := &fakeEC2{
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(inst), nil
		},
		createSnapshot: func(_ context.Context, in *ec2.CreateSnapshotInput) (*ec2.CreateSnapshotOutput, error) {
			snappedVolume = awssdk.ToString(in.VolumeId)
			return &ec2.CreateSnapshotOutput{
				SnapshotId: awssdk.String("snap-1"),
				StartTime:  awssdk.Time(time.Unix(1700000000, 0).UTC()),
				VolumeSize: awssdk.Int32(20),
			}, nil
		},
	}
	o := newTestOrchestrator(t, client)

	snap, err := o.CreateSnapshot(context.Background(), "i-1", "backup-1")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if snappedVolume != "vol-root" {
		t.Errorf("snapped volume = %q, want vol-root", snappedVolume)
	}
	if snap.Name != "backup-1" || snap.VMID != "i-1" {
		t.Errorf("snap = %+v", snap)
	}
	if snap.SizeBytes != 20*gibiBytes {
		t.Errorf("size = %d, want %d", snap.SizeBytes, 20*gibiBytes)
	}
}

func TestCreateSnapshot_NoRootVolume(t *testing.T) {
	inst := runningInstance("i-1")
	inst.BlockDeviceMappings = nil
	client := &fakeEC2{describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
		return describeOutput(inst), nil
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.CreateSnapshot(context.Background(), "i-1", "backup-1")
	if err == nil {
		t.Fatal("expected error for instance without root volume")
	}
}

func TestCreateSnapshot_InvalidName(t *testing.T) {
	o := newTestOrchestrator(t, &fakeEC2{})
	_, err := o.CreateSnapshot(context.Background(), "i-1", "")
	if !errors.Is(err, compute.ErrInvalidSnapshotName) {
		t.Fatalf("err = %v, want ErrInvalidSnapshotName", err)
	}
}

func TestDeleteSnapshot_Happy(t *testing.T) {
	var deleted string
	client := &fakeEC2{
		describeSnapshots: func(context.Context, *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{Snapshots: []ec2types.Snapshot{{
				SnapshotId: awssdk.String("snap-9"),
				Tags: []ec2types.Tag{
					{Key: awssdk.String(snapshotNameTagKey), Value: awssdk.String("backup-1")},
				},
			}}}, nil
		},
		deleteSnapshot: func(_ context.Context, in *ec2.DeleteSnapshotInput) (*ec2.DeleteSnapshotOutput, error) {
			deleted = awssdk.ToString(in.SnapshotId)
			return &ec2.DeleteSnapshotOutput{}, nil
		},
	}
	o := newTestOrchestrator(t, client)
	if err := o.DeleteSnapshot(context.Background(), "i-1", "backup-1"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if deleted != "snap-9" {
		t.Errorf("deleted = %q, want snap-9", deleted)
	}
}

func TestDeleteSnapshot_NotFound(t *testing.T) {
	client := &fakeEC2{describeSnapshots: func(context.Context, *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
		return &ec2.DescribeSnapshotsOutput{}, nil
	}}
	o := newTestOrchestrator(t, client)
	err := o.DeleteSnapshot(context.Background(), "i-1", "missing")
	if !errors.Is(err, compute.ErrSnapshotNotFound) {
		t.Fatalf("err = %v, want ErrSnapshotNotFound", err)
	}
}

func TestListSnapshots_Happy(t *testing.T) {
	client := &fakeEC2{describeSnapshots: func(context.Context, *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
		return &ec2.DescribeSnapshotsOutput{Snapshots: []ec2types.Snapshot{
			{SnapshotId: awssdk.String("snap-1"), VolumeSize: awssdk.Int32(10), StartTime: awssdk.Time(time.Now()), Tags: []ec2types.Tag{{Key: awssdk.String(snapshotNameTagKey), Value: awssdk.String("a")}}},
			{SnapshotId: awssdk.String("snap-2"), VolumeSize: awssdk.Int32(30), StartTime: awssdk.Time(time.Now()), Tags: []ec2types.Tag{{Key: awssdk.String(snapshotNameTagKey), Value: awssdk.String("b")}}},
		}}, nil
	}}
	o := newTestOrchestrator(t, client)
	snaps, err := o.ListSnapshots(context.Background(), "i-1")
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("len = %d, want 2", len(snaps))
	}
	if snaps[0].Name != "a" || snaps[1].SizeBytes != 30*gibiBytes {
		t.Errorf("snaps = %+v", snaps)
	}
}

func TestListSnapshots_InvalidInstanceID(t *testing.T) {
	o := newTestOrchestrator(t, &fakeEC2{})
	_, err := o.ListSnapshots(context.Background(), "")
	if !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("err = %v, want ErrInvalidInstanceID", err)
	}
}

func TestRestoreSnapshot_FullSequence(t *testing.T) {
	// Instance is already stopped so the stop wait resolves immediately.
	inst := runningInstance("i-1")
	inst.State = &ec2types.InstanceState{Name: ec2types.InstanceStateNameStopped}

	var (
		detached, created, attached, started bool
	)
	client := &fakeEC2{
		describeSnapshots: func(context.Context, *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
			return &ec2.DescribeSnapshotsOutput{Snapshots: []ec2types.Snapshot{{
				SnapshotId: awssdk.String("snap-1"),
				Tags:       []ec2types.Tag{{Key: awssdk.String(snapshotNameTagKey), Value: awssdk.String("backup-1")}},
			}}}, nil
		},
		describeInstances: func(context.Context, *ec2.DescribeInstancesInput) (*ec2.DescribeInstancesOutput, error) {
			return describeOutput(inst), nil
		},
		detachVolume: func(context.Context, *ec2.DetachVolumeInput) (*ec2.DetachVolumeOutput, error) {
			detached = true
			return &ec2.DetachVolumeOutput{}, nil
		},
		describeVolumes: func(context.Context, *ec2.DescribeVolumesInput) (*ec2.DescribeVolumesOutput, error) {
			return &ec2.DescribeVolumesOutput{Volumes: []ec2types.Volume{{State: ec2types.VolumeStateAvailable}}}, nil
		},
		createVolume: func(context.Context, *ec2.CreateVolumeInput) (*ec2.CreateVolumeOutput, error) {
			created = true
			return &ec2.CreateVolumeOutput{VolumeId: awssdk.String("vol-new")}, nil
		},
		attachVolume: func(_ context.Context, in *ec2.AttachVolumeInput) (*ec2.AttachVolumeOutput, error) {
			attached = true
			if awssdk.ToString(in.VolumeId) != "vol-new" {
				t.Errorf("attach volume = %q", awssdk.ToString(in.VolumeId))
			}
			return &ec2.AttachVolumeOutput{}, nil
		},
		startInstances: func(context.Context, *ec2.StartInstancesInput) (*ec2.StartInstancesOutput, error) {
			started = true
			return &ec2.StartInstancesOutput{}, nil
		},
	}
	o := newTestOrchestrator(t, client)

	if err := o.RestoreSnapshot(context.Background(), "i-1", "backup-1"); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	if !detached || !created || !attached || !started {
		t.Fatalf("sequence incomplete: detached=%v created=%v attached=%v started=%v", detached, created, attached, started)
	}
}

func TestRestoreSnapshot_SnapshotNotFound(t *testing.T) {
	client := &fakeEC2{describeSnapshots: func(context.Context, *ec2.DescribeSnapshotsInput) (*ec2.DescribeSnapshotsOutput, error) {
		return &ec2.DescribeSnapshotsOutput{}, nil
	}}
	o := newTestOrchestrator(t, client)
	err := o.RestoreSnapshot(context.Background(), "i-1", "missing")
	if !errors.Is(err, compute.ErrSnapshotNotFound) {
		t.Fatalf("err = %v, want ErrSnapshotNotFound", err)
	}
}
