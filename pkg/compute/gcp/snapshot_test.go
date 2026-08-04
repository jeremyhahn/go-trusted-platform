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
	"errors"
	"testing"

	computepb "cloud.google.com/go/compute/apiv1/computepb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

func TestCreateSnapshot_Happy(t *testing.T) {
	inst := runningInstance("node-01")
	var snappedDisk string
	client := &fakeGCE{
		getInstance: func(context.Context, string) (*computepb.Instance, error) { return inst, nil },
		createDiskSnapshot: func(_ context.Context, diskName string, snap *computepb.Snapshot) (*computepb.Snapshot, error) {
			snappedDisk = diskName
			return &computepb.Snapshot{
				Name:              ptr("backup-1"),
				DiskSizeGb:        ptr(int64(20)),
				CreationTimestamp: ptr("2023-11-14T22:13:20Z"),
			}, nil
		},
	}
	o := newTestOrchestrator(t, client)

	snap, err := o.CreateSnapshot(context.Background(), "node-01", "backup-1")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if snappedDisk != "node-01" {
		t.Errorf("snapped disk = %q, want node-01", snappedDisk)
	}
	if snap.Name != "backup-1" || snap.VMID != "node-01" {
		t.Errorf("snap = %+v", snap)
	}
	if snap.SizeBytes != 20*gibiBytes {
		t.Errorf("size = %d, want %d", snap.SizeBytes, 20*gibiBytes)
	}
}

func TestCreateSnapshot_NoBootDisk(t *testing.T) {
	inst := runningInstance("node-01")
	inst.Disks = nil
	client := &fakeGCE{getInstance: func(context.Context, string) (*computepb.Instance, error) {
		return inst, nil
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.CreateSnapshot(context.Background(), "node-01", "backup-1")
	if err == nil {
		t.Fatal("expected error for instance without boot disk")
	}
}

func TestCreateSnapshot_InvalidName(t *testing.T) {
	o := newTestOrchestrator(t, &fakeGCE{})
	_, err := o.CreateSnapshot(context.Background(), "node-01", "")
	if !errors.Is(err, compute.ErrInvalidSnapshotName) {
		t.Fatalf("err = %v, want ErrInvalidSnapshotName", err)
	}
}

func TestDeleteSnapshot_Happy(t *testing.T) {
	var deleted string
	client := &fakeGCE{
		listSnapshots: func(context.Context, string) ([]*computepb.Snapshot, error) {
			return []*computepb.Snapshot{{
				Name:   ptr("snap-9"),
				Labels: map[string]string{snapNameLabelKey: "backup-1"},
			}}, nil
		},
		deleteSnapshot: func(_ context.Context, name string) error {
			deleted = name
			return nil
		},
	}
	o := newTestOrchestrator(t, client)
	if err := o.DeleteSnapshot(context.Background(), "node-01", "backup-1"); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if deleted != "snap-9" {
		t.Errorf("deleted = %q, want snap-9", deleted)
	}
}

func TestDeleteSnapshot_NotFound(t *testing.T) {
	client := &fakeGCE{listSnapshots: func(context.Context, string) ([]*computepb.Snapshot, error) {
		return nil, nil
	}}
	o := newTestOrchestrator(t, client)
	err := o.DeleteSnapshot(context.Background(), "node-01", "missing")
	if !errors.Is(err, compute.ErrSnapshotNotFound) {
		t.Fatalf("err = %v, want ErrSnapshotNotFound", err)
	}
}

func TestListSnapshots_Happy(t *testing.T) {
	client := &fakeGCE{listSnapshots: func(context.Context, string) ([]*computepb.Snapshot, error) {
		return []*computepb.Snapshot{
			{Name: ptr("snap-1"), DiskSizeGb: ptr(int64(10)), Labels: map[string]string{snapNameLabelKey: "a"}},
			{Name: ptr("snap-2"), DiskSizeGb: ptr(int64(30)), Labels: map[string]string{snapNameLabelKey: "b"}},
		}, nil
	}}
	o := newTestOrchestrator(t, client)
	snaps, err := o.ListSnapshots(context.Background(), "node-01")
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
	o := newTestOrchestrator(t, &fakeGCE{})
	_, err := o.ListSnapshots(context.Background(), "")
	if !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("err = %v, want ErrInvalidInstanceID", err)
	}
}

func TestRestoreSnapshot_FullSequence(t *testing.T) {
	// Instance is already TERMINATED so the stop wait resolves immediately.
	inst := runningInstance("node-01")
	inst.Status = ptr(statusTerminated)

	var detached, inserted, attached, started bool
	client := &fakeGCE{
		listSnapshots: func(context.Context, string) ([]*computepb.Snapshot, error) {
			return []*computepb.Snapshot{{
				Name:   ptr("snap-1"),
				Labels: map[string]string{snapNameLabelKey: "backup-1"},
			}}, nil
		},
		getInstance:  func(context.Context, string) (*computepb.Instance, error) { return inst, nil },
		stopInstance: func(context.Context, string) error { return nil },
		detachDisk: func(context.Context, string, string) error {
			detached = true
			return nil
		},
		insertDisk: func(_ context.Context, d *computepb.Disk) error {
			inserted = true
			if d.GetSourceSnapshot() == "" {
				t.Error("expected source snapshot on restore disk")
			}
			return nil
		},
		attachDisk: func(_ context.Context, _ string, d *computepb.AttachedDisk) error {
			attached = true
			if !d.GetBoot() {
				t.Error("restore disk must be attached as boot")
			}
			return nil
		},
		startInstance: func(context.Context, string) error {
			started = true
			return nil
		},
	}
	o := newTestOrchestrator(t, client)

	if err := o.RestoreSnapshot(context.Background(), "node-01", "backup-1"); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	if !detached || !inserted || !attached || !started {
		t.Fatalf("sequence incomplete: detached=%v inserted=%v attached=%v started=%v", detached, inserted, attached, started)
	}
}

func TestRestoreSnapshot_SnapshotNotFound(t *testing.T) {
	client := &fakeGCE{listSnapshots: func(context.Context, string) ([]*computepb.Snapshot, error) {
		return nil, nil
	}}
	o := newTestOrchestrator(t, client)
	err := o.RestoreSnapshot(context.Background(), "node-01", "missing")
	if !errors.Is(err, compute.ErrSnapshotNotFound) {
		t.Fatalf("err = %v, want ErrSnapshotNotFound", err)
	}
}
