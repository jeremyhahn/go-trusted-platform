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
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	armcompute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v6"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute"
)

func snapshotWithTags(name, vmID, snapName string, sizeGB int32) *armcompute.Snapshot {
	return &armcompute.Snapshot{
		Name: to.Ptr(name),
		ID:   to.Ptr("/subscriptions/sub-1/resourceGroups/rg-1/providers/Microsoft.Compute/snapshots/" + name),
		Tags: map[string]*string{
			managedTagKey:  to.Ptr(managedTagValue),
			vmIDTagKey:     to.Ptr(vmID),
			snapNameTagKey: to.Ptr(snapName),
		},
		Properties: &armcompute.SnapshotProperties{DiskSizeGB: to.Ptr(sizeGB)},
	}
}

func TestCreateSnapshot_Happy(t *testing.T) {
	vm := managedVM("node-01")
	var sourceDisk string
	client := &fakeARM{
		getVM: func(context.Context, string) (*armcompute.VirtualMachine, error) { return vm, nil },
		createSnapshot: func(_ context.Context, name string, params armcompute.Snapshot) (*armcompute.Snapshot, error) {
			sourceDisk = derefStr(params.Properties.CreationData.SourceResourceID)
			return &armcompute.Snapshot{
				Name:       to.Ptr(name),
				Properties: &armcompute.SnapshotProperties{DiskSizeGB: to.Ptr(int32(30))},
			}, nil
		},
	}
	o := newTestOrchestrator(t, client)

	snap, err := o.CreateSnapshot(context.Background(), "node-01", "backup-1")
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if sourceDisk == "" {
		t.Error("expected source disk ID on snapshot creation data")
	}
	if snap.Name != "backup-1" || snap.VMID != "node-01" {
		t.Errorf("snap = %+v", snap)
	}
	if snap.SizeBytes != 30*gibiBytes {
		t.Errorf("size = %d, want %d", snap.SizeBytes, 30*gibiBytes)
	}
}

func TestCreateSnapshot_NoOSDisk(t *testing.T) {
	vm := managedVM("node-01")
	vm.Properties.StorageProfile = nil
	client := &fakeARM{getVM: func(context.Context, string) (*armcompute.VirtualMachine, error) {
		return vm, nil
	}}
	o := newTestOrchestrator(t, client)
	_, err := o.CreateSnapshot(context.Background(), "node-01", "backup-1")
	if err == nil {
		t.Fatal("expected error for VM without managed OS disk")
	}
}

func TestCreateSnapshot_InvalidName(t *testing.T) {
	o := newTestOrchestrator(t, &fakeARM{})
	_, err := o.CreateSnapshot(context.Background(), "node-01", "")
	if !errors.Is(err, compute.ErrInvalidSnapshotName) {
		t.Fatalf("err = %v, want ErrInvalidSnapshotName", err)
	}
}

func TestDeleteSnapshot_Happy(t *testing.T) {
	var deleted string
	client := &fakeARM{
		listSnapshots: func(context.Context) ([]*armcompute.Snapshot, error) {
			return []*armcompute.Snapshot{snapshotWithTags("node-01-backup-1", "node-01", "backup-1", 20)}, nil
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
	if deleted != "node-01-backup-1" {
		t.Errorf("deleted = %q, want node-01-backup-1", deleted)
	}
}

func TestDeleteSnapshot_NotFound(t *testing.T) {
	client := &fakeARM{listSnapshots: func(context.Context) ([]*armcompute.Snapshot, error) {
		return nil, nil
	}}
	o := newTestOrchestrator(t, client)
	err := o.DeleteSnapshot(context.Background(), "node-01", "missing")
	if !errors.Is(err, compute.ErrSnapshotNotFound) {
		t.Fatalf("err = %v, want ErrSnapshotNotFound", err)
	}
}

func TestListSnapshots_FiltersByVMID(t *testing.T) {
	client := &fakeARM{listSnapshots: func(context.Context) ([]*armcompute.Snapshot, error) {
		return []*armcompute.Snapshot{
			snapshotWithTags("s1", "node-01", "a", 10),
			snapshotWithTags("s2", "other", "b", 30),
			snapshotWithTags("s3", "node-01", "c", 30),
		}, nil
	}}
	o := newTestOrchestrator(t, client)
	snaps, err := o.ListSnapshots(context.Background(), "node-01")
	if err != nil {
		t.Fatalf("ListSnapshots: %v", err)
	}
	if len(snaps) != 2 {
		t.Fatalf("len = %d, want 2 (filtered by vm-id)", len(snaps))
	}
	if snaps[0].Name != "a" {
		t.Errorf("snaps[0].Name = %q, want a", snaps[0].Name)
	}
}

func TestListSnapshots_InvalidInstanceID(t *testing.T) {
	o := newTestOrchestrator(t, &fakeARM{})
	_, err := o.ListSnapshots(context.Background(), "")
	if !errors.Is(err, compute.ErrInvalidInstanceID) {
		t.Fatalf("err = %v, want ErrInvalidInstanceID", err)
	}
}

func TestRestoreSnapshot_FullSequence(t *testing.T) {
	vm := managedVM("node-01")
	var dealloc, created, updated, started bool
	client := &fakeARM{
		listSnapshots: func(context.Context) ([]*armcompute.Snapshot, error) {
			return []*armcompute.Snapshot{snapshotWithTags("node-01-backup-1", "node-01", "backup-1", 20)}, nil
		},
		getVM:        func(context.Context, string) (*armcompute.VirtualMachine, error) { return vm, nil },
		deallocateVM: func(context.Context, string) error { dealloc = true; return nil },
		instanceView: func(context.Context, string) (*armcompute.VirtualMachineInstanceView, error) {
			return powerView(powerStateDeallocated), nil
		},
		createDisk: func(_ context.Context, name string, params armcompute.Disk) (*armcompute.Disk, error) {
			created = true
			if params.Properties.CreationData.SourceResourceID == nil {
				t.Error("expected snapshot source on restore disk")
			}
			return &armcompute.Disk{Name: to.Ptr(name), ID: to.Ptr("/disks/" + name)}, nil
		},
		updateVM: func(_ context.Context, _ string, up armcompute.VirtualMachineUpdate) (*armcompute.VirtualMachine, error) {
			updated = true
			if up.Properties.StorageProfile == nil || up.Properties.StorageProfile.OSDisk == nil {
				t.Error("expected OS disk swap in update")
			}
			return vm, nil
		},
		startVM: func(context.Context, string) error { started = true; return nil },
	}
	o := newTestOrchestrator(t, client)

	if err := o.RestoreSnapshot(context.Background(), "node-01", "backup-1"); err != nil {
		t.Fatalf("RestoreSnapshot: %v", err)
	}
	if !dealloc || !created || !updated || !started {
		t.Fatalf("sequence incomplete: dealloc=%v created=%v updated=%v started=%v", dealloc, created, updated, started)
	}
}

func TestRestoreSnapshot_SnapshotNotFound(t *testing.T) {
	client := &fakeARM{listSnapshots: func(context.Context) ([]*armcompute.Snapshot, error) {
		return nil, nil
	}}
	o := newTestOrchestrator(t, client)
	err := o.RestoreSnapshot(context.Background(), "node-01", "missing")
	if !errors.Is(err, compute.ErrSnapshotNotFound) {
		t.Fatalf("err = %v, want ErrSnapshotNotFound", err)
	}
}
