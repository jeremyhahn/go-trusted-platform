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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeSnapshotOps is an in-memory vmSnapshotOps seam.
type fakeSnapshotOps struct {
	createErr  error
	restoreErr error
	deleteErr  error
	listErr    error

	infos []qemu.SnapshotInfo

	created  []string
	restored []string
	deleted  []string
}

func (f *fakeSnapshotOps) Create(ctx context.Context, name string) error {
	if f.createErr != nil {
		return f.createErr
	}
	f.created = append(f.created, name)
	f.infos = append(f.infos, qemu.SnapshotInfo{
		Name:        name,
		ID:          "1",
		VMStateSize: 1024,
		Date:        time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC),
	})
	return nil
}

func (f *fakeSnapshotOps) Restore(ctx context.Context, name string) error {
	if f.restoreErr != nil {
		return f.restoreErr
	}
	f.restored = append(f.restored, name)
	return nil
}

func (f *fakeSnapshotOps) Delete(ctx context.Context, name string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, name)
	return nil
}

func (f *fakeSnapshotOps) List(ctx context.Context) ([]qemu.SnapshotInfo, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.infos, nil
}

func (f *fakeSnapshotOps) Get(ctx context.Context, name string) (*qemu.SnapshotInfo, error) {
	for i := range f.infos {
		if f.infos[i].Name == name {
			return &f.infos[i], nil
		}
	}
	return nil, qemu.ErrSnapshotNotFound{Name: name}
}

// newSnapshotTestOrchestrator builds a QEMU orchestrator with a fake QMP
// snapshot seam and no real VM processes.
func newSnapshotTestOrchestrator(t *testing.T) (*QEMUOrchestrator, *fakeSnapshotOps) {
	t.Helper()

	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = t.TempDir()

	orch, err := NewQEMUOrchestrator(config, logging.DefaultLogger())
	require.NoError(t, err)

	ops := &fakeSnapshotOps{}
	orch.snapshotOpsFor = func(ctx context.Context, inst *qemuInstance) (vmSnapshotOps, error) {
		return ops, nil
	}

	t.Cleanup(func() {
		// Fake instances have no qemu.VM; clear them before Close so the
		// orchestrator shutdown does not dereference nil VMs.
		orch.mu.Lock()
		orch.instances = make(map[string]*qemuInstance)
		orch.mu.Unlock()
		require.NoError(t, orch.Close())
	})

	return orch, ops
}

// addFakeVMInstance injects an instance directly into the orchestrator
// (bypassing Create, which would exec qemu-img).
func addFakeVMInstance(t *testing.T, orch *QEMUOrchestrator, id string, running bool, diskPath, tpmSocket string) {
	t.Helper()

	inst := &Instance{
		ID:    id,
		Name:  "test-vm",
		Type:  ComputeTypeVM,
		State: StateStopped,
		Config: &InstanceConfig{
			DiskPath: diskPath,
		},
		Metadata: make(map[string]string),
	}
	if tpmSocket != "" {
		inst.Metadata["tpm_socket"] = tpmSocket
	}

	orch.mu.Lock()
	orch.instances[id] = &qemuInstance{instance: inst}
	orch.mu.Unlock()

	require.NoError(t, orch.lifecycle.SetState(id, StateCreating))
	require.NoError(t, orch.lifecycle.SetState(id, StateStopped))
	if running {
		require.NoError(t, orch.lifecycle.SetState(id, StateStarting))
		require.NoError(t, orch.lifecycle.SetState(id, StateRunning))
		inst.State = StateRunning
	}
}

func TestQEMUOrchestrator_CreateSnapshot(t *testing.T) {
	orch, ops := newSnapshotTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "")

	snapshot, err := orch.CreateSnapshot(context.Background(), "vm1", "snap1")
	require.NoError(t, err)
	require.NotNil(t, snapshot)
	assert.Equal(t, "snap1", snapshot.Name)
	assert.Equal(t, "vm1", snapshot.VMID)
	assert.Equal(t, int64(1024), snapshot.SizeBytes)
	assert.Equal(t, []string{"snap1"}, ops.created)
}

func TestQEMUOrchestrator_CreateSnapshot_Errors(t *testing.T) {
	orch, ops := newSnapshotTestOrchestrator(t)
	addFakeVMInstance(t, orch, "running-vm", true, "/vms/x/disk.qcow2", "")
	addFakeVMInstance(t, orch, "stopped-vm", false, "/vms/y/disk.qcow2", "")
	addFakeVMInstance(t, orch, "raw-vm", true, "/vms/z/disk.raw", "")

	ctx := context.Background()

	t.Run("invalid snapshot name", func(t *testing.T) {
		_, err := orch.CreateSnapshot(ctx, "running-vm", "1-bad name!")
		assert.ErrorIs(t, err, ErrInvalidSnapshotName)
	})

	t.Run("empty snapshot name", func(t *testing.T) {
		_, err := orch.CreateSnapshot(ctx, "running-vm", "")
		assert.ErrorIs(t, err, ErrInvalidSnapshotName)
	})

	t.Run("empty instance ID", func(t *testing.T) {
		_, err := orch.CreateSnapshot(ctx, "", "snap1")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})

	t.Run("instance not found", func(t *testing.T) {
		_, err := orch.CreateSnapshot(ctx, "missing", "snap1")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})

	t.Run("stopped VM", func(t *testing.T) {
		_, err := orch.CreateSnapshot(ctx, "stopped-vm", "snap1")
		assert.ErrorIs(t, err, ErrInstanceNotRunning)
	})

	t.Run("non-qcow2 disk", func(t *testing.T) {
		_, err := orch.CreateSnapshot(ctx, "raw-vm", "snap1")
		assert.ErrorIs(t, err, ErrUnsupportedDiskFormat)
	})

	t.Run("QMP failure", func(t *testing.T) {
		ops.createErr = errors.New("savevm failed")
		defer func() { ops.createErr = nil }()

		_, err := orch.CreateSnapshot(ctx, "running-vm", "snap1")
		require.Error(t, err)
	})
}

func TestQEMUOrchestrator_RestoreSnapshot(t *testing.T) {
	orch, ops := newSnapshotTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "")

	require.NoError(t, orch.RestoreSnapshot(context.Background(), "vm1", "snap1"))
	assert.Equal(t, []string{"snap1"}, ops.restored)
}

func TestQEMUOrchestrator_RestoreSnapshot_Errors(t *testing.T) {
	orch, ops := newSnapshotTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "")

	ctx := context.Background()

	t.Run("invalid name", func(t *testing.T) {
		err := orch.RestoreSnapshot(ctx, "vm1", "all")
		assert.ErrorIs(t, err, ErrInvalidSnapshotName)
	})

	t.Run("snapshot not found translated", func(t *testing.T) {
		ops.restoreErr = qemu.ErrSnapshotNotFound{Name: "missing"}
		defer func() { ops.restoreErr = nil }()

		err := orch.RestoreSnapshot(ctx, "vm1", "missing")
		assert.ErrorIs(t, err, ErrSnapshotNotFound)
	})

	t.Run("instance not found", func(t *testing.T) {
		err := orch.RestoreSnapshot(ctx, "missing", "snap1")
		assert.ErrorIs(t, err, ErrInstanceNotFound)
	})
}

func TestQEMUOrchestrator_DeleteSnapshot(t *testing.T) {
	orch, ops := newSnapshotTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "")

	require.NoError(t, orch.DeleteSnapshot(context.Background(), "vm1", "snap1"))
	assert.Equal(t, []string{"snap1"}, ops.deleted)
}

func TestQEMUOrchestrator_DeleteSnapshot_Errors(t *testing.T) {
	orch, ops := newSnapshotTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "")

	ctx := context.Background()

	t.Run("invalid name", func(t *testing.T) {
		err := orch.DeleteSnapshot(ctx, "vm1", "")
		assert.ErrorIs(t, err, ErrInvalidSnapshotName)
	})

	t.Run("snapshot not found translated", func(t *testing.T) {
		ops.deleteErr = qemu.ErrSnapshotNotFound{Name: "missing"}
		defer func() { ops.deleteErr = nil }()

		err := orch.DeleteSnapshot(ctx, "vm1", "missing")
		assert.ErrorIs(t, err, ErrSnapshotNotFound)
	})
}

func TestQEMUOrchestrator_ListSnapshots(t *testing.T) {
	orch, ops := newSnapshotTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "")

	ops.infos = []qemu.SnapshotInfo{
		{Name: "snap1", VMStateSize: 100, Date: time.Now()},
		{Name: "snap2", VMStateSize: 200, Date: time.Now()},
	}

	snapshots, err := orch.ListSnapshots(context.Background(), "vm1")
	require.NoError(t, err)
	require.Len(t, snapshots, 2)
	assert.Equal(t, "snap1", snapshots[0].Name)
	assert.Equal(t, "vm1", snapshots[0].VMID)
	assert.Equal(t, int64(100), snapshots[0].SizeBytes)
	assert.Equal(t, "snap2", snapshots[1].Name)
}

func TestQEMUOrchestrator_ListSnapshots_Errors(t *testing.T) {
	orch, ops := newSnapshotTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "")
	addFakeVMInstance(t, orch, "stopped-vm", false, "/vms/s/disk.qcow2", "")

	ctx := context.Background()

	t.Run("stopped VM", func(t *testing.T) {
		_, err := orch.ListSnapshots(ctx, "stopped-vm")
		assert.ErrorIs(t, err, ErrInstanceNotRunning)
	})

	t.Run("QMP failure", func(t *testing.T) {
		ops.listErr = errors.New("monitor gone")
		defer func() { ops.listErr = nil }()

		_, err := orch.ListSnapshots(ctx, "vm1")
		require.Error(t, err)
	})

	t.Run("empty instance ID", func(t *testing.T) {
		_, err := orch.ListSnapshots(ctx, "")
		assert.ErrorIs(t, err, ErrInvalidInstanceID)
	})
}

func TestQEMUOrchestrator_SnapshotSession_OpsFactoryError(t *testing.T) {
	orch, _ := newSnapshotTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "")

	factoryErr := errors.New("monitor connect failed")
	orch.snapshotOpsFor = func(ctx context.Context, inst *qemuInstance) (vmSnapshotOps, error) {
		return nil, factoryErr
	}

	_, err := orch.CreateSnapshot(context.Background(), "vm1", "snap1")
	assert.ErrorIs(t, err, factoryErr)
}
