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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDiskMon struct {
	blockdevAdd  []string
	deviceAdd    []string
	deviceDel    []string
	blockdevDel  []string
	resizeNode   []string
	resizeDevice []string
	resizeSize   []int64

	addErr    error
	devAddErr error
	devDelErr error
	resizeErr error
}

func (f *fakeDiskMon) BlockdevAddQcow2(ctx context.Context, nodeName, filename string) error {
	f.blockdevAdd = append(f.blockdevAdd, nodeName)
	return f.addErr
}
func (f *fakeDiskMon) AddVirtioBlkDevice(ctx context.Context, deviceID, nodeName string) error {
	f.deviceAdd = append(f.deviceAdd, deviceID)
	return f.devAddErr
}
func (f *fakeDiskMon) DeviceDel(ctx context.Context, deviceID string) error {
	f.deviceDel = append(f.deviceDel, deviceID)
	return f.devDelErr
}
func (f *fakeDiskMon) BlockdevDel(ctx context.Context, nodeName string) error {
	f.blockdevDel = append(f.blockdevDel, nodeName)
	return nil
}
func (f *fakeDiskMon) BlockResize(ctx context.Context, nodeName, device string, sizeBytes int64) error {
	f.resizeNode = append(f.resizeNode, nodeName)
	f.resizeDevice = append(f.resizeDevice, device)
	f.resizeSize = append(f.resizeSize, sizeBytes)
	return f.resizeErr
}

// installDiskSeams wires the disk QMP + qemu-img seams and returns a restorer.
func installDiskSeams(t *testing.T, mon *fakeDiskMon, imgErr error) *[]string {
	t.Helper()
	origMon, origImg := vmDiskMonitorFor, execQemuImg
	imgCalls := &[]string{}
	vmDiskMonitorFor = func(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance) (diskMonitorOps, error) {
		return mon, nil
	}
	execQemuImg = func(ctx context.Context, args ...string) error {
		*imgCalls = append(*imgCalls, args[0])
		return imgErr
	}
	t.Cleanup(func() {
		vmDiskMonitorFor = origMon
		execQemuImg = origImg
	})
	return imgCalls
}

func TestNextVirtioSlot(t *testing.T) {
	assert.Equal(t, 1, nextVirtioSlot(nil))
	assert.Equal(t, 3, nextVirtioSlot([]DiskInfo{{Index: 1}, {Index: 2}}))
	assert.Equal(t, 6, nextVirtioSlot([]DiskInfo{{Index: 5}}))
}

func TestGenerateDiskID(t *testing.T) {
	a, b := generateDiskID(), generateDiskID()
	assert.Len(t, a, 16)
	assert.NotEqual(t, a, b)
}

func TestAttachDisk_HappyExistingImage(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	diskPath := filepath.Join(wd, "data.qcow2")
	require.NoError(t, os.WriteFile(diskPath, []byte("x"), 0o644))
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd})

	mon := &fakeDiskMon{}
	imgCalls := installDiskSeams(t, mon, nil)

	info, err := orch.AttachDisk(context.Background(), "vm1", DiskAttachRequest{ID: "d1", Path: diskPath})
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "d1", info.ID)
	assert.Equal(t, "virtio", info.Bus)
	assert.Equal(t, 1, info.Index)
	assert.Equal(t, "node-d1", info.NodeName)
	assert.Equal(t, "disk-d1", info.DeviceID)
	assert.True(t, info.Hotplugged)
	assert.Empty(t, *imgCalls) // existing image: no qemu-img create
	assert.Equal(t, []string{"node-d1"}, mon.blockdevAdd)
	assert.Equal(t, []string{"disk-d1"}, mon.deviceAdd)

	inst, _ := orch.Get(context.Background(), "vm1")
	require.Len(t, inst.Disks, 1)
}

func TestAttachDisk_CreatesImage(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd})

	mon := &fakeDiskMon{}
	imgCalls := installDiskSeams(t, mon, nil)

	info, err := orch.AttachDisk(context.Background(), "vm1", DiskAttachRequest{
		Path:   filepath.Join(wd, "new.qcow2"),
		SizeGB: 5,
	})
	require.NoError(t, err)
	assert.Equal(t, uint64(5), info.SizeGB)
	assert.Equal(t, []string{"create"}, *imgCalls)
}

func TestAttachDisk_Errors(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	insertVMInstance(t, orch, "run", true, &InstanceConfig{WorkDir: wd})
	insertVMInstance(t, orch, "stop", false, &InstanceConfig{WorkDir: wd})
	installDiskSeams(t, &fakeDiskMon{}, nil)

	cases := []struct {
		name string
		id   string
		req  DiskAttachRequest
		want error
	}{
		{"empty id", "", DiskAttachRequest{Path: "/x"}, ErrInvalidInstanceID},
		{"empty path", "run", DiskAttachRequest{}, ErrInvalidDiskRequest},
		{"bad bus", "run", DiskAttachRequest{Path: "/x", Bus: "scsi"}, ErrInvalidDiskRequest},
		{"not found", "ghost", DiskAttachRequest{Path: "/x"}, ErrInstanceNotFound},
		{"not running", "stop", DiskAttachRequest{Path: "/x"}, ErrInstanceNotRunning},
		{"create needs size", "run", DiskAttachRequest{Path: filepath.Join(wd, "nope.qcow2")}, ErrInvalidDiskRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := orch.AttachDisk(context.Background(), tc.id, tc.req)
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestAttachDisk_Duplicate(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	diskPath := filepath.Join(wd, "d.qcow2")
	require.NoError(t, os.WriteFile(diskPath, []byte("x"), 0o644))
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd})
	qi.instance.Disks = []DiskInfo{{ID: "dup"}}
	installDiskSeams(t, &fakeDiskMon{}, nil)

	_, err := orch.AttachDisk(context.Background(), "vm1", DiskAttachRequest{ID: "dup", Path: diskPath})
	assert.ErrorIs(t, err, ErrDiskAlreadyAttached)
}

func TestAttachDisk_DeviceAddRollback(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	diskPath := filepath.Join(wd, "d.qcow2")
	require.NoError(t, os.WriteFile(diskPath, []byte("x"), 0o644))
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd})

	mon := &fakeDiskMon{devAddErr: errors.New("device_add boom")}
	installDiskSeams(t, mon, nil)

	_, err := orch.AttachDisk(context.Background(), "vm1", DiskAttachRequest{ID: "d1", Path: diskPath})
	require.Error(t, err)
	assert.Equal(t, []string{"node-d1"}, mon.blockdevDel, "orphaned node must be rolled back")
}

func TestDetachDisk(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd})
	qi.instance.Disks = []DiskInfo{{ID: "d1", NodeName: "node-d1", DeviceID: "disk-d1"}}
	mon := &fakeDiskMon{}
	installDiskSeams(t, mon, nil)

	require.NoError(t, orch.DetachDisk(context.Background(), "vm1", "d1"))
	assert.Equal(t, []string{"disk-d1"}, mon.deviceDel)
	assert.Equal(t, []string{"node-d1"}, mon.blockdevDel)

	inst, _ := orch.Get(context.Background(), "vm1")
	assert.Empty(t, inst.Disks)
}

func TestDetachDisk_Errors(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	insertVMInstance(t, orch, "run", true, &InstanceConfig{WorkDir: wd})
	insertVMInstance(t, orch, "stop", false, &InstanceConfig{WorkDir: wd})
	installDiskSeams(t, &fakeDiskMon{}, nil)

	_, _ = orch, wd
	assert.ErrorIs(t, orch.DetachDisk(context.Background(), "", "d"), ErrInvalidInstanceID)
	assert.ErrorIs(t, orch.DetachDisk(context.Background(), "run", ""), ErrInvalidDiskRequest)
	assert.ErrorIs(t, orch.DetachDisk(context.Background(), "ghost", "d"), ErrInstanceNotFound)
	assert.ErrorIs(t, orch.DetachDisk(context.Background(), "stop", "d"), ErrInstanceNotRunning)
	assert.ErrorIs(t, orch.DetachDisk(context.Background(), "run", "missing"), ErrDiskNotFound)
}

func TestResizeDisk_OnlineTracked(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd, DiskPath: "/boot.qcow2"})
	qi.instance.Disks = []DiskInfo{{ID: "d1", NodeName: "node-d1", Path: "/d1.qcow2", SizeGB: 5}}
	mon := &fakeDiskMon{}
	installDiskSeams(t, mon, nil)

	require.NoError(t, orch.ResizeDisk(context.Background(), "vm1", "d1", 10))
	assert.Equal(t, []string{"node-d1"}, mon.resizeNode)
	assert.Equal(t, []int64{10 * (1 << 30)}, mon.resizeSize)

	inst, _ := orch.Get(context.Background(), "vm1")
	assert.Equal(t, uint64(10), inst.Disks[0].SizeGB)
}

func TestResizeDisk_OnlineBootDisk(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd, DiskPath: "/boot.qcow2"})
	mon := &fakeDiskMon{}
	installDiskSeams(t, mon, nil)

	require.NoError(t, orch.ResizeDisk(context.Background(), "vm1", "hd0", 20))
	assert.Equal(t, []string{""}, mon.resizeNode)
	assert.Equal(t, []string{"hd0"}, mon.resizeDevice)
}

func TestResizeDisk_OfflineBootDisk(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	insertVMInstance(t, orch, "vm1", false, &InstanceConfig{WorkDir: wd, DiskPath: "/boot.qcow2"})
	mon := &fakeDiskMon{}
	imgCalls := installDiskSeams(t, mon, nil)

	require.NoError(t, orch.ResizeDisk(context.Background(), "vm1", "", 30))
	assert.Equal(t, []string{"resize"}, *imgCalls)
	assert.Empty(t, mon.resizeNode)
}

func TestResizeDisk_Errors(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd, DiskPath: "/boot.qcow2"})
	installDiskSeams(t, &fakeDiskMon{}, nil)

	assert.ErrorIs(t, orch.ResizeDisk(context.Background(), "", "d", 10), ErrInvalidInstanceID)
	assert.ErrorIs(t, orch.ResizeDisk(context.Background(), "vm1", "d", 0), ErrInvalidDiskRequest)
	assert.ErrorIs(t, orch.ResizeDisk(context.Background(), "ghost", "d", 10), ErrInstanceNotFound)
	assert.ErrorIs(t, orch.ResizeDisk(context.Background(), "vm1", "unknown", 10), ErrDiskNotFound)
}
