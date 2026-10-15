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
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// bytesPerGiB is the multiplier used to translate gibibyte disk sizes into the
// byte counts QMP block_resize expects.
const bytesPerGiB int64 = 1 << 30

// diskMonitorOps abstracts the QMP disk-management surface the orchestrator
// uses so tests can inject a fake QMP seam.
type diskMonitorOps interface {
	BlockdevAddQcow2(ctx context.Context, nodeName, filename string) error
	AddVirtioBlkDevice(ctx context.Context, deviceID, nodeName string) error
	DeviceDel(ctx context.Context, deviceID string) error
	BlockdevDel(ctx context.Context, nodeName string) error
	BlockResize(ctx context.Context, nodeName, device string, sizeBytes int64) error
}

// Compile-time proof that the real monitor satisfies the disk seam.
var _ diskMonitorOps = (*qemu.Monitor)(nil)

// Seams for disk management. They are package-level function variables so unit
// tests can substitute host primitives without a real VM.
var (
	// vmDiskMonitorFor returns the QMP disk operations for an instance.
	vmDiskMonitorFor = defaultVMDiskMonitorFor

	// execQemuImg runs a qemu-img subcommand (image create / offline resize).
	execQemuImg = defaultExecQemuImg
)

// bootDiskAliases are the disk IDs that address a VM's primary boot disk, which
// is tracked implicitly through InstanceConfig.DiskPath rather than the Disks
// list. The boot drive is attached with the legacy id "hd0".
var bootDiskAliases = map[string]bool{"": true, "hd0": true, "root": true, "boot": true, "disk0": true}

// generateDiskID returns a random hex disk identifier.
func generateDiskID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// nextVirtioSlot returns the next free bus slot ordinal. Slot 0 is reserved for
// the boot disk, so hot-plugged disks start at 1.
func nextVirtioSlot(disks []DiskInfo) int {
	next := 1
	for i := range disks {
		if disks[i].Index >= next {
			next = disks[i].Index + 1
		}
	}
	return next
}

// AttachDisk hot-plugs a virtio-blk disk onto a running VM. It performs the QMP
// two-step (blockdev-add then device_add), creating the backing qcow2 image
// first when it does not yet exist, and records the disk on the instance.
func (o *QEMUOrchestrator) AttachDisk(ctx context.Context, instanceID string, req DiskAttachRequest) (*DiskInfo, error) {
	if instanceID == "" {
		return nil, ErrInvalidInstanceID
	}
	if req.Path == "" {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidDiskRequest, Cause: &MessageError{Msg: "disk path is required"}}
	}
	bus := req.Bus
	if bus == "" {
		bus = "virtio"
	}
	if bus != "virtio" {
		return nil, &SentinelCauseError{Sentinel: ErrInvalidDiskRequest, Cause: &MessageError{Msg: "only the virtio bus supports hotplug"}}
	}

	o.mu.RLock()
	inst, exists := o.instances[instanceID]
	o.mu.RUnlock()
	if !exists {
		return nil, ErrInstanceNotFound
	}

	// Hotplug requires a running VM with an active QMP monitor.
	state, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return nil, err
	}
	if state != StateRunning {
		return nil, &SentinelCauseError{Sentinel: ErrInstanceNotRunning, Cause: &MessageError{Msg: "disk hotplug requires a running VM"}}
	}

	inst.mu.Lock()
	defer inst.mu.Unlock()

	diskID := req.ID
	if diskID == "" {
		diskID = generateDiskID()
	}
	for i := range inst.instance.Disks {
		if inst.instance.Disks[i].ID == diskID {
			return nil, &SentinelCauseError{Sentinel: ErrDiskAlreadyAttached, Cause: &MessageError{Msg: diskID}}
		}
	}

	// Create the backing image on demand.
	if _, statErr := os.Stat(req.Path); statErr != nil {
		if !os.IsNotExist(statErr) {
			return nil, &WrappedError{Msg: "failed to stat disk image", Err: statErr}
		}
		if req.SizeGB == 0 {
			return nil, &SentinelCauseError{Sentinel: ErrInvalidDiskRequest, Cause: &MessageError{Msg: "size is required to create a new disk image"}}
		}
		if err := execQemuImg(ctx, "create", "-f", "qcow2", req.Path, fmt.Sprintf("%dG", req.SizeGB)); err != nil {
			return nil, &WrappedError{Msg: "failed to create disk image", Err: err}
		}
	}

	mon, err := vmDiskMonitorFor(ctx, o, inst)
	if err != nil {
		return nil, err
	}

	nodeName := "node-" + diskID
	deviceID := "disk-" + diskID

	if err := mon.BlockdevAddQcow2(ctx, nodeName, req.Path); err != nil {
		return nil, &WrappedError{Msg: "blockdev-add failed", Err: err}
	}
	if err := mon.AddVirtioBlkDevice(ctx, deviceID, nodeName); err != nil {
		// Roll back the orphaned block node so a retry can succeed.
		if delErr := mon.BlockdevDel(ctx, nodeName); delErr != nil {
			o.logger.Warnf("disk attach rollback: blockdev-del %s failed: %v", nodeName, delErr)
		}
		return nil, &WrappedError{Msg: "device_add failed", Err: err}
	}

	info := DiskInfo{
		ID:         diskID,
		Path:       req.Path,
		Bus:        "virtio",
		Index:      nextVirtioSlot(inst.instance.Disks),
		SizeGB:     req.SizeGB,
		NodeName:   nodeName,
		DeviceID:   deviceID,
		Readonly:   req.Readonly,
		Hotplugged: true,
	}
	inst.instance.Disks = append(inst.instance.Disks, info)
	inst.instance.UpdatedAt = time.Now()

	o.logger.Infof("Attached disk %s (%s) to VM %s", diskID, req.Path, instanceID)
	return &info, nil
}

// DetachDisk unplugs a previously attached disk from a running VM via QMP
// device_del + blockdev-del. QEMU processes device_del asynchronously (the
// guest must release the device), so blockdev-del is best-effort and logged on
// failure; the disk is untracked once device_del is accepted.
func (o *QEMUOrchestrator) DetachDisk(ctx context.Context, instanceID, diskID string) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}
	if diskID == "" {
		return &SentinelCauseError{Sentinel: ErrInvalidDiskRequest, Cause: &MessageError{Msg: "disk ID is required"}}
	}

	o.mu.RLock()
	inst, exists := o.instances[instanceID]
	o.mu.RUnlock()
	if !exists {
		return ErrInstanceNotFound
	}

	state, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return err
	}
	if state != StateRunning {
		return &SentinelCauseError{Sentinel: ErrInstanceNotRunning, Cause: &MessageError{Msg: "disk unplug requires a running VM"}}
	}

	inst.mu.Lock()
	defer inst.mu.Unlock()

	idx := -1
	for i := range inst.instance.Disks {
		if inst.instance.Disks[i].ID == diskID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return &SentinelCauseError{Sentinel: ErrDiskNotFound, Cause: &MessageError{Msg: diskID}}
	}
	disk := inst.instance.Disks[idx]

	mon, err := vmDiskMonitorFor(ctx, o, inst)
	if err != nil {
		return err
	}

	if err := mon.DeviceDel(ctx, disk.DeviceID); err != nil {
		return &WrappedError{Msg: "device_del failed", Err: err}
	}
	if err := mon.BlockdevDel(ctx, disk.NodeName); err != nil {
		// The guest may not have released the device yet; the node lingers
		// until QEMU reaps it. Log and proceed with untracking.
		o.logger.Warnf("disk detach: blockdev-del %s pending guest release: %v", disk.NodeName, err)
	}

	inst.instance.Disks = append(inst.instance.Disks[:idx], inst.instance.Disks[idx+1:]...)
	inst.instance.UpdatedAt = time.Now()

	o.logger.Infof("Detached disk %s from VM %s", diskID, instanceID)
	return nil
}

// ResizeDisk changes a disk's virtual size. On a running VM the resize is
// online via QMP block_resize; on a stopped VM it is offline via qemu-img
// resize. The boot disk (tracked through InstanceConfig.DiskPath) is addressed
// by any of its aliases; additional disks are addressed by their attach ID.
func (o *QEMUOrchestrator) ResizeDisk(ctx context.Context, instanceID, diskID string, newSizeGB uint64) error {
	if instanceID == "" {
		return ErrInvalidInstanceID
	}
	if newSizeGB == 0 {
		return &SentinelCauseError{Sentinel: ErrInvalidDiskRequest, Cause: &MessageError{Msg: "new size must be greater than zero"}}
	}

	o.mu.RLock()
	inst, exists := o.instances[instanceID]
	o.mu.RUnlock()
	if !exists {
		return ErrInstanceNotFound
	}

	state, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return err
	}

	inst.mu.Lock()
	defer inst.mu.Unlock()

	// Resolve the target disk: an additional (tracked) disk, otherwise the
	// boot disk when the ID is one of its aliases.
	var (
		path     string
		nodeName string
		device   string
		trackIdx = -1
	)
	for i := range inst.instance.Disks {
		if inst.instance.Disks[i].ID == diskID {
			path = inst.instance.Disks[i].Path
			nodeName = inst.instance.Disks[i].NodeName
			trackIdx = i
			break
		}
	}
	if trackIdx < 0 {
		if !bootDiskAliases[diskID] || inst.instance.Config == nil || inst.instance.Config.DiskPath == "" {
			return &SentinelCauseError{Sentinel: ErrDiskNotFound, Cause: &MessageError{Msg: diskID}}
		}
		path = inst.instance.Config.DiskPath
		device = "hd0"
	}

	if state == StateRunning {
		mon, monErr := vmDiskMonitorFor(ctx, o, inst)
		if monErr != nil {
			return monErr
		}
		if err := mon.BlockResize(ctx, nodeName, device, int64(newSizeGB)*bytesPerGiB); err != nil {
			return &WrappedError{Msg: "online block_resize failed", Err: err}
		}
	} else {
		if err := execQemuImg(ctx, "resize", path, fmt.Sprintf("%dG", newSizeGB)); err != nil {
			return &WrappedError{Msg: "offline qemu-img resize failed", Err: err}
		}
	}

	if trackIdx >= 0 {
		inst.instance.Disks[trackIdx].SizeGB = newSizeGB
	}
	inst.instance.UpdatedAt = time.Now()

	o.logger.Infof("Resized disk %s on VM %s to %dG (online=%t)", diskID, instanceID, newSizeGB, state == StateRunning)
	return nil
}

// defaultVMDiskMonitorFor connects the instance's QMP monitor (reusing an
// existing connection) and returns the disk operations bound to it.
func defaultVMDiskMonitorFor(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance) (diskMonitorOps, error) {
	mon, err := instanceMonitor(ctx, inst)
	if err != nil {
		return nil, err
	}
	return mon, nil
}

// defaultExecQemuImg runs a qemu-img subcommand.
func defaultExecQemuImg(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "qemu-img", args...)
	if output, err := cmd.CombinedOutput(); err != nil {
		return &WrappedError{Msg: "qemu-img " + args[0] + ": " + string(output), Err: err}
	}
	return nil
}
