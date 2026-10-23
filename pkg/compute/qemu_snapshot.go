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
	"path/filepath"
	"strings"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// Compile-time proof that QEMUOrchestrator provides the VM snapshot
// capability.
var _ VMSnapshotter = (*QEMUOrchestrator)(nil)

// vmSnapshotOps abstracts the qemu.SnapshotManager surface the orchestrator
// uses so tests can inject a fake QMP seam.
type vmSnapshotOps interface {
	Create(ctx context.Context, name string) error
	Restore(ctx context.Context, name string) error
	Delete(ctx context.Context, name string) error
	List(ctx context.Context) ([]qemu.SnapshotInfo, error)
	Get(ctx context.Context, name string) (*qemu.SnapshotInfo, error)
}

// Compile-time proof that the real snapshot manager satisfies the seam.
var _ vmSnapshotOps = (*qemu.SnapshotManager)(nil)

// defaultSnapshotOps connects the instance's QMP monitor (lazily, reusing an
// existing connection) and returns a snapshot manager bound to it. The
// monitor connection is owned by the qemu.VM, which closes it when the VM
// stops, so no socket leaks across VM restarts.
func (o *QEMUOrchestrator) defaultSnapshotOps(ctx context.Context, qemuInst *qemuInstance) (vmSnapshotOps, error) {
	mon := qemuInst.vm.Monitor()
	if mon == nil || !mon.IsConnected() {
		if err := qemuInst.vm.ConnectMonitor(ctx); err != nil {
			return nil, &WrappedError{Msg: "failed to connect QMP monitor", Err: err}
		}
		mon = qemuInst.vm.Monitor()
	}
	return qemu.NewSnapshotManager(mon, o.logger)
}

// snapshotSession validates the instance and returns it together with the
// snapshot operations bound to its QMP monitor. Internal QEMU snapshots
// require a qcow2 disk image and a running VM (savevm/loadvm are QMP
// commands); both preconditions surface typed errors.
//
// The caller must hold qemuInst.mu for the duration of the snapshot
// operation to serialize QMP access against lifecycle transitions.
func (o *QEMUOrchestrator) snapshotSession(ctx context.Context, instanceID string) (*qemuInstance, vmSnapshotOps, error) {
	if instanceID == "" {
		return nil, nil, ErrInvalidInstanceID
	}

	o.mu.RLock()
	qemuInst, exists := o.instances[instanceID]
	o.mu.RUnlock()

	if !exists {
		return nil, nil, ErrInstanceNotFound
	}

	// Internal snapshots are stored inside the qcow2 image; any other disk
	// format cannot hold them, so reject instead of silently attempting.
	if qemuInst.instance.Config == nil ||
		!strings.EqualFold(filepath.Ext(qemuInst.instance.Config.DiskPath), ".qcow2") {
		return nil, nil, &SentinelCauseError{
			Sentinel: ErrUnsupportedDiskFormat,
			Cause:    &MessageError{Msg: "instance disk image is not qcow2"},
		}
	}

	// savevm/loadvm/delvm/info-snapshots are QMP commands: they require a
	// running QEMU process with an active monitor socket.
	state, err := o.lifecycle.GetState(instanceID)
	if err != nil {
		return nil, nil, err
	}
	if state != StateRunning {
		return nil, nil, &SentinelCauseError{
			Sentinel: ErrInstanceNotRunning,
			Cause:    &MessageError{Msg: "internal QEMU snapshots require a running VM with an active QMP monitor"},
		}
	}

	ops, err := o.snapshotOpsFor(ctx, qemuInst)
	if err != nil {
		return nil, nil, err
	}

	return qemuInst, ops, nil
}

// translateSnapshotError maps qemu snapshot errors onto compute sentinels so
// protocol surfaces can classify them without importing pkg/qemu.
func translateSnapshotError(err error) error {
	if err == nil {
		return nil
	}
	var notFound qemu.ErrSnapshotNotFound
	if errors.As(err, &notFound) {
		return &SentinelCauseError{Sentinel: ErrSnapshotNotFound, Cause: err}
	}
	var invalidName qemu.ErrSnapshotInvalidName
	if errors.As(err, &invalidName) {
		return &SentinelCauseError{Sentinel: ErrInvalidSnapshotName, Cause: err}
	}
	return err
}

// CreateSnapshot creates an internal QEMU snapshot (memory + disk) of a
// running VM instance via savevm over QMP.
func (o *QEMUOrchestrator) CreateSnapshot(ctx context.Context, instanceID, snapshotName string) (*VMSnapshot, error) {
	if !qemu.IsValidSnapshotName(snapshotName) {
		return nil, &SentinelCauseError{
			Sentinel: ErrInvalidSnapshotName,
			Cause:    &MessageError{Msg: "snapshot name must start with a letter or underscore, contain only alphanumerics, underscores, hyphens, and dots, and not be a reserved word"},
		}
	}

	qemuInst, ops, err := o.snapshotSession(ctx, instanceID)
	if err != nil {
		return nil, err
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	if err := ops.Create(ctx, snapshotName); err != nil {
		return nil, translateSnapshotError(err)
	}

	snapshot := &VMSnapshot{
		Name:      snapshotName,
		VMID:      instanceID,
		CreatedAt: time.Now(),
	}

	// Enrich with QEMU's snapshot record; a lookup failure after a
	// successful savevm is not fatal.
	if info, getErr := ops.Get(ctx, snapshotName); getErr == nil {
		if !info.Date.IsZero() {
			snapshot.CreatedAt = info.Date
		}
		snapshot.SizeBytes = int64(info.VMStateSize)
	} else {
		o.logger.Warnf("Snapshot %s created but metadata lookup failed: %v", snapshotName, getErr)
	}

	o.logger.Infof("Created snapshot %s for VM instance %s", snapshotName, instanceID)

	return snapshot, nil
}

// RestoreSnapshot restores a running VM instance to a previously created
// internal snapshot via loadvm over QMP.
func (o *QEMUOrchestrator) RestoreSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	if !qemu.IsValidSnapshotName(snapshotName) {
		return &SentinelCauseError{
			Sentinel: ErrInvalidSnapshotName,
			Cause:    &MessageError{Msg: "snapshot name failed validation"},
		}
	}

	qemuInst, ops, err := o.snapshotSession(ctx, instanceID)
	if err != nil {
		return err
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	if err := ops.Restore(ctx, snapshotName); err != nil {
		return translateSnapshotError(err)
	}

	o.logger.Infof("Restored snapshot %s for VM instance %s", snapshotName, instanceID)

	return nil
}

// DeleteSnapshot deletes an internal snapshot from a running VM instance via
// delvm over QMP.
func (o *QEMUOrchestrator) DeleteSnapshot(ctx context.Context, instanceID, snapshotName string) error {
	if !qemu.IsValidSnapshotName(snapshotName) {
		return &SentinelCauseError{
			Sentinel: ErrInvalidSnapshotName,
			Cause:    &MessageError{Msg: "snapshot name failed validation"},
		}
	}

	qemuInst, ops, err := o.snapshotSession(ctx, instanceID)
	if err != nil {
		return err
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	// QEMU's delvm succeeds for a name no disk holds, so a snapshot that is
	// already gone would read as deleted: look it up first and answer
	// NotFound instead.
	if _, err := ops.Get(ctx, snapshotName); err != nil {
		return translateSnapshotError(err)
	}

	if err := ops.Delete(ctx, snapshotName); err != nil {
		return translateSnapshotError(err)
	}

	o.logger.Infof("Deleted snapshot %s for VM instance %s", snapshotName, instanceID)

	return nil
}

// ListSnapshots lists all internal snapshots of a running VM instance via
// "info snapshots" over QMP.
func (o *QEMUOrchestrator) ListSnapshots(ctx context.Context, instanceID string) ([]*VMSnapshot, error) {
	qemuInst, ops, err := o.snapshotSession(ctx, instanceID)
	if err != nil {
		return nil, err
	}

	qemuInst.mu.Lock()
	defer qemuInst.mu.Unlock()

	infos, err := ops.List(ctx)
	if err != nil {
		return nil, translateSnapshotError(err)
	}

	snapshots := make([]*VMSnapshot, 0, len(infos))
	for i := range infos {
		snapshots = append(snapshots, &VMSnapshot{
			Name:      infos[i].Name,
			VMID:      instanceID,
			CreatedAt: infos[i].Date,
			SizeBytes: int64(infos[i].VMStateSize),
		})
	}

	return snapshots, nil
}
