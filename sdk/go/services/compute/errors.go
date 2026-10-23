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

import "fmt"

// VM Errors

// ErrCreateVMFailed is returned when VM creation fails.
type ErrCreateVMFailed struct {
	Cause error
}

func (e *ErrCreateVMFailed) Error() string {
	return fmt.Sprintf("failed to create VM: %v", e.Cause)
}

func (e *ErrCreateVMFailed) Unwrap() error {
	return e.Cause
}

// ErrStartVMFailed is returned when starting a VM fails.
type ErrStartVMFailed struct {
	ID    string
	Cause error
}

func (e *ErrStartVMFailed) Error() string {
	return fmt.Sprintf("failed to start VM %s: %v", e.ID, e.Cause)
}

func (e *ErrStartVMFailed) Unwrap() error {
	return e.Cause
}

// ErrStopVMFailed is returned when stopping a VM fails.
type ErrStopVMFailed struct {
	ID    string
	Cause error
}

func (e *ErrStopVMFailed) Error() string {
	return fmt.Sprintf("failed to stop VM %s: %v", e.ID, e.Cause)
}

func (e *ErrStopVMFailed) Unwrap() error {
	return e.Cause
}

// ErrRebootVMFailed is returned when rebooting a VM fails.
type ErrRebootVMFailed struct {
	ID    string
	Cause error
}

func (e *ErrRebootVMFailed) Error() string {
	return fmt.Sprintf("failed to reboot VM %s: %v", e.ID, e.Cause)
}

func (e *ErrRebootVMFailed) Unwrap() error {
	return e.Cause
}

// ErrSuspendVMFailed is returned when suspending a VM fails.
type ErrSuspendVMFailed struct {
	ID    string
	Cause error
}

func (e *ErrSuspendVMFailed) Error() string {
	return fmt.Sprintf("failed to suspend VM %s: %v", e.ID, e.Cause)
}

func (e *ErrSuspendVMFailed) Unwrap() error {
	return e.Cause
}

// ErrResumeVMFailed is returned when resuming a VM fails.
type ErrResumeVMFailed struct {
	ID    string
	Cause error
}

func (e *ErrResumeVMFailed) Error() string {
	return fmt.Sprintf("failed to resume VM %s: %v", e.ID, e.Cause)
}

func (e *ErrResumeVMFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteVMFailed is returned when deleting a VM fails.
type ErrDeleteVMFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteVMFailed) Error() string {
	return fmt.Sprintf("failed to delete VM %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteVMFailed) Unwrap() error {
	return e.Cause
}

// ErrGetVMFailed is returned when getting a VM fails.
type ErrGetVMFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetVMFailed) Error() string {
	return fmt.Sprintf("failed to get VM %s: %v", e.ID, e.Cause)
}

func (e *ErrGetVMFailed) Unwrap() error {
	return e.Cause
}

// ErrListVMsFailed is returned when listing VMs fails.
type ErrListVMsFailed struct {
	Cause error
}

func (e *ErrListVMsFailed) Error() string {
	return fmt.Sprintf("failed to list VMs: %v", e.Cause)
}

func (e *ErrListVMsFailed) Unwrap() error {
	return e.Cause
}

// ErrGetVMMetricsFailed is returned when getting VM metrics fails.
type ErrGetVMMetricsFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetVMMetricsFailed) Error() string {
	return fmt.Sprintf("failed to get VM metrics for %s: %v", e.ID, e.Cause)
}

func (e *ErrGetVMMetricsFailed) Unwrap() error {
	return e.Cause
}

// ErrMigrateVMFailed is returned when VM migration fails.
type ErrMigrateVMFailed struct {
	VMID  string
	Cause error
}

func (e *ErrMigrateVMFailed) Error() string {
	return fmt.Sprintf("failed to migrate VM %s: %v", e.VMID, e.Cause)
}

func (e *ErrMigrateVMFailed) Unwrap() error {
	return e.Cause
}

// ErrPrepareMigrationFailed is returned when the destination cannot prepare
// to receive a migrating VM.
type ErrPrepareMigrationFailed struct {
	VMName string
	Cause  error
}

func (e *ErrPrepareMigrationFailed) Error() string {
	return fmt.Sprintf("failed to prepare migration of VM %s: %v", e.VMName, e.Cause)
}

func (e *ErrPrepareMigrationFailed) Unwrap() error {
	return e.Cause
}

// ErrFinalizeMigrationFailed is returned when finalizing a received migration
// fails.
type ErrFinalizeMigrationFailed struct {
	ReceiverID string
	Cause      error
}

func (e *ErrFinalizeMigrationFailed) Error() string {
	return fmt.Sprintf("failed to finalize migration receiver %s: %v", e.ReceiverID, e.Cause)
}

func (e *ErrFinalizeMigrationFailed) Unwrap() error {
	return e.Cause
}

// Disk Errors

// ErrAttachDiskFailed is returned when attaching a disk fails.
type ErrAttachDiskFailed struct {
	VMID  string
	Cause error
}

func (e *ErrAttachDiskFailed) Error() string {
	return fmt.Sprintf("failed to attach disk to VM %s: %v", e.VMID, e.Cause)
}

func (e *ErrAttachDiskFailed) Unwrap() error {
	return e.Cause
}

// ErrDetachDiskFailed is returned when detaching a disk fails.
type ErrDetachDiskFailed struct {
	VMID   string
	DiskID string
	Cause  error
}

func (e *ErrDetachDiskFailed) Error() string {
	return fmt.Sprintf("failed to detach disk %s from VM %s: %v", e.DiskID, e.VMID, e.Cause)
}

func (e *ErrDetachDiskFailed) Unwrap() error {
	return e.Cause
}

// ErrResizeDiskFailed is returned when resizing a disk fails.
type ErrResizeDiskFailed struct {
	VMID   string
	DiskID string
	Cause  error
}

func (e *ErrResizeDiskFailed) Error() string {
	return fmt.Sprintf("failed to resize disk %s for VM %s: %v", e.DiskID, e.VMID, e.Cause)
}

func (e *ErrResizeDiskFailed) Unwrap() error {
	return e.Cause
}

// Snapshot Errors

// ErrCreateSnapshotFailed is returned when creating a snapshot fails.
type ErrCreateSnapshotFailed struct {
	VMID  string
	Cause error
}

func (e *ErrCreateSnapshotFailed) Error() string {
	return fmt.Sprintf("failed to create snapshot for VM %s: %v", e.VMID, e.Cause)
}

func (e *ErrCreateSnapshotFailed) Unwrap() error {
	return e.Cause
}

// ErrRestoreSnapshotFailed is returned when restoring a snapshot fails.
type ErrRestoreSnapshotFailed struct {
	VMID       string
	SnapshotID string
	Cause      error
}

func (e *ErrRestoreSnapshotFailed) Error() string {
	return fmt.Sprintf("failed to restore snapshot %s for VM %s: %v", e.SnapshotID, e.VMID, e.Cause)
}

func (e *ErrRestoreSnapshotFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteSnapshotFailed is returned when deleting a snapshot fails.
type ErrDeleteSnapshotFailed struct {
	VMID       string
	SnapshotID string
	Cause      error
}

func (e *ErrDeleteSnapshotFailed) Error() string {
	return fmt.Sprintf("failed to delete snapshot %s for VM %s: %v", e.SnapshotID, e.VMID, e.Cause)
}

func (e *ErrDeleteSnapshotFailed) Unwrap() error {
	return e.Cause
}

// ErrListSnapshotsFailed is returned when listing snapshots fails.
type ErrListSnapshotsFailed struct {
	VMID  string
	Cause error
}

func (e *ErrListSnapshotsFailed) Error() string {
	return fmt.Sprintf("failed to list snapshots for VM %s: %v", e.VMID, e.Cause)
}

func (e *ErrListSnapshotsFailed) Unwrap() error {
	return e.Cause
}

// ErrGetSnapshotFailed is returned when reading one snapshot fails.
type ErrGetSnapshotFailed struct {
	VMID       string
	SnapshotID string
	Cause      error
}

func (e *ErrGetSnapshotFailed) Error() string {
	return fmt.Sprintf("failed to get snapshot %s for VM %s: %v", e.SnapshotID, e.VMID, e.Cause)
}

func (e *ErrGetSnapshotFailed) Unwrap() error {
	return e.Cause
}

// Container Errors

// ErrCreateContainerFailed is returned when container creation fails.
type ErrCreateContainerFailed struct {
	Cause error
}

func (e *ErrCreateContainerFailed) Error() string {
	return fmt.Sprintf("failed to create container: %v", e.Cause)
}

func (e *ErrCreateContainerFailed) Unwrap() error {
	return e.Cause
}

// ErrStartContainerFailed is returned when starting a container fails.
type ErrStartContainerFailed struct {
	ID    string
	Cause error
}

func (e *ErrStartContainerFailed) Error() string {
	return fmt.Sprintf("failed to start container %s: %v", e.ID, e.Cause)
}

func (e *ErrStartContainerFailed) Unwrap() error {
	return e.Cause
}

// ErrStopContainerFailed is returned when stopping a container fails.
type ErrStopContainerFailed struct {
	ID    string
	Cause error
}

func (e *ErrStopContainerFailed) Error() string {
	return fmt.Sprintf("failed to stop container %s: %v", e.ID, e.Cause)
}

func (e *ErrStopContainerFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteContainerFailed is returned when deleting a container fails.
type ErrDeleteContainerFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteContainerFailed) Error() string {
	return fmt.Sprintf("failed to delete container %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteContainerFailed) Unwrap() error {
	return e.Cause
}

// ErrGetContainerFailed is returned when getting a container fails.
type ErrGetContainerFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetContainerFailed) Error() string {
	return fmt.Sprintf("failed to get container %s: %v", e.ID, e.Cause)
}

func (e *ErrGetContainerFailed) Unwrap() error {
	return e.Cause
}

// ErrListContainersFailed is returned when listing containers fails.
type ErrListContainersFailed struct {
	Cause error
}

func (e *ErrListContainersFailed) Error() string {
	return fmt.Sprintf("failed to list containers: %v", e.Cause)
}

func (e *ErrListContainersFailed) Unwrap() error {
	return e.Cause
}

// ErrExecContainerFailed is returned when executing a command in a container fails.
type ErrExecContainerFailed struct {
	ID    string
	Cause error
}

func (e *ErrExecContainerFailed) Error() string {
	return fmt.Sprintf("failed to exec in container %s: %v", e.ID, e.Cause)
}

func (e *ErrExecContainerFailed) Unwrap() error {
	return e.Cause
}

// ErrGetContainerMetricsFailed is returned when getting container metrics fails.
type ErrGetContainerMetricsFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetContainerMetricsFailed) Error() string {
	return fmt.Sprintf("failed to get container metrics for %s: %v", e.ID, e.Cause)
}

func (e *ErrGetContainerMetricsFailed) Unwrap() error {
	return e.Cause
}

// Attestation Errors

// ErrAttestVMFailed is returned when VM attestation fails.
type ErrAttestVMFailed struct {
	VMID  string
	Cause error
}

func (e *ErrAttestVMFailed) Error() string {
	return fmt.Sprintf("failed to attest VM %s: %v", e.VMID, e.Cause)
}

func (e *ErrAttestVMFailed) Unwrap() error {
	return e.Cause
}

// ErrVerifyVMAttestationFailed is returned when VM attestation verification fails.
type ErrVerifyVMAttestationFailed struct {
	VMID  string
	Cause error
}

func (e *ErrVerifyVMAttestationFailed) Error() string {
	return fmt.Sprintf("failed to verify VM attestation for %s: %v", e.VMID, e.Cause)
}

func (e *ErrVerifyVMAttestationFailed) Unwrap() error {
	return e.Cause
}
