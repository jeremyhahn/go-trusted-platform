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

package qemu

import "fmt"

// ErrSnapshotNotFound is returned when a requested snapshot does not exist.
type ErrSnapshotNotFound struct {
	Name string
}

func (e ErrSnapshotNotFound) Error() string {
	return fmt.Sprintf("snapshot not found: %s", e.Name)
}

// ErrSnapshotCreateFailed is returned when snapshot creation fails.
type ErrSnapshotCreateFailed struct {
	Name  string
	Cause error
}

func (e ErrSnapshotCreateFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to create snapshot %q: %v", e.Name, e.Cause)
	}
	return fmt.Sprintf("failed to create snapshot %q", e.Name)
}

func (e ErrSnapshotCreateFailed) Unwrap() error {
	return e.Cause
}

// ErrSnapshotRestoreFailed is returned when snapshot restoration fails.
type ErrSnapshotRestoreFailed struct {
	Name  string
	Cause error
}

func (e ErrSnapshotRestoreFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to restore snapshot %q: %v", e.Name, e.Cause)
	}
	return fmt.Sprintf("failed to restore snapshot %q", e.Name)
}

func (e ErrSnapshotRestoreFailed) Unwrap() error {
	return e.Cause
}

// ErrSnapshotDeleteFailed is returned when snapshot deletion fails.
type ErrSnapshotDeleteFailed struct {
	Name  string
	Cause error
}

func (e ErrSnapshotDeleteFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to delete snapshot %q: %v", e.Name, e.Cause)
	}
	return fmt.Sprintf("failed to delete snapshot %q", e.Name)
}

func (e ErrSnapshotDeleteFailed) Unwrap() error {
	return e.Cause
}

// ErrSnapshotListFailed is returned when listing snapshots fails.
type ErrSnapshotListFailed struct {
	Cause error
}

func (e ErrSnapshotListFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to list snapshots: %v", e.Cause)
	}
	return "failed to list snapshots"
}

func (e ErrSnapshotListFailed) Unwrap() error {
	return e.Cause
}

// ErrSnapshotInvalidName is returned when a snapshot name is invalid.
type ErrSnapshotInvalidName struct {
	Name   string
	Reason string
}

func (e ErrSnapshotInvalidName) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("invalid snapshot name %q: %s", e.Name, e.Reason)
	}
	return fmt.Sprintf("invalid snapshot name %q", e.Name)
}

// ErrSnapshotVMNotPaused is returned when an operation requires the VM
// to be paused but it is not.
type ErrSnapshotVMNotPaused struct {
	Operation string
}

func (e ErrSnapshotVMNotPaused) Error() string {
	if e.Operation != "" {
		return fmt.Sprintf("VM must be paused for %s operation", e.Operation)
	}
	return "VM must be paused for this operation"
}

// ErrSnapshotManagerNotInitialized is returned when the snapshot manager
// is used before initialization.
type ErrSnapshotManagerNotInitialized struct{}

func (e ErrSnapshotManagerNotInitialized) Error() string {
	return "snapshot manager is not initialized"
}

// ErrSnapshotAlreadyExists is returned when attempting to create a snapshot
// with a name that already exists.
type ErrSnapshotAlreadyExists struct {
	Name string
}

func (e ErrSnapshotAlreadyExists) Error() string {
	return fmt.Sprintf("snapshot already exists: %s", e.Name)
}

// ErrSnapshotParseError is returned when parsing snapshot information fails.
type ErrSnapshotParseError struct {
	Line  string
	Cause error
}

func (e ErrSnapshotParseError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("failed to parse snapshot info %q: %v", e.Line, e.Cause)
	}
	return fmt.Sprintf("failed to parse snapshot info %q", e.Line)
}

func (e ErrSnapshotParseError) Unwrap() error {
	return e.Cause
}
