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

import "errors"

var (
	// ErrDiskNotFound is returned when a disk ID does not match any disk
	// attached to the instance.
	ErrDiskNotFound = errors.New("disk not found")

	// ErrDiskAlreadyAttached is returned when attaching a disk whose ID is
	// already present on the instance.
	ErrDiskAlreadyAttached = errors.New("disk already attached")

	// ErrInvalidDiskRequest is returned when a disk attach/resize request is
	// missing required fields or carries an unsupported bus.
	ErrInvalidDiskRequest = errors.New("invalid disk request")

	// ErrConsoleUnavailable is returned when a VM console cannot be reached
	// (the VM is not running or its console socket is absent).
	ErrConsoleUnavailable = errors.New("VM console unavailable")

	// ErrVMMetricsUnavailable is returned when VM metrics cannot be sampled
	// (the VM process is not running or has no PID).
	ErrVMMetricsUnavailable = errors.New("VM metrics unavailable")

	// ErrVMLogsUnavailable is returned when a VM's serial transcript cannot be
	// located.
	ErrVMLogsUnavailable = errors.New("VM logs unavailable")
)
