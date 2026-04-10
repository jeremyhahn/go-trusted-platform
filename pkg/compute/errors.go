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
	// ErrInstanceNotFound is returned when an instance cannot be found
	ErrInstanceNotFound = errors.New("instance not found")

	// ErrInstanceAlreadyExists is returned when creating an instance that already exists
	ErrInstanceAlreadyExists = errors.New("instance already exists")

	// ErrInstanceNotRunning is returned when attempting an operation on a stopped instance
	ErrInstanceNotRunning = errors.New("instance is not running")

	// ErrInstanceAlreadyRunning is returned when attempting to start an already running instance
	ErrInstanceAlreadyRunning = errors.New("instance is already running")

	// ErrInvalidConfiguration is returned when the configuration is invalid
	ErrInvalidConfiguration = errors.New("invalid configuration")

	// ErrInvalidInstanceID is returned when an instance ID is invalid
	ErrInvalidInstanceID = errors.New("invalid instance ID")

	// ErrInvalidProfile is returned when a device profile is invalid
	ErrInvalidProfile = errors.New("invalid device profile")

	// ErrNetworkAttachmentFailed is returned when network attachment fails
	ErrNetworkAttachmentFailed = errors.New("network attachment failed")

	// ErrNetworkDetachmentFailed is returned when network detachment fails
	ErrNetworkDetachmentFailed = errors.New("network detachment failed")

	// ErrOrchestratorNotInitialized is returned when orchestrator is not properly initialized
	ErrOrchestratorNotInitialized = errors.New("orchestrator not initialized")

	// ErrUnsupportedOperation is returned when an operation is not supported
	ErrUnsupportedOperation = errors.New("unsupported operation")

	// ErrInvalidState is returned when an instance is in an invalid state for the requested operation
	ErrInvalidState = errors.New("invalid instance state")

	// ErrTimeout is returned when an operation times out
	ErrTimeout = errors.New("operation timeout")

	// ErrResourceExhausted is returned when system resources are exhausted
	ErrResourceExhausted = errors.New("resource exhausted")
)
