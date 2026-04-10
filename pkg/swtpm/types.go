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

package swtpm

import "errors"

var (
	// ErrSWTPMNotInstalled is returned when swtpm is not installed on the system
	ErrSWTPMNotInstalled = errors.New("swtpm not installed")

	// ErrSocketNotReady is returned when the swtpm socket is not ready for connections
	ErrSocketNotReady = errors.New("swtpm socket not ready")

	// ErrInitFailed is returned when swtpm initialization fails
	ErrInitFailed = errors.New("swtpm initialization failed")

	// ErrAlreadyRunning is returned when attempting to start swtpm that is already running
	ErrAlreadyRunning = errors.New("swtpm already running")

	// ErrNotRunning is returned when attempting to stop swtpm that is not running
	ErrNotRunning = errors.New("swtpm not running")

	// ErrInvalidConfig is returned when the configuration is invalid
	ErrInvalidConfig = errors.New("invalid swtpm configuration")

	// ErrTimeout is returned when an operation times out
	ErrTimeout = errors.New("operation timed out")

	// ErrStartupFailed is returned when TPM2_Startup command fails
	ErrStartupFailed = errors.New("TPM2_Startup failed")
)
