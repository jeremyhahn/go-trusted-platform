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

package app

import "fmt"

// ErrBMCRestoreNoCertRestorer is returned when RestoreBMC is called but no
// cert restorer is available (BMC certificate config is missing).
type ErrBMCRestoreNoCertRestorer struct {
	DeviceID uint64
}

// Error implements error.
func (e ErrBMCRestoreNoCertRestorer) Error() string {
	return fmt.Sprintf("app: BMC restore (device %d): no cert restorer available; BMC certificate config is required", e.DeviceID)
}

// ErrBMCRestoreCert is returned when the factory-certificate restore step fails.
type ErrBMCRestoreCert struct {
	DeviceID uint64
	Cause    error
}

// Error implements error.
func (e ErrBMCRestoreCert) Error() string {
	return fmt.Sprintf("app: BMC restore (device %d): cert restore failed: %v", e.DeviceID, e.Cause)
}

// Unwrap returns the underlying error.
func (e ErrBMCRestoreCert) Unwrap() error { return e.Cause }
