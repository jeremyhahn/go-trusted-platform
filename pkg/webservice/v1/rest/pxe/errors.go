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

package pxe

// ErrUnknownDeviceState is returned when a gateway reports a state that is
// not a provisioning state.
type ErrUnknownDeviceState struct {
	State string
}

func (e *ErrUnknownDeviceState) Error() string {
	return "unknown provisioning state: " + e.State
}

// ErrInvalidInstallStatus is returned when an install-complete report
// carries a status other than "success" or "failure".
type ErrInvalidInstallStatus struct {
	Status string
}

func (e *ErrInvalidInstallStatus) Error() string {
	return "install status must be success or failure, got: " + e.Status
}
