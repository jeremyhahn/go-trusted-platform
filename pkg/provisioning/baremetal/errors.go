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

package baremetal

import (
	"fmt"
	"time"
)

// ErrProvisionNotFound indicates the requested provision ID does not exist.
type ErrProvisionNotFound struct {
	ProvisionID string
}

// Error returns the error message.
func (e ErrProvisionNotFound) Error() string {
	return fmt.Sprintf("baremetal: provision not found: %s", e.ProvisionID)
}

// ErrProfileNoBMC indicates the profile does not have BMC configuration.
type ErrProfileNoBMC struct {
	ProfileID uint64
}

// Error returns the error message.
func (e ErrProfileNoBMC) Error() string {
	return fmt.Sprintf("baremetal: profile %d has no BMC configuration", e.ProfileID)
}

// ErrProvisionInProgress indicates a provision is already running for the profile.
type ErrProvisionInProgress struct {
	ProfileID uint64
}

// Error returns the error message.
func (e ErrProvisionInProgress) Error() string {
	return fmt.Sprintf("baremetal: provision already in progress for profile %d", e.ProfileID)
}

// ErrProvisionFailed indicates a provisioning step failed.
type ErrProvisionFailed struct {
	ProfileID uint64
	Step      string
	Cause     error
}

// Error returns the error message.
func (e ErrProvisionFailed) Error() string {
	msg := fmt.Sprintf("baremetal: provision failed for profile %d at step %q", e.ProfileID, e.Step)
	if e.Cause != nil {
		msg = fmt.Sprintf("%s: %v", msg, e.Cause)
	}
	return msg
}

// Unwrap returns the underlying cause.
func (e ErrProvisionFailed) Unwrap() error {
	return e.Cause
}

// ErrInstallTimeout indicates the OS installation exceeded the allowed duration.
type ErrInstallTimeout struct {
	ProfileID uint64
	Timeout   time.Duration
}

// Error returns the error message.
func (e ErrInstallTimeout) Error() string {
	return fmt.Sprintf("baremetal: install timeout for profile %d after %s", e.ProfileID, e.Timeout)
}

// ErrInvalidProvisionRequest indicates the provision request is invalid.
type ErrInvalidProvisionRequest struct {
	Reason string
}

// Error returns the error message.
func (e ErrInvalidProvisionRequest) Error() string {
	return fmt.Sprintf("baremetal: invalid provision request: %s", e.Reason)
}
