// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package attestation

import "fmt"

// ErrInvalidDeviceID reports a device id that is not a positive decimal
// integer. Device ids are the platform's numeric device ids rendered in
// decimal; the collector keys its reports by exactly that string.
type ErrInvalidDeviceID struct {
	ID string
}

func (e ErrInvalidDeviceID) Error() string {
	return fmt.Sprintf("invalid device id %q: a device id is a positive decimal integer", e.ID)
}

// ErrNeverCollected reports a device the collector has never reached. It is
// its own state: no report exists, so there is no verdict to show, failed or
// otherwise.
type ErrNeverCollected struct {
	DeviceID string
}

func (e ErrNeverCollected) Error() string {
	return fmt.Sprintf("device %s has never been collected: no attestation report exists yet. "+
		"This is not a negative verdict; check that the device has a dialable address "+
		"(a platform DNS record or an authenticated heartbeat) and that the node admits "+
		"this control plane (platformctl attestation callers)", e.DeviceID)
}

// ErrListReportsFailed reports a failed fleet read.
type ErrListReportsFailed struct {
	Reason string
}

func (e ErrListReportsFailed) Error() string {
	return "failed to list device attestation reports: " + e.Reason
}

// ErrGetReportFailed reports a failed single-device read other than never
// collected.
type ErrGetReportFailed struct {
	DeviceID string
	Reason   string
}

func (e ErrGetReportFailed) Error() string {
	return fmt.Sprintf("failed to get the attestation report for device %s: %s", e.DeviceID, e.Reason)
}

// ErrRefreshFailed reports a refresh the collector did not accept.
type ErrRefreshFailed struct {
	DeviceID string
	Reason   string
}

func (e ErrRefreshFailed) Error() string {
	return fmt.Sprintf("failed to enqueue an attestation refresh for device %s: %s", e.DeviceID, e.Reason)
}

// ErrDescribeCallersFailed reports a failed caller-policy read.
type ErrDescribeCallersFailed struct {
	Reason string
}

func (e ErrDescribeCallersFailed) Error() string {
	return "failed to describe the attestation caller policy: " + e.Reason
}

// ErrFollowVerdictsFailed reports a verdict follow that could not start or
// whose stream broke. A follow the operator stopped is not an error.
type ErrFollowVerdictsFailed struct {
	Reason string
}

func (e ErrFollowVerdictsFailed) Error() string {
	return "failed to follow device verdicts: " + e.Reason
}
