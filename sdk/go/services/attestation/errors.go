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

package attestation

import "fmt"

// ErrGetManifestFailed is returned when manifest retrieval fails.
type ErrGetManifestFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetManifestFailed) Error() string {
	return fmt.Sprintf("failed to get manifest %s: %v", e.ID, e.Cause)
}

func (e *ErrGetManifestFailed) Unwrap() error {
	return e.Cause
}

// ErrBuildManifestFailed is returned when building a manifest fails.
type ErrBuildManifestFailed struct {
	Cause error
}

func (e *ErrBuildManifestFailed) Error() string {
	return fmt.Sprintf("failed to build manifest: %v", e.Cause)
}

func (e *ErrBuildManifestFailed) Unwrap() error {
	return e.Cause
}

// ErrVerifyManifestFailed is returned when manifest verification fails.
type ErrVerifyManifestFailed struct {
	Cause error
}

func (e *ErrVerifyManifestFailed) Error() string {
	return fmt.Sprintf("failed to verify manifest: %v", e.Cause)
}

func (e *ErrVerifyManifestFailed) Unwrap() error {
	return e.Cause
}

// ErrListManifestsFailed is returned when listing manifests fails.
type ErrListManifestsFailed struct {
	Cause error
}

func (e *ErrListManifestsFailed) Error() string {
	return fmt.Sprintf("failed to list manifests: %v", e.Cause)
}

func (e *ErrListManifestsFailed) Unwrap() error {
	return e.Cause
}

// ErrDeleteManifestFailed is returned when manifest deletion fails.
type ErrDeleteManifestFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteManifestFailed) Error() string {
	return fmt.Sprintf("failed to delete manifest %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteManifestFailed) Unwrap() error {
	return e.Cause
}

// ErrGetQuoteFailed is returned when getting attestation quote fails.
type ErrGetQuoteFailed struct {
	Cause error
}

func (e *ErrGetQuoteFailed) Error() string {
	return fmt.Sprintf("failed to get attestation quote: %v", e.Cause)
}

func (e *ErrGetQuoteFailed) Unwrap() error {
	return e.Cause
}

// ErrVerifyQuoteFailed is returned when verifying attestation quote fails.
type ErrVerifyQuoteFailed struct {
	Cause error
}

func (e *ErrVerifyQuoteFailed) Error() string {
	return fmt.Sprintf("failed to verify attestation quote: %v", e.Cause)
}

func (e *ErrVerifyQuoteFailed) Unwrap() error {
	return e.Cause
}

// ErrCollectHostAttestationFailed is returned when collecting host attestation fails.
type ErrCollectHostAttestationFailed struct {
	Cause error
}

func (e *ErrCollectHostAttestationFailed) Error() string {
	return fmt.Sprintf("failed to collect host attestation: %v", e.Cause)
}

func (e *ErrCollectHostAttestationFailed) Unwrap() error {
	return e.Cause
}

// ErrCollectVMAttestationFailed is returned when collecting VM attestation fails.
type ErrCollectVMAttestationFailed struct {
	VMID  string
	Cause error
}

func (e *ErrCollectVMAttestationFailed) Error() string {
	return fmt.Sprintf("failed to collect VM attestation for %s: %v", e.VMID, e.Cause)
}

func (e *ErrCollectVMAttestationFailed) Unwrap() error {
	return e.Cause
}

// ErrCollectContainerAttestationFailed is returned when collecting container attestation fails.
type ErrCollectContainerAttestationFailed struct {
	ContainerID string
	Cause       error
}

func (e *ErrCollectContainerAttestationFailed) Error() string {
	return fmt.Sprintf("failed to collect container attestation for %s: %v", e.ContainerID, e.Cause)
}

func (e *ErrCollectContainerAttestationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeviceIDRequired is returned when a device report operation is called
// without a device id, before any request is sent.
type ErrDeviceIDRequired struct{}

func (e *ErrDeviceIDRequired) Error() string {
	return "attestation: a device id is required"
}

// ErrNoDeviceReport is returned when the collector has never reached the
// device: no report exists. It is a distinct state, not a failed verdict.
type ErrNoDeviceReport struct {
	DeviceID string
	Cause    error
}

func (e *ErrNoDeviceReport) Error() string {
	return fmt.Sprintf("attestation: no report has been collected for device %s", e.DeviceID)
}

func (e *ErrNoDeviceReport) Unwrap() error {
	return e.Cause
}

// ErrListDeviceReportsFailed is returned when listing device reports fails.
type ErrListDeviceReportsFailed struct {
	Cause error
}

func (e *ErrListDeviceReportsFailed) Error() string {
	return fmt.Sprintf("failed to list device attestation reports: %v", e.Cause)
}

func (e *ErrListDeviceReportsFailed) Unwrap() error {
	return e.Cause
}

// ErrGetDeviceReportFailed is returned when reading a device report fails
// for any reason other than the device never having been collected.
type ErrGetDeviceReportFailed struct {
	DeviceID string
	Cause    error
}

func (e *ErrGetDeviceReportFailed) Error() string {
	return fmt.Sprintf("failed to get attestation report for device %s: %v", e.DeviceID, e.Cause)
}

func (e *ErrGetDeviceReportFailed) Unwrap() error {
	return e.Cause
}

// ErrRefreshDeviceReportFailed is returned when the refresh could not be
// enqueued with the collector.
type ErrRefreshDeviceReportFailed struct {
	DeviceID string
	Cause    error
}

func (e *ErrRefreshDeviceReportFailed) Error() string {
	return fmt.Sprintf("failed to enqueue attestation refresh for device %s: %v", e.DeviceID, e.Cause)
}

func (e *ErrRefreshDeviceReportFailed) Unwrap() error {
	return e.Cause
}

// ErrDescribeCallerPolicyFailed is returned when the caller policy could
// not be read.
type ErrDescribeCallerPolicyFailed struct {
	Cause error
}

func (e *ErrDescribeCallerPolicyFailed) Error() string {
	return fmt.Sprintf("failed to describe attestation caller policy: %v", e.Cause)
}

func (e *ErrDescribeCallerPolicyFailed) Unwrap() error {
	return e.Cause
}

// ErrStreamDeviceVerdictsFailed is returned when the device verdict stream
// could not be opened.
type ErrStreamDeviceVerdictsFailed struct {
	Cause error
}

func (e *ErrStreamDeviceVerdictsFailed) Error() string {
	return fmt.Sprintf("failed to stream device verdicts: %v", e.Cause)
}

func (e *ErrStreamDeviceVerdictsFailed) Unwrap() error {
	return e.Cause
}
