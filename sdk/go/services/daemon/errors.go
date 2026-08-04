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

package daemon

import (
	"errors"
	"fmt"
)

// Sentinel errors for common conditions.
var (
	// ErrSystemInfoNotAvailable indicates that system info is not available in the response.
	ErrSystemInfoNotAvailable = errors.New("system info not available")

	// ErrTPMInfoNotAvailable indicates that TPM info is not available in the response.
	ErrTPMInfoNotAvailable = errors.New("TPM info not available")

	// ErrNilConfigSection indicates that a nil config section was provided.
	ErrNilConfigSection = errors.New("config section cannot be nil")

	// ErrNilRequest indicates that a nil request was provided.
	ErrNilRequest = errors.New("request cannot be nil")
)

// ErrGetStatusFailed is returned when getting daemon status fails.
type ErrGetStatusFailed struct {
	Cause error
}

func (e *ErrGetStatusFailed) Error() string {
	return fmt.Sprintf("failed to get daemon status: %v", e.Cause)
}

func (e *ErrGetStatusFailed) Unwrap() error {
	return e.Cause
}

// ErrGetHealthFailed is returned when getting daemon health fails.
type ErrGetHealthFailed struct {
	Cause error
}

func (e *ErrGetHealthFailed) Error() string {
	return fmt.Sprintf("failed to get daemon health: %v", e.Cause)
}

func (e *ErrGetHealthFailed) Unwrap() error {
	return e.Cause
}

// ErrShutdownFailed is returned when shutdown fails.
type ErrShutdownFailed struct {
	Cause error
}

func (e *ErrShutdownFailed) Error() string {
	return fmt.Sprintf("failed to shutdown daemon: %v", e.Cause)
}

func (e *ErrShutdownFailed) Unwrap() error {
	return e.Cause
}

// ErrRestartFailed is returned when platform restart fails.
type ErrRestartFailed struct {
	Cause error
}

func (e *ErrRestartFailed) Error() string {
	return fmt.Sprintf("failed to restart platform: %v", e.Cause)
}

func (e *ErrRestartFailed) Unwrap() error {
	return e.Cause
}

// ErrGetVersionFailed is returned when getting version fails.
type ErrGetVersionFailed struct {
	Cause error
}

func (e *ErrGetVersionFailed) Error() string {
	return fmt.Sprintf("failed to get daemon version: %v", e.Cause)
}

func (e *ErrGetVersionFailed) Unwrap() error {
	return e.Cause
}

// ErrGetSystemInfoFailed is returned when getting system info fails.
type ErrGetSystemInfoFailed struct {
	Cause error
}

func (e *ErrGetSystemInfoFailed) Error() string {
	return fmt.Sprintf("failed to get system info: %v", e.Cause)
}

func (e *ErrGetSystemInfoFailed) Unwrap() error {
	return e.Cause
}

// ErrGetTPMInfoFailed is returned when getting TPM info fails.
type ErrGetTPMInfoFailed struct {
	Cause error
}

func (e *ErrGetTPMInfoFailed) Error() string {
	return fmt.Sprintf("failed to get TPM info: %v", e.Cause)
}

func (e *ErrGetTPMInfoFailed) Unwrap() error {
	return e.Cause
}

// ErrGetConfigFailed is returned when getting configuration fails.
type ErrGetConfigFailed struct {
	Cause error
}

func (e *ErrGetConfigFailed) Error() string {
	return fmt.Sprintf("failed to get configuration: %v", e.Cause)
}

func (e *ErrGetConfigFailed) Unwrap() error {
	return e.Cause
}

// ErrUpdateConfigFailed is returned when updating configuration fails.
type ErrUpdateConfigFailed struct {
	Section string
	Cause   error
}

func (e *ErrUpdateConfigFailed) Error() string {
	if e.Section != "" {
		return fmt.Sprintf("failed to update configuration section %s: %v", e.Section, e.Cause)
	}
	return fmt.Sprintf("failed to update configuration: %v", e.Cause)
}

func (e *ErrUpdateConfigFailed) Unwrap() error {
	return e.Cause
}

// ErrReloadConfigFailed is returned when reloading configuration fails.
type ErrReloadConfigFailed struct {
	Cause error
}

func (e *ErrReloadConfigFailed) Error() string {
	return fmt.Sprintf("failed to reload configuration: %v", e.Cause)
}

func (e *ErrReloadConfigFailed) Unwrap() error {
	return e.Cause
}

// ErrStartServiceFailed is returned when starting a service fails.
type ErrStartServiceFailed struct {
	Service string
	Cause   error
}

func (e *ErrStartServiceFailed) Error() string {
	return fmt.Sprintf("failed to start service %s: %v", e.Service, e.Cause)
}

func (e *ErrStartServiceFailed) Unwrap() error {
	return e.Cause
}

// ErrStopServiceFailed is returned when stopping a service fails.
type ErrStopServiceFailed struct {
	Service string
	Cause   error
}

func (e *ErrStopServiceFailed) Error() string {
	return fmt.Sprintf("failed to stop service %s: %v", e.Service, e.Cause)
}

func (e *ErrStopServiceFailed) Unwrap() error {
	return e.Cause
}

// ErrRestartServiceFailed is returned when restarting a service fails.
type ErrRestartServiceFailed struct {
	Service string
	Cause   error
}

func (e *ErrRestartServiceFailed) Error() string {
	return fmt.Sprintf("failed to restart service %s: %v", e.Service, e.Cause)
}

func (e *ErrRestartServiceFailed) Unwrap() error {
	return e.Cause
}

// ErrGetServiceStatusFailed is returned when getting service status fails.
type ErrGetServiceStatusFailed struct {
	Service string
	Cause   error
}

func (e *ErrGetServiceStatusFailed) Error() string {
	return fmt.Sprintf("failed to get status for service %s: %v", e.Service, e.Cause)
}

func (e *ErrGetServiceStatusFailed) Unwrap() error {
	return e.Cause
}

// ErrListServicesFailed is returned when listing services fails.
type ErrListServicesFailed struct {
	Cause error
}

func (e *ErrListServicesFailed) Error() string {
	return fmt.Sprintf("failed to list services: %v", e.Cause)
}

func (e *ErrListServicesFailed) Unwrap() error {
	return e.Cause
}

// ErrListEntityTypesFailed is returned when listing entity types fails.
type ErrListEntityTypesFailed struct {
	Cause error
}

func (e *ErrListEntityTypesFailed) Error() string {
	return fmt.Sprintf("failed to list entity types: %v", e.Cause)
}

func (e *ErrListEntityTypesFailed) Unwrap() error {
	return e.Cause
}

// ErrDumpEntityTypeFailed is returned when dumping entity type fails.
type ErrDumpEntityTypeFailed struct {
	EntityType string
	Cause      error
}

func (e *ErrDumpEntityTypeFailed) Error() string {
	if e.EntityType != "" {
		return fmt.Sprintf("failed to dump entity type %s: %v", e.EntityType, e.Cause)
	}
	return fmt.Sprintf("failed to dump entity types: %v", e.Cause)
}

func (e *ErrDumpEntityTypeFailed) Unwrap() error {
	return e.Cause
}

// ErrStreamEventsFailed is returned when opening event stream fails.
type ErrStreamEventsFailed struct {
	Cause error
}

func (e *ErrStreamEventsFailed) Error() string {
	return fmt.Sprintf("failed to open event stream: %v", e.Cause)
}

func (e *ErrStreamEventsFailed) Unwrap() error {
	return e.Cause
}

// ErrStreamLogsFailed is returned when opening log stream fails.
type ErrStreamLogsFailed struct {
	Cause error
}

func (e *ErrStreamLogsFailed) Error() string {
	return fmt.Sprintf("failed to open log stream: %v", e.Cause)
}

func (e *ErrStreamLogsFailed) Unwrap() error {
	return e.Cause
}

// ErrStreamMetricsFailed is returned when opening metrics stream fails.
type ErrStreamMetricsFailed struct {
	Cause error
}

func (e *ErrStreamMetricsFailed) Error() string {
	return fmt.Sprintf("failed to open metrics stream: %v", e.Cause)
}

func (e *ErrStreamMetricsFailed) Unwrap() error {
	return e.Cause
}

// ErrStreamRecvFailed is returned when receiving from a stream fails.
type ErrStreamRecvFailed struct {
	StreamType string
	Cause      error
}

func (e *ErrStreamRecvFailed) Error() string {
	return fmt.Sprintf("failed to receive from %s stream: %v", e.StreamType, e.Cause)
}

func (e *ErrStreamRecvFailed) Unwrap() error {
	return e.Cause
}
