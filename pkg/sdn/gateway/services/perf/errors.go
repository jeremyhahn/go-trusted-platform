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

package perf

import (
	"errors"
	"fmt"
)

var (
	// ErrOVSRequired is returned by New when no OVS client is supplied.
	ErrOVSRequired = errors.New("perf: OVS client is required")

	// ErrAppCtlUnavailable is returned by Datapath and Conntrack when
	// the service was built without an ovs-appctl runner.
	ErrAppCtlUnavailable = errors.New("perf: ovs-appctl runner not available")

	// ErrNoBridgeAvailable is returned when no bridge exists to measure
	// against and none was configured.
	ErrNoBridgeAvailable = errors.New("perf: no OVS bridge available")
)

// ErrInvalidFlowCount is returned when a flow measurement count is out of
// range.
type ErrInvalidFlowCount struct {
	// Count is the rejected count.
	Count int

	// Max is the maximum allowed count.
	Max int
}

// Error implements the error interface.
func (e *ErrInvalidFlowCount) Error() string {
	return fmt.Sprintf("perf: flow count %d out of range (1-%d)", e.Count, e.Max)
}

// ErrBridgeUnavailable is returned when the measurement bridge cannot be
// resolved or validated.
type ErrBridgeUnavailable struct {
	// Bridge is the requested bridge name, empty during discovery.
	Bridge string

	// Cause is the underlying OVS error.
	Cause error
}

// Error implements the error interface.
func (e *ErrBridgeUnavailable) Error() string {
	if e.Bridge == "" {
		return "perf: bridge discovery failed: " + e.Cause.Error()
	}
	return "perf: bridge " + e.Bridge + " unavailable: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrBridgeUnavailable) Unwrap() error { return e.Cause }

// ErrFlowInstallFailed is returned when the measured flow install fails.
type ErrFlowInstallFailed struct {
	// Bridge is the measurement bridge.
	Bridge string

	// Cause is the underlying OVS/OpenFlow error.
	Cause error
}

// Error implements the error interface.
func (e *ErrFlowInstallFailed) Error() string {
	return "perf: flow install on " + e.Bridge + " failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrFlowInstallFailed) Unwrap() error { return e.Cause }

// ErrFlowTeardownFailed is returned when the cookie-scoped cleanup of
// ephemeral perf flows fails after a successful install.
type ErrFlowTeardownFailed struct {
	// Bridge is the measurement bridge.
	Bridge string

	// Cause is the underlying OVS/OpenFlow error.
	Cause error
}

// Error implements the error interface.
func (e *ErrFlowTeardownFailed) Error() string {
	return "perf: flow teardown on " + e.Bridge + " failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrFlowTeardownFailed) Unwrap() error { return e.Cause }
