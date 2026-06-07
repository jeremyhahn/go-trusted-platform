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

//go:build integration

package barrier_gate

import "fmt"

// ErrPlatformdLaunch indicates the harness could not start a fresh
// platformd process. The Phase string identifies where in the lifecycle
// the failure happened (mkdir, exec, log open, etc).
type ErrPlatformdLaunch struct {
	Phase string
	Cause error
}

// Error returns a human-readable description.
func (e *ErrPlatformdLaunch) Error() string {
	return fmt.Sprintf("barrier_gate: platformd launch failed during %s: %v", e.Phase, e.Cause)
}

// Unwrap returns the underlying cause for errors.Is / errors.As.
func (e *ErrPlatformdLaunch) Unwrap() error { return e.Cause }

// ErrGateWaitTimeout indicates the gate /healthz endpoint did not
// converge on the expected condition within the configured deadline.
type ErrGateWaitTimeout struct {
	Want  string
	Last  string
	Cause error
}

// Error returns a human-readable description.
func (e *ErrGateWaitTimeout) Error() string {
	return fmt.Sprintf("barrier_gate: gate /healthz never reached %q (last=%q): %v",
		e.Want, e.Last, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrGateWaitTimeout) Unwrap() error { return e.Cause }

// ErrGateStillBound indicates the gate listener is still accepting
// connections after the deadline expired. The gate must shut down once
// the barrier transitions to unsealed so the production listeners can
// bind the same well-known endpoints.
type ErrGateStillBound struct {
	Endpoint string
	Cause    error
}

// Error returns a human-readable description.
func (e *ErrGateStillBound) Error() string {
	return fmt.Sprintf("barrier_gate: gate endpoint %s still accepting after handoff: %v",
		e.Endpoint, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrGateStillBound) Unwrap() error { return e.Cause }

// ErrProductionPortNotBound indicates a production transport endpoint
// did not come up within the deadline after the gate released. The M6
// handoff contract requires production transports to bind once the
// barrier unseals.
type ErrProductionPortNotBound struct {
	Protocol string
	Endpoint string
	Cause    error
}

// Error returns a human-readable description.
func (e *ErrProductionPortNotBound) Error() string {
	return fmt.Sprintf("barrier_gate: production %s endpoint %s never bound after gate release: %v",
		e.Protocol, e.Endpoint, e.Cause)
}

// Unwrap returns the underlying cause.
func (e *ErrProductionPortNotBound) Unwrap() error { return e.Cause }

// ErrTransportShouldRefuse indicates a remote transport accepted a
// connection while the daemon was still in init-only (gated) mode.
type ErrTransportShouldRefuse struct {
	Protocol string
	Endpoint string
}

// Error returns a human-readable description.
func (e *ErrTransportShouldRefuse) Error() string {
	return fmt.Sprintf("barrier_gate: %s endpoint %s should refuse connections in init-only mode",
		e.Protocol, e.Endpoint)
}

// ErrGateRequestFailed indicates a POST /init or POST /unseal request
// could not be issued, or the response status was not 200 OK.
type ErrGateRequestFailed struct {
	Op     string
	Status int
	Body   string
	Cause  error
}

// Error returns a human-readable description.
func (e *ErrGateRequestFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("barrier_gate: %s request failed: %v", e.Op, e.Cause)
	}
	return fmt.Sprintf("barrier_gate: %s returned status=%d body=%q", e.Op, e.Status, e.Body)
}

// Unwrap returns the underlying cause for errors.Is / errors.As.
func (e *ErrGateRequestFailed) Unwrap() error { return e.Cause }

// ErrUnexpectedGateState indicates the gate /healthz endpoint reported
// a state that does not match the test's pre-conditions.
type ErrUnexpectedGateState struct {
	Want string
	Got  string
}

// Error returns a human-readable description.
func (e *ErrUnexpectedGateState) Error() string {
	return fmt.Sprintf("barrier_gate: gate state=%q, want %q", e.Got, e.Want)
}

// ErrInitResponseInvalid indicates the /init response did not contain
// the expected fields (e.g. missing ceremony_id).
type ErrInitResponseInvalid struct {
	Reason string
}

// Error returns a human-readable description.
func (e *ErrInitResponseInvalid) Error() string {
	return "barrier_gate: /init response invalid: " + e.Reason
}


// ErrUDPPortNotBound indicates a UDP probe to the supplied address
// successfully claimed the port — meaning the production listener was
// NOT holding it. Used by AssertProductionTransportsAccept's QUIC check.
type ErrUDPPortNotBound struct {
	Endpoint string
}

// Error returns a human-readable description.
func (e *ErrUDPPortNotBound) Error() string {
	return "barrier_gate: UDP endpoint " + e.Endpoint + " not bound (no production listener holds it)"
}
