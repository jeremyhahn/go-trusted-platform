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

package commands

// ErrServeStartup reports that `platformd serve` could not complete startup.
//
// One type with a Phase rather than seventeen types, because the thing a caller
// needs to distinguish is WHICH phase failed, and a service manager needs only
// that startup failed at all. Phase is the operator-facing name of the step;
// Cause is the underlying error and is reachable through errors.As/errors.Is.
//
// The exit code does NOT vary by phase, and that is deliberate. The distinction
// with a real consumer is retryable versus permanent, and it is not knowable at
// these call sites: a daemon that fails to start may be hitting a port conflict
// (a retry helps) or a bad configuration (a retry never will), and the function
// cannot tell which. A code scheme that cannot be populated accurately is worse
// than none, so every startup failure exits 1 — the code cmd/platformd/main.go
// already produces for every other failure — and the phases carry the detail.
type ErrServeStartup struct {
	// Phase names the startup step that failed, in operator terms.
	Phase string

	// Cause is the underlying error, or nil where the failure is a capability
	// check with no error value of its own.
	Cause error
}

// Error implements the error interface.
func (e ErrServeStartup) Error() string {
	if e.Cause != nil {
		return "platformd serve: " + e.Phase + ": " + e.Cause.Error()
	}
	return "platformd serve: " + e.Phase
}

// Unwrap exposes the underlying cause to errors.Is and errors.As.
func (e ErrServeStartup) Unwrap() error { return e.Cause }
