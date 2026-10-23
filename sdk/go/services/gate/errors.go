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

package gate

import "strconv"

// ErrInvalidEndpoint indicates the endpoint is neither a unix:// socket path
// nor a loopback host:port.
type ErrInvalidEndpoint struct {
	Endpoint string
	Reason   string
}

// Error implements the error interface.
func (e *ErrInvalidEndpoint) Error() string {
	return "gate: invalid endpoint " + strconv.Quote(e.Endpoint) + ": " + e.Reason
}

// ErrInitFailed indicates POST /init could not be sent or its reply could
// not be read.
type ErrInitFailed struct {
	Cause error
}

// Error implements the error interface.
func (e *ErrInitFailed) Error() string {
	return "gate: init failed: " + e.Cause.Error()
}

// Unwrap returns the underlying cause.
func (e *ErrInitFailed) Unwrap() error { return e.Cause }

// ErrInitRejected indicates the daemon answered POST /init with a non-200
// status. 409 means the platform is already initialized by a different
// request; 503 means the daemon has no init backend.
type ErrInitRejected struct {
	StatusCode int
	Message    string
}

// Error implements the error interface.
func (e *ErrInitRejected) Error() string {
	msg := "gate: init rejected with HTTP " + strconv.Itoa(e.StatusCode)
	if e.Message != "" {
		msg += ": " + e.Message
	}
	return msg
}
