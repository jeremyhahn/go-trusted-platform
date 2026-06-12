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

package bmc_integration

import "fmt"

// =============================================================================
// CLI Adapter Errors
// =============================================================================

// ErrCLICommandFailed is returned when a CLI command fails to execute.
type ErrCLICommandFailed struct {
	Command string
	Output  string
	Err     error
}

func (e ErrCLICommandFailed) Error() string {
	if e.Output != "" {
		return fmt.Sprintf("bmc: CLI command %q failed: %v (output: %s)", e.Command, e.Err, e.Output)
	}
	return fmt.Sprintf("bmc: CLI command %q failed: %v", e.Command, e.Err)
}

func (e ErrCLICommandFailed) Unwrap() error { return e.Err }

// ErrCLIOutputParseFailed is returned when CLI output cannot be parsed.
type ErrCLIOutputParseFailed struct {
	Operation string
	Output    string
	Err       error
}

func (e ErrCLIOutputParseFailed) Error() string {
	return fmt.Sprintf("bmc: failed to parse CLI output for %s: %v (output: %s)", e.Operation, e.Err, e.Output)
}

func (e ErrCLIOutputParseFailed) Unwrap() error { return e.Err }

// ErrCLIBinaryNotFound is returned when the platformctl binary cannot be found.
type ErrCLIBinaryNotFound struct {
	Path string
}

func (e ErrCLIBinaryNotFound) Error() string {
	return fmt.Sprintf("bmc: platformctl binary not found at path: %s", e.Path)
}

// ErrCLIConfigCreationFailed is returned when a temporary CLI config file
// cannot be created during test setup.
type ErrCLIConfigCreationFailed struct {
	Cause error
}

func (e ErrCLIConfigCreationFailed) Error() string {
	return fmt.Sprintf("bmc: failed to create CLI test config: %v", e.Cause)
}

func (e ErrCLIConfigCreationFailed) Unwrap() error { return e.Cause }

// =============================================================================
// REST Adapter Errors
// =============================================================================

// ErrRESTConnectionFailed indicates the REST API connection failed.
type ErrRESTConnectionFailed struct {
	URL string
	Err error
}

func (e ErrRESTConnectionFailed) Error() string {
	return fmt.Sprintf("bmc: REST API connection failed to %s: %v", e.URL, e.Err)
}

func (e ErrRESTConnectionFailed) Unwrap() error { return e.Err }

// ErrRESTRequestFailed indicates the HTTP request failed.
type ErrRESTRequestFailed struct {
	Err error
}

func (e ErrRESTRequestFailed) Error() string {
	return fmt.Sprintf("bmc: HTTP request failed: %v", e.Err)
}

func (e ErrRESTRequestFailed) Unwrap() error { return e.Err }

// ErrRESTAPIError indicates an error response from the REST API.
type ErrRESTAPIError struct {
	StatusCode int
	Message    string
}

func (e ErrRESTAPIError) Error() string {
	return fmt.Sprintf("bmc: REST API error (status %d): %s", e.StatusCode, e.Message)
}

// =============================================================================
// gRPC Adapter Errors
// =============================================================================

// ErrGRPCConnectionFailed indicates a gRPC connection failure.
type ErrGRPCConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCConnectionFailed) Error() string {
	return fmt.Sprintf("bmc: gRPC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnectionFailed) Unwrap() error { return e.Err }

// ErrGRPCCallFailed indicates a gRPC method call failure.
type ErrGRPCCallFailed struct {
	Method string
	Err    error
}

func (e ErrGRPCCallFailed) Error() string {
	return fmt.Sprintf("bmc: gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error { return e.Err }

// =============================================================================
// QUIC Adapter Errors
// =============================================================================

// ErrQUICNotImplemented indicates the QUIC adapter is not yet wired for BMC.
type ErrQUICNotImplemented struct{}

func (e ErrQUICNotImplemented) Error() string {
	return "bmc: QUIC protocol adapter not implemented for BMC service"
}

// ErrQUICConnectionFailed indicates a QUIC connection failure.
type ErrQUICConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICConnectionFailed) Error() string {
	return fmt.Sprintf("bmc: QUIC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrQUICConnectionFailed) Unwrap() error { return e.Err }

// ErrQUICCallFailed indicates a QUIC sub-operation failure.
type ErrQUICCallFailed struct {
	Method string
	Err    error
}

func (e ErrQUICCallFailed) Error() string {
	return fmt.Sprintf("bmc: QUIC call %s failed: %v", e.Method, e.Err)
}

func (e ErrQUICCallFailed) Unwrap() error { return e.Err }

// =============================================================================
// MCP Adapter Errors
// =============================================================================

// ErrMCPNotImplemented indicates the MCP adapter is not yet wired for BMC.
type ErrMCPNotImplemented struct{}

func (e ErrMCPNotImplemented) Error() string {
	return "bmc: MCP protocol adapter not implemented for BMC service"
}

// ErrMCPConnectionFailed indicates the MCP connection failed.
type ErrMCPConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPConnectionFailed) Error() string {
	return fmt.Sprintf("bmc: MCP connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrMCPConnectionFailed) Unwrap() error { return e.Err }

// ErrMCPCallFailed indicates an MCP tool call failure.
type ErrMCPCallFailed struct {
	Tool string
	Err  error
}

func (e ErrMCPCallFailed) Error() string {
	return fmt.Sprintf("bmc: MCP tool %s failed: %v", e.Tool, e.Err)
}

func (e ErrMCPCallFailed) Unwrap() error { return e.Err }

// =============================================================================
// Unix Socket Adapter Errors
// =============================================================================

// ErrUnixConnectionFailed indicates the Unix socket connection failed.
type ErrUnixConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixConnectionFailed) Error() string {
	return fmt.Sprintf("bmc: Unix connection failed to %s: %v", e.Path, e.Err)
}

func (e ErrUnixConnectionFailed) Unwrap() error { return e.Err }

// ErrUnixBackendUnavailable indicates the backend is not responding.
type ErrUnixBackendUnavailable struct {
	Err error
}

func (e ErrUnixBackendUnavailable) Error() string {
	return fmt.Sprintf("bmc: Unix backend unavailable: %v", e.Err)
}

func (e ErrUnixBackendUnavailable) Unwrap() error { return e.Err }

// ErrUnixRPCFailed indicates a gRPC call over Unix socket failed.
type ErrUnixRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixRPCFailed) Error() string {
	return fmt.Sprintf("bmc: Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixRPCFailed) Unwrap() error { return e.Err }

// =============================================================================
// Enrollment Errors
// =============================================================================

// ErrEnrollServiceUnavailable indicates the enrollment ceremony service is not
// wired or not available on the current transport. Tests treat this as a
// tolerated outcome that reflects a legitimate deployment-config gap rather
// than a transport-level failure.
type ErrEnrollServiceUnavailable struct {
	Protocol string
	Reason   string
}

func (e ErrEnrollServiceUnavailable) Error() string {
	return fmt.Sprintf("bmc: enroll service unavailable on %s: %s", e.Protocol, e.Reason)
}

// =============================================================================
// Restore Errors
// =============================================================================

// ErrRestoreServiceUnavailable indicates the factory-certificate restore service
// is not wired or not available on the current transport. Tests treat this as a
// tolerated outcome that reflects a legitimate deployment-config gap rather than
// a transport-level failure.
type ErrRestoreServiceUnavailable struct {
	Protocol string
	Reason   string
}

func (e ErrRestoreServiceUnavailable) Error() string {
	return fmt.Sprintf("bmc: restore service unavailable on %s: %s", e.Protocol, e.Reason)
}
