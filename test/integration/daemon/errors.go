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

package daemon

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
		return fmt.Sprintf("CLI command %q failed: %v (output: %s)", e.Command, e.Err, e.Output)
	}
	return fmt.Sprintf("CLI command %q failed: %v", e.Command, e.Err)
}

func (e ErrCLICommandFailed) Unwrap() error {
	return e.Err
}

// ErrCLIOutputParseFailed is returned when CLI output cannot be parsed.
type ErrCLIOutputParseFailed struct {
	Operation string
	Output    string
	Err       error
}

func (e ErrCLIOutputParseFailed) Error() string {
	return fmt.Sprintf("failed to parse CLI output for %s: %v (output: %s)", e.Operation, e.Err, e.Output)
}

func (e ErrCLIOutputParseFailed) Unwrap() error {
	return e.Err
}

// ErrCLIBinaryNotFound is returned when the platformctl binary cannot be found.
type ErrCLIBinaryNotFound struct {
	Path string
}

func (e ErrCLIBinaryNotFound) Error() string {
	return fmt.Sprintf("platformctl binary not found at path: %s", e.Path)
}

// ErrCLIConfigCreationFailed is returned when the temporary CLI config file
// cannot be created during test setup.
type ErrCLIConfigCreationFailed struct {
	Cause error
}

func (e ErrCLIConfigCreationFailed) Error() string {
	return fmt.Sprintf("failed to create CLI test config: %v", e.Cause)
}

func (e ErrCLIConfigCreationFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// REST Adapter Errors
// =============================================================================

// ErrRESTConnectionFailed indicates the REST API connection failed.
type ErrRESTConnectionFailed struct {
	URL string
	Err error
}

func (e ErrRESTConnectionFailed) Error() string {
	return fmt.Sprintf("REST API connection failed to %s: %v", e.URL, e.Err)
}

func (e ErrRESTConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrRESTRequestFailed indicates the HTTP request failed.
type ErrRESTRequestFailed struct {
	Err error
}

func (e ErrRESTRequestFailed) Error() string {
	return fmt.Sprintf("HTTP request failed: %v", e.Err)
}

func (e ErrRESTRequestFailed) Unwrap() error {
	return e.Err
}

// ErrRESTAPIError indicates an error response from the REST API.
type ErrRESTAPIError struct {
	StatusCode int
	Message    string
}

func (e ErrRESTAPIError) Error() string {
	return fmt.Sprintf("REST API error (status %d): %s", e.StatusCode, e.Message)
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
	return fmt.Sprintf("gRPC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCCallFailed indicates a gRPC method call failure.
type ErrGRPCCallFailed struct {
	Method string
	Err    error
}

func (e ErrGRPCCallFailed) Error() string {
	return fmt.Sprintf("gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// QUIC Adapter Errors
// =============================================================================

// ErrQUICConnectionFailed indicates a QUIC connection failure.
type ErrQUICConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrQUICConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrQUICRequestFailed indicates a QUIC request failure.
type ErrQUICRequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICRequestFailed) Error() string {
	return fmt.Sprintf("QUIC request %s failed (status 0x%02X): %s", e.Operation, e.Status, e.Message)
}

// ErrQUICEncodeFailed indicates payload encoding failure.
type ErrQUICEncodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICEncodeFailed) Error() string {
	return fmt.Sprintf("QUIC encode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICEncodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICDecodeFailed indicates payload decoding failure.
type ErrQUICDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICDecodeFailed) Error() string {
	return fmt.Sprintf("QUIC decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICDecodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICStreamFailed indicates a stream operation failure.
type ErrQUICStreamFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICStreamFailed) Error() string {
	return fmt.Sprintf("QUIC stream operation %s failed: %v", e.Operation, e.Err)
}

func (e ErrQUICStreamFailed) Unwrap() error {
	return e.Err
}

// ErrQUICClientClosed indicates the client is closed.
type ErrQUICClientClosed struct{}

func (e ErrQUICClientClosed) Error() string {
	return "QUIC client is closed"
}

// =============================================================================
// MCP Adapter Errors
// =============================================================================

// ErrMCPConnectionFailed indicates the MCP connection failed.
type ErrMCPConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrMCPConnectionFailed) Error() string {
	return fmt.Sprintf("MCP connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrMCPConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrMCPInitializeFailed indicates MCP initialization failed.
type ErrMCPInitializeFailed struct {
	Err error
}

func (e ErrMCPInitializeFailed) Error() string {
	return fmt.Sprintf("MCP initialization failed: %v", e.Err)
}

func (e ErrMCPInitializeFailed) Unwrap() error {
	return e.Err
}

// ErrMCPToolCallFailed indicates an MCP tool call failed.
type ErrMCPToolCallFailed struct {
	Tool    string
	Code    int
	Message string
}

func (e ErrMCPToolCallFailed) Error() string {
	return fmt.Sprintf("MCP tool %q call failed (code %d): %s", e.Tool, e.Code, e.Message)
}

// ErrMCPResponseParseFailed indicates MCP response parsing failed.
type ErrMCPResponseParseFailed struct {
	Operation string
	Err       error
}

func (e ErrMCPResponseParseFailed) Error() string {
	return fmt.Sprintf("failed to parse MCP response for %s: %v", e.Operation, e.Err)
}

func (e ErrMCPResponseParseFailed) Unwrap() error {
	return e.Err
}

// ErrMCPRequestFailed indicates an MCP HTTP request failed.
type ErrMCPRequestFailed struct {
	Err error
}

func (e ErrMCPRequestFailed) Error() string {
	return fmt.Sprintf("MCP request failed: %v", e.Err)
}

func (e ErrMCPRequestFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Unix Socket Adapter Errors
// =============================================================================

// ErrUnixConnectionFailed indicates the Unix socket connection failed.
type ErrUnixConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixConnectionFailed) Error() string {
	return fmt.Sprintf("Unix connection failed to %s: %v", e.Path, e.Err)
}

func (e ErrUnixConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixBackendUnavailable indicates the backend is not responding.
type ErrUnixBackendUnavailable struct {
	Err error
}

func (e ErrUnixBackendUnavailable) Error() string {
	return fmt.Sprintf("Unix backend unavailable: %v", e.Err)
}

func (e ErrUnixBackendUnavailable) Unwrap() error {
	return e.Err
}

// ErrUnixRPCFailed indicates a gRPC call over Unix socket failed.
type ErrUnixRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixRPCFailed) Error() string {
	return fmt.Sprintf("Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixRPCFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Service Errors
// =============================================================================

// ErrServiceNotFound indicates the service was not found.
type ErrServiceNotFound struct {
	ServiceName string
}

func (e ErrServiceNotFound) Error() string {
	return fmt.Sprintf("service not found: %s", e.ServiceName)
}

// ErrServiceActionFailed indicates a service action failed.
type ErrServiceActionFailed struct {
	ServiceName string
	Action      string
	Reason      string
}

func (e ErrServiceActionFailed) Error() string {
	return fmt.Sprintf("service %s action %s failed: %s", e.ServiceName, e.Action, e.Reason)
}
