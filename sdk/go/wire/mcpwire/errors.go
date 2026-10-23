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

package mcpwire

import (
	"net/http"
	"strconv"
	"time"

	"google.golang.org/grpc/codes"
)

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}

// HTTPStatusError is a non-2xx HTTP answer to an MCP request. The MCP server
// answers every JSON-RPC request with 200, so a status error comes from the
// HTTP layer: a proxy refusing the caller, a rate limit, or a server that is
// not ready.
type HTTPStatusError struct {
	StatusCode int

	// RetryAfter is the wait the answer's Retry-After header asked for;
	// HasRetryAfter is false when the header was absent or unreadable.
	RetryAfter    time.Duration
	HasRetryAfter bool
}

// Error names the status code and its text.
func (e *HTTPStatusError) Error() string {
	return "MCP server answered HTTP " + strconv.Itoa(e.StatusCode) + " " + http.StatusText(e.StatusCode)
}

// Class returns the platform error class the status code stands for, the
// same class the REST transport decodes it to, and codes.Unknown for a code
// the table does not name.
func (e *HTTPStatusError) Class() codes.Code {
	if class, ok := classForHTTPStatus[e.StatusCode]; ok {
		return class
	}
	return codes.Unknown
}
