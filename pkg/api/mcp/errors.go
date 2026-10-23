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

package mcp

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}

// HTTPTLSRequiredError is returned by Start when the HTTP transport has no
// usable server certificate. The HTTP transport serves TLS 1.3 only and
// never falls back to plaintext.
type HTTPTLSRequiredError struct {
	Addr string
}

// Error implements the error interface.
func (e *HTTPTLSRequiredError) Error() string {
	return "mcp: HTTP transport on " + e.Addr + " requires a TLS server certificate; plaintext is not served"
}

// HTTPListenError is returned by Start when the HTTP transport cannot bind
// its listen address.
type HTTPListenError struct {
	Addr string
	Err  error
}

// Error implements the error interface.
func (e *HTTPListenError) Error() string {
	return "mcp: listen on " + e.Addr + ": " + e.Err.Error()
}

// Unwrap returns the bind failure.
func (e *HTTPListenError) Unwrap() error {
	return e.Err
}
