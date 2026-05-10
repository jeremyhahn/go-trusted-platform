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

package smc

import "fmt"

// ErrLoginFailed indicates /cgi/login.cgi did not return a session cookie.
type ErrLoginFailed struct {
	StatusCode int
	Message    string
}

func (e ErrLoginFailed) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("smc: CGI login failed: status=%d: %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("smc: CGI login failed: status=%d", e.StatusCode)
}

// ErrNoSessionCookie indicates the login response did not contain the
// expected SID cookie.
type ErrNoSessionCookie struct{}

func (ErrNoSessionCookie) Error() string {
	return "smc: CGI login succeeded but no SID cookie was returned"
}

// ErrUploadFailed indicates the SSL upload CGI returned an error response.
type ErrUploadFailed struct {
	StatusCode int
	Body       string
}

func (e ErrUploadFailed) Error() string {
	return fmt.Sprintf("smc: CGI SSL upload failed: status=%d: %s", e.StatusCode, truncate(e.Body, 200))
}

// ErrValidateFailed indicates the SSL validation CGI rejected the new cert.
type ErrValidateFailed struct {
	StatusCode int
	Body       string
}

func (e ErrValidateFailed) Error() string {
	return fmt.Sprintf("smc: CGI SSL validate failed: status=%d: %s", e.StatusCode, truncate(e.Body, 200))
}

// ErrResetFailed indicates the BMC reset CGI returned an error.
type ErrResetFailed struct {
	StatusCode int
}

func (e ErrResetFailed) Error() string {
	return fmt.Sprintf("smc: CGI BMC reset failed: status=%d", e.StatusCode)
}

// ErrInvalidInput indicates a caller-supplied argument failed validation
// before any HTTP request was made.
type ErrInvalidInput struct {
	Field  string
	Reason string
}

func (e ErrInvalidInput) Error() string {
	return fmt.Sprintf("smc: invalid %s: %s", e.Field, e.Reason)
}

// ErrTransport wraps a network-level error.
type ErrTransport struct {
	Op    string
	Cause error
}

func (e ErrTransport) Error() string {
	return fmt.Sprintf("smc: %s: %v", e.Op, e.Cause)
}

func (e ErrTransport) Unwrap() error { return e.Cause }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
